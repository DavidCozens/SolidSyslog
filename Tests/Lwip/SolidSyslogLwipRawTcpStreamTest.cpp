#include <stddef.h>
#include <stdint.h>

#include "TestUtils.h"
#include "CppUTest/TestHarness.h"

using namespace CososoTesting;

#include <string.h>

#include "ConfigLockFake.h"
#include "ErrorHandlerFake.h"
#include "LwipFakeMarshalGuard.h"
#include "LwipPbufFake.h"
#include "LwipTcpFake.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogLwipRawAddress.h"
#include "SolidSyslogLwipRawAddressPrivate.h"
#include "SolidSyslogLwipRawTcpStream.h"
#include "SolidSyslogLwipRawTcpStreamErrors.h"
#include "SolidSyslogNullStream.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogStreamDefinition.h"
#include "SolidSyslogTunables.h"
#include "lwip/err.h"
#include "lwip/ip.h"
#include "lwip/ip4_addr.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/tcpbase.h"

static const uint16_t TEST_PORT = 514;

// Asserts handle is non-null and not one of the slots in pool.
#define CHECK_IS_FALLBACK(handle, pool)                                                \
    {                                                                                  \
        CHECK_TEXT((handle) != nullptr, "Fallback handle was nullptr");                \
        for (auto* slot : (pool))                                                      \
        {                                                                              \
            CHECK_TEXT(slot != nullptr, "pool slot was nullptr (FillPool failed?)");   \
            CHECK_TEXT((handle) != slot, "Fallback handle collided with a pool slot"); \
        }                                                                              \
    }

// Asserts the most recent ErrorHandlerFake call matched (severity, source, code).
#define CHECK_REPORTED(severity, source, expectedCategory, code) \
    CHECK_ERROR_REPORTED_ONCE((severity), &(source), (expectedCategory), (code))

// Asserts the lwIP API call recorded the pcb the wrapper got back from
// tcp_new - proves the wrapper forwarded the right handle. `getter` is
// the LwipTcpFake_LastXxxPcb accessor function (zero-arg).
// clang-format off
#define CHECK_FORWARDED_PCB(getter) POINTERS_EQUAL(LwipTcpFake_LastTcpNewReturned(), getter())
// clang-format on

namespace
{
unsigned FakeSleep_CallCount = 0;
int FakeSleep_LastMs = 0;

void FakeSleep_Reset()
{
    FakeSleep_CallCount = 0;
    FakeSleep_LastMs = 0;
}

extern "C" void FakeSleep(int milliseconds)
{
    FakeSleep_CallCount++;
    FakeSleep_LastMs = milliseconds;
}

unsigned FakeGetConnectTimeoutMs_CallCount = 0;
void* FakeGetConnectTimeoutMs_LastContext = nullptr;
uint32_t FakeGetConnectTimeoutMs_ReturnValue = SOLIDSYSLOG_TCP_CONNECT_TIMEOUT_MS;

void FakeGetConnectTimeoutMs_Reset()
{
    FakeGetConnectTimeoutMs_CallCount = 0;
    FakeGetConnectTimeoutMs_LastContext = reinterpret_cast<void*>(0x1U);
    FakeGetConnectTimeoutMs_ReturnValue = SOLIDSYSLOG_TCP_CONNECT_TIMEOUT_MS;
}

extern "C" uint32_t FakeGetConnectTimeoutMs(void* context)
{
    FakeGetConnectTimeoutMs_CallCount++;
    FakeGetConnectTimeoutMs_LastContext = context;
    return FakeGetConnectTimeoutMs_ReturnValue;
}
} // namespace

/* Shared fixture: every TcpStream lifecycle test needs the fakes reset, a
 * fresh stream + address handle pair, teardown of both, and the leak
 * invariant - every tcp_pcb handed out by tcp_new must come back via
 * tcp_close / tcp_abort / null-via-tcp_err by the end of the test. */
// clang-format off
TEST_BASE(LwipRawTcpStreamTestBase)
{
    struct SolidSyslogLwipRawTcpStreamConfig config{};
    struct SolidSyslogStream* stream = nullptr;
    struct SolidSyslogAddress* address = nullptr;
    char sendBuffer[16] = {};
    char readBuffer[16] = {};

    void createFakesAndHandles()
    {
        LwipTcpFake_Reset();
        LwipPbufFake_Reset();
        FakeSleep_Reset();
        FakeGetConnectTimeoutMs_Reset();
        LwipFakeMarshalGuard_Reset();
        SolidSyslogLwipRaw_SetMarshal(LwipFakeMarshalGuard_TrackingMarshal);
        config = {};
        config.Sleep = FakeSleep;
        stream = SolidSyslogLwipRawTcpStream_Create(&config);
        address = SolidSyslogLwipRawAddress_Create();
        struct SolidSyslogLwipRawAddress* lwipAddress = SolidSyslogLwipRawAddress_As(address);
        IP4_ADDR(&lwipAddress->Ip, 127, 0, 0, 1);
        lwipAddress->Port = TEST_PORT;
    }

    void destroyHandlesAndCheckNoLeak() const
    {
        SolidSyslogLwipRawAddress_Destroy(address);
        SolidSyslogLwipRawTcpStream_Destroy(stream);
        LONGS_EQUAL_TEXT(0, LwipTcpFake_OutstandingPcbCount(), "leaked tcp_pcb past teardown");
        LONGS_EQUAL_TEXT(0, LwipPbufFake_OutstandingPbufCount(), "leaked pbuf past teardown");
        LwipFakeMarshalGuard_CheckNoBreach();
        SolidSyslogLwipRaw_SetMarshal(nullptr);
    }

    /* Send through the abstract base against the shared sendBuffer. Default
     * length 1 covers the lifecycle / pcb-forwarding tests that don't care
     * about content; size-specific tests pass it explicitly. */
    [[nodiscard]] bool sendBytes(size_t length = 1U) const
    {
        return SolidSyslogStream_Send(stream, sendBuffer, length);
    }

    /* Read through the abstract base into the shared readBuffer. Default
     * capacity is the full buffer; partial-drain tests pass it explicitly. */
    [[nodiscard]] SolidSyslogSsize readBytes(size_t capacity = sizeof(readBuffer))
    {
        return SolidSyslogStream_Read(stream, readBuffer, capacity);
    }

    /* Drive the wrapper's tcp_recv callback with a fabricated incoming
     * pbuf. Caller supplies stack storage for the pbuf so multi-pbuf
     * tests can verify queue head advancement by pointer identity.
     * Returns the err_t the wrapper's callback returned - ERR_OK means
     * the wrapper took ownership of the pbuf (leak counter bumped here);
     * non-ERR_OK means lwIP retains the pbuf and the counter stays put,
     * so backpressure tests can pin the contract without imbalance. */
    static err_t pushIncomingPbuf(struct pbuf* p, const void* data, uint16_t len)
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) -- pbuf->payload is void*; tests pass string literals
        p->payload = const_cast<void*>(data);
        p->len = len;
        p->tot_len = len;
        p->next = nullptr;
        tcp_recv_fn recvCb = LwipTcpFake_LastRecvFn();
        err_t result = recvCb(LwipTcpFake_LastCallbackArg(), LwipTcpFake_LastTcpNewReturned(), p, ERR_OK);
        if (result == ERR_OK)
        {
            LwipPbufFake_NoteIncomingPbuf();
        }
        return result;
    }

    /* Drive the wrapper's tcp_recv callback with a fabricated TWO-link pbuf
     * chain (head -> tail), as lwIP delivers whenever a segment spans more
     * than one pool pbuf (tot_len > len). The head's tot_len spans both
     * links so the wrapper must walk head->next to recover every byte.
     * Same ownership / leak-balance contract as pushIncomingPbuf. */
    static err_t pushIncomingChain(
        struct pbuf* head,
        const void* headData,
        uint16_t headLen,
        struct pbuf* tail,
        const void* tailData,
        uint16_t tailLen
    )
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) -- pbuf->payload is void*; tests pass string literals
        tail->payload = const_cast<void*>(tailData);
        tail->len = tailLen;
        tail->tot_len = tailLen;
        tail->next = nullptr;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) -- pbuf->payload is void*; tests pass string literals
        head->payload = const_cast<void*>(headData);
        head->len = headLen;
        head->tot_len = static_cast<uint16_t>(headLen + tailLen);
        head->next = tail;
        tcp_recv_fn recvCb = LwipTcpFake_LastRecvFn();
        err_t result = recvCb(LwipTcpFake_LastCallbackArg(), LwipTcpFake_LastTcpNewReturned(), head, ERR_OK);
        if (result == ERR_OK)
        {
            LwipPbufFake_NoteIncomingPbuf();
        }
        return result;
    }

    /* Drive the wrapper's tcp_recv callback with NULL p - peer half-close
     * (FIN). lwIP retains the pcb; only the receive half is gone. */
    static void pushPeerFin()
    {
        tcp_recv_fn recvCb = LwipTcpFake_LastRecvFn();
        (void) recvCb(LwipTcpFake_LastCallbackArg(), LwipTcpFake_LastTcpNewReturned(), nullptr, ERR_OK);
    }

    /* Drive the wrapper's tcp_err callback - lwIP releases the pcb
     * upstream before this fires, so the leak invariant needs the
     * matching NotePcbReleasedByErr. */
    static void pushTcpErr(int8_t err)
    {
        tcp_err_fn errCb = LwipTcpFake_LastErrFn();
        errCb(LwipTcpFake_LastCallbackArg(), (err_t) err);
        LwipTcpFake_NotePcbReleasedByErr();
    }
};

TEST_GROUP_BASE(SolidSyslogLwipRawTcpStream, LwipRawTcpStreamTestBase)
{
    void setup() override
    {
        createFakesAndHandles();
    }

    void teardown() override
    {
        destroyHandlesAndCheckNoLeak();
    }
};

TEST_GROUP_BASE(SolidSyslogLwipRawTcpStreamConnected, LwipRawTcpStreamTestBase)
{
    void setup() override
    {
        createFakesAndHandles();
        SolidSyslogStream_Open(stream, address);
    }

    void teardown() override
    {
        destroyHandlesAndCheckNoLeak();
    }
};
// clang-format on

/* ------------------------------------------------------------------
 * Created-but-not-opened tests
 * ----------------------------------------------------------------*/

TEST(SolidSyslogLwipRawTcpStream, CreateReturnsNonNullStream)
{
    CHECK(stream != nullptr);
}

TEST(SolidSyslogLwipRawTcpStream, CreatedStreamIsNotTheNullStreamSingleton)
{
    CHECK(stream != SolidSyslogNullStream_Get());
}

TEST(SolidSyslogLwipRawTcpStream, DestroyReleasesSlotToPool)
{
    SolidSyslogLwipRawTcpStream_Destroy(stream);

    stream = SolidSyslogLwipRawTcpStream_Create(&config);

    CHECK(stream != SolidSyslogNullStream_Get());
}

TEST(SolidSyslogLwipRawTcpStream, CreateWithNullConfigReturnsFallback)
{
    struct SolidSyslogStream* fallback = SolidSyslogLwipRawTcpStream_Create(nullptr);

    POINTERS_EQUAL(SolidSyslogNullStream_Get(), fallback);
}

TEST(SolidSyslogLwipRawTcpStream, CreateWithNullSleepReturnsFallback)
{
    struct SolidSyslogLwipRawTcpStreamConfig badConfig{};
    badConfig.Sleep = nullptr;

    struct SolidSyslogStream* fallback = SolidSyslogLwipRawTcpStream_Create(&badConfig);

    POINTERS_EQUAL(SolidSyslogNullStream_Get(), fallback);
}

TEST(SolidSyslogLwipRawTcpStream, CloseBeforeOpenIsNoOp)
{
    SolidSyslogStream_Close(stream);

    CALLED_FAKE(LwipTcpFake_TcpClose, NEVER);
    CALLED_FAKE(LwipTcpFake_TcpAbort, NEVER);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, CloseDetachesTheStreamFromThePcbItCloses)
{
    SolidSyslogStream_Close(stream);

    POINTERS_EQUAL(nullptr, LwipTcpFake_LastCallbackArg());
    CHECK_TRUE(LwipTcpFake_LastErrFn() == nullptr);
    CHECK_TRUE(LwipTcpFake_LastRecvFn() == nullptr);
    CHECK_TRUE(LwipTcpFake_LastSentFn() == nullptr);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, CloseAbortsThePcbWhenTheCloseCannotBeQueued)
{
    LwipTcpFake_SetTcpCloseError(ERR_MEM);

    SolidSyslogStream_Close(stream);

    CALLED_FAKE(LwipTcpFake_TcpAbort, ONCE);
}

TEST(SolidSyslogLwipRawTcpStream, SendBeforeOpenReturnsFalse)
{
    CHECK_FALSE(sendBytes());
    CALLED_FAKE(LwipTcpFake_TcpWrite, NEVER);
}

TEST(SolidSyslogLwipRawTcpStream, ReadBeforeOpenReturnsMinusOne)
{
    LONGS_EQUAL(-1, readBytes());
}

TEST(SolidSyslogLwipRawTcpStream, OpenCallsTcpNew)
{
    SolidSyslogStream_Open(stream, address);

    CALLED_FAKE(LwipTcpFake_TcpNew, ONCE);
}

TEST(SolidSyslogLwipRawTcpStream, OpenReturnsTrueOnSuccessfulConnect)
{
    CHECK_TRUE(SolidSyslogStream_Open(stream, address));
}

TEST(SolidSyslogLwipRawTcpStream, OpenReturnsFalseWhenTcpNewFails)
{
    LwipTcpFake_SetTcpNewFails(true);

    CHECK_FALSE(SolidSyslogStream_Open(stream, address));
    CALLED_FAKE(LwipTcpFake_TcpConnect, NEVER);
}

TEST(SolidSyslogLwipRawTcpStream, OpenSetsKeepaliveOnPcb)
{
    SolidSyslogStream_Open(stream, address);

    CHECK((LwipTcpFake_LastTcpNewReturned()->so_options & SOF_KEEPALIVE) != 0);
}

// Nagle is disabled (TF_NODELAY set) so small, un-pipelined writes - octet-framed
// records, and the multi-segment handshake flights of a stacked TLS layer - go out
// immediately instead of being held until the previous segment is ACKed (which
// deadlocks a TLS handshake mid-flight against a peer that ACKs per-flight).
TEST(SolidSyslogLwipRawTcpStream, OpenDisablesNagleOnPcb)
{
    SolidSyslogStream_Open(stream, address);

    CHECK((LwipTcpFake_LastTcpNewReturned()->flags & TF_NODELAY) != 0);
}

TEST(SolidSyslogLwipRawTcpStream, OpenRegistersTcpArgRecvErrSentCallbacks)
{
    SolidSyslogStream_Open(stream, address);

    CALLED_FAKE(LwipTcpFake_TcpArg, ONCE);
    CALLED_FAKE(LwipTcpFake_TcpRecv, ONCE);
    CALLED_FAKE(LwipTcpFake_TcpErr, ONCE);
    CALLED_FAKE(LwipTcpFake_TcpSent, ONCE);
    CHECK(LwipTcpFake_LastRecvFn() != nullptr);
    CHECK(LwipTcpFake_LastErrFn() != nullptr);
    CHECK(LwipTcpFake_LastSentFn() != nullptr);
    CHECK(LwipTcpFake_LastCallbackArg() != nullptr);
}

TEST(SolidSyslogLwipRawTcpStream, OpenCallsTcpConnectWithAddressIpAndPort)
{
    SolidSyslogStream_Open(stream, address);

    CALLED_FAKE(LwipTcpFake_TcpConnect, ONCE);
    CHECK_FORWARDED_PCB(LwipTcpFake_LastConnectPcb);
    POINTERS_EQUAL(&SolidSyslogLwipRawAddress_AsConst(address)->Ip, LwipTcpFake_LastConnectIpaddr());
    LONGS_EQUAL(TEST_PORT, LwipTcpFake_LastConnectPort());
    CHECK(LwipTcpFake_LastConnectedFn() != nullptr);
}

TEST(SolidSyslogLwipRawTcpStream, OpenReturnsFalseAndAbortsWhenConnectedCallbackFiresErrored)
{
    LwipTcpFake_SetConnectCallbackResult(ERR_RST);

    CHECK_FALSE(SolidSyslogStream_Open(stream, address));
    CALLED_FAKE(LwipTcpFake_TcpAbort, ONCE);
    CALLED_FAKE(LwipTcpFake_TcpClose, NEVER);
}

TEST(SolidSyslogLwipRawTcpStream, OpenReturnsFalseAndAbortsOnImmediateTcpConnectError)
{
    LwipTcpFake_SetTcpConnectError(ERR_VAL);

    CHECK_FALSE(SolidSyslogStream_Open(stream, address));
    CALLED_FAKE(LwipTcpFake_TcpAbort, ONCE);
    CALLED_FAKE(LwipTcpFake_TcpClose, NEVER);
}

TEST(SolidSyslogLwipRawTcpStream, OpenReturnsFalseAndAbortsOnConnectTimeout)
{
    LwipTcpFake_SetConnectCallbackFires(false);

    CHECK_FALSE(SolidSyslogStream_Open(stream, address));
    CALLED_FAKE(LwipTcpFake_TcpAbort, ONCE);
    CALLED_FAKE(LwipTcpFake_TcpClose, NEVER);
}

TEST(SolidSyslogLwipRawTcpStream, OpenSleepsBetweenPollsDuringTimeoutPath)
{
    LwipTcpFake_SetConnectCallbackFires(false);

    SolidSyslogStream_Open(stream, address);

    /* timeout / poll periods -> exactly that many sleeps before giving up. */
    LONGS_EQUAL(SOLIDSYSLOG_TCP_CONNECT_TIMEOUT_MS / SOLIDSYSLOG_LWIP_RAW_TCP_CONNECT_POLL_MS, FakeSleep_CallCount);
    LONGS_EQUAL(SOLIDSYSLOG_LWIP_RAW_TCP_CONNECT_POLL_MS, FakeSleep_LastMs);
}

TEST(SolidSyslogLwipRawTcpStream, OpenHappyPathDoesNotSleep)
{
    SolidSyslogStream_Open(stream, address);

    LONGS_EQUAL(0, FakeSleep_CallCount);
}

TEST(SolidSyslogLwipRawTcpStream, OpenRespectsRuntimeTunableConnectTimeout)
{
    LwipTcpFake_SetConnectCallbackFires(false);
    /* Re-create the stream with a getter installed. The default fixture's
     * stream uses NULL getter (falls back to the compile-time tunable);
     * we want to verify the getter is honoured on the timeout deadline. */
    SolidSyslogLwipRawTcpStream_Destroy(stream);
    config.GetConnectTimeoutMs = FakeGetConnectTimeoutMs;
    config.ConnectTimeoutContext = reinterpret_cast<void*>(0xABCDU);
    FakeGetConnectTimeoutMs_ReturnValue = 20U;
    stream = SolidSyslogLwipRawTcpStream_Create(&config);

    SolidSyslogStream_Open(stream, address);

    /* 20 ms / 10 ms poll = 2 polls. */
    LONGS_EQUAL(2, FakeSleep_CallCount);
    CHECK(FakeGetConnectTimeoutMs_CallCount >= 1U);
    POINTERS_EQUAL(reinterpret_cast<void*>(0xABCDU), FakeGetConnectTimeoutMs_LastContext);
}

/* ------------------------------------------------------------------
 * Open-already-called tests
 * ----------------------------------------------------------------*/

TEST(SolidSyslogLwipRawTcpStreamConnected, ReopenDoesNotAllocateNewPcb)
{
    CHECK_TRUE(SolidSyslogStream_Open(stream, address));

    CALLED_FAKE(LwipTcpFake_TcpNew, ONCE);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, CloseCallsTcpCloseOnOpenPcb)
{
    SolidSyslogStream_Close(stream);

    CALLED_FAKE(LwipTcpFake_TcpClose, ONCE);
    CHECK_FORWARDED_PCB(LwipTcpFake_LastClosePcb);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, SecondCloseDoesNotCloseAgain)
{
    SolidSyslogStream_Close(stream);

    SolidSyslogStream_Close(stream);

    CALLED_FAKE(LwipTcpFake_TcpClose, ONCE);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, CloseThenOpenAllocatesFreshPcb)
{
    SolidSyslogStream_Close(stream);

    SolidSyslogStream_Open(stream, address);

    CALLED_FAKE(LwipTcpFake_TcpNew, TWICE);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, DestroyClosesOpenPcb)
{
    SolidSyslogLwipRawTcpStream_Destroy(stream);
    stream = nullptr;

    CALLED_FAKE(LwipTcpFake_TcpClose, ONCE);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, DestroyAfterCloseDoesNotCloseAgain)
{
    SolidSyslogStream_Close(stream);

    SolidSyslogLwipRawTcpStream_Destroy(stream);
    stream = nullptr;

    CALLED_FAKE(LwipTcpFake_TcpClose, ONCE);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, TcpErrCallbackReleasesPcbWithoutCallingTcpClose)
{
    /* Drive the err callback the wrapper registered. lwIP releases the
     * pcb upstream before invoking err - the wrapper must null its Pcb
     * field and NOT call tcp_close (use-after-free). */
    pushTcpErr(ERR_RST);

    SolidSyslogStream_Close(stream);

    CALLED_FAKE(LwipTcpFake_TcpClose, NEVER);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, SentCallbackReturnsErrOkAsNoOpStub)
{
    /* TCP_WRITE_FLAG_COPY means caller buffers are released at Send return -
     * no per-ACK accounting needed. The slot exists because lwIP wants the
     * callback set when the pcb is wired. */
    tcp_sent_fn sentCb = LwipTcpFake_LastSentFn();

    LONGS_EQUAL(ERR_OK, sentCb(LwipTcpFake_LastCallbackArg(), LwipTcpFake_LastTcpNewReturned(), 0));
}

TEST(SolidSyslogLwipRawTcpStreamConnected, DestroyAfterTcpErrDoesNotCallTcpClose)
{
    pushTcpErr(ERR_RST);

    SolidSyslogLwipRawTcpStream_Destroy(stream);
    stream = nullptr;

    CALLED_FAKE(LwipTcpFake_TcpClose, NEVER);
}

/* ------------------------------------------------------------------
 * Send tests
 * ----------------------------------------------------------------*/

TEST(SolidSyslogLwipRawTcpStreamConnected, SendCallsTcpWriteWithCopyFlagAndSize)
{
    memcpy(sendBuffer, "hello", 5);

    (void) sendBytes(5);

    CALLED_FAKE(LwipTcpFake_TcpWrite, ONCE);
    CHECK_FORWARDED_PCB(LwipTcpFake_LastWritePcb);
    POINTERS_EQUAL(sendBuffer, LwipTcpFake_LastWriteDataptr());
    LONGS_EQUAL(5, LwipTcpFake_LastWriteLength());
    LONGS_EQUAL(TCP_WRITE_FLAG_COPY, LwipTcpFake_LastWriteApiFlags());
}

TEST(SolidSyslogLwipRawTcpStreamConnected, SendCallsTcpOutputAfterTcpWrite)
{
    (void) sendBytes();

    CALLED_FAKE(LwipTcpFake_TcpOutput, ONCE);
    CHECK_FORWARDED_PCB(LwipTcpFake_LastOutputPcb);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, SendReturnsTrueOnTcpWriteAndOutputOk)
{
    CHECK_TRUE(sendBytes());
}

TEST(SolidSyslogLwipRawTcpStreamConnected, SendReturnsFalseAndClosesOnTcpWriteFails)
{
    LwipTcpFake_SetTcpWriteError(ERR_MEM);

    CHECK_FALSE(sendBytes());
    CALLED_FAKE(LwipTcpFake_TcpOutput, NEVER);
    CALLED_FAKE(LwipTcpFake_TcpClose, ONCE);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, SendReturnsTrueWhenTcpOutputDefersWithErrMem)
{
    /* tcp_write succeeded -> data is in pcb->snd_buf; ERR_MEM from
     * tcp_output just means lwIP will retry on the next tcp_tmr tick.
     * lwIP owns the bytes, so the wrapper reports success (mirrors POSIX's
     * "kernel accepted into send buffer" semantics). */
    LwipTcpFake_SetTcpOutputError(ERR_MEM);

    CHECK_TRUE(sendBytes());
    CALLED_FAKE(LwipTcpFake_TcpClose, NEVER);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, SendReturnsFalseAndClosesOnTcpOutputOtherError)
{
    LwipTcpFake_SetTcpOutputError(ERR_CONN);

    CHECK_FALSE(sendBytes());
    CALLED_FAKE(LwipTcpFake_TcpClose, ONCE);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, SendAfterTcpErrReturnsFalse)
{
    pushTcpErr(ERR_RST);

    CHECK_FALSE(sendBytes());
    CALLED_FAKE(LwipTcpFake_TcpWrite, NEVER);
}

/* ------------------------------------------------------------------
 * Read tests + RX queue behaviour
 * ----------------------------------------------------------------*/

TEST(SolidSyslogLwipRawTcpStreamConnected, ReadReturnsZeroWhenQueueEmpty)
{
    /* Would-block semantic - keeps the connection alive. */
    LONGS_EQUAL(0, readBytes());
    CALLED_FAKE(LwipTcpFake_TcpClose, NEVER);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, ReadDrainsHeadPbufAndAcksWithTcpRecved)
{
    struct pbuf p = {};
    const char data[] = "ack";
    pushIncomingPbuf(&p, data, sizeof(data) - 1);

    SolidSyslogSsize n = readBytes();

    LONGS_EQUAL(3, n);
    MEMCMP_EQUAL(data, readBuffer, 3);
    CALLED_FAKE(LwipTcpFake_TcpRecved, ONCE);
    LONGS_EQUAL(3, LwipTcpFake_LastRecvedLen());
    CHECK_FORWARDED_PCB(LwipTcpFake_LastRecvedPcb);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, ReadFreesPbufWhenFullyDrained)
{
    struct pbuf p = {};
    const char data[] = "x";
    pushIncomingPbuf(&p, data, 1);

    (void) readBytes();

    CALLED_FAKE(LwipPbufFake_PbufFree, ONCE);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, ReadReturnsPartialWhenBufferSmallerThanHeadPbuf)
{
    struct pbuf p = {};
    const char data[] = "abcde";
    pushIncomingPbuf(&p, data, 5);

    SolidSyslogSsize first = readBytes(2);

    LONGS_EQUAL(2, first);
    MEMCMP_EQUAL("ab", readBuffer, 2);
    /* Head not yet drained - pbuf still queued. */
    CALLED_FAKE(LwipPbufFake_PbufFree, NEVER);

    SolidSyslogSsize second = readBytes();

    LONGS_EQUAL(3, second);
    MEMCMP_EQUAL("cde", readBuffer, 3);
    CALLED_FAKE(LwipPbufFake_PbufFree, ONCE);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, ReadAdvancesPastDrainedPbufToNextInQueue)
{
    struct pbuf p1 = {};
    struct pbuf p2 = {};
    const char d1[] = "AA";
    const char d2[] = "BB";
    pushIncomingPbuf(&p1, d1, 2);
    pushIncomingPbuf(&p2, d2, 2);

    SolidSyslogSsize n1 = readBytes();
    SolidSyslogSsize n2 = readBytes();

    LONGS_EQUAL(2, n1);
    LONGS_EQUAL(2, n2);
    /* Both pbufs were freed as each was drained. */
    LONGS_EQUAL(2, LwipPbufFake_PbufFreeCallCount());
}

TEST(SolidSyslogLwipRawTcpStreamConnected, ReadDrainsEveryLinkOfAChainedPbuf)
{
    struct pbuf link1 = {};
    struct pbuf link2 = {};
    pushIncomingChain(&link1, "AB", 2, &link2, "CD", 2);

    SolidSyslogSsize n = readBytes();

    LONGS_EQUAL(4, n);
    MEMCMP_EQUAL("ABCD", readBuffer, 4);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, ReadAcrossChainedPbufLinkBoundaryPreservesByteOrder)
{
    struct pbuf link1 = {};
    struct pbuf link2 = {};
    pushIncomingChain(&link1, "AB", 2, &link2, "CD", 2);

    /* A 3-byte read straddles the link boundary - two bytes from link1, one
     * from link2 - and the chain is not yet fully drained. */
    SolidSyslogSsize first = readBytes(3);

    LONGS_EQUAL(3, first);
    MEMCMP_EQUAL("ABC", readBuffer, 3);
    CALLED_FAKE(LwipPbufFake_PbufFree, NEVER);

    /* The final byte comes from the tail link; the whole chain frees once. */
    SolidSyslogSsize second = readBytes();

    LONGS_EQUAL(1, second);
    MEMCMP_EQUAL("D", readBuffer, 1);
    CALLED_FAKE(LwipPbufFake_PbufFree, ONCE);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, ReadReportsOnlyBytesActuallyCopiedWhenTotLenOverstatesChain)
{
    /* A malformed pbuf: tot_len claims 4 bytes but the single link holds only
     * 2 and there is no next link. The drain must report what lwIP actually
     * copied (2), never the phantom tail the overstated tot_len implies -
     * advancing past un-copied bytes would feed stale buffer content to a
     * stacked TLS record stream. */
    struct pbuf link = {};
    const char data[] = "AB";
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) -- pbuf->payload is void*; tests pass string literals
    link.payload = const_cast<void*>(static_cast<const void*>(data));
    link.len = 2;
    link.tot_len = 4;
    link.next = nullptr;
    tcp_recv_fn recvCb = LwipTcpFake_LastRecvFn();
    (void) recvCb(LwipTcpFake_LastCallbackArg(), LwipTcpFake_LastTcpNewReturned(), &link, ERR_OK);
    LwipPbufFake_NoteIncomingPbuf();

    SolidSyslogSsize n = readBytes();

    LONGS_EQUAL(2, n);
    MEMCMP_EQUAL("AB", readBuffer, 2);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, SendReturnsFalseAfterPeerFin)
{
    pushPeerFin();

    /* A peer half-close (FIN) leaves the pcb alive but the connection doomed.
     * Send must report failure - without it the StreamSender keeps writing into
     * the dead connection and never reconnects after the server recovers. */
    CHECK_FALSE(sendBytes());
    CALLED_FAKE(LwipTcpFake_TcpWrite, NEVER);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, ReadReturnsMinusOneAfterPeerFinAndDrainsBeforeEof)
{
    struct pbuf p = {};
    const char data[] = "z";
    pushIncomingPbuf(&p, data, 1);
    pushPeerFin();

    /* Queued bytes drain first. */
    LONGS_EQUAL(1, readBytes());
    /* Then the next Read sees empty queue + Errored and returns -1, closing
     * the pcb internally per the Stream contract. */
    LONGS_EQUAL(-1, readBytes());
    CALLED_FAKE(LwipTcpFake_TcpClose, ONCE);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, ReadReturnsMinusOneAfterTcpErrWithoutQueuedData)
{
    pushTcpErr(ERR_RST);

    LONGS_EQUAL(-1, readBytes());
    /* Pcb already nulled by tcp_err - no tcp_close. */
    CALLED_FAKE(LwipTcpFake_TcpClose, NEVER);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, RecvCallbackBackpressuresWhenQueueFull)
{
    struct pbuf pbufs[SOLIDSYSLOG_LWIP_RAW_TCP_RX_QUEUE_SIZE] = {};
    for (auto& p : pbufs)
    {
        pushIncomingPbuf(&p, "1", 1);
    }

    /* Next pbuf - queue is full, callback returns non-ERR_OK and
     * pushIncomingPbuf's auto-balancing leaves the outstanding count
     * untouched so teardown's leak invariant still passes. */
    struct pbuf overflow = {};
    err_t result = pushIncomingPbuf(&overflow, "1", 1);

    CHECK(result != ERR_OK);
}

TEST(SolidSyslogLwipRawTcpStreamConnected, DestroyDrainsRxQueueOnCleanup)
{
    struct pbuf p1 = {};
    struct pbuf p2 = {};
    const char d[] = "xy";
    pushIncomingPbuf(&p1, d, 2);
    pushIncomingPbuf(&p2, d, 2);

    SolidSyslogLwipRawTcpStream_Destroy(stream);
    stream = nullptr;

    LONGS_EQUAL(2, LwipPbufFake_PbufFreeCallCount());
    /* Leak invariant (pinned in shared teardown) confirms both pbufs
     * were freed. */
}

TEST(SolidSyslogLwipRawTcpStreamConnected, CloseDrainsRxQueueBeforeTcpClose)
{
    struct pbuf p = {};
    const char d[] = "q";
    pushIncomingPbuf(&p, d, 1);

    SolidSyslogStream_Close(stream);

    CALLED_FAKE(LwipPbufFake_PbufFree, ONCE);
    CALLED_FAKE(LwipTcpFake_TcpClose, ONCE);
}

/* ------------------------------------------------------------------
 * Pool tests - handed-out handles never call lwIP, so they don't need
 * the fake state. Same TEST_GROUP shape as Commit 1.
 * ----------------------------------------------------------------*/

// clang-format off
TEST_GROUP(SolidSyslogLwipRawTcpStreamPool)
{
    struct SolidSyslogLwipRawTcpStreamConfig validConfig{};
    struct SolidSyslogStream* pooled[SOLIDSYSLOG_TCP_STREAM_POOL_SIZE] = {};
    struct SolidSyslogStream* overflow                                          = nullptr;

    void setup() override
    {
        LwipTcpFake_Reset();
        FakeSleep_Reset();
        validConfig = {};
        validConfig.Sleep = FakeSleep;
    }

    void teardown() override
    {
        for (auto* handle : pooled)
        {
            if (handle != nullptr)
            {
                SolidSyslogLwipRawTcpStream_Destroy(handle);
            }
        }
        if (overflow != nullptr)
        {
            SolidSyslogLwipRawTcpStream_Destroy(overflow);
        }
        ConfigLockFake_Uninstall();
    }

    void FillPool()
    {
        for (auto*& slot : pooled)
        {
            slot = SolidSyslogLwipRawTcpStream_Create(&validConfig);
        }
    }
};

// clang-format on

TEST(SolidSyslogLwipRawTcpStreamPool, FillingPoolThenOverflowReturnsDistinctFallback)
{
    FillPool();

    overflow = SolidSyslogLwipRawTcpStream_Create(&validConfig);

    CHECK_IS_FALLBACK(overflow, pooled);
}

TEST(SolidSyslogLwipRawTcpStreamPool, ExhaustedCreateReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    FillPool();

    overflow = SolidSyslogLwipRawTcpStream_Create(&validConfig);

    CHECK_REPORTED(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SolidSyslogLwipRawTcpStreamErrorSource,
        SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
        SOLIDSYSLOG_LWIPRAW_TCP_STREAM_ERROR_POOL_EXHAUSTED
    );
}

TEST(SolidSyslogLwipRawTcpStreamPool, CreateWithNullConfigReportsError)
{
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogLwipRawTcpStream_Create(nullptr);

    CHECK_REPORTED(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SolidSyslogLwipRawTcpStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_LWIPRAW_TCP_STREAM_ERROR_NULL_CONFIG
    );
}

TEST(SolidSyslogLwipRawTcpStreamPool, CreateWithNullSleepReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    validConfig.Sleep = nullptr;

    SolidSyslogLwipRawTcpStream_Create(&validConfig);

    CHECK_REPORTED(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SolidSyslogLwipRawTcpStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_LWIPRAW_TCP_STREAM_ERROR_NULL_SLEEP
    );
}

TEST(SolidSyslogLwipRawTcpStreamPool, FallbackVtableMethodsAreNoOps)
{
    FillPool();
    overflow = SolidSyslogLwipRawTcpStream_Create(&validConfig);
    char buffer[1] = {0};

    CHECK_TRUE(SolidSyslogStream_Open(overflow, nullptr));
    CHECK_TRUE(SolidSyslogStream_Send(overflow, "x", 1));
    LONGS_EQUAL(0, SolidSyslogStream_Read(overflow, buffer, sizeof(buffer)));
    SolidSyslogStream_Close(overflow);
}

TEST(SolidSyslogLwipRawTcpStreamPool, CreateAcquiresAndReleasesConfigLockOnFirstFreeSlot)
{
    ConfigLockFake_Install();

    pooled[0] = SolidSyslogLwipRawTcpStream_Create(&validConfig);

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogLwipRawTcpStreamPool, CreateLocksOncePerSlotProbedWhenPoolIsFull)
{
    FillPool();
    ConfigLockFake_Install();

    overflow = SolidSyslogLwipRawTcpStream_Create(&validConfig);

    LONGS_EQUAL(SOLIDSYSLOG_TCP_STREAM_POOL_SIZE, ConfigLockFake_LockCallCount());
    LONGS_EQUAL(SOLIDSYSLOG_TCP_STREAM_POOL_SIZE, ConfigLockFake_UnlockCallCount());
}

TEST(SolidSyslogLwipRawTcpStreamPool, DestroyOfPooledHandleLocksOnce)
{
    pooled[0] = SolidSyslogLwipRawTcpStream_Create(&validConfig);
    ConfigLockFake_Install();

    SolidSyslogLwipRawTcpStream_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogLwipRawTcpStreamPool, DestroyOfUnknownHandleDoesNotLock)
{
    ConfigLockFake_Install();
    struct SolidSyslogStream stranger = {};

    SolidSyslogLwipRawTcpStream_Destroy(&stranger);

    CALLED_FAKE(ConfigLockFake_Lock, NEVER);
    CALLED_FAKE(ConfigLockFake_Unlock, NEVER);
}

TEST(SolidSyslogLwipRawTcpStreamPool, DestroyOfUnknownHandleReportsWarning)
{
    ErrorHandlerFake_Install(nullptr);
    struct SolidSyslogStream stranger = {};

    SolidSyslogLwipRawTcpStream_Destroy(&stranger);

    CHECK_REPORTED(
        SOLIDSYSLOG_SEVERITY_WARNING,
        SolidSyslogLwipRawTcpStreamErrorSource,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_LWIPRAW_TCP_STREAM_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogLwipRawTcpStreamPool, DestroyOfStaleHandleReportsWarning)
{
    pooled[0] = SolidSyslogLwipRawTcpStream_Create(&validConfig);
    struct SolidSyslogStream* stale = pooled[0];
    SolidSyslogLwipRawTcpStream_Destroy(pooled[0]);
    pooled[0] = nullptr;
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogLwipRawTcpStream_Destroy(stale);

    CHECK_REPORTED(
        SOLIDSYSLOG_SEVERITY_WARNING,
        SolidSyslogLwipRawTcpStreamErrorSource,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_LWIPRAW_TCP_STREAM_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogLwipRawTcpStream, VersionIsAlwaysZeroBecauseNothingChangesAtRuntime)
{
    LONGS_EQUAL(0, SolidSyslogStream_Version(stream));
}
