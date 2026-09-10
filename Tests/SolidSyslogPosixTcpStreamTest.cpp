#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <stddef.h>
#include <stdint.h>
#include <cerrno>

#include "TestUtils.h"
#include "CppUTest/TestHarness.h"

using namespace CososoTesting;
#include "ConfigLockFake.h"
#include "ErrorHandlerFake.h"
#include "SocketFake.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogPosixAddress.h"
#include "SolidSyslogPosixAddressPrivate.h"
#include "SolidSyslogPosixTcpStream.h"
#include "SolidSyslogPosixTcpStreamErrors.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogStreamDefinition.h"
#include "SolidSyslogTransport.h"
#include "SolidSyslogTunables.h"

namespace
{
int FakeGetConnectTimeoutMs_CallCount = 0;
void* FakeGetConnectTimeoutMs_LastContext = nullptr;
uint32_t FakeGetConnectTimeoutMs_ReturnValue = 200U;

void FakeGetConnectTimeoutMs_Reset()
{
    FakeGetConnectTimeoutMs_CallCount = 0;
    FakeGetConnectTimeoutMs_LastContext = reinterpret_cast<void*>(0x1U); /* sentinel - overwritten on first call */
    FakeGetConnectTimeoutMs_ReturnValue = 200U;
}

extern "C" uint32_t FakeGetConnectTimeoutMs(void* context)
{
    FakeGetConnectTimeoutMs_CallCount++;
    FakeGetConnectTimeoutMs_LastContext = context;
    return FakeGetConnectTimeoutMs_ReturnValue;
}
} // namespace

// clang-format off
static const char* const TEST_MESSAGE     = "hello";
static const size_t      TEST_MESSAGE_LEN = 5;
static const char* const TEST_ADDRESS     = "127.0.0.1";
static const int         TEST_PORT        = 514;

TEST_GROUP(SolidSyslogPosixTcpStream)
{
    struct SolidSyslogStream* stream = nullptr;
    struct SolidSyslogAddress* addr = nullptr;

    void setup() override
    {
        SocketFake_Reset();
        FakeGetConnectTimeoutMs_Reset();
        stream                  = SolidSyslogPosixTcpStream_Create(nullptr);
        addr                    = SolidSyslogPosixAddress_Create();
        struct sockaddr_in* sin = SolidSyslogPosixAddress_AsSockaddrIn(addr);
        sin->sin_family         = AF_INET;
        sin->sin_port           = htons(TEST_PORT);
        inet_pton(AF_INET, TEST_ADDRESS, &sin->sin_addr);
    }

    void teardown() override
    {
        SolidSyslogPosixAddress_Destroy(addr);
        SolidSyslogPosixTcpStream_Destroy(stream);
    }

    [[nodiscard]] SolidSyslogSsize Read16ByteBuffer() const
    {
        char buf[16];
        return SolidSyslogStream_Read(stream, buf, sizeof(buf));
    }

    /* Replaces the default NULL-config stream with one that uses the fake
     * getter, then drives Open through the bounded-wait path. Each test sets
     * only the fake-getter return value (or context) it needs different from
     * the defaults restored in setup(). */
    void OpenStreamWithFakeGetter()
    {
        SolidSyslogPosixTcpStream_Destroy(stream);
        struct SolidSyslogPosixTcpStreamConfig config = {};
        config.GetConnectTimeoutMs                    = FakeGetConnectTimeoutMs;
        stream                                        = SolidSyslogPosixTcpStream_Create(&config);

        SocketFake_SetConnectFailsWithErrno(EINPROGRESS);
        SolidSyslogStream_Open(stream, addr);
    }
};

// clang-format on

#define CHECK_SOCKET_CLOSED_ONCE()                                     \
    {                                                                  \
        CALLED_FAKE(SocketFake_Close, ONCE);                           \
        LONGS_EQUAL(SocketFake_SocketFd(), SocketFake_LastClosedFd()); \
    }

TEST(SolidSyslogPosixTcpStream, CreateDestroyWorksWithoutCrashing)
{
}

TEST(SolidSyslogPosixTcpStream, OpenCallsSocketOnce)
{
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(SocketFake_Socket, ONCE);
}

TEST(SolidSyslogPosixTcpStream, OpenCallsSocketWithAF_INET)
{
    SolidSyslogStream_Open(stream, addr);
    LONGS_EQUAL(AF_INET, SocketFake_SocketDomain());
}

TEST(SolidSyslogPosixTcpStream, OpenCallsSocketWithSOCK_STREAM)
{
    SolidSyslogStream_Open(stream, addr);
    LONGS_EQUAL(SOCK_STREAM, SocketFake_SocketType());
}

TEST(SolidSyslogPosixTcpStream, OpenEnablesTcpNoDelay)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(SocketFake_HasSetSockOpt(IPPROTO_TCP, TCP_NODELAY));
}

TEST(SolidSyslogPosixTcpStream, OpenEnablesSoKeepalive)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(SocketFake_HasSetSockOpt(SOL_SOCKET, SO_KEEPALIVE));
    LONGS_EQUAL(1, SocketFake_LastSetSockOptValue(SOL_SOCKET, SO_KEEPALIVE));
}

TEST(SolidSyslogPosixTcpStream, OpenSetsTcpKeepIdleTo45Seconds)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(SocketFake_HasSetSockOpt(IPPROTO_TCP, TCP_KEEPIDLE));
    LONGS_EQUAL(45, SocketFake_LastSetSockOptValue(IPPROTO_TCP, TCP_KEEPIDLE));
}

TEST(SolidSyslogPosixTcpStream, OpenSetsTcpKeepIntvlTo10Seconds)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(SocketFake_HasSetSockOpt(IPPROTO_TCP, TCP_KEEPINTVL));
    LONGS_EQUAL(10, SocketFake_LastSetSockOptValue(IPPROTO_TCP, TCP_KEEPINTVL));
}

TEST(SolidSyslogPosixTcpStream, OpenSetsTcpKeepCntTo4)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(SocketFake_HasSetSockOpt(IPPROTO_TCP, TCP_KEEPCNT));
    LONGS_EQUAL(4, SocketFake_LastSetSockOptValue(IPPROTO_TCP, TCP_KEEPCNT));
}

TEST(SolidSyslogPosixTcpStream, OpenSetsTcpUserTimeoutTo30000Milliseconds)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(SocketFake_HasSetSockOpt(IPPROTO_TCP, TCP_USER_TIMEOUT));
    LONGS_EQUAL(30000, SocketFake_LastSetSockOptValue(IPPROTO_TCP, TCP_USER_TIMEOUT));
}

TEST(SolidSyslogPosixTcpStream, OpenSetsNonBlockingFlagBeforeConnect)
{
    SolidSyslogStream_Open(stream, addr);
    /* Non-blocking is set via fcntl(F_SETFL, ... | O_NONBLOCK) so connect()
       returns EINPROGRESS immediately and the caller can bound the wait. */
    CHECK_TRUE(SocketFake_FcntlSetFlSetNonBlocking());
}

TEST(SolidSyslogPosixTcpStream, OpenFailsWhenFcntlSetFlFails)
{
    /* If the kernel refuses to put the socket into non-blocking mode the
       caller cannot bound the connect wait - fail fast. */
    SocketFake_SetFcntlSetFlFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CALLED_FAKE(SocketFake_Close, ONCE);
}

TEST(SolidSyslogPosixTcpStream, OpenCallsConnectWithSocketFd)
{
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(SocketFake_Connect, ONCE);
    LONGS_EQUAL(SocketFake_SocketFd(), SocketFake_LastConnectFd());
}

TEST(SolidSyslogPosixTcpStream, OpenCallsConnectWithProvidedAddress)
{
    SolidSyslogStream_Open(stream, addr);
    LONGS_EQUAL(TEST_PORT, SocketFake_LastConnectPort());
    STRCMP_EQUAL(TEST_ADDRESS, SocketFake_LastConnectAddrAsString());
}

TEST(SolidSyslogPosixTcpStream, OpenReturnsTrueOnSuccess)
{
    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogPosixTcpStream, OpenReturnsFalseOnConnectFailure)
{
    SocketFake_SetConnectFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogPosixTcpStream, OpenReturnsFalseWhenSocketFails)
{
    SocketFake_SetSocketFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogPosixTcpStream, OpenSkipsConnectAndSetsockoptWhenSocketFails)
{
    SocketFake_SetSocketFails(true);
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(SocketFake_Connect, NEVER);
    CALLED_FAKE(SocketFake_SetSockOpt, NEVER);
}

TEST(SolidSyslogPosixTcpStream, SendReturnsFalseOnShortWrite)
{
    SolidSyslogStream_Open(stream, addr);
    SocketFake_SetSendReturn(3);
    CHECK_FALSE(SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN));
}

TEST(SolidSyslogPosixTcpStream, SendDoesNotRetryAfterShortWrite)
{
    SolidSyslogStream_Open(stream, addr);
    SocketFake_SetSendReturn(3);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    CALLED_FAKE(SocketFake_Send, ONCE);
}

TEST(SolidSyslogPosixTcpStream, SendReturnsFalseOnEintr)
{
    /* Non-blocking + fail-fast: any failure from a single send() call closes
       the socket and surfaces failure. EINTR is no longer retried. */
    SolidSyslogStream_Open(stream, addr);
    SocketFake_FailNextSendWithErrno(EINTR);
    CHECK_FALSE(SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN));
}

TEST(SolidSyslogPosixTcpStream, SendReturnsFalseOnEagain)
{
    SolidSyslogStream_Open(stream, addr);
    SocketFake_FailNextSendWithErrno(EAGAIN);
    CHECK_FALSE(SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN));
}

TEST(SolidSyslogPosixTcpStream, SendClosesSocketOnFailure)
{
    SolidSyslogStream_Open(stream, addr);
    SocketFake_SetSendFails(true);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    CHECK_SOCKET_CLOSED_ONCE();
}

TEST(SolidSyslogPosixTcpStream, OpenClosesSocketOnConnectFailure)
{
    SocketFake_SetConnectFails(true);
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(SocketFake_Close, ONCE);
    LONGS_EQUAL(SocketFake_SocketFd(), SocketFake_LastClosedFd());
}

TEST(SolidSyslogPosixTcpStream, SendCallsSendOnce)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    CALLED_FAKE(SocketFake_Send, ONCE);
}

TEST(SolidSyslogPosixTcpStream, SendPassesBuffer)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    STRCMP_EQUAL(TEST_MESSAGE, SocketFake_SendBufAsString(0));
}

TEST(SolidSyslogPosixTcpStream, SendPassesLength)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    LONGS_EQUAL(TEST_MESSAGE_LEN, SocketFake_SendLen(0));
}

TEST(SolidSyslogPosixTcpStream, SendPassesMSG_NOSIGNALFlag)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    LONGS_EQUAL(MSG_NOSIGNAL, SocketFake_SendFlags(0));
}

TEST(SolidSyslogPosixTcpStream, SendPassesSocketFd)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    LONGS_EQUAL(SocketFake_SocketFd(), SocketFake_LastSendFd());
}

TEST(SolidSyslogPosixTcpStream, SendReturnsTrueOnSuccess)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN));
}

TEST(SolidSyslogPosixTcpStream, SendReturnsFalseOnSendFailure)
{
    SolidSyslogStream_Open(stream, addr);
    SocketFake_SetSendFails(true);
    CHECK_FALSE(SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN));
}

TEST(SolidSyslogPosixTcpStream, CloseCallsCloseOnce)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Close(stream);
    CALLED_FAKE(SocketFake_Close, ONCE);
}

TEST(SolidSyslogPosixTcpStream, CloseCalledWithSocketFd)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Close(stream);
    LONGS_EQUAL(SocketFake_SocketFd(), SocketFake_LastClosedFd());
}

TEST(SolidSyslogPosixTcpStream, CloseIsNoOpWhenNotOpen)
{
    SolidSyslogStream_Close(stream);
    CALLED_FAKE(SocketFake_Close, NEVER);
}

TEST(SolidSyslogPosixTcpStream, ReadCallsRecvOnce)
{
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogStream_Read(stream, buf, sizeof(buf));
    CALLED_FAKE(SocketFake_Recv, ONCE);
}

TEST(SolidSyslogPosixTcpStream, ReadPassesSocketFdToRecv)
{
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogStream_Read(stream, buf, sizeof(buf));
    LONGS_EQUAL(SocketFake_SocketFd(), SocketFake_LastRecvFd());
}

TEST(SolidSyslogPosixTcpStream, ReadPassesBufferToRecv)
{
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogStream_Read(stream, buf, sizeof(buf));
    POINTERS_EQUAL(buf, SocketFake_LastRecvBuf());
}

TEST(SolidSyslogPosixTcpStream, ReadPassesLengthToRecv)
{
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogStream_Read(stream, buf, sizeof(buf));
    LONGS_EQUAL(sizeof(buf), SocketFake_LastRecvLen());
}

TEST(SolidSyslogPosixTcpStream, ReadPassesZeroFlagsToRecv)
{
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogStream_Read(stream, buf, sizeof(buf));
    LONGS_EQUAL(0, SocketFake_LastRecvFlags());
}

TEST(SolidSyslogPosixTcpStream, ReadReturnsRecvReturnValue)
{
    SocketFake_SetRecvReturn(7);
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogSsize n = SolidSyslogStream_Read(stream, buf, sizeof(buf));
    LONGS_EQUAL(7, n);
}

TEST(SolidSyslogPosixTcpStream, DestroyClosesOpenSocket)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogPosixTcpStream_Destroy(stream);
    CALLED_FAKE(SocketFake_Close, ONCE);
}

TEST(SolidSyslogPosixTcpStream, DestroyClosesWithSocketFd)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogPosixTcpStream_Destroy(stream);
    LONGS_EQUAL(SocketFake_SocketFd(), SocketFake_LastClosedFd());
}

TEST(SolidSyslogPosixTcpStream, DefaultPortMatchesRfc6587)
{
    LONGS_EQUAL(601, SOLIDSYSLOG_TCP_DEFAULT_PORT);
}

/* ----------------------------------------------------------------------
 * Non-blocking connect with bounded wait - keeps the service-thread drain
 * rate insensitive to a slow or refused peer.
 * -------------------------------------------------------------------- */

TEST(SolidSyslogPosixTcpStream, OpenSkipsSelectWhenConnectReturnsImmediately)
{
    /* Default fake connect returns 0 (immediate success); select must not be
       reached because connect short-circuits the wait. */
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(SocketFake_Select, NEVER);
}

TEST(SolidSyslogPosixTcpStream, OpenInvokesSelectWhenConnectReturnsEinprogress)
{
    SocketFake_SetConnectFailsWithErrno(EINPROGRESS);
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(SocketFake_Select, ONCE);
}

TEST(SolidSyslogPosixTcpStream, OpenPassesBoundedConnectTimeoutToSelect)
{
    SocketFake_SetConnectFailsWithErrno(EINPROGRESS);
    SolidSyslogStream_Open(stream, addr);
    /* Default tunable SOLIDSYSLOG_TCP_CONNECT_TIMEOUT_MS = 200 -> 0 s + 200 000 µs. */
    LONGS_EQUAL(0, SocketFake_LastSelectTimeoutSec());
    LONGS_EQUAL(200000, SocketFake_LastSelectTimeoutUsec());
}

TEST(SolidSyslogPosixTcpStream, OpenInvokesConfiguredConnectTimeoutGetter)
{
    OpenStreamWithFakeGetter();

    LONGS_EQUAL(1, FakeGetConnectTimeoutMs_CallCount);
}

TEST(SolidSyslogPosixTcpStream, OpenUsesGetterReturnValueAsConnectTimeout)
{
    FakeGetConnectTimeoutMs_ReturnValue = 1234U;

    OpenStreamWithFakeGetter();

    /* 1234 ms = 1 s + 234 000 µs. */
    LONGS_EQUAL(1, SocketFake_LastSelectTimeoutSec());
    LONGS_EQUAL(234000, SocketFake_LastSelectTimeoutUsec());
}

TEST(SolidSyslogPosixTcpStream, GetterReceivesNullContextWhenContextNotConfigured)
{
    OpenStreamWithFakeGetter();

    POINTERS_EQUAL(nullptr, FakeGetConnectTimeoutMs_LastContext);
}

TEST(SolidSyslogPosixTcpStream, OpenSucceedsWhenSelectReportsWritableAndZeroSO_ERROR)
{
    SocketFake_SetConnectFailsWithErrno(EINPROGRESS);
    SocketFake_SetSelectWritable(true);
    SocketFake_SetSoError(0);
    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogPosixTcpStream, OpenFailsWhenSelectReportsTimeout)
{
    SocketFake_SetConnectFailsWithErrno(EINPROGRESS);
    SocketFake_SetSelectWritable(false);
    SocketFake_SetSelectReturn(0);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogPosixTcpStream, OpenClosesSocketOnSelectTimeout)
{
    SocketFake_SetConnectFailsWithErrno(EINPROGRESS);
    SocketFake_SetSelectWritable(false);
    SocketFake_SetSelectReturn(0);
    SolidSyslogStream_Open(stream, addr);
    CHECK_SOCKET_CLOSED_ONCE();
}

TEST(SolidSyslogPosixTcpStream, OpenFailsWhenSelectFlagsErrorOnFd)
{
    SocketFake_SetConnectFailsWithErrno(EINPROGRESS);
    SocketFake_SetSelectWritable(false);
    SocketFake_SetSelectError(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogPosixTcpStream, OpenFailsWhenDeferredSO_ERRORIsNonZero)
{
    /* select reports writable, but SO_ERROR on the socket reveals the
       deferred connect failure (e.g. ECONNREFUSED). */
    SocketFake_SetConnectFailsWithErrno(EINPROGRESS);
    SocketFake_SetSelectWritable(true);
    SocketFake_SetSoError(ECONNREFUSED);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogPosixTcpStream, OpenReadsSO_ERRORAfterSelectWritable)
{
    SocketFake_SetConnectFailsWithErrno(EINPROGRESS);
    SolidSyslogStream_Open(stream, addr);
    LONGS_EQUAL(SOL_SOCKET, SocketFake_LastGetSockOptLevel());
    LONGS_EQUAL(SO_ERROR, SocketFake_LastGetSockOptOptname());
}

TEST(SolidSyslogPosixTcpStream, OpenFailsWhenConnectFailsImmediatelyWithRefused)
{
    /* Non-EINPROGRESS errors are immediate failures - no select wait, no
       SO_ERROR check, just fail fast. */
    SocketFake_SetConnectFailsWithErrno(ECONNREFUSED);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CALLED_FAKE(SocketFake_Select, NEVER);
}

TEST(SolidSyslogPosixTcpStream, OpenFailsWhenSO_ERRORLookupFails)
{
    SocketFake_SetConnectFailsWithErrno(EINPROGRESS);
    SocketFake_SetSelectWritable(true);
    SocketFake_SetSoErrorLookupFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

/* ----------------------------------------------------------------------
 * Non-blocking Read contract: bytes -> return them; nothing -> 0;
 * EOF/error -> close internally and return -1.
 * -------------------------------------------------------------------- */

TEST(SolidSyslogPosixTcpStream, ReadReturnsZeroOnEagain)
{
    SolidSyslogStream_Open(stream, addr);
    SocketFake_FailNextRecvWithErrno(EAGAIN);
    LONGS_EQUAL(0, Read16ByteBuffer());
}

TEST(SolidSyslogPosixTcpStream, ReadReturnsZeroOnWouldBlock)
{
    SolidSyslogStream_Open(stream, addr);
    SocketFake_FailNextRecvWithErrno(EWOULDBLOCK);
    LONGS_EQUAL(0, Read16ByteBuffer());
}

TEST(SolidSyslogPosixTcpStream, ReadReturnsNegativeOneOnEofAndClosesSocket)
{
    SolidSyslogStream_Open(stream, addr);
    SocketFake_SetRecvReturn(0); /* EOF */
    LONGS_EQUAL(-1, Read16ByteBuffer());
    CHECK_SOCKET_CLOSED_ONCE();
}

TEST(SolidSyslogPosixTcpStream, ReadReturnsNegativeOneOnErrorAndClosesSocket)
{
    SolidSyslogStream_Open(stream, addr);
    SocketFake_FailNextRecvWithErrno(ECONNRESET);
    LONGS_EQUAL(-1, Read16ByteBuffer());
    CHECK_SOCKET_CLOSED_ONCE();
}

#define CHECK_IS_FALLBACK(handle, pool)                                                \
    {                                                                                  \
        CHECK_TEXT((handle) != nullptr, "Fallback handle was nullptr");                \
        for (auto* slot : (pool))                                                      \
        {                                                                              \
            CHECK_TEXT(slot != nullptr, "pool slot was nullptr (FillPool failed?)");   \
            CHECK_TEXT((handle) != slot, "Fallback handle collided with a pool slot"); \
        }                                                                              \
    }

// clang-format off
TEST_GROUP(SolidSyslogPosixTcpStreamPool)
{
    struct SolidSyslogStream* pooled[SOLIDSYSLOG_TCP_STREAM_POOL_SIZE] = {};
    struct SolidSyslogStream* overflow                                       = nullptr;

    void teardown() override
    {
        for (auto* handle : pooled)
        {
            if (handle != nullptr)
            {
                SolidSyslogPosixTcpStream_Destroy(handle);
            }
        }
        if (overflow != nullptr)
        {
            SolidSyslogPosixTcpStream_Destroy(overflow);
        }
        ConfigLockFake_Uninstall();
    }

    void FillPool()
    {
        for (auto*& slot : pooled)
        {
            slot = SolidSyslogPosixTcpStream_Create(nullptr);
        }
    }
};

// clang-format on

TEST(SolidSyslogPosixTcpStreamPool, FillingPoolThenOverflowReturnsDistinctFallback)
{
    FillPool();

    overflow = SolidSyslogPosixTcpStream_Create(nullptr);

    CHECK_IS_FALLBACK(overflow, pooled);
}

TEST(SolidSyslogPosixTcpStreamPool, ExhaustedCreateReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    FillPool();

    overflow = SolidSyslogPosixTcpStream_Create(nullptr);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogPosixTcpStreamErrorSource,
        SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
        SOLIDSYSLOG_POSIX_TCP_STREAM_ERROR_POOL_EXHAUSTED
    );
}

TEST(SolidSyslogPosixTcpStreamPool, FallbackSendReturnsTrue)
{
    FillPool();
    overflow = SolidSyslogPosixTcpStream_Create(nullptr);

    CHECK_TRUE(SolidSyslogStream_Send(overflow, "x", 1));
}

TEST(SolidSyslogPosixTcpStreamPool, CreateAcquiresAndReleasesConfigLockOnFirstFreeSlot)
{
    ConfigLockFake_Install();

    pooled[0] = SolidSyslogPosixTcpStream_Create(nullptr);

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogPosixTcpStreamPool, CreateLocksOncePerSlotProbedWhenPoolIsFull)
{
    FillPool();
    ConfigLockFake_Install();

    overflow = SolidSyslogPosixTcpStream_Create(nullptr);

    LONGS_EQUAL(SOLIDSYSLOG_TCP_STREAM_POOL_SIZE, ConfigLockFake_LockCallCount());
    LONGS_EQUAL(SOLIDSYSLOG_TCP_STREAM_POOL_SIZE, ConfigLockFake_UnlockCallCount());
}

TEST(SolidSyslogPosixTcpStreamPool, DestroyOfPooledHandleLocksOnce)
{
    pooled[0] = SolidSyslogPosixTcpStream_Create(nullptr);
    ConfigLockFake_Install();

    SolidSyslogPosixTcpStream_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogPosixTcpStreamPool, DestroyOfUnknownHandleDoesNotLock)
{
    ConfigLockFake_Install();
    struct SolidSyslogStream stranger = {};

    SolidSyslogPosixTcpStream_Destroy(&stranger);

    CALLED_FAKE(ConfigLockFake_Lock, NEVER);
    CALLED_FAKE(ConfigLockFake_Unlock, NEVER);
}

TEST(SolidSyslogPosixTcpStreamPool, DestroyOfUnknownHandleReportsWarning)
{
    ErrorHandlerFake_Install(nullptr);
    struct SolidSyslogStream stranger = {};

    SolidSyslogPosixTcpStream_Destroy(&stranger);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogPosixTcpStreamErrorSource,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_POSIX_TCP_STREAM_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogPosixTcpStreamPool, DestroyOfStaleHandleReportsWarning)
{
    pooled[0] = SolidSyslogPosixTcpStream_Create(nullptr);
    SolidSyslogPosixTcpStream_Destroy(pooled[0]);
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogPosixTcpStream_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogPosixTcpStreamErrorSource,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_POSIX_TCP_STREAM_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogPosixTcpStream, VersionIsAlwaysZeroBecauseNothingChangesAtRuntime)
{
    LONGS_EQUAL(0, SolidSyslogStream_Version(stream));
}
