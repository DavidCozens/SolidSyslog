#include "TestUtils.h"
#include "CppUTest/TestHarness.h"

using namespace CososoTesting;
#include "ConfigLockFake.h"
#include "ErrorHandlerFake.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogStreamDefinition.h"
#include "SolidSyslogTransport.h"
#include "SolidSyslogTunables.h"
#include "SolidSyslogWinsockAddress.h"
#include "SolidSyslogWinsockAddressPrivate.h"
#include "SolidSyslogWinsockTcpStream.h"
#include "SolidSyslogWinsockTcpStreamErrors.h"
#include "SolidSyslogWinsockTcpStreamInternal.h"
#include "WinsockFake.h"
#include <cstdint>
#include <winsock2.h>
#include <ws2tcpip.h>

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

TEST_GROUP(SolidSyslogWinsockTcpStream)
{
    struct SolidSyslogStream* stream = nullptr;
    struct SolidSyslogAddress* addr = nullptr;

    void setup() override
    {
        WinsockFake_Reset();
        FakeGetConnectTimeoutMs_Reset();
        UT_PTR_SET(WinsockTcpStream_socket,           WinsockFake_socket);
        UT_PTR_SET(WinsockTcpStream_connect,          WinsockFake_connect);
        UT_PTR_SET(WinsockTcpStream_send,             WinsockFake_send);
        UT_PTR_SET(WinsockTcpStream_recv,             WinsockFake_recv);
        UT_PTR_SET(WinsockTcpStream_setsockopt,       WinsockFake_setsockopt);
        UT_PTR_SET(WinsockTcpStream_getsockopt,       WinsockFake_getsockopt);
        UT_PTR_SET(WinsockTcpStream_closesocket,      WinsockFake_closesocket);
        UT_PTR_SET(WinsockTcpStream_ioctlsocket,      WinsockFake_ioctlsocket);
        UT_PTR_SET(WinsockTcpStream_select,           WinsockFake_select);
        UT_PTR_SET(WinsockTcpStream_WSAGetLastError,  WinsockFake_WSAGetLastError);
        stream                  = SolidSyslogWinsockTcpStream_Create(nullptr);
        addr                    = SolidSyslogWinsockAddress_Create();
        struct sockaddr_in* sin = SolidSyslogWinsockAddress_AsSockaddrIn(addr);
        sin->sin_family         = AF_INET;
        sin->sin_port           = htons(TEST_PORT);
        inet_pton(AF_INET, TEST_ADDRESS, &sin->sin_addr);
    }

    void teardown() override
    {
        SolidSyslogWinsockAddress_Destroy(addr);
        SolidSyslogWinsockTcpStream_Destroy(stream);
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
        SolidSyslogWinsockTcpStream_Destroy(stream);
        struct SolidSyslogWinsockTcpStreamConfig config = {};
        config.GetConnectTimeoutMs                      = FakeGetConnectTimeoutMs;
        stream                                          = SolidSyslogWinsockTcpStream_Create(&config);

        WinsockFake_SetConnectFailsWithLastError(WSAEWOULDBLOCK);
        SolidSyslogStream_Open(stream, addr);
    }
};

// clang-format on

#define CHECK_SOCKET_CLOSED_ONCE()                                   \
    {                                                                \
        CALLED_FAKE(WinsockFake_Close, ONCE);                        \
        CHECK(WinsockFake_SocketFd() == WinsockFake_LastClosedFd()); \
    }

TEST(SolidSyslogWinsockTcpStream, CreateDestroyWorksWithoutCrashing)
{
}

TEST(SolidSyslogWinsockTcpStream, OpenCallsSocketOnce)
{
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(WinsockFake_Socket, ONCE);
}

TEST(SolidSyslogWinsockTcpStream, OpenCallsSocketWithAF_INET)
{
    SolidSyslogStream_Open(stream, addr);
    LONGS_EQUAL(AF_INET, WinsockFake_SocketDomain());
}

TEST(SolidSyslogWinsockTcpStream, OpenCallsSocketWithSOCK_STREAM)
{
    SolidSyslogStream_Open(stream, addr);
    LONGS_EQUAL(SOCK_STREAM, WinsockFake_SocketType());
}

TEST(SolidSyslogWinsockTcpStream, OpenEnablesTcpNoDelay)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(WinsockFake_HasSetSockOpt(IPPROTO_TCP, TCP_NODELAY));
}

TEST(SolidSyslogWinsockTcpStream, OpenEnablesSoKeepalive)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(WinsockFake_HasSetSockOpt(SOL_SOCKET, SO_KEEPALIVE));
    LONGS_EQUAL(1, WinsockFake_LastSetSockOptValue(SOL_SOCKET, SO_KEEPALIVE));
}

TEST(SolidSyslogWinsockTcpStream, OpenSetsTcpKeepIdleTo45Seconds)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(WinsockFake_HasSetSockOpt(IPPROTO_TCP, TCP_KEEPIDLE));
    LONGS_EQUAL(45, WinsockFake_LastSetSockOptValue(IPPROTO_TCP, TCP_KEEPIDLE));
}

TEST(SolidSyslogWinsockTcpStream, OpenSetsTcpKeepIntvlTo10Seconds)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(WinsockFake_HasSetSockOpt(IPPROTO_TCP, TCP_KEEPINTVL));
    LONGS_EQUAL(10, WinsockFake_LastSetSockOptValue(IPPROTO_TCP, TCP_KEEPINTVL));
}

TEST(SolidSyslogWinsockTcpStream, OpenSetsTcpKeepCntTo4)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(WinsockFake_HasSetSockOpt(IPPROTO_TCP, TCP_KEEPCNT));
    LONGS_EQUAL(4, WinsockFake_LastSetSockOptValue(IPPROTO_TCP, TCP_KEEPCNT));
}

TEST(SolidSyslogWinsockTcpStream, OpenCallsConnectWithSocketFd)
{
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(WinsockFake_Connect, ONCE);
    CHECK(WinsockFake_SocketFd() == WinsockFake_LastConnectFd());
}

TEST(SolidSyslogWinsockTcpStream, OpenCallsConnectWithProvidedAddress)
{
    SolidSyslogStream_Open(stream, addr);
    LONGS_EQUAL(TEST_PORT, WinsockFake_LastConnectPort());
    STRCMP_EQUAL(TEST_ADDRESS, WinsockFake_LastConnectAddrAsString());
}

TEST(SolidSyslogWinsockTcpStream, OpenReturnsTrueOnSuccess)
{
    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogWinsockTcpStream, OpenReturnsFalseOnConnectFailure)
{
    WinsockFake_SetConnectFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogWinsockTcpStream, OpenReturnsFalseWhenSocketFails)
{
    WinsockFake_SetSocketFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogWinsockTcpStream, OpenSkipsConnectAndSetsockoptWhenSocketFails)
{
    WinsockFake_SetSocketFails(true);
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(WinsockFake_Connect, NEVER);
    CALLED_FAKE(WinsockFake_SetSockOpt, NEVER);
}

TEST(SolidSyslogWinsockTcpStream, OpenClosesSocketOnConnectFailure)
{
    WinsockFake_SetConnectFails(true);
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(WinsockFake_Close, ONCE);
    CHECK(WinsockFake_SocketFd() == WinsockFake_LastClosedFd());
}

/* ----------------------------------------------------------------------
 * Non-blocking connect with bounded wait - the production path that
 * keeps the BlockStore service thread's drain rate from being throttled
 * by Windows' default ~2 s connect()-retry on a refused loopback port.
 * -------------------------------------------------------------------- */

TEST(SolidSyslogWinsockTcpStream, OpenSetsNonBlockingMode)
{
    SolidSyslogStream_Open(stream, addr);
    /* Single FIONBIO call: non-blocking on (1). The socket stays non-blocking
       so Send/Read are also fail-fast - no SO_SNDTIMEO needed. */
    CALLED_FAKE(WinsockFake_Fionbio, ONCE);
    LONGS_EQUAL(1, WinsockFake_FionbioArgAt(0));
}

TEST(SolidSyslogWinsockTcpStream, OpenSkipsSelectWhenConnectReturnsImmediately)
{
    /* Default fake connect returns 0 (immediate success); select must not be
       reached because connect short-circuits the wait. */
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(WinsockFake_Select, NEVER);
}

TEST(SolidSyslogWinsockTcpStream, OpenInvokesSelectWhenConnectReturnsWouldBlock)
{
    WinsockFake_SetConnectFailsWithLastError(WSAEWOULDBLOCK);
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(WinsockFake_Select, ONCE);
}

TEST(SolidSyslogWinsockTcpStream, OpenPassesBoundedConnectTimeoutToSelect)
{
    WinsockFake_SetConnectFailsWithLastError(WSAEWOULDBLOCK);
    SolidSyslogStream_Open(stream, addr);
    /* Default tunable SOLIDSYSLOG_TCP_CONNECT_TIMEOUT_MS = 200 -> 0 s + 200 000 µs. */
    LONGS_EQUAL(0, WinsockFake_LastSelectTimeoutSec());
    LONGS_EQUAL(200000, WinsockFake_LastSelectTimeoutUsec());
}

TEST(SolidSyslogWinsockTcpStream, OpenInvokesConfiguredConnectTimeoutGetter)
{
    OpenStreamWithFakeGetter();

    LONGS_EQUAL(1, FakeGetConnectTimeoutMs_CallCount);
}

TEST(SolidSyslogWinsockTcpStream, OpenUsesGetterReturnValueAsConnectTimeout)
{
    FakeGetConnectTimeoutMs_ReturnValue = 1234U;

    OpenStreamWithFakeGetter();

    /* 1234 ms = 1 s + 234 000 µs. */
    LONGS_EQUAL(1, WinsockFake_LastSelectTimeoutSec());
    LONGS_EQUAL(234000, WinsockFake_LastSelectTimeoutUsec());
}

TEST(SolidSyslogWinsockTcpStream, GetterReceivesNullContextWhenContextNotConfigured)
{
    OpenStreamWithFakeGetter();

    POINTERS_EQUAL(nullptr, FakeGetConnectTimeoutMs_LastContext);
}

TEST(SolidSyslogWinsockTcpStream, OpenSucceedsWhenSelectReportsWritableAndZeroSO_ERROR)
{
    WinsockFake_SetConnectFailsWithLastError(WSAEWOULDBLOCK);
    WinsockFake_SetSelectWritable(true);
    WinsockFake_SetSoError(0);
    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogWinsockTcpStream, OpenFailsWhenSelectReportsTimeout)
{
    WinsockFake_SetConnectFailsWithLastError(WSAEWOULDBLOCK);
    WinsockFake_SetSelectWritable(false);
    WinsockFake_SetSelectReturn(0);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogWinsockTcpStream, OpenClosesSocketOnSelectTimeout)
{
    WinsockFake_SetConnectFailsWithLastError(WSAEWOULDBLOCK);
    WinsockFake_SetSelectWritable(false);
    WinsockFake_SetSelectReturn(0);
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(WinsockFake_Close, ONCE);
    CHECK(WinsockFake_SocketFd() == WinsockFake_LastClosedFd());
}

TEST(SolidSyslogWinsockTcpStream, OpenFailsWhenSelectFlagsErrorOnFd)
{
    WinsockFake_SetConnectFailsWithLastError(WSAEWOULDBLOCK);
    WinsockFake_SetSelectWritable(false);
    WinsockFake_SetSelectError(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogWinsockTcpStream, OpenFailsWhenDeferredSO_ERRORIsNonZero)
{
    /* select reports writable, but SO_ERROR on the socket reveals the
       deferred connect failure (e.g. WSAECONNREFUSED). */
    WinsockFake_SetConnectFailsWithLastError(WSAEWOULDBLOCK);
    WinsockFake_SetSelectWritable(true);
    WinsockFake_SetSoError(WSAECONNREFUSED);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogWinsockTcpStream, OpenReadsSO_ERRORAfterSelectWritable)
{
    WinsockFake_SetConnectFailsWithLastError(WSAEWOULDBLOCK);
    SolidSyslogStream_Open(stream, addr);
    LONGS_EQUAL(SOL_SOCKET, WinsockFake_LastGetSockOptLevel());
    LONGS_EQUAL(SO_ERROR, WinsockFake_LastGetSockOptOptname());
}

TEST(SolidSyslogWinsockTcpStream, OpenFailsWhenIoctlsocketFails)
{
    /* If the kernel refuses to put the socket into non-blocking mode the
       caller cannot bound the connect wait - fail fast rather than fall
       back to blocking-connect's ~2 s retry behaviour. */
    WinsockFake_SetIoctlSocketFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogWinsockTcpStream, OpenFailsWhenConnectFailsImmediatelyWithRefused)
{
    /* Non-WSAEWOULDBLOCK errors (e.g. WSAECONNREFUSED) are immediate failures -
       no select wait, no SO_ERROR check, just fail fast. */
    WinsockFake_SetConnectFailsWithLastError(WSAECONNREFUSED);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CALLED_FAKE(WinsockFake_Select, NEVER);
}

TEST(SolidSyslogWinsockTcpStream, SendCallsSendOnce)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    CALLED_FAKE(WinsockFake_Send, ONCE);
}

TEST(SolidSyslogWinsockTcpStream, SendPassesBuffer)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    STRCMP_EQUAL(TEST_MESSAGE, WinsockFake_SendBufAsString(0));
}

TEST(SolidSyslogWinsockTcpStream, SendPassesLength)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    LONGS_EQUAL(TEST_MESSAGE_LEN, WinsockFake_SendLen(0));
}

TEST(SolidSyslogWinsockTcpStream, SendPassesZeroFlags)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    LONGS_EQUAL(0, WinsockFake_SendFlags(0));
}

TEST(SolidSyslogWinsockTcpStream, SendPassesSocketFd)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    CHECK(WinsockFake_SocketFd() == WinsockFake_LastSendFd());
}

TEST(SolidSyslogWinsockTcpStream, SendReturnsTrueOnSuccess)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN));
}

TEST(SolidSyslogWinsockTcpStream, SendReturnsFalseOnSendFailure)
{
    SolidSyslogStream_Open(stream, addr);
    WinsockFake_SetSendFails(true);
    CHECK_FALSE(SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN));
}

TEST(SolidSyslogWinsockTcpStream, SendReturnsFalseOnShortWrite)
{
    SolidSyslogStream_Open(stream, addr);
    WinsockFake_SetSendReturn(3);
    CHECK_FALSE(SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN));
}

TEST(SolidSyslogWinsockTcpStream, SendDoesNotRetryAfterShortWrite)
{
    SolidSyslogStream_Open(stream, addr);
    WinsockFake_SetSendReturn(3);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    CALLED_FAKE(WinsockFake_Send, ONCE);
}

TEST(SolidSyslogWinsockTcpStream, SendClosesSocketOnFailure)
{
    SolidSyslogStream_Open(stream, addr);
    WinsockFake_SetSendFails(true);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    CHECK_SOCKET_CLOSED_ONCE();
}

TEST(SolidSyslogWinsockTcpStream, CloseCallsCloseOnce)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Close(stream);
    CALLED_FAKE(WinsockFake_Close, ONCE);
}

TEST(SolidSyslogWinsockTcpStream, CloseCalledWithSocketFd)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Close(stream);
    CHECK(WinsockFake_SocketFd() == WinsockFake_LastClosedFd());
}

TEST(SolidSyslogWinsockTcpStream, CloseIsNoOpWhenNotOpen)
{
    SolidSyslogStream_Close(stream);
    CALLED_FAKE(WinsockFake_Close, NEVER);
}

TEST(SolidSyslogWinsockTcpStream, ReadCallsRecvOnce)
{
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogStream_Read(stream, buf, sizeof(buf));
    CALLED_FAKE(WinsockFake_Recv, ONCE);
}

TEST(SolidSyslogWinsockTcpStream, ReadPassesSocketFdToRecv)
{
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogStream_Read(stream, buf, sizeof(buf));
    CHECK(WinsockFake_SocketFd() == WinsockFake_LastRecvFd());
}

TEST(SolidSyslogWinsockTcpStream, ReadPassesBufferToRecv)
{
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogStream_Read(stream, buf, sizeof(buf));
    POINTERS_EQUAL(buf, WinsockFake_LastRecvBuf());
}

TEST(SolidSyslogWinsockTcpStream, ReadPassesLengthToRecv)
{
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogStream_Read(stream, buf, sizeof(buf));
    LONGS_EQUAL(sizeof(buf), WinsockFake_LastRecvLen());
}

TEST(SolidSyslogWinsockTcpStream, ReadPassesZeroFlagsToRecv)
{
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogStream_Read(stream, buf, sizeof(buf));
    LONGS_EQUAL(0, WinsockFake_LastRecvFlags());
}

TEST(SolidSyslogWinsockTcpStream, ReadReturnsRecvReturnValue)
{
    WinsockFake_SetRecvReturn(7);
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogSsize n = SolidSyslogStream_Read(stream, buf, sizeof(buf));
    LONGS_EQUAL(7, n);
}

TEST(SolidSyslogWinsockTcpStream, ReadReturnsZeroOnWouldBlock)
{
    SolidSyslogStream_Open(stream, addr);
    WinsockFake_FailNextRecvWithLastError(WSAEWOULDBLOCK);
    LONGS_EQUAL(0, Read16ByteBuffer());
}

TEST(SolidSyslogWinsockTcpStream, ReadReturnsNegativeOneOnEofAndClosesSocket)
{
    SolidSyslogStream_Open(stream, addr);
    WinsockFake_SetRecvReturn(0); /* EOF */
    LONGS_EQUAL(-1, Read16ByteBuffer());
    CHECK_SOCKET_CLOSED_ONCE();
}

TEST(SolidSyslogWinsockTcpStream, ReadReturnsNegativeOneOnErrorAndClosesSocket)
{
    SolidSyslogStream_Open(stream, addr);
    WinsockFake_FailNextRecvWithLastError(WSAECONNRESET);
    LONGS_EQUAL(-1, Read16ByteBuffer());
    CHECK_SOCKET_CLOSED_ONCE();
}

TEST(SolidSyslogWinsockTcpStream, DestroyClosesOpenSocket)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogWinsockTcpStream_Destroy(stream);
    CALLED_FAKE(WinsockFake_Close, ONCE);
}

// clang-format off
TEST_GROUP(SolidSyslogWinsockTcpStreamPool)
{
    struct SolidSyslogStream* pooled[SOLIDSYSLOG_TCP_STREAM_POOL_SIZE] = {};
    struct SolidSyslogStream* overflow                                         = nullptr;

    void teardown() override
    {
        for (auto* handle : pooled)
        {
            if (handle != nullptr)
            {
                SolidSyslogWinsockTcpStream_Destroy(handle);
            }
        }
        if (overflow != nullptr)
        {
            SolidSyslogWinsockTcpStream_Destroy(overflow);
        }
        ConfigLockFake_Uninstall();
    }

    void FillPool()
    {
        for (auto*& slot : pooled)
        {
            slot = SolidSyslogWinsockTcpStream_Create(nullptr);
        }
    }
};

// clang-format on

TEST(SolidSyslogWinsockTcpStreamPool, FillingPoolThenOverflowReturnsDistinctFallback)
{
    FillPool();

    overflow = SolidSyslogWinsockTcpStream_Create(nullptr);

    CHECK_IS_FALLBACK(overflow, pooled);
}

TEST(SolidSyslogWinsockTcpStreamPool, ExhaustedCreateReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    FillPool();

    overflow = SolidSyslogWinsockTcpStream_Create(nullptr);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogWinsockTcpStreamErrorSource,
        SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
        SOLIDSYSLOG_WINSOCK_TCP_STREAM_ERROR_POOL_EXHAUSTED
    );
}

TEST(SolidSyslogWinsockTcpStreamPool, FallbackSendIsNoOp)
{
    FillPool();
    overflow = SolidSyslogWinsockTcpStream_Create(nullptr);

    CHECK_TRUE(SolidSyslogStream_Send(overflow, "x", 1));
}

TEST(SolidSyslogWinsockTcpStreamPool, CreateAcquiresAndReleasesConfigLockOnFirstFreeSlot)
{
    ConfigLockFake_Install();

    pooled[0] = SolidSyslogWinsockTcpStream_Create(nullptr);

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogWinsockTcpStreamPool, CreateLocksOncePerSlotProbedWhenPoolIsFull)
{
    FillPool();
    ConfigLockFake_Install();

    overflow = SolidSyslogWinsockTcpStream_Create(nullptr);

    LONGS_EQUAL(SOLIDSYSLOG_TCP_STREAM_POOL_SIZE, ConfigLockFake_LockCallCount());
    LONGS_EQUAL(SOLIDSYSLOG_TCP_STREAM_POOL_SIZE, ConfigLockFake_UnlockCallCount());
}

TEST(SolidSyslogWinsockTcpStreamPool, DestroyOfPooledHandleLocksOnce)
{
    pooled[0] = SolidSyslogWinsockTcpStream_Create(nullptr);
    ConfigLockFake_Install();

    SolidSyslogWinsockTcpStream_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogWinsockTcpStreamPool, DestroyOfUnknownHandleDoesNotLock)
{
    ConfigLockFake_Install();
    struct SolidSyslogStream stranger = {};

    SolidSyslogWinsockTcpStream_Destroy(&stranger);

    CALLED_FAKE(ConfigLockFake_Lock, NEVER);
    CALLED_FAKE(ConfigLockFake_Unlock, NEVER);
}

TEST(SolidSyslogWinsockTcpStreamPool, DestroyOfUnknownHandleReportsWarning)
{
    ErrorHandlerFake_Install(nullptr);
    struct SolidSyslogStream stranger = {};

    SolidSyslogWinsockTcpStream_Destroy(&stranger);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogWinsockTcpStreamErrorSource,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_WINSOCK_TCP_STREAM_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogWinsockTcpStreamPool, DestroyOfStaleHandleReportsWarning)
{
    pooled[0] = SolidSyslogWinsockTcpStream_Create(nullptr);
    SolidSyslogWinsockTcpStream_Destroy(pooled[0]);
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogWinsockTcpStream_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogWinsockTcpStreamErrorSource,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_WINSOCK_TCP_STREAM_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogWinsockTcpStream, DestroyClosesWithSocketFd)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogWinsockTcpStream_Destroy(stream);
    CHECK(WinsockFake_SocketFd() == WinsockFake_LastClosedFd());
}

TEST(SolidSyslogWinsockTcpStream, DefaultPortMatchesRfc6587)
{
    LONGS_EQUAL(601, SOLIDSYSLOG_TCP_DEFAULT_PORT);
}

TEST(SolidSyslogWinsockTcpStream, VersionIsAlwaysZeroBecauseNothingChangesAtRuntime)
{
    LONGS_EQUAL(0, SolidSyslogStream_Version(stream));
}
