#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "CppUTest/TestHarness.h"
#include "ErrorHandlerFake.h"
#include "SocketFake.h"
#include "SolidSyslogEndpoint.h"
#include "SolidSyslogEndpointHost.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogFormatter.h"
#include "SolidSyslogPosixResolver.h"
#include "SolidSyslogPosixAddress.h"
#include "SolidSyslogPosixTcpStream.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogSender.h"
#include "SolidSyslogSenderCategories.h"
#include "SolidSyslogStreamSender.h"
#include "SolidSyslogStreamSenderErrors.h"
#include "SolidSyslogTunables.h"
#include "StreamFake.h"
#include "TestUtils.h"

using namespace CososoTesting;

// clang-format off
static const char* const TEST_HOST           = "127.0.0.1";
static const int         TEST_PORT           = 514;
static const char* const TEST_ALTERNATE_HOST = "192.168.1.1";
static const int         TEST_ALTERNATE_PORT = 9999;
static const char* const TEST_MESSAGE        = "hello";
static const size_t      TEST_MESSAGE_LEN    = 5;
// clang-format on

static int GetPort()
{
    return TEST_PORT;
}

static const char* GetHost()
{
    return TEST_HOST;
}

static int GetAlternatePort()
{
    return TEST_ALTERNATE_PORT;
}

static const char* GetAlternateHost()
{
    return TEST_ALTERNATE_HOST;
}

static int SpyGetPortCallCount;

static int SpyGetPort()
{
    SpyGetPortCallCount++;
    return TEST_PORT;
}

static int SpyGetHostCallCount;

static const char* SpyGetHost()
{
    SpyGetHostCallCount++;
    return TEST_HOST;
}

// Endpoint stubs - delegate to per-test function pointers so existing
// callback-spy tests in TEST_GROUP(SolidSyslogStreamSenderConfig) keep counting
// callback invocations through the new endpoint path. endpointVersion is the
// per-test version reported by TestEndpointVersion; bump it between Sends to
// drive fingerprint-reconnection tests.
static const char* (*endpointGetHost)() = GetHost;
static int (*endpointGetPort)() = GetPort;
static uint32_t endpointVersion = 0;
static void* endpointContext;
static void* endpointVersionContext;

static void TestEndpoint(struct SolidSyslogEndpoint* endpoint, void* context)
{
    endpointContext = context;
    SolidSyslogEndpointHost_String(endpoint->Host, endpointGetHost(), SOLIDSYSLOG_MAX_HOST_SIZE);
    endpoint->Port = (uint16_t) endpointGetPort();
}

static uint32_t TestEndpointVersion(void* context) // NOLINT(modernize-use-trailing-return-type)
{
    endpointVersionContext = context;
    return endpointVersion;
}

// clang-format off
TEST_GROUP(SolidSyslogStreamSender)
{
    struct SolidSyslogResolver*      resolver = nullptr;
    struct SolidSyslogStream*        stream = nullptr;
    struct SolidSyslogAddress*       address = nullptr;
    struct SolidSyslogStreamSenderConfig config;
    struct SolidSyslogSender* sender = nullptr;

    void setup() override
    {
        SocketFake_Reset();
        endpointGetHost = GetHost;
        endpointVersion = 0;
        endpointGetPort = GetPort;
        resolver        = SolidSyslogPosixResolver_Create();
        stream          = SolidSyslogPosixTcpStream_Create(nullptr);
        address         = SolidSyslogPosixAddress_Create();
        config          = {resolver, stream, address, TestEndpoint, TestEndpointVersion, nullptr};
        sender = SolidSyslogStreamSender_Create(&config);
    }

    void teardown() override
    {
        SolidSyslogStreamSender_Destroy(sender);
        SolidSyslogPosixAddress_Destroy(address);
        SolidSyslogPosixTcpStream_Destroy(stream);
        SolidSyslogPosixResolver_Destroy(resolver);
    }

    void Send() const
    {
        SolidSyslogSender_Send(sender, TEST_MESSAGE, TEST_MESSAGE_LEN);
    }
};

// clang-format on

TEST(SolidSyslogStreamSender, CreateReturnsNonNull)
{
    CHECK_TRUE(sender != nullptr);
}

TEST(SolidSyslogStreamSender, CreateDoesNotOpenSocket)
{
    CALLED_FAKE(SocketFake_Socket, NEVER);
}

TEST(SolidSyslogStreamSender, FirstSendOpensStreamSocket)
{
    Send();
    CALLED_FAKE(SocketFake_Socket, ONCE);
    LONGS_EQUAL(AF_INET, SocketFake_SocketDomain());
    LONGS_EQUAL(SOCK_STREAM, SocketFake_SocketType());
}

TEST(SolidSyslogStreamSender, FirstSendSetsTcpNoDelay)
{
    Send();
    CHECK_TRUE(SocketFake_HasSetSockOpt(IPPROTO_TCP, TCP_NODELAY));
}

TEST(SolidSyslogStreamSender, EndpointCallbacksReceiveEndpointContext)
{
    int context = 0;
    SolidSyslogStreamSender_Destroy(sender);
    config.EndpointContext = &context;
    sender = SolidSyslogStreamSender_Create(&config);
    Send();
    POINTERS_EQUAL(&context, endpointContext);
    POINTERS_EQUAL(&context, endpointVersionContext);
}

// clang-format off
TEST_GROUP(SolidSyslogStreamSenderDestroy)
{
    struct SolidSyslogResolver*      resolver = nullptr;
    struct SolidSyslogStream*        stream = nullptr;
    struct SolidSyslogAddress*       address = nullptr;
    struct SolidSyslogStreamSenderConfig config;

    void setup() override
    {
        SocketFake_Reset();
        endpointGetHost = GetHost;
        endpointVersion = 0;
        endpointGetPort = GetPort;
        resolver        = SolidSyslogPosixResolver_Create();
        stream          = SolidSyslogPosixTcpStream_Create(nullptr);
        address         = SolidSyslogPosixAddress_Create();
        config = {resolver, stream, address, TestEndpoint, TestEndpointVersion, nullptr};
    }

    void teardown() override
    {
        SolidSyslogPosixAddress_Destroy(address);
        SolidSyslogPosixTcpStream_Destroy(stream);
        SolidSyslogPosixResolver_Destroy(resolver);
    }

    void CreateAndDestroy()
    {
        struct SolidSyslogSender* localSender = SolidSyslogStreamSender_Create(&config);
        SolidSyslogStreamSender_Destroy(localSender);
    }
};

// clang-format on

TEST(SolidSyslogStreamSenderDestroy, DestroyWithoutSendDoesNotClose)
{
    CreateAndDestroy();
    CALLED_FAKE(SocketFake_Close, NEVER);
}

TEST(SolidSyslogStreamSenderDestroy, DestroyAfterSendClosesSocket)
{
    struct SolidSyslogSender* sender = SolidSyslogStreamSender_Create(&config);
    SolidSyslogSender_Send(sender, "x", 1);
    SolidSyslogStreamSender_Destroy(sender);
    CALLED_FAKE(SocketFake_Close, ONCE);
    LONGS_EQUAL(SocketFake_SocketFd(), SocketFake_LastClosedFd());
}

TEST(SolidSyslogStreamSenderDestroy, DestroyAfterDisconnectDoesNotDoubleClose)
{
    struct SolidSyslogSender* sender = SolidSyslogStreamSender_Create(&config);
    SolidSyslogSender_Send(sender, "x", 1);
    SolidSyslogSender_Disconnect(sender);
    SolidSyslogStreamSender_Destroy(sender);
    CALLED_FAKE(SocketFake_Close, ONCE);
}

TEST(SolidSyslogStreamSenderDestroy, UseAfterDestroyIsCrashSafeViaNullSenderVtable)
{
    /* After Destroy the slot's abstract-base vtable is the shared NullSender's, so
     * calling Send/Disconnect through the stale handle is a safe no-op rather than a
     * NULL-fn-pointer crash. NullSender.Send returns true (drop-on-floor). */
    struct SolidSyslogSender* sender = SolidSyslogStreamSender_Create(&config);
    SolidSyslogStreamSender_Destroy(sender);
    CHECK_TRUE(SolidSyslogSender_Send(sender, TEST_MESSAGE, TEST_MESSAGE_LEN));
    SolidSyslogSender_Disconnect(sender);
}

TEST(SolidSyslogStreamSender, SendConnectsOnFirstCall)
{
    Send();
    CALLED_FAKE(SocketFake_Connect, ONCE);
}

TEST(SolidSyslogStreamSender, SendConnectsWithCorrectPort)
{
    Send();
    LONGS_EQUAL(TEST_PORT, SocketFake_LastConnectPort());
}

TEST(SolidSyslogStreamSender, SendConnectsWithCorrectAddress)
{
    Send();
    STRCMP_EQUAL(TEST_HOST, SocketFake_LastConnectAddrAsString());
}

TEST(SolidSyslogStreamSender, SendConnectsWithSocketFd)
{
    Send();
    LONGS_EQUAL(SocketFake_SocketFd(), SocketFake_LastConnectFd());
}

TEST(SolidSyslogStreamSender, SecondSendDoesNotReconnect)
{
    Send();
    Send();
    CALLED_FAKE(SocketFake_Connect, ONCE);
}

TEST(SolidSyslogStreamSender, SendTransmitsOctetCountingPrefix)
{
    Send();
    STRCMP_EQUAL("5 ", SocketFake_SendBufAsString(0));
}

TEST(SolidSyslogStreamSender, SendTransmitsMessageBody)
{
    Send();
    STRCMP_EQUAL(TEST_MESSAGE, SocketFake_SendBufAsString(1));
}

TEST(SolidSyslogStreamSender, SendMakesTwoSendCalls)
{
    Send();
    CALLED_FAKE(SocketFake_Send, TWICE);
}

TEST(SolidSyslogStreamSender, SendUsesSocketFd)
{
    Send();
    LONGS_EQUAL(SocketFake_SocketFd(), SocketFake_LastSendFd());
}

TEST(SolidSyslogStreamSender, SendReturnsTrueOnSuccess)
{
    CHECK_TRUE(SolidSyslogSender_Send(sender, TEST_MESSAGE, TEST_MESSAGE_LEN));
}

TEST(SolidSyslogStreamSender, DisconnectAfterSendClosesSocket)
{
    Send();
    SolidSyslogSender_Disconnect(sender);
    CALLED_FAKE(SocketFake_Close, ONCE);
}

TEST(SolidSyslogStreamSender, DisconnectIsIdempotent)
{
    Send();
    SolidSyslogSender_Disconnect(sender);
    SolidSyslogSender_Disconnect(sender);
    CALLED_FAKE(SocketFake_Close, ONCE);
}

TEST(SolidSyslogStreamSender, SendAfterDisconnectReopensSocket)
{
    Send();
    SolidSyslogSender_Disconnect(sender);
    Send();
    CALLED_FAKE(SocketFake_Socket, TWICE);
}

TEST(SolidSyslogStreamSender, SendAfterDisconnectResolves)
{
    Send();
    SolidSyslogSender_Disconnect(sender);
    Send();
    CALLED_FAKE(SocketFake_GetAddrInfo, TWICE);
}

TEST(SolidSyslogStreamSender, DisconnectWithoutSendDoesNotClose)
{
    SolidSyslogSender_Disconnect(sender);
    CALLED_FAKE(SocketFake_Close, NEVER);
}

TEST(SolidSyslogStreamSender, EndpointVersionChangeBetweenSendsTriggersReconnect)
{
    Send();
    endpointVersion = 1;
    Send();
    CALLED_FAKE(SocketFake_Connect, TWICE);
}

TEST(SolidSyslogStreamSender, EndpointVersionChangeUsesNewPortOnReconnect)
{
    Send();
    endpointVersion = 1;
    endpointGetPort = GetAlternatePort;
    Send();
    LONGS_EQUAL(TEST_ALTERNATE_PORT, SocketFake_LastConnectPort());
}

// clang-format off
TEST_GROUP(SolidSyslogStreamSenderConfig)
{
    const char* (*getHostFn)(void) = GetHost;
    int (*getPortFn)(void) = GetPort;
    struct SolidSyslogStream*        stream   = nullptr;
    struct SolidSyslogResolver*      resolver = nullptr;
    struct SolidSyslogAddress*       address  = nullptr;
    struct SolidSyslogSender* sender = nullptr;

    void setup() override
    {
        SocketFake_Reset();
        SpyGetPortCallCount = 0;
        SpyGetHostCallCount = 0;
        endpointGetHost  = GetHost;
        endpointVersion  = 0;
        endpointGetPort  = GetPort;
    }

    void teardown() override
    {
        SolidSyslogStreamSender_Destroy(sender);
        SolidSyslogPosixAddress_Destroy(address);
        SolidSyslogPosixTcpStream_Destroy(stream);
        SolidSyslogPosixResolver_Destroy(resolver);
    }

    void CreateSender()
    {
        endpointGetHost = getHostFn;
        endpointGetPort = getPortFn;
        resolver = SolidSyslogPosixResolver_Create();
        stream   = SolidSyslogPosixTcpStream_Create(nullptr);
        address  = SolidSyslogPosixAddress_Create();
        struct SolidSyslogStreamSenderConfig config = {resolver, stream, address, TestEndpoint, TestEndpointVersion, nullptr};
        sender = SolidSyslogStreamSender_Create(&config);
    }

    void Send() const
    {
        SolidSyslogSender_Send(sender, TEST_MESSAGE, TEST_MESSAGE_LEN);
    }
};

// clang-format on

TEST(SolidSyslogStreamSenderConfig, GetPortCalledOnFirstSend)
{
    getPortFn = SpyGetPort;
    CreateSender();
    CALLED_FUNCTION(SpyGetPort, NEVER);
    Send();
    CALLED_FUNCTION(SpyGetPort, ONCE);
}

TEST(SolidSyslogStreamSenderConfig, GetPortNotCalledOnSecondSend)
{
    getPortFn = SpyGetPort;
    CreateSender();
    Send();
    Send();
    CALLED_FUNCTION(SpyGetPort, ONCE);
}

TEST(SolidSyslogStreamSenderConfig, ConnectsWithAlternatePort)
{
    getPortFn = GetAlternatePort;
    CreateSender();
    Send();
    LONGS_EQUAL(TEST_ALTERNATE_PORT, SocketFake_LastConnectPort());
}

TEST(SolidSyslogStreamSenderConfig, GetHostCalledOnFirstSend)
{
    getHostFn = SpyGetHost;
    CreateSender();
    CALLED_FUNCTION(SpyGetHost, NEVER);
    Send();
    CALLED_FUNCTION(SpyGetHost, ONCE);
}

TEST(SolidSyslogStreamSenderConfig, GetHostNotCalledOnSecondSend)
{
    getHostFn = SpyGetHost;
    CreateSender();
    Send();
    Send();
    CALLED_FUNCTION(SpyGetHost, ONCE);
}

TEST(SolidSyslogStreamSenderConfig, ConnectsWithAlternateHost)
{
    getHostFn = GetAlternateHost;
    CreateSender();
    Send();
    STRCMP_EQUAL(TEST_ALTERNATE_HOST, SocketFake_LastConnectAddrAsString());
}

TEST(SolidSyslogStreamSenderConfig, GetAddrInfoCalledWithHostname)
{
    getHostFn = SpyGetHost;
    CreateSender();
    Send();
    STRCMP_EQUAL(TEST_HOST, SocketFake_LastGetAddrInfoHostname());
}

// clang-format off
TEST_GROUP(SolidSyslogStreamSenderFailure)
{
    struct SolidSyslogResolver*      resolver = nullptr;
    struct SolidSyslogStream*        stream = nullptr;
    struct SolidSyslogAddress*       address = nullptr;
    struct SolidSyslogStreamSenderConfig config;
    struct SolidSyslogSender* sender = nullptr;

    void setup() override
    {
        SocketFake_Reset();
        endpointGetHost = GetHost;
        endpointVersion = 0;
        endpointGetPort = GetPort;
        resolver        = SolidSyslogPosixResolver_Create();
        stream          = SolidSyslogPosixTcpStream_Create(nullptr);
        address         = SolidSyslogPosixAddress_Create();
        config          = {resolver, stream, address, TestEndpoint, TestEndpointVersion, nullptr};
        sender = SolidSyslogStreamSender_Create(&config);
    }

    void teardown() override
    {
        SolidSyslogStreamSender_Destroy(sender);
        SolidSyslogPosixAddress_Destroy(address);
        SolidSyslogPosixTcpStream_Destroy(stream);
        SolidSyslogPosixResolver_Destroy(resolver);
    }

    // NOLINTNEXTLINE(modernize-use-nodiscard) -- test helper; return value intentionally ignored in some tests
    bool Send() const
    {
        return SolidSyslogSender_Send(sender, TEST_MESSAGE, TEST_MESSAGE_LEN);
    }
};

// clang-format on

TEST(SolidSyslogStreamSenderFailure, SendReturnsFalseWhenConnectFails)
{
    SocketFake_SetConnectFails(true);
    CHECK_FALSE(Send());
}

TEST(SolidSyslogStreamSenderFailure, ConnectFailureClosesSocket)
{
    SocketFake_SetConnectFails(true);
    Send();
    CALLED_FAKE(SocketFake_Close, ONCE);
}

TEST(SolidSyslogStreamSenderFailure, SendReturnsFalseWhenSendFails)
{
    SocketFake_SetSendFails(true);
    CHECK_FALSE(Send());
}

TEST(SolidSyslogStreamSenderFailure, SendFailureClosesSocket)
{
    SocketFake_SetSendFails(true);
    Send();
    CALLED_FAKE(SocketFake_Close, ONCE);
}

TEST(SolidSyslogStreamSenderFailure, DestroyAfterSendFailureDoesNotDoubleClose)
{
    SocketFake_SetSendFails(true);
    Send();
    SolidSyslogStreamSender_Destroy(sender);
    CALLED_FAKE(SocketFake_Close, ONCE);
}

TEST(SolidSyslogStreamSenderFailure, SendFailureMarksDisconnected)
{
    Send();
    CALLED_FAKE(SocketFake_Connect, ONCE);
    SocketFake_SetSendFails(true);
    Send();
    SocketFake_SetSendFails(false);
    Send();
    CALLED_FAKE(SocketFake_Connect, TWICE);
}

TEST(SolidSyslogStreamSenderFailure, ReconnectCreatesNewSocket)
{
    Send();
    int firstSocketCallCount = SocketFake_SocketCallCount();
    SocketFake_SetSendFails(true);
    Send();
    SocketFake_SetSendFails(false);
    Send();
    CALLED_FAKE(SocketFake_Socket, firstSocketCallCount + 1);
}

TEST(SolidSyslogStreamSenderFailure, ReconnectSetsTcpNoDelay)
{
    Send();
    SocketFake_SetSendFails(true);
    Send();
    SocketFake_SetSendFails(false);
    Send();
    /* Two opens (initial + reconnect); each runs the full ConfigureSocket
       sequence: TCP_NODELAY + SO_KEEPALIVE + TCP_KEEPIDLE + TCP_KEEPINTVL +
       TCP_KEEPCNT + TCP_USER_TIMEOUT = 6 setsockopt calls per Open. */
    CALLED_FAKE(SocketFake_SetSockOpt, 12);
    CHECK_TRUE(SocketFake_HasSetSockOpt(IPPROTO_TCP, TCP_NODELAY));
}

TEST(SolidSyslogStreamSenderFailure, ReconnectResolvesDns)
{
    Send();
    SocketFake_SetSendFails(true);
    Send();
    SocketFake_SetSendFails(false);
    Send();
    CALLED_FAKE(SocketFake_GetAddrInfo, TWICE);
}

TEST(SolidSyslogStreamSenderFailure, ReconnectConnectsWithNewFd)
{
    Send();
    SocketFake_SetSendFails(true);
    Send();
    SocketFake_SetSendFails(false);
    Send();
    LONGS_EQUAL(SocketFake_SocketFd(), SocketFake_LastConnectFd());
}

TEST(SolidSyslogStreamSenderFailure, SuccessfulSendAfterReconnect)
{
    Send();
    SocketFake_SetSendFails(true);
    Send();
    SocketFake_SetSendFails(false);
    CHECK_TRUE(Send());
}

TEST(SolidSyslogStreamSenderFailure, SendUsesMsgNoSignal)
{
    Send();
    LONGS_EQUAL(MSG_NOSIGNAL, SocketFake_SendFlags(0));
    LONGS_EQUAL(MSG_NOSIGNAL, SocketFake_SendFlags(1));
}

TEST(SolidSyslogStreamSenderFailure, SendReturnsFalseWhenBodySendFails)
{
    SocketFake_FailSendOnCall(1);
    CHECK_FALSE(Send());
}

TEST(SolidSyslogStreamSenderFailure, BodySendFailureClosesSocket)
{
    SocketFake_FailSendOnCall(1);
    Send();
    CALLED_FAKE(SocketFake_Close, ONCE);
}

TEST(SolidSyslogStreamSenderFailure, SendReturnsFalseWhenResolverFails)
{
    SocketFake_SetGetAddrInfoFails(true);
    CHECK_FALSE(Send());
}

TEST(SolidSyslogStreamSenderFailure, SendDoesNotOpenStreamWhenResolverFails)
{
    SocketFake_SetGetAddrInfoFails(true);
    Send();
    CALLED_FAKE(SocketFake_Socket, NEVER);
    CALLED_FAKE(SocketFake_Connect, NEVER);
}

TEST(SolidSyslogStreamSenderFailure, SendReturnsTrueWhenResolverSucceeds)
{
    CHECK_TRUE(Send());
}

TEST(SolidSyslogStreamSenderFailure, SendRecoversAfterTransientResolveFailure)
{
    SocketFake_SetGetAddrInfoFails(true);
    CHECK_FALSE(Send());
    SocketFake_SetGetAddrInfoFails(false);
    CHECK_TRUE(Send());
}

TEST(SolidSyslogStreamSenderFailure, NoEndpointConfiguredConnectsToPortZero)
{
    /* Drop the setup-built sender so the pool slot is free for the no-endpoint variant -
     * with pool semantics a second live Create on a SIZE=1 pool would otherwise overflow
     * to NullSender. Reassigning to `sender` lets teardown release the no-endpoint sender. */
    SolidSyslogStreamSender_Destroy(sender);
    struct SolidSyslogStreamSenderConfig configNoEndpoint = {resolver, stream, address, nullptr, nullptr, nullptr};
    sender = SolidSyslogStreamSender_Create(&configNoEndpoint);
    SolidSyslogSender_Send(sender, TEST_MESSAGE, TEST_MESSAGE_LEN);
    CALLED_FAKE(SocketFake_Connect, ONCE);
    LONGS_EQUAL(0, SocketFake_LastConnectPort());
}

// Pool tests - prove SOLIDSYSLOG_STREAM_SENDER_POOL_SIZE caps live instances
// and overflow falls back to the shared SolidSyslogNullSender. Generic
// pool mechanics (lock counts, per-probe locking, stale-handle warning)
// are covered by SolidSyslogPoolAllocatorTest.cpp.

// clang-format off
TEST_GROUP(SolidSyslogStreamSenderPool)
{
    struct SolidSyslogResolver*      resolver = nullptr;
    struct SolidSyslogStream*        stream = nullptr;
    struct SolidSyslogAddress*       address = nullptr;
    struct SolidSyslogStreamSenderConfig config;
    struct SolidSyslogSender* pooled[SOLIDSYSLOG_STREAM_SENDER_POOL_SIZE] = {};
    struct SolidSyslogSender* overflow                                     = nullptr;

    void setup() override
    {
        SocketFake_Reset();
        endpointGetHost = GetHost;
        endpointVersion = 0;
        endpointGetPort = GetPort;
        resolver        = SolidSyslogPosixResolver_Create();
        stream          = SolidSyslogPosixTcpStream_Create(nullptr);
        address         = SolidSyslogPosixAddress_Create();
        config = {resolver, stream, address, TestEndpoint, TestEndpointVersion, nullptr};
    }

    void teardown() override
    {
        for (auto* handle : pooled)
        {
            if (handle != nullptr)
            {
                SolidSyslogStreamSender_Destroy(handle);
            }
        }
        if (overflow != nullptr)
        {
            SolidSyslogStreamSender_Destroy(overflow);
        }
        SolidSyslogPosixAddress_Destroy(address);
        SolidSyslogPosixTcpStream_Destroy(stream);
        SolidSyslogPosixResolver_Destroy(resolver);
    }

    struct SolidSyslogSender* MakeSender()
    {
        return SolidSyslogStreamSender_Create(&config);
    }

    void FillPool()
    {
        for (auto*& slot : pooled)
        {
            slot = MakeSender();
        }
    }
};

// clang-format on

TEST(SolidSyslogStreamSenderPool, OverflowReportsPoolExhausted)
{
    FillPool();
    ErrorHandlerFake_Install(nullptr);

    overflow = MakeSender();

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogStreamSenderErrorSource,
        SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
        SOLIDSYSLOG_STREAM_SENDER_ERROR_POOL_EXHAUSTED
    );
}

TEST(SolidSyslogStreamSenderPool, FillingPoolThenOverflowReturnsDistinctFallback)
{
    FillPool();

    overflow = MakeSender();

    CHECK_TEXT(overflow != nullptr, "Fallback handle was nullptr");
    for (auto* slot : pooled)
    {
        CHECK_TEXT(slot != nullptr, "pool slot was nullptr (FillPool failed?)");
        CHECK_TEXT(overflow != slot, "Fallback handle collided with a pool slot");
    }
}

// Bad-setup tests - SolidSyslogStreamSender_Create rejects NULL config /
// Resolver / Stream / Address by emitting a CRITICAL SolidSyslog_Error (fatal
// bad-config - the integrator must fix it in code) and returning the shared
// SolidSyslogNullSender without consuming a pool slot. Matches the
// SolidSyslogUdpSenderBadSetup contract from S12.06 (severity raised
// ERROR->CRITICAL in S12.33).

/* Macro (not function) so test failures report the caller's __FILE__/__LINE__. */
#define CHECK_STREAMSENDER_BAD_SETUP_ERROR(expectedCategory, expectedCode) \
    CHECK_ERROR_REPORTED_ONCE(                                             \
        SOLIDSYSLOG_SEVERITY_CRITICAL,                                     \
        &SolidSyslogStreamSenderErrorSource,                               \
        (expectedCategory),                                                \
        (expectedCode)                                                     \
    )

// clang-format off
TEST_GROUP(SolidSyslogStreamSenderBadSetup)
{
    struct SolidSyslogResolver*          resolver = nullptr;
    struct SolidSyslogStream*            stream   = nullptr;
    struct SolidSyslogAddress*           address  = nullptr;
    struct SolidSyslogStreamSenderConfig config{};
    struct SolidSyslogSender*            sender   = nullptr;
    int                                  sentinel = 0;

    void setup() override
    {
        SocketFake_Reset();
        endpointGetHost = GetHost;
        endpointVersion = 0;
        endpointGetPort = GetPort;
        resolver = SolidSyslogPosixResolver_Create();
        stream   = SolidSyslogPosixTcpStream_Create(nullptr);
        address  = SolidSyslogPosixAddress_Create();
        config   = {resolver, stream, address, TestEndpoint, TestEndpointVersion, nullptr};
        ErrorHandlerFake_Install(&sentinel);
    }

    void teardown() override
    {
        SolidSyslogStreamSender_Destroy(sender);
        SolidSyslogPosixAddress_Destroy(address);
        SolidSyslogPosixTcpStream_Destroy(stream);
        SolidSyslogPosixResolver_Destroy(resolver);
    }
};

// clang-format on

TEST(SolidSyslogStreamSenderBadSetup, CreateWithNullConfigReportsError)
{
    SolidSyslogStreamSender_Create(nullptr);
    CHECK_STREAMSENDER_BAD_SETUP_ERROR(SOLIDSYSLOG_CAT_BAD_CONFIG, SOLIDSYSLOG_STREAM_SENDER_ERROR_NULL_CONFIG);
}

TEST(SolidSyslogStreamSenderBadSetup, CreateWithNullResolverReportsError)
{
    config.Resolver = nullptr;
    SolidSyslogStreamSender_Create(&config);
    CHECK_STREAMSENDER_BAD_SETUP_ERROR(SOLIDSYSLOG_CAT_BAD_CONFIG, SOLIDSYSLOG_STREAM_SENDER_ERROR_NULL_RESOLVER);
}

TEST(SolidSyslogStreamSenderBadSetup, CreateWithNullStreamReportsError)
{
    config.Stream = nullptr;
    SolidSyslogStreamSender_Create(&config);
    CHECK_STREAMSENDER_BAD_SETUP_ERROR(SOLIDSYSLOG_CAT_BAD_CONFIG, SOLIDSYSLOG_STREAM_SENDER_ERROR_NULL_STREAM);
}

TEST(SolidSyslogStreamSenderBadSetup, CreateWithNullAddressReportsError)
{
    config.Address = nullptr;
    SolidSyslogStreamSender_Create(&config);
    CHECK_STREAMSENDER_BAD_SETUP_ERROR(SOLIDSYSLOG_CAT_BAD_CONFIG, SOLIDSYSLOG_STREAM_SENDER_ERROR_NULL_ADDRESS);
}

TEST(SolidSyslogStreamSenderBadSetup, SendOnBadSetupSenderReturnsTrue)
{
    sender = SolidSyslogStreamSender_Create(nullptr);
    CHECK_TRUE(SolidSyslogSender_Send(sender, TEST_MESSAGE, TEST_MESSAGE_LEN));
}

TEST(SolidSyslogStreamSenderBadSetup, DisconnectOnBadSetupSenderDoesNotCrash)
{
    sender = SolidSyslogStreamSender_Create(nullptr);
    SolidSyslogSender_Disconnect(sender);
}

// Delivery-health tests - the sender holds one DeliveryHealthy edge bit
// (initial true). It emits one DELIVERY_FAILED (ERR) event on the
// healthy->down transition and one DELIVERY_RESTORED (NOTICE) event on the
// down->healthy transition; staying down stays silent (anti-flood). The
// StreamFake's sticky SetSendFails toggle drives the underlying Stream_Send
// boolean directly, isolating the edge logic from any platform stack.

// clang-format off
TEST_GROUP(SolidSyslogStreamSenderDeliveryHealth)
{
    struct SolidSyslogResolver*          resolver = nullptr;
    struct SolidSyslogStream*            stream   = nullptr;
    struct SolidSyslogAddress*           address  = nullptr;
    struct SolidSyslogStreamSenderConfig config{};
    struct SolidSyslogSender*            sender   = nullptr;
    int                                  sentinel = 0;

    void setup() override
    {
        SocketFake_Reset();
        endpointGetHost = GetHost;
        endpointVersion = 0;
        endpointGetPort = GetPort;
        resolver = SolidSyslogPosixResolver_Create();
        stream   = StreamFake_Create();
        address  = SolidSyslogPosixAddress_Create();
        config   = {resolver, stream, address, TestEndpoint, TestEndpointVersion, nullptr};
        sender   = SolidSyslogStreamSender_Create(&config);
        ErrorHandlerFake_Install(&sentinel);
    }

    void teardown() override
    {
        SolidSyslogStreamSender_Destroy(sender);
        SolidSyslogPosixAddress_Destroy(address);
        StreamFake_Destroy(stream);
        SolidSyslogPosixResolver_Destroy(resolver);
    }

    void Send() const
    {
        SolidSyslogSender_Send(sender, TEST_MESSAGE, TEST_MESSAGE_LEN);
    }
};

// clang-format on

TEST(SolidSyslogStreamSenderDeliveryHealth, FirstFailingSendReportsDeliveryFailed)
{
    StreamFake_SetSendFails(stream, true);
    Send();
    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogStreamSenderErrorSource,
        SOLIDSYSLOG_CAT_SENDER_DELIVERY_FAILED,
        SOLIDSYSLOG_STREAM_SENDER_ERROR_DELIVERY_FAILED
    );
}

TEST(SolidSyslogStreamSenderDeliveryHealth, StayingDownReportsDeliveryFailedOnlyOnce)
{
    StreamFake_SetSendFails(stream, true);
    Send();
    Send();
    Send();
    CALLED_FAKE(ErrorHandlerFake_Handle, ONCE);
}

TEST(SolidSyslogStreamSenderDeliveryHealth, RecoveryAfterDownReportsDeliveryRestored)
{
    StreamFake_SetSendFails(stream, true);
    Send();
    StreamFake_SetSendFails(stream, false);
    Send();
    CALLED_FAKE(ErrorHandlerFake_Handle, TWICE);
    /* The second event, so the count stays explicit rather than pinned at ONCE. */
    CHECK_ERROR_EVENT(
        SOLIDSYSLOG_SEVERITY_NOTICE,
        &SolidSyslogStreamSenderErrorSource,
        SOLIDSYSLOG_CAT_SENDER_DELIVERY_RESTORED,
        SOLIDSYSLOG_STREAM_SENDER_ERROR_DELIVERY_RESTORED
    );
}

TEST(SolidSyslogStreamSenderDeliveryHealth, StayingUpReportsNothing)
{
    Send();
    Send();
    CALLED_FAKE(ErrorHandlerFake_Handle, NEVER);
}

// The stream reports its own configuration version through the Stream vtable,
// so a rotated credential or a changed pinned peer reconnects on the next Send
// without the integrator calling Disconnect from off the servicing thread.
// StreamFake_SetVersion stands in for whatever the integrator bumps.

// clang-format off
TEST_GROUP(SolidSyslogStreamSenderStreamVersion)
{
    struct SolidSyslogResolver*          resolver = nullptr;
    struct SolidSyslogStream*            stream   = nullptr;
    struct SolidSyslogAddress*           address  = nullptr;
    struct SolidSyslogStreamSenderConfig config{};
    struct SolidSyslogSender*            sender   = nullptr;

    void setup() override
    {
        SocketFake_Reset();
        endpointGetHost = GetHost;
        endpointVersion = 0;
        endpointGetPort = GetPort;
        resolver = SolidSyslogPosixResolver_Create();
        stream   = StreamFake_Create();
        address  = SolidSyslogPosixAddress_Create();
        config   = {resolver, stream, address, TestEndpoint, TestEndpointVersion, nullptr};
        sender   = SolidSyslogStreamSender_Create(&config);
    }

    void teardown() override
    {
        SolidSyslogStreamSender_Destroy(sender);
        SolidSyslogPosixAddress_Destroy(address);
        StreamFake_Destroy(stream);
        SolidSyslogPosixResolver_Destroy(resolver);
    }

    void Send() const
    {
        SolidSyslogSender_Send(sender, TEST_MESSAGE, TEST_MESSAGE_LEN);
    }
};

// clang-format on

TEST(SolidSyslogStreamSenderStreamVersion, VersionChangeBetweenSendsReopensTheStream)
{
    Send();
    StreamFake_SetVersion(stream, 1);
    Send();
    LONGS_EQUAL(2, StreamFake_OpenCallCount(stream));
}

TEST(SolidSyslogStreamSenderStreamVersion, SendStillSucceedsAcrossTheReconnect)
{
    Send();
    StreamFake_SetVersion(stream, 1);
    CHECK_TRUE(SolidSyslogSender_Send(sender, TEST_MESSAGE, TEST_MESSAGE_LEN));
}
