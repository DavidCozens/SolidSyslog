#include <stddef.h>
#include <stdint.h>

#include "TestUtils.h"
#include "CppUTest/TestHarness.h"

using namespace CososoTesting;

#include "ConfigLockFake.h"
#include "ErrorHandlerFake.h"
#include "FreeRTOS.h"
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRtosArpFake.h"
#include "FreeRtosSocketsFake.h"
#include "FreeRtosTaskFake.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogPlusTcpAddress.h"
#include "SolidSyslogPlusTcpAddressPrivate.h"
#include "SolidSyslogPlusTcpTcpStream.h"
#include "SolidSyslogPlusTcpTcpStreamErrors.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogStreamDefinition.h"
#include "SolidSyslogTunables.h"

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

static const uint16_t TEST_PORT = 514;
static const char TEST_MESSAGE[] = "hello";
static const size_t TEST_MESSAGE_LEN = sizeof(TEST_MESSAGE) - 1U;
static const BaseType_t TEST_SHORT_WRITE_BYTES = 3;
static const BaseType_t TEST_READ_BYTES = 7;

namespace
{
int FakeGetConnectTimeoutMs_CallCount = 0;
void* FakeGetConnectTimeoutMs_LastContext = nullptr;
uint32_t FakeGetConnectTimeoutMs_ReturnValue = SOLIDSYSLOG_TCP_CONNECT_TIMEOUT_MS;

void FakeGetConnectTimeoutMs_Reset()
{
    FakeGetConnectTimeoutMs_CallCount = 0;
    FakeGetConnectTimeoutMs_LastContext = reinterpret_cast<void*>(0x1U); /* sentinel - overwritten on first call */
    FakeGetConnectTimeoutMs_ReturnValue = SOLIDSYSLOG_TCP_CONNECT_TIMEOUT_MS;
}

extern "C" uint32_t FakeGetConnectTimeoutMs(void* context)
{
    FakeGetConnectTimeoutMs_CallCount++;
    FakeGetConnectTimeoutMs_LastContext = context;
    return FakeGetConnectTimeoutMs_ReturnValue;
}
} // namespace

// clang-format off
TEST_GROUP(SolidSyslogPlusTcpTcpStream)
{
    struct SolidSyslogStream*           stream = nullptr;
    struct SolidSyslogAddress*          addr = nullptr;
    char                                readBuffer[16] = {0};

    void setup() override
    {
        FreeRtosSocketsFake_Reset();
        FreeRtosArpFake_Reset();
        FreeRtosTaskFake_Reset();
        FakeGetConnectTimeoutMs_Reset();
        stream                        = SolidSyslogPlusTcpTcpStream_Create(nullptr);
        addr                          = SolidSyslogPlusTcpAddress_Create();
        struct freertos_sockaddr* sin = SolidSyslogPlusTcpAddress_AsFreertosSockaddr(addr);
        sin->sin_family               = FREERTOS_AF_INET;
        sin->sin_port                 = FreeRTOS_htons(TEST_PORT);
        sin->sin_address.ulIP_IPv4    = FreeRTOS_inet_addr_quick(10, 0, 2, 2);
    }

    void teardown() override
    {
        SolidSyslogPlusTcpAddress_Destroy(addr);
        if (stream != nullptr)
        {
            SolidSyslogPlusTcpTcpStream_Destroy(stream);
        }
    }

    void openStream() const
    {
        SolidSyslogStream_Open(stream, addr);
    }

    SolidSyslogSsize readIntoBuffer()
    {
        return SolidSyslogStream_Read(stream, readBuffer, sizeof(readBuffer));
    }

    /* Replaces the default NULL-config stream with one that uses the fake
     * getter, then drives Open through the bounded-wait path. Each test sets
     * only the fake-getter return value (or context) it needs different from
     * the defaults restored in setup(). */
    void openStreamWithFakeGetter()
    {
        SolidSyslogPlusTcpTcpStream_Destroy(stream);
        struct SolidSyslogPlusTcpTcpStreamConfig config = {};
        config.GetConnectTimeoutMs                       = FakeGetConnectTimeoutMs;
        stream                                           = SolidSyslogPlusTcpTcpStream_Create(&config);
        SolidSyslogStream_Open(stream, addr);
    }
};

// clang-format on

#define CHECK_SOCKET_CLOSED_ONCE()                                                                             \
    {                                                                                                          \
        CALLED_FAKE(FreeRtosSocketsFake_Closesocket, ONCE);                                                    \
        POINTERS_EQUAL(FreeRtosSocketsFake_LastSocketReturned(), FreeRtosSocketsFake_LastClosesocketSocket()); \
    }

TEST(SolidSyslogPlusTcpTcpStream, CreateReturnsNonNullStream)

{
    CHECK(stream != nullptr);
}

TEST(SolidSyslogPlusTcpTcpStream, OpenCreatesTcpSocket)

{
    openStream();
    CALLED_FAKE(FreeRtosSocketsFake_Socket, ONCE);
    LONGS_EQUAL(FREERTOS_AF_INET, FreeRtosSocketsFake_LastSocketDomain());
    LONGS_EQUAL(FREERTOS_SOCK_STREAM, FreeRtosSocketsFake_LastSocketType());
    LONGS_EQUAL(FREERTOS_IPPROTO_TCP, FreeRtosSocketsFake_LastSocketProtocol());
}

TEST(SolidSyslogPlusTcpTcpStream, OpenReturnsTrueOnSuccess)

{
    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogPlusTcpTcpStream, OpenReturnsFalseWhenSocketFails)

{
    FreeRtosSocketsFake_SetSocketFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogPlusTcpTcpStream, OpenChecksIfDestinationIsInArpCache)

{
    openStream();
    CALLED_FAKE(FreeRtosArpFake_IsIpInArpCache, ONCE);
    LONGS_EQUAL(FreeRTOS_inet_addr_quick(10, 0, 2, 2), FreeRtosArpFake_LastIsIpInArpCacheArg());
}

TEST(SolidSyslogPlusTcpTcpStream, OpenFiresArpProbeOnCacheMiss)

{
    openStream();
    CALLED_FAKE(FreeRtosArpFake_OutputArpRequest, ONCE);
    LONGS_EQUAL(FreeRTOS_inet_addr_quick(10, 0, 2, 2), FreeRtosArpFake_LastOutputArpRequestArg());
}

TEST(SolidSyslogPlusTcpTcpStream, OpenYieldsAfterArpProbeOnCacheMiss)

{
    openStream();
    CALLED_FAKE(FreeRtosTaskFake_VTaskDelay, ONCE);
}

TEST(SolidSyslogPlusTcpTcpStream, OpenSkipsArpProbeAndYieldOnCacheHit)

{
    FreeRtosArpFake_SetCacheHit(true);
    openStream();
    CALLED_FAKE(FreeRtosArpFake_OutputArpRequest, NEVER);
    CALLED_FAKE(FreeRtosTaskFake_VTaskDelay, NEVER);
}

TEST(SolidSyslogPlusTcpTcpStream, OpenSetsConnectTimeoutBeforeConnect)

{
    openStream();
    LONGS_EQUAL(pdMS_TO_TICKS(SOLIDSYSLOG_TCP_CONNECT_TIMEOUT_MS), FreeRtosSocketsFake_SndTimeoAtConnect());
}

TEST(SolidSyslogPlusTcpTcpStream, OpenSetsRecvTimeoutBeforeConnect)

{
    openStream();
    LONGS_EQUAL(pdMS_TO_TICKS(SOLIDSYSLOG_TCP_CONNECT_TIMEOUT_MS), FreeRtosSocketsFake_RcvTimeoAtConnect());
}

TEST(SolidSyslogPlusTcpTcpStream, OpenInvokesConfiguredConnectTimeoutGetter)

{
    openStreamWithFakeGetter();

    LONGS_EQUAL(1, FakeGetConnectTimeoutMs_CallCount);
}

TEST(SolidSyslogPlusTcpTcpStream, OpenUsesGetterReturnValueAsConnectTimeout)

{
    FakeGetConnectTimeoutMs_ReturnValue = 1234U;

    openStreamWithFakeGetter();

    LONGS_EQUAL(pdMS_TO_TICKS(1234), FreeRtosSocketsFake_RcvTimeoAtConnect());
}

TEST(SolidSyslogPlusTcpTcpStream, GetterReceivesNullContextWhenContextNotConfigured)

{
    openStreamWithFakeGetter();

    POINTERS_EQUAL(nullptr, FakeGetConnectTimeoutMs_LastContext);
}

TEST(SolidSyslogPlusTcpTcpStream, OpenCallsConnectWithSocketAndAddress)

{
    openStream();
    CALLED_FAKE(FreeRtosSocketsFake_Connect, ONCE);
    POINTERS_EQUAL(FreeRtosSocketsFake_LastSocketReturned(), FreeRtosSocketsFake_LastConnectSocket());
    POINTERS_EQUAL(SolidSyslogPlusTcpAddress_AsConstFreertosSockaddr(addr), FreeRtosSocketsFake_LastConnectAddress());
    LONGS_EQUAL(sizeof(struct freertos_sockaddr), FreeRtosSocketsFake_LastConnectAddressLength());
}

TEST(SolidSyslogPlusTcpTcpStream, OpenClearsSendTimeoutAfterConnect)

{
    openStream();
    LONGS_EQUAL(0, FreeRtosSocketsFake_LastSndTimeoSet());
}

TEST(SolidSyslogPlusTcpTcpStream, OpenClearsRecvTimeoutAfterConnect)

{
    openStream();
    LONGS_EQUAL(0, FreeRtosSocketsFake_LastRcvTimeoSet());
    LONGS_EQUAL(2, FreeRtosSocketsFake_RcvTimeoSetCallCount());
}

TEST(SolidSyslogPlusTcpTcpStream, OpenCallsSetsockoptWithReturnedSocketAndLevelZero)

{
    openStream();
    POINTERS_EQUAL(FreeRtosSocketsFake_LastSocketReturned(), FreeRtosSocketsFake_LastSetsockoptSocket());
    LONGS_EQUAL(0, FreeRtosSocketsFake_LastSetsockoptLevel());
}

TEST(SolidSyslogPlusTcpTcpStream, OpenPassesTickTypeSizedOptionLengthToSetsockopt)

{
    openStream();
    LONGS_EQUAL(sizeof(TickType_t), FreeRtosSocketsFake_LastSetsockoptOptionLength());
}

TEST(SolidSyslogPlusTcpTcpStream, OpenReturnsFalseOnConnectFailure)

{
    FreeRtosSocketsFake_SetConnectFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogPlusTcpTcpStream, OpenClosesSocketOnConnectFailure)

{
    FreeRtosSocketsFake_SetConnectFails(true);
    openStream();
    CHECK_SOCKET_CLOSED_ONCE();
}

TEST(SolidSyslogPlusTcpTcpStream, OpenIsIdempotent)

{
    openStream();
    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
    CALLED_FAKE(FreeRtosSocketsFake_Socket, ONCE);
    CALLED_FAKE(FreeRtosSocketsFake_Connect, ONCE);
}

TEST(SolidSyslogPlusTcpTcpStream, SendFailsBeforeOpen)

{
    CHECK_FALSE(SolidSyslogStream_Send(stream, "x", 1));
    CALLED_FAKE(FreeRtosSocketsFake_Send, NEVER);
}

TEST(SolidSyslogPlusTcpTcpStream, SendCallsFreeRtosSendWithSocketBufferAndLength)

{
    openStream();
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    CALLED_FAKE(FreeRtosSocketsFake_Send, ONCE);
    POINTERS_EQUAL(FreeRtosSocketsFake_LastSocketReturned(), FreeRtosSocketsFake_LastSendSocket());
    POINTERS_EQUAL(TEST_MESSAGE, FreeRtosSocketsFake_LastSendBuffer());
    LONGS_EQUAL(TEST_MESSAGE_LEN, FreeRtosSocketsFake_LastSendLength());
    LONGS_EQUAL(0, FreeRtosSocketsFake_LastSendFlags());
}

TEST(SolidSyslogPlusTcpTcpStream, SendReturnsTrueOnFullWrite)

{
    openStream();
    CHECK_TRUE(SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN));
}

TEST(SolidSyslogPlusTcpTcpStream, SendReturnsFalseOnShortWrite)

{
    openStream();
    FreeRtosSocketsFake_SetSendReturn(TEST_SHORT_WRITE_BYTES);
    CHECK_FALSE(SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN));
}

TEST(SolidSyslogPlusTcpTcpStream, SendDoesNotRetryAfterShortWrite)

{
    openStream();
    FreeRtosSocketsFake_SetSendReturn(TEST_SHORT_WRITE_BYTES);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    CALLED_FAKE(FreeRtosSocketsFake_Send, ONCE);
}

TEST(SolidSyslogPlusTcpTcpStream, SendClosesSocketOnShortWrite)

{
    openStream();
    FreeRtosSocketsFake_SetSendReturn(TEST_SHORT_WRITE_BYTES);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    CHECK_SOCKET_CLOSED_ONCE();
}

TEST(SolidSyslogPlusTcpTcpStream, SendReturnsFalseOnError)

{
    openStream();
    FreeRtosSocketsFake_SetSendFails(true);
    CHECK_FALSE(SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN));
}

TEST(SolidSyslogPlusTcpTcpStream, SendClosesSocketOnError)

{
    openStream();
    FreeRtosSocketsFake_SetSendFails(true);
    SolidSyslogStream_Send(stream, TEST_MESSAGE, TEST_MESSAGE_LEN);
    CHECK_SOCKET_CLOSED_ONCE();
}

TEST(SolidSyslogPlusTcpTcpStream, ReadReturnsNegativeOneBeforeOpen)

{
    LONGS_EQUAL(-1, readIntoBuffer());
    CALLED_FAKE(FreeRtosSocketsFake_Recv, NEVER);
}

TEST(SolidSyslogPlusTcpTcpStream, ReadCallsFreeRtosRecvWithSocketBufferAndLength)

{
    openStream();
    readIntoBuffer();
    CALLED_FAKE(FreeRtosSocketsFake_Recv, ONCE);
    POINTERS_EQUAL(FreeRtosSocketsFake_LastSocketReturned(), FreeRtosSocketsFake_LastRecvSocket());
    POINTERS_EQUAL(readBuffer, FreeRtosSocketsFake_LastRecvBuffer());
    LONGS_EQUAL(sizeof(readBuffer), FreeRtosSocketsFake_LastRecvLength());
    LONGS_EQUAL(0, FreeRtosSocketsFake_LastRecvFlags());
}

TEST(SolidSyslogPlusTcpTcpStream, ReadReturnsBytesOnSuccess)

{
    openStream();
    FreeRtosSocketsFake_SetRecvReturn(TEST_READ_BYTES);
    LONGS_EQUAL(TEST_READ_BYTES, readIntoBuffer());
}

TEST(SolidSyslogPlusTcpTcpStream, ReadReturnsZeroWhenWouldBlock)

{
    openStream();
    FreeRtosSocketsFake_SetRecvReturn(0);
    LONGS_EQUAL(0, readIntoBuffer());
}

TEST(SolidSyslogPlusTcpTcpStream, ReadLeavesSocketOpenWhenWouldBlock)

{
    openStream();
    FreeRtosSocketsFake_SetRecvReturn(0);
    readIntoBuffer();
    CALLED_FAKE(FreeRtosSocketsFake_Closesocket, NEVER);
}

TEST(SolidSyslogPlusTcpTcpStream, ReadReturnsNegativeOneOnErrorAndClosesSocket)

{
    openStream();
    FreeRtosSocketsFake_SetRecvFails(true);
    LONGS_EQUAL(-1, readIntoBuffer());
    CHECK_SOCKET_CLOSED_ONCE();
}

TEST(SolidSyslogPlusTcpTcpStream, CloseWithoutOpenIsNoOp)

{
    SolidSyslogStream_Close(stream);
    CALLED_FAKE(FreeRtosSocketsFake_Closesocket, NEVER);
}

TEST(SolidSyslogPlusTcpTcpStream, CloseClosesOpenSocket)

{
    openStream();
    SolidSyslogStream_Close(stream);
    CHECK_SOCKET_CLOSED_ONCE();
}

TEST(SolidSyslogPlusTcpTcpStream, CloseIsIdempotent)

{
    openStream();
    SolidSyslogStream_Close(stream);
    SolidSyslogStream_Close(stream);
    CALLED_FAKE(FreeRtosSocketsFake_Closesocket, ONCE);
}

TEST(SolidSyslogPlusTcpTcpStream, DestroyClosesOpenSocket)

{
    openStream();
    SolidSyslogPlusTcpTcpStream_Destroy(stream);
    stream = nullptr;
    CHECK_SOCKET_CLOSED_ONCE();
}

TEST(SolidSyslogPlusTcpTcpStream, DestroyAfterCloseDoesNotCloseAgain)

{
    openStream();
    SolidSyslogStream_Close(stream);
    SolidSyslogPlusTcpTcpStream_Destroy(stream);
    stream = nullptr;
    CALLED_FAKE(FreeRtosSocketsFake_Closesocket, ONCE);
}

// clang-format off
TEST_GROUP(SolidSyslogPlusTcpTcpStreamPool)
{
    struct SolidSyslogStream* pooled[SOLIDSYSLOG_TCP_STREAM_POOL_SIZE] = {};
    struct SolidSyslogStream* overflow                                           = nullptr;

    void setup() override
    {
        FreeRtosSocketsFake_Reset();
    }

    void teardown() override
    {
        for (auto* handle : pooled)
        {
            if (handle != nullptr)
            {
                SolidSyslogPlusTcpTcpStream_Destroy(handle);
            }
        }
        if (overflow != nullptr)
        {
            SolidSyslogPlusTcpTcpStream_Destroy(overflow);
        }
        ConfigLockFake_Uninstall();
    }

    void FillPool()
    {
        for (auto*& slot : pooled)
        {
            slot = SolidSyslogPlusTcpTcpStream_Create(nullptr);
        }
    }
};

// clang-format on

TEST(SolidSyslogPlusTcpTcpStreamPool, FillingPoolThenOverflowReturnsDistinctFallback)

{
    FillPool();

    overflow = SolidSyslogPlusTcpTcpStream_Create(nullptr);

    CHECK_IS_FALLBACK(overflow, pooled);
}

TEST(SolidSyslogPlusTcpTcpStreamPool, ExhaustedCreateReportsError)

{
    ErrorHandlerFake_Install(nullptr);
    FillPool();

    overflow = SolidSyslogPlusTcpTcpStream_Create(nullptr);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogPlusTcpTcpStreamErrorSource,
        SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
        SOLIDSYSLOG_PLUSTCP_TCP_STREAM_ERROR_POOL_EXHAUSTED
    );
}

TEST(SolidSyslogPlusTcpTcpStreamPool, FallbackVtableMethodsAreNoOps)

{
    FillPool();
    overflow = SolidSyslogPlusTcpTcpStream_Create(nullptr);
    struct SolidSyslogAddress* localAddr = SolidSyslogPlusTcpAddress_Create();
    char buf[8] = {0};
    FreeRtosSocketsFake_Reset();

    /* NullStream's Open/Send/Read return safe values so the Service algorithm
     * does not tear the (non-existent) connection down on the fallback. */
    CHECK_TRUE(SolidSyslogStream_Open(overflow, localAddr));
    CHECK_TRUE(SolidSyslogStream_Send(overflow, buf, sizeof(buf)));
    LONGS_EQUAL(0, SolidSyslogStream_Read(overflow, buf, sizeof(buf)));
    SolidSyslogStream_Close(overflow);
    SolidSyslogPlusTcpAddress_Destroy(localAddr);

    CALLED_FAKE(FreeRtosSocketsFake_Socket, NEVER);
    CALLED_FAKE(FreeRtosSocketsFake_Connect, NEVER);
    CALLED_FAKE(FreeRtosSocketsFake_Send, NEVER);
    CALLED_FAKE(FreeRtosSocketsFake_Recv, NEVER);
    CALLED_FAKE(FreeRtosSocketsFake_Closesocket, NEVER);
}

TEST(SolidSyslogPlusTcpTcpStreamPool, CreateAcquiresAndReleasesConfigLockOnFirstFreeSlot)

{
    ConfigLockFake_Install();

    pooled[0] = SolidSyslogPlusTcpTcpStream_Create(nullptr);

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogPlusTcpTcpStreamPool, CreateLocksOncePerSlotProbedWhenPoolIsFull)

{
    FillPool();
    ConfigLockFake_Install();

    overflow = SolidSyslogPlusTcpTcpStream_Create(nullptr);

    LONGS_EQUAL(SOLIDSYSLOG_TCP_STREAM_POOL_SIZE, ConfigLockFake_LockCallCount());
    LONGS_EQUAL(SOLIDSYSLOG_TCP_STREAM_POOL_SIZE, ConfigLockFake_UnlockCallCount());
}

TEST(SolidSyslogPlusTcpTcpStreamPool, DestroyOfPooledHandleLocksOnce)

{
    pooled[0] = SolidSyslogPlusTcpTcpStream_Create(nullptr);
    ConfigLockFake_Install();

    SolidSyslogPlusTcpTcpStream_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogPlusTcpTcpStreamPool, DestroyOfUnknownHandleDoesNotLock)

{
    ConfigLockFake_Install();
    struct SolidSyslogStream stranger = {};

    SolidSyslogPlusTcpTcpStream_Destroy(&stranger);

    CALLED_FAKE(ConfigLockFake_Lock, NEVER);
    CALLED_FAKE(ConfigLockFake_Unlock, NEVER);
}

TEST(SolidSyslogPlusTcpTcpStreamPool, DestroyOfUnknownHandleReportsWarning)

{
    ErrorHandlerFake_Install(nullptr);
    struct SolidSyslogStream stranger = {};

    SolidSyslogPlusTcpTcpStream_Destroy(&stranger);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogPlusTcpTcpStreamErrorSource,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_PLUSTCP_TCP_STREAM_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogPlusTcpTcpStreamPool, DestroyOfStaleHandleReportsWarning)

{
    pooled[0] = SolidSyslogPlusTcpTcpStream_Create(nullptr);
    SolidSyslogPlusTcpTcpStream_Destroy(pooled[0]);
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogPlusTcpTcpStream_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogPlusTcpTcpStreamErrorSource,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_PLUSTCP_TCP_STREAM_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogPlusTcpTcpStream, VersionIsAlwaysZeroBecauseNothingChangesAtRuntime)
{
    LONGS_EQUAL(0, SolidSyslogStream_Version(stream));
}
