#include "CppUTest/TestHarness.h"

extern "C"
{
#include "ConfigLockFake.h"
#include "ErrorHandlerFake.h"
#include "OpenSslCredentialsFake.h"
#include "OpenSslFake.h"
#include "SolidSyslogNullStream.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogStreamDefinition.h"
#include "SolidSyslogOpenSslStream.h"
#include "SolidSyslogOpenSslStreamErrors.h"
#include "SolidSyslogTunables.h"
#include "StreamFake.h"
}

#include "SolidSyslogErrorCategory.h"
#include "TestUtils.h"

using namespace CososoTesting;

namespace
{
void NoOpSleep(int milliseconds)
{
    (void) milliseconds;
}
} // namespace

// Asserts Create refused the configuration and handed back the shared NullStream.
#define CHECK_NULL_STREAM(handle) POINTERS_EQUAL(SolidSyslogNullStream_Get(), (handle))

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

// clang-format off
TEST_GROUP(SolidSyslogOpenSslStreamPool)
{
    struct SolidSyslogStream*         transport = nullptr;
    struct SolidSyslogOpenSslStreamConfig config    = {};
    struct SolidSyslogStream* pooled[SOLIDSYSLOG_TLS_STREAM_POOL_SIZE] = {};
    struct SolidSyslogStream* overflow                                 = nullptr;

    void setup() override
    {
        OpenSslFake_Reset();
        transport = StreamFake_Create();
        config.Transport = transport;
        config.Sleep = NoOpSleep;
        OpenSslCredentialsFake_Reset();
        config.Credentials = OpenSslCredentialsFake_Get();
    }

    void teardown() override
    {
        for (auto* handle : pooled)
        {
            if (handle != nullptr)
            {
                SolidSyslogOpenSslStream_Destroy(handle);
            }
        }
        if (overflow != nullptr)
        {
            SolidSyslogOpenSslStream_Destroy(overflow);
        }
        StreamFake_Destroy(transport);
        ConfigLockFake_Uninstall();
    }

    void FillPool()
    {
        for (auto*& slot : pooled)
        {
            slot = SolidSyslogOpenSslStream_Create(&config);
        }
    }
};

// clang-format on

TEST(SolidSyslogOpenSslStreamPool, CreateWithNullConfigReturnsFallback)
{
    struct SolidSyslogStream* fallback = SolidSyslogOpenSslStream_Create(nullptr);

    CHECK_NULL_STREAM(fallback);
}

TEST(SolidSyslogOpenSslStreamPool, CreateWithNullConfigReportsError)
{
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogOpenSslStream_Create(nullptr);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogOpenSslStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_CONFIG
    );
}

TEST(SolidSyslogOpenSslStreamPool, CreateWithNullCredentialsReturnsFallback)
{
    config.Credentials = nullptr;

    struct SolidSyslogStream* fallback = SolidSyslogOpenSslStream_Create(&config);

    CHECK_NULL_STREAM(fallback);
}

TEST(SolidSyslogOpenSslStreamPool, CreateWithNullCredentialsReportsError)
{
    config.Credentials = nullptr;
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogOpenSslStream_Create(&config);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogOpenSslStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_CREDENTIALS
    );
}

TEST(SolidSyslogOpenSslStreamPool, CreateWithNullTransportReturnsFallback)
{
    config.Transport = nullptr;

    struct SolidSyslogStream* fallback = SolidSyslogOpenSslStream_Create(&config);

    CHECK_NULL_STREAM(fallback);
}

TEST(SolidSyslogOpenSslStreamPool, CreateWithNullTransportReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    config.Transport = nullptr;

    SolidSyslogOpenSslStream_Create(&config);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogOpenSslStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_TRANSPORT
    );
}

TEST(SolidSyslogOpenSslStreamPool, CreateWithNullSleepReturnsFallback)
{
    config.Sleep = nullptr;

    struct SolidSyslogStream* fallback = SolidSyslogOpenSslStream_Create(&config);

    CHECK_NULL_STREAM(fallback);
}

TEST(SolidSyslogOpenSslStreamPool, CreateWithNullSleepReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    config.Sleep = nullptr;

    SolidSyslogOpenSslStream_Create(&config);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogOpenSslStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_SLEEP
    );
}

TEST(SolidSyslogOpenSslStreamPool, FillingPoolThenOverflowReturnsDistinctFallback)
{
    FillPool();

    overflow = SolidSyslogOpenSslStream_Create(&config);

    CHECK_IS_FALLBACK(overflow, pooled);
}

TEST(SolidSyslogOpenSslStreamPool, ExhaustedCreateReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    FillPool();

    overflow = SolidSyslogOpenSslStream_Create(&config);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogOpenSslStreamErrorSource,
        SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_POOL_EXHAUSTED
    );
}

TEST(SolidSyslogOpenSslStreamPool, FallbackSendReturnsTrueToDropOnTheFloor)
{
    FillPool();
    overflow = SolidSyslogOpenSslStream_Create(&config);

    CHECK_TRUE(SolidSyslogStream_Send(overflow, "x", 1));
}

TEST(SolidSyslogOpenSslStreamPool, CreateAcquiresAndReleasesConfigLockOnFirstFreeSlot)
{
    ConfigLockFake_Install();

    pooled[0] = SolidSyslogOpenSslStream_Create(&config);

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogOpenSslStreamPool, CreateLocksOncePerSlotProbedWhenPoolIsFull)
{
    FillPool();
    ConfigLockFake_Install();

    overflow = SolidSyslogOpenSslStream_Create(&config);

    LONGS_EQUAL(SOLIDSYSLOG_TLS_STREAM_POOL_SIZE, ConfigLockFake_LockCallCount());
    LONGS_EQUAL(SOLIDSYSLOG_TLS_STREAM_POOL_SIZE, ConfigLockFake_UnlockCallCount());
}

TEST(SolidSyslogOpenSslStreamPool, DestroyOfPooledHandleLocksOnce)
{
    pooled[0] = SolidSyslogOpenSslStream_Create(&config);
    ConfigLockFake_Install();

    SolidSyslogOpenSslStream_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogOpenSslStreamPool, DestroyOfUnknownHandleDoesNotLock)
{
    ConfigLockFake_Install();
    struct SolidSyslogStream stranger = {};

    SolidSyslogOpenSslStream_Destroy(&stranger);

    CALLED_FAKE(ConfigLockFake_Lock, NEVER);
    CALLED_FAKE(ConfigLockFake_Unlock, NEVER);
}

TEST(SolidSyslogOpenSslStreamPool, DestroyOfUnknownHandleReportsWarning)
{
    ErrorHandlerFake_Install(nullptr);
    struct SolidSyslogStream stranger = {};

    SolidSyslogOpenSslStream_Destroy(&stranger);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogOpenSslStreamErrorSource,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_TLS_STREAM_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogOpenSslStreamPool, DestroyOfStaleHandleReportsWarning)
{
    pooled[0] = SolidSyslogOpenSslStream_Create(&config);
    SolidSyslogOpenSslStream_Destroy(pooled[0]);
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogOpenSslStream_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogOpenSslStreamErrorSource,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_TLS_STREAM_ERROR_UNKNOWN_DESTROY
    );
}
