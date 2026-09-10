#include "CppUTest/TestHarness.h"

extern "C"
{
#include <mbedtls/ctr_drbg.h>

#include "ConfigLockFake.h"
#include "ErrorHandlerFake.h"
#include "MbedTlsCredentialsFake.h"
#include "SolidSyslogMbedTlsCredentialsDefinition.h"
#include "SolidSyslogMbedTlsStream.h"
#include "SolidSyslogMbedTlsStreamErrors.h"
#include "SolidSyslogNullStream.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogStreamDefinition.h"
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
TEST_GROUP(SolidSyslogMbedTlsStreamPool)
{
    mbedtls_ctr_drbg_context              rng       = {};
    struct SolidSyslogStream*             transport = nullptr;
    struct SolidSyslogMbedTlsStreamConfig config    = {};
    struct SolidSyslogStream* pooled[SOLIDSYSLOG_TLS_STREAM_POOL_SIZE] = {};
    struct SolidSyslogStream* overflow                                      = nullptr;

    void setup() override
    {
        /* A real transport handle keeps Destroy -> Cleanup -> Close on the
         * vtable-routed transport safe; mirrors the OpenSslStream
         * pool-test pattern. */
        transport        = StreamFake_Create();
        config.Transport = transport;
        config.Sleep     = NoOpSleep;
        config.Rng       = &rng;
        MbedTlsCredentialsFake_Reset();
        config.Credentials = MbedTlsCredentialsFake_Get();
    }

    void teardown() override
    {
        for (auto* handle : pooled)
        {
            if (handle != nullptr)
            {
                SolidSyslogMbedTlsStream_Destroy(handle);
            }
        }
        if (overflow != nullptr)
        {
            SolidSyslogMbedTlsStream_Destroy(overflow);
        }
        StreamFake_Destroy(transport);
        ConfigLockFake_Uninstall();
    }

    void FillPool()
    {
        for (auto*& slot : pooled)
        {
            slot = SolidSyslogMbedTlsStream_Create(&config);
        }
    }
};

// clang-format on

TEST(SolidSyslogMbedTlsStreamPool, CreateWithNullConfigReturnsFallback)
{
    struct SolidSyslogStream* fallback = SolidSyslogMbedTlsStream_Create(nullptr);

    CHECK_NULL_STREAM(fallback);
}

TEST(SolidSyslogMbedTlsStreamPool, CreateWithNullConfigReportsError)
{
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogMbedTlsStream_Create(nullptr);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogMbedTlsStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_CONFIG
    );
}

TEST(SolidSyslogMbedTlsStreamPool, CreateWithNullTransportReturnsFallback)
{
    config.Transport = nullptr;

    struct SolidSyslogStream* fallback = SolidSyslogMbedTlsStream_Create(&config);

    CHECK_NULL_STREAM(fallback);
}

TEST(SolidSyslogMbedTlsStreamPool, CreateWithNullTransportReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    config.Transport = nullptr;

    SolidSyslogMbedTlsStream_Create(&config);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogMbedTlsStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_TRANSPORT
    );
}

TEST(SolidSyslogMbedTlsStreamPool, CreateWithNullSleepReturnsFallback)
{
    config.Sleep = nullptr;

    struct SolidSyslogStream* fallback = SolidSyslogMbedTlsStream_Create(&config);

    CHECK_NULL_STREAM(fallback);
}

TEST(SolidSyslogMbedTlsStreamPool, CreateWithNullSleepReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    config.Sleep = nullptr;

    SolidSyslogMbedTlsStream_Create(&config);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogMbedTlsStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_SLEEP
    );
}

TEST(SolidSyslogMbedTlsStreamPool, CreateWithNullRngReturnsFallback)
{
    config.Rng = nullptr;

    struct SolidSyslogStream* fallback = SolidSyslogMbedTlsStream_Create(&config);

    CHECK_NULL_STREAM(fallback);
}

TEST(SolidSyslogMbedTlsStreamPool, CreateWithNullRngReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    config.Rng = nullptr;

    SolidSyslogMbedTlsStream_Create(&config);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogMbedTlsStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_RNG
    );
}

TEST(SolidSyslogMbedTlsStreamPool, CreateWithNullCredentialsReturnsFallback)
{
    config.Credentials = nullptr;

    struct SolidSyslogStream* fallback = SolidSyslogMbedTlsStream_Create(&config);

    CHECK_NULL_STREAM(fallback);
}

TEST(SolidSyslogMbedTlsStreamPool, CreateWithNullCredentialsReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    config.Credentials = nullptr;

    SolidSyslogMbedTlsStream_Create(&config);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogMbedTlsStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_CREDENTIALS
    );
}

TEST(SolidSyslogMbedTlsStreamPool, CreateReturnsHandleDistinctFromFallback)
{
    struct SolidSyslogStream* handle = SolidSyslogMbedTlsStream_Create(&config);

    CHECK_TEXT(handle != nullptr, "Create returned nullptr");
    CHECK_TEXT(handle != SolidSyslogNullStream_Get(), "Create returned the NullStream fallback");

    SolidSyslogMbedTlsStream_Destroy(handle);
}

TEST(SolidSyslogMbedTlsStreamPool, FillingPoolThenOverflowReturnsDistinctFallback)
{
    FillPool();

    overflow = SolidSyslogMbedTlsStream_Create(&config);

    CHECK_IS_FALLBACK(overflow, pooled);
}

TEST(SolidSyslogMbedTlsStreamPool, ExhaustedCreateReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    FillPool();

    overflow = SolidSyslogMbedTlsStream_Create(&config);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogMbedTlsStreamErrorSource,
        SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_POOL_EXHAUSTED
    );
}

TEST(SolidSyslogMbedTlsStreamPool, FallbackSendReturnsTrueToDropOnTheFloor)
{
    FillPool();
    overflow = SolidSyslogMbedTlsStream_Create(&config);

    CHECK_TRUE(SolidSyslogStream_Send(overflow, "x", 1));
}

TEST(SolidSyslogMbedTlsStreamPool, CreateAcquiresAndReleasesConfigLockOnFirstFreeSlot)
{
    ConfigLockFake_Install();

    pooled[0] = SolidSyslogMbedTlsStream_Create(&config);

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogMbedTlsStreamPool, CreateLocksOncePerSlotProbedWhenPoolIsFull)
{
    FillPool();
    ConfigLockFake_Install();

    overflow = SolidSyslogMbedTlsStream_Create(&config);

    LONGS_EQUAL(SOLIDSYSLOG_TLS_STREAM_POOL_SIZE, ConfigLockFake_LockCallCount());
    LONGS_EQUAL(SOLIDSYSLOG_TLS_STREAM_POOL_SIZE, ConfigLockFake_UnlockCallCount());
}

TEST(SolidSyslogMbedTlsStreamPool, DestroyOfPooledHandleLocksOnce)
{
    pooled[0] = SolidSyslogMbedTlsStream_Create(&config);
    ConfigLockFake_Install();

    SolidSyslogMbedTlsStream_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogMbedTlsStreamPool, DestroyOfUnknownHandleDoesNotLock)
{
    ConfigLockFake_Install();
    struct SolidSyslogStream stranger = {};

    SolidSyslogMbedTlsStream_Destroy(&stranger);

    CALLED_FAKE(ConfigLockFake_Lock, NEVER);
    CALLED_FAKE(ConfigLockFake_Unlock, NEVER);
}

TEST(SolidSyslogMbedTlsStreamPool, DestroyOfUnknownHandleReportsWarning)
{
    ErrorHandlerFake_Install(nullptr);
    struct SolidSyslogStream stranger = {};

    SolidSyslogMbedTlsStream_Destroy(&stranger);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogMbedTlsStreamErrorSource,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_TLS_STREAM_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogMbedTlsStreamPool, DestroyOfStaleHandleReportsWarning)
{
    pooled[0] = SolidSyslogMbedTlsStream_Create(&config);
    SolidSyslogMbedTlsStream_Destroy(pooled[0]);
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogMbedTlsStream_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogMbedTlsStreamErrorSource,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_TLS_STREAM_ERROR_UNKNOWN_DESTROY
    );
}
