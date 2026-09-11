#include <cstring>

#include <mbedtls/cipher.h>
#include <mbedtls/ctr_drbg.h>

#include "CppUTest/TestHarness.h"

extern "C"
{
#include "ConfigLockFake.h"
#include "ErrorHandlerFake.h"
#include "MbedTlsFake.h"
#include "SolidSyslogMbedTlsAesGcmPolicy.h"
#include "SolidSyslogMbedTlsAesGcmPolicyErrors.h"
#include "SolidSyslogNullSecurityPolicy.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogSecurityPolicyDefinition.h"
#include "SolidSyslogTunables.h"
}

#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogSecurityPolicyCategories.h"
#include "TestUtils.h"

using namespace CososoTesting;

enum
{
    AES_256_KEY_SIZE = 32,
    AES_256_KEY_BITS = 256,
    GCM_NONCE_SIZE = 12,
    GCM_TAG_SIZE = 16,
    AES_GCM_TRAILER_SIZE = GCM_NONCE_SIZE + GCM_TAG_SIZE,
    TEST_HEADER_LEN = 4,
    TEST_BODY_LEN = 8,
    TEST_CONTENT_LEN = TEST_HEADER_LEN + TEST_BODY_LEN,
    TEST_KEY_BYTE = 0x2B
};

/* The buffer + capacity the policy handed to GetKey on the most recent fetch. */
static const uint8_t* lastGetKeyBuffer = nullptr;
static size_t lastGetKeyCapacity = 0;

/* Settable key accessor. `keyAvailable` false -> GetKey fails; `keyByte` sets the
 * key contents (vary it to forge a wrong key); `keyLengthToReport` lets a test
 * report a non-32-byte key. */
static bool keyAvailable = true;
static uint8_t keyByte = TEST_KEY_BYTE;
static size_t keyLengthToReport = AES_256_KEY_SIZE;

static bool TestGetKey(void* context, uint8_t* keyOut, size_t capacity, size_t* keyLengthOut)
{
    (void) context;
    lastGetKeyBuffer = keyOut;
    lastGetKeyCapacity = capacity;
    if (!keyAvailable)
    {
        return false;
    }
    size_t written = (keyLengthToReport < capacity) ? keyLengthToReport : capacity;
    memset(keyOut, keyByte, written);
    *keyLengthOut = keyLengthToReport;
    return true;
}

#define CHECK_REPORTED_ERROR(severity, expectedCategory, code) \
    CHECK_ERROR_REPORTED_ONCE((severity), &SolidSyslogMbedTlsAesGcmPolicyErrorSource, (expectedCategory), (code))

#define CHECK_IS_NULL_FALLBACK(handle) POINTERS_EQUAL(SolidSyslogNullSecurityPolicy_Get(), (handle))

/* One macro per direction so each fallible mbedTLS GCM call's failure path reads
 * as a one-line test: seal/open must fail closed and report once. Used only
 * inside the Seal fixture (they reference its seal()/open() helpers). */
#define CHECK_SEAL_REPORTS_ENCRYPT_FAILURE_AT(step)         \
    {                                                       \
        ErrorHandlerFake_Install(nullptr);                  \
        MbedTlsFake_SetGcmStepFails(step);                  \
        CHECK_FALSE(seal());                                \
        CHECK_REPORTED_ERROR(                               \
            SOLIDSYSLOG_SEVERITY_ERROR,                     \
            SOLIDSYSLOG_CAT_SECURITY_POLICY_SEAL_FAILED,    \
            SOLIDSYSLOG_AES_GCM_POLICY_ERROR_ENCRYPT_FAILED \
        );                                                  \
    }

#define CHECK_OPEN_REPORTS_DECRYPT_FAILURE_AT(step)         \
    {                                                       \
        ErrorHandlerFake_Install(nullptr);                  \
        MbedTlsFake_SetGcmStepFails(step);                  \
        CHECK_FALSE(open());                                \
        CHECK_REPORTED_ERROR(                               \
            SOLIDSYSLOG_SEVERITY_ERROR,                     \
            SOLIDSYSLOG_CAT_SECURITY_POLICY_OPEN_FAILED,    \
            SOLIDSYSLOG_AES_GCM_POLICY_ERROR_DECRYPT_FAILED \
        );                                                  \
    }

// clang-format off
TEST_BASE(MbedTlsAesGcmPolicyTestBase)
{
    struct SolidSyslogMbedTlsAesGcmPolicyConfig config = {};
    mbedtls_ctr_drbg_context rng = {};

    void armConfig()
    {
        MbedTlsFake_Reset();
        lastGetKeyBuffer   = nullptr;
        lastGetKeyCapacity = 0;
        keyAvailable       = true;
        keyByte            = TEST_KEY_BYTE;
        keyLengthToReport  = AES_256_KEY_SIZE;
        config.GetKey      = TestGetKey;
        config.KeyContext  = nullptr;
        config.Rng         = &rng;
    }
};

TEST_GROUP_BASE(SolidSyslogMbedTlsAesGcmPolicy, MbedTlsAesGcmPolicyTestBase)
{
    struct SolidSyslogSecurityPolicy* pooled[SOLIDSYSLOG_AES_GCM_POLICY_POOL_SIZE] = {};
    struct SolidSyslogSecurityPolicy* overflow = nullptr;

    void setup() override
    {
        armConfig();
    }

    void teardown() override
    {
        for (auto* handle : pooled)
        {
            if (handle != nullptr)
            {
                SolidSyslogMbedTlsAesGcmPolicy_Destroy(handle);
            }
        }
        if (overflow != nullptr)
        {
            SolidSyslogMbedTlsAesGcmPolicy_Destroy(overflow);
        }
        ConfigLockFake_Uninstall();
    }

    void FillPool()
    {
        for (auto*& slot : pooled)
        {
            slot = SolidSyslogMbedTlsAesGcmPolicy_Create(&config);
        }
    }
};

TEST_GROUP_BASE(SolidSyslogMbedTlsAesGcmPolicySeal, MbedTlsAesGcmPolicyTestBase)
{
    struct SolidSyslogSecurityPolicy* policy = nullptr;
    uint8_t content[TEST_CONTENT_LEN] = {};
    uint8_t originalBody[TEST_BODY_LEN] = {};
    uint8_t trailer[AES_GCM_TRAILER_SIZE] = {};

    void setup() override
    {
        armConfig();
        policy = SolidSyslogMbedTlsAesGcmPolicy_Create(&config);

        static const uint8_t header[TEST_HEADER_LEN] = {0xA5, 0x5A, 0x08, 0x00};
        static const uint8_t body[TEST_BODY_LEN] = {'p', 'l', 'a', 'i', 'n', 't', 'x', 't'};
        memcpy(content, header, TEST_HEADER_LEN);
        memcpy(&content[TEST_HEADER_LEN], body, TEST_BODY_LEN);
        memcpy(originalBody, body, TEST_BODY_LEN);
    }

    void teardown() override
    {
        SolidSyslogMbedTlsAesGcmPolicy_Destroy(policy);
        ConfigLockFake_Uninstall();
    }

    bool seal()
    {
        struct SolidSyslogSecurityRecord rec = {content, TEST_CONTENT_LEN, TEST_HEADER_LEN, trailer};
        return policy->SealRecord(policy, &rec);
    }

    bool open()
    {
        struct SolidSyslogSecurityRecord rec = {content, TEST_CONTENT_LEN, TEST_HEADER_LEN, trailer};
        return policy->OpenRecord(policy, &rec);
    }
};

// clang-format on

TEST(SolidSyslogMbedTlsAesGcmPolicy, CreateReturnsHandleDistinctFromFallback)
{
    struct SolidSyslogSecurityPolicy* handle = SolidSyslogMbedTlsAesGcmPolicy_Create(&config);

    CHECK_TEXT(handle != nullptr, "Create returned nullptr");
    CHECK_TEXT(handle != SolidSyslogNullSecurityPolicy_Get(), "Create returned the Null fallback");

    SolidSyslogMbedTlsAesGcmPolicy_Destroy(handle);
}

TEST(SolidSyslogMbedTlsAesGcmPolicy, TrailerSizeIsTwentyEight)
{
    struct SolidSyslogSecurityPolicy* handle = SolidSyslogMbedTlsAesGcmPolicy_Create(&config);

    LONGS_EQUAL(AES_GCM_TRAILER_SIZE, handle->TrailerSize);

    SolidSyslogMbedTlsAesGcmPolicy_Destroy(handle);
}

TEST(SolidSyslogMbedTlsAesGcmPolicy, FillingPoolThenOverflowReturnsNullFallback)
{
    FillPool();

    overflow = SolidSyslogMbedTlsAesGcmPolicy_Create(&config);

    CHECK_IS_NULL_FALLBACK(overflow);
}

TEST(SolidSyslogMbedTlsAesGcmPolicy, ExhaustedCreateReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    FillPool();

    overflow = SolidSyslogMbedTlsAesGcmPolicy_Create(&config);

    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_POOL_EXHAUSTED
    );
}

TEST(SolidSyslogMbedTlsAesGcmPolicy, NullConfigReturnsNullFallback)
{
    CHECK_IS_NULL_FALLBACK(SolidSyslogMbedTlsAesGcmPolicy_Create(nullptr));
}

TEST(SolidSyslogMbedTlsAesGcmPolicy, NullGetKeyReturnsNullFallback)
{
    config.GetKey = nullptr;

    CHECK_IS_NULL_FALLBACK(SolidSyslogMbedTlsAesGcmPolicy_Create(&config));
}

TEST(SolidSyslogMbedTlsAesGcmPolicy, NullRngReturnsNullFallback)
{
    config.Rng = nullptr;

    CHECK_IS_NULL_FALLBACK(SolidSyslogMbedTlsAesGcmPolicy_Create(&config));
}

TEST(SolidSyslogMbedTlsAesGcmPolicy, BadConfigReportsError)
{
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogMbedTlsAesGcmPolicy_Create(nullptr);

    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_BAD_CONFIG
    );
}

TEST(SolidSyslogMbedTlsAesGcmPolicy, CreateAcquiresAndReleasesConfigLockOnFirstFreeSlot)
{
    ConfigLockFake_Install();

    pooled[0] = SolidSyslogMbedTlsAesGcmPolicy_Create(&config);

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogMbedTlsAesGcmPolicy, DestroyOfPooledHandleLocksOnce)
{
    pooled[0] = SolidSyslogMbedTlsAesGcmPolicy_Create(&config);
    ConfigLockFake_Install();

    SolidSyslogMbedTlsAesGcmPolicy_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogMbedTlsAesGcmPolicy, DestroyOfUnknownHandleReportsWarning)
{
    ErrorHandlerFake_Install(nullptr);
    struct SolidSyslogSecurityPolicy stranger = {};

    SolidSyslogMbedTlsAesGcmPolicy_Destroy(&stranger);

    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_WARNING,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogMbedTlsAesGcmPolicy, DestroyOfStaleHandleReportsWarning)
{
    pooled[0] = SolidSyslogMbedTlsAesGcmPolicy_Create(&config);
    SolidSyslogMbedTlsAesGcmPolicy_Destroy(pooled[0]);
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogMbedTlsAesGcmPolicy_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_WARNING,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogMbedTlsAesGcmPolicySeal, SealRecordGeneratesAFreshNonceIntoTheTrailer)
{
    CHECK_TRUE(seal());

    /* The nonce is drawn from the injected CTR-DRBG straight into the trailer. */
    LONGS_EQUAL(1, MbedTlsFake_CtrDrbgRandomCallCount());
    LONGS_EQUAL(GCM_NONCE_SIZE, MbedTlsFake_LastCtrDrbgRandomLen());
    POINTERS_EQUAL(trailer, MbedTlsFake_LastCtrDrbgRandomBuf());
    POINTERS_EQUAL(&rng, MbedTlsFake_LastCtrDrbgRandomContext());
    /* The fake's CTR-DRBG fills 0xA0, 0xA1, ... - assert it reached the trailer. */
    static const uint8_t expectedNonce[GCM_NONCE_SIZE] =
        {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB};
    MEMCMP_EQUAL(expectedNonce, trailer, GCM_NONCE_SIZE);
}

TEST(SolidSyslogMbedTlsAesGcmPolicySeal, SealRecordPassesTheBodyAsPlaintextToEncrypt)
{
    CHECK_TRUE(seal());

    /* Production hands mbedTLS the body region (Content past HeaderLength), not
     * the header - that the body region is what gets encrypted is the wiring
     * under test. Whether the ciphertext genuinely differs is the integration
     * suite's concern. */
    LONGS_EQUAL(TEST_BODY_LEN, MbedTlsFake_LastGcmPlaintextLen());
    MEMCMP_EQUAL(originalBody, MbedTlsFake_LastGcmPlaintext(), TEST_BODY_LEN);
}

TEST(SolidSyslogMbedTlsAesGcmPolicySeal, SealRecordAuthenticatesTheHeaderAsAssociatedData)
{
    CHECK_TRUE(seal());

    LONGS_EQUAL(TEST_HEADER_LEN, MbedTlsFake_LastGcmAadLen());
    MEMCMP_EQUAL(content, MbedTlsFake_LastGcmAad(), TEST_HEADER_LEN);
}

TEST(SolidSyslogMbedTlsAesGcmPolicySeal, SealRecordUsesTheFetchedKeyAsAes256)
{
    uint8_t expectedKey[AES_256_KEY_SIZE];
    memset(expectedKey, TEST_KEY_BYTE, sizeof expectedKey);

    CHECK_TRUE(seal());

    LONGS_EQUAL(1, MbedTlsFake_GcmSealCount());
    MEMCMP_EQUAL(expectedKey, MbedTlsFake_LastGcmKey(), AES_256_KEY_SIZE);
    UNSIGNED_LONGS_EQUAL(AES_256_KEY_BITS, MbedTlsFake_LastGcmKeyBits());
    LONGS_EQUAL(MBEDTLS_CIPHER_ID_AES, MbedTlsFake_LastGcmCipher());
}

TEST(SolidSyslogMbedTlsAesGcmPolicySeal, OpenReadsTheNonceFromTheTrailer)
{
    CHECK_TRUE(seal());

    CHECK_TRUE(open());

    /* Open must decrypt with the nonce the seal wrote into the trailer. */
    MEMCMP_EQUAL(trailer, MbedTlsFake_LastGcmNonce(), GCM_NONCE_SIZE);
}

TEST(SolidSyslogMbedTlsAesGcmPolicySeal, OpenReturnsTrueWhenDecryptionSucceeds)
{
    CHECK_TRUE(seal());

    CHECK_TRUE(open());

    LONGS_EQUAL(1, MbedTlsFake_GcmOpenCount());
}

/* A tag mismatch (tamper or wrong key) surfaces as mbedtls_gcm_auth_decrypt
 * returning MBEDTLS_ERR_GCM_AUTH_FAILED. Production must fail closed but stay
 * silent - that is the expected outcome, not a library error. Real tamper /
 * wrong-key rejection lives in the integration suite; here we only prove the
 * adapter's verdict-propagation and silence. */
TEST(SolidSyslogMbedTlsAesGcmPolicySeal, OpenReturnsFalseWithoutReportingWhenAuthenticationFails)
{
    ErrorHandlerFake_Install(nullptr);
    MbedTlsFake_SetGcmAuthFails(true);

    CHECK_FALSE(open());
    CALLED_FAKE(ErrorHandlerFake_Handle, NEVER);
}

TEST(SolidSyslogMbedTlsAesGcmPolicySeal, SealFailsClosedWhenKeyUnavailable)
{
    ErrorHandlerFake_Install(nullptr);
    keyAvailable = false;

    CHECK_FALSE(seal());
    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_ERROR,
        SOLIDSYSLOG_CAT_SECURITY_POLICY_KEY_UNAVAILABLE,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_KEY_UNAVAILABLE
    );
}

TEST(SolidSyslogMbedTlsAesGcmPolicySeal, SealFailsClosedWhenKeyIsWrongLength)
{
    ErrorHandlerFake_Install(nullptr);
    keyLengthToReport = 16; /* AES-256 requires exactly 32 bytes */

    CHECK_FALSE(seal());
    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_ERROR,
        SOLIDSYSLOG_CAT_SECURITY_POLICY_KEY_UNAVAILABLE,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_KEY_UNAVAILABLE
    );
}

TEST(SolidSyslogMbedTlsAesGcmPolicySeal, OpenFailsClosedWhenKeyUnavailable)
{
    CHECK_TRUE(seal());
    ErrorHandlerFake_Install(nullptr);
    keyAvailable = false;

    CHECK_FALSE(open());
    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_ERROR,
        SOLIDSYSLOG_CAT_SECURITY_POLICY_KEY_UNAVAILABLE,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_KEY_UNAVAILABLE
    );
}

TEST(SolidSyslogMbedTlsAesGcmPolicySeal, SealReportsNonceFailure)
{
    ErrorHandlerFake_Install(nullptr);
    MbedTlsFake_SetCtrDrbgRandomFails(true);

    CHECK_FALSE(seal());
    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_ERROR,
        SOLIDSYSLOG_CAT_SECURITY_POLICY_SEAL_FAILED,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_NONCE_FAILED
    );
}

/* Seal threads setkey then crypt_and_tag; a non-zero from either must fail
 * closed and report ENCRYPT_FAILED. One test per call pins each step. */
TEST(SolidSyslogMbedTlsAesGcmPolicySeal, SealReportsErrorWhenSettingKeyFails)
{
    CHECK_SEAL_REPORTS_ENCRYPT_FAILURE_AT(MBEDTLSFAKE_GCM_STEP_SETKEY);
}

TEST(SolidSyslogMbedTlsAesGcmPolicySeal, SealReportsErrorWhenEncryptingFails)
{
    CHECK_SEAL_REPORTS_ENCRYPT_FAILURE_AT(MBEDTLSFAKE_GCM_STEP_CRYPT_AND_TAG);
}

/* Open's setkey failure and a genuine (non-auth) auth_decrypt error both report
 * DECRYPT_FAILED. The auth-mismatch verdict is separate - that fail-closed-but-
 * silent path is OpenReturnsFalseWithoutReporting... above. */
TEST(SolidSyslogMbedTlsAesGcmPolicySeal, OpenReportsErrorWhenSettingKeyFails)
{
    CHECK_OPEN_REPORTS_DECRYPT_FAILURE_AT(MBEDTLSFAKE_GCM_STEP_SETKEY);
}

TEST(SolidSyslogMbedTlsAesGcmPolicySeal, OpenReportsErrorWhenDecryptingFails)
{
    CHECK_OPEN_REPORTS_DECRYPT_FAILURE_AT(MBEDTLSFAKE_GCM_STEP_AUTH_DECRYPT);
}

TEST(SolidSyslogMbedTlsAesGcmPolicySeal, SealWipesTheKeyBufferAfterUse)
{
    CHECK_TRUE(seal());

    LONGS_EQUAL(1, MbedTlsFake_PlatformZeroizeCallCount());
    POINTERS_EQUAL(lastGetKeyBuffer, MbedTlsFake_LastPlatformZeroizeBuf());
    LONGS_EQUAL(lastGetKeyCapacity, MbedTlsFake_LastPlatformZeroizeLen());
}
