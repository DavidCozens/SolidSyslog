#include <cstring>

#include "CppUTest/TestHarness.h"

extern "C"
{
#include "ConfigLockFake.h"
#include "ErrorHandlerFake.h"
#include "OpenSslFake.h"
#include "SolidSyslogNullSecurityPolicy.h"
#include "SolidSyslogOpenSslAesGcmPolicy.h"
#include "SolidSyslogOpenSslAesGcmPolicyErrors.h"
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
    CHECK_ERROR_REPORTED_ONCE((severity), &SolidSyslogOpenSslAesGcmPolicyErrorSource, (expectedCategory), (code))

#define CHECK_IS_NULL_FALLBACK(handle) POINTERS_EQUAL(SolidSyslogNullSecurityPolicy_Get(), (handle))

/* One macro per direction so each EVP step's failure path reads as a one-line
 * test: seal/open must fail closed and report once. Used only inside the Seal
 * fixture (they reference its seal()/open() helpers). */
#define CHECK_SEAL_REPORTS_ENCRYPT_FAILURE_AT(step)         \
    {                                                       \
        ErrorHandlerFake_Install(nullptr);                  \
        OpenSslFake_SetGcmStepFails(step);                  \
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
        OpenSslFake_SetGcmStepFails(step);                  \
        CHECK_FALSE(open());                                \
        CHECK_REPORTED_ERROR(                               \
            SOLIDSYSLOG_SEVERITY_ERROR,                     \
            SOLIDSYSLOG_CAT_SECURITY_POLICY_OPEN_FAILED,    \
            SOLIDSYSLOG_AES_GCM_POLICY_ERROR_DECRYPT_FAILED \
        );                                                  \
    }

// clang-format off
TEST_BASE(OpenSslAesGcmPolicyTestBase)
{
    struct SolidSyslogOpenSslAesGcmPolicyConfig config = {};

    void armConfig()
    {
        OpenSslFake_Reset();
        lastGetKeyBuffer   = nullptr;
        lastGetKeyCapacity = 0;
        keyAvailable       = true;
        keyByte            = TEST_KEY_BYTE;
        keyLengthToReport  = AES_256_KEY_SIZE;
        config.GetKey      = TestGetKey;
        config.KeyContext  = nullptr;
    }
};

TEST_GROUP_BASE(SolidSyslogOpenSslAesGcmPolicy, OpenSslAesGcmPolicyTestBase)
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
                SolidSyslogOpenSslAesGcmPolicy_Destroy(handle);
            }
        }
        if (overflow != nullptr)
        {
            SolidSyslogOpenSslAesGcmPolicy_Destroy(overflow);
        }
        ConfigLockFake_Uninstall();
    }

    void FillPool()
    {
        for (auto*& slot : pooled)
        {
            slot = SolidSyslogOpenSslAesGcmPolicy_Create(&config);
        }
    }
};

TEST_GROUP_BASE(SolidSyslogOpenSslAesGcmPolicySeal, OpenSslAesGcmPolicyTestBase)
{
    struct SolidSyslogSecurityPolicy* policy = nullptr;
    uint8_t content[TEST_CONTENT_LEN] = {};
    uint8_t originalBody[TEST_BODY_LEN] = {};
    uint8_t trailer[AES_GCM_TRAILER_SIZE] = {};

    void setup() override
    {
        armConfig();
        policy = SolidSyslogOpenSslAesGcmPolicy_Create(&config);

        static const uint8_t header[TEST_HEADER_LEN] = {0xA5, 0x5A, 0x08, 0x00};
        static const uint8_t body[TEST_BODY_LEN] = {'p', 'l', 'a', 'i', 'n', 't', 'x', 't'};
        memcpy(content, header, TEST_HEADER_LEN);
        memcpy(&content[TEST_HEADER_LEN], body, TEST_BODY_LEN);
        memcpy(originalBody, body, TEST_BODY_LEN);
    }

    void teardown() override
    {
        SolidSyslogOpenSslAesGcmPolicy_Destroy(policy);
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

TEST(SolidSyslogOpenSslAesGcmPolicy, CreateReturnsHandleDistinctFromFallback)
{
    struct SolidSyslogSecurityPolicy* handle = SolidSyslogOpenSslAesGcmPolicy_Create(&config);

    CHECK_TEXT(handle != nullptr, "Create returned nullptr");
    CHECK_TEXT(handle != SolidSyslogNullSecurityPolicy_Get(), "Create returned the Null fallback");

    SolidSyslogOpenSslAesGcmPolicy_Destroy(handle);
}

TEST(SolidSyslogOpenSslAesGcmPolicy, TrailerSizeIsTwentyEight)
{
    struct SolidSyslogSecurityPolicy* handle = SolidSyslogOpenSslAesGcmPolicy_Create(&config);

    LONGS_EQUAL(AES_GCM_TRAILER_SIZE, handle->TrailerSize);

    SolidSyslogOpenSslAesGcmPolicy_Destroy(handle);
}

TEST(SolidSyslogOpenSslAesGcmPolicy, FillingPoolThenOverflowReturnsNullFallback)
{
    FillPool();

    overflow = SolidSyslogOpenSslAesGcmPolicy_Create(&config);

    CHECK_IS_NULL_FALLBACK(overflow);
}

TEST(SolidSyslogOpenSslAesGcmPolicy, ExhaustedCreateReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    FillPool();

    overflow = SolidSyslogOpenSslAesGcmPolicy_Create(&config);

    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_POOL_EXHAUSTED
    );
}

TEST(SolidSyslogOpenSslAesGcmPolicy, NullConfigReturnsNullFallback)
{
    CHECK_IS_NULL_FALLBACK(SolidSyslogOpenSslAesGcmPolicy_Create(nullptr));
}

TEST(SolidSyslogOpenSslAesGcmPolicy, NullGetKeyReturnsNullFallback)
{
    config.GetKey = nullptr;

    CHECK_IS_NULL_FALLBACK(SolidSyslogOpenSslAesGcmPolicy_Create(&config));
}

TEST(SolidSyslogOpenSslAesGcmPolicy, BadConfigReportsError)
{
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogOpenSslAesGcmPolicy_Create(nullptr);

    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_BAD_CONFIG
    );
}

TEST(SolidSyslogOpenSslAesGcmPolicy, CreateAcquiresAndReleasesConfigLockOnFirstFreeSlot)
{
    ConfigLockFake_Install();

    pooled[0] = SolidSyslogOpenSslAesGcmPolicy_Create(&config);

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogOpenSslAesGcmPolicy, DestroyOfPooledHandleLocksOnce)
{
    pooled[0] = SolidSyslogOpenSslAesGcmPolicy_Create(&config);
    ConfigLockFake_Install();

    SolidSyslogOpenSslAesGcmPolicy_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogOpenSslAesGcmPolicy, DestroyOfUnknownHandleReportsWarning)
{
    ErrorHandlerFake_Install(nullptr);
    struct SolidSyslogSecurityPolicy stranger = {};

    SolidSyslogOpenSslAesGcmPolicy_Destroy(&stranger);

    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_WARNING,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogOpenSslAesGcmPolicy, DestroyOfStaleHandleReportsWarning)
{
    pooled[0] = SolidSyslogOpenSslAesGcmPolicy_Create(&config);
    SolidSyslogOpenSslAesGcmPolicy_Destroy(pooled[0]);
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogOpenSslAesGcmPolicy_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_WARNING,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealRecordGeneratesAFreshNonceIntoTheTrailer)
{
    CHECK_TRUE(seal());

    LONGS_EQUAL(1, OpenSslFake_RandBytesCallCount());
    LONGS_EQUAL(GCM_NONCE_SIZE, OpenSslFake_LastRandBytesLen());
    POINTERS_EQUAL(trailer, OpenSslFake_LastRandBytesBuf());
    /* The fake's RAND_bytes fills 0xA0, 0xA1, ... - assert it reached the trailer. */
    static const uint8_t expectedNonce[GCM_NONCE_SIZE] =
        {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB};
    MEMCMP_EQUAL(expectedNonce, trailer, GCM_NONCE_SIZE);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealRecordPassesTheBodyAsPlaintextToEncrypt)
{
    CHECK_TRUE(seal());

    /* Production hands EVP the body region (Content past HeaderLength), not the
     * header - that the body region is what gets encrypted is the wiring under
     * test. Whether the ciphertext genuinely differs is the integration suite's
     * concern. */
    LONGS_EQUAL(TEST_BODY_LEN, OpenSslFake_LastGcmPlaintextLen());
    MEMCMP_EQUAL(originalBody, OpenSslFake_LastGcmPlaintext(), TEST_BODY_LEN);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealRecordAuthenticatesTheHeaderAsAssociatedData)
{
    CHECK_TRUE(seal());

    LONGS_EQUAL(TEST_HEADER_LEN, OpenSslFake_LastGcmAadLen());
    MEMCMP_EQUAL(content, OpenSslFake_LastGcmAad(), TEST_HEADER_LEN);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealRecordUsesTheFetchedKey)
{
    uint8_t expectedKey[AES_256_KEY_SIZE];
    memset(expectedKey, TEST_KEY_BYTE, sizeof expectedKey);

    CHECK_TRUE(seal());

    LONGS_EQUAL(1, OpenSslFake_GcmSealCount());
    MEMCMP_EQUAL(expectedKey, OpenSslFake_LastGcmKey(), AES_256_KEY_SIZE);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, OpenReadsTheNonceFromTheTrailer)
{
    CHECK_TRUE(seal());

    CHECK_TRUE(open());

    /* Open must decrypt with the nonce the seal wrote into the trailer. */
    MEMCMP_EQUAL(trailer, OpenSslFake_LastGcmNonce(), GCM_NONCE_SIZE);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, OpenReturnsTrueWhenDecryptionSucceeds)
{
    CHECK_TRUE(seal());

    CHECK_TRUE(open());

    LONGS_EQUAL(1, OpenSslFake_GcmOpenCount());
}

/* A tag mismatch (tamper or wrong key) surfaces as EVP_DecryptFinal_ex returning
 * 0. Production must fail closed but stay silent - that is the expected outcome,
 * not a library error. Real tamper/wrong-key rejection lives in the integration
 * suite; here we only prove the adapter's verdict-propagation and silence. */
TEST(SolidSyslogOpenSslAesGcmPolicySeal, OpenReturnsFalseWithoutReportingWhenAuthenticationFails)
{
    ErrorHandlerFake_Install(nullptr);
    OpenSslFake_SetGcmStepFails(OPENSSLFAKE_GCM_STEP_FINAL);

    CHECK_FALSE(open());
    CALLED_FAKE(ErrorHandlerFake_Handle, NEVER);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealFailsClosedWhenKeyUnavailable)
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

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealFailsClosedWhenKeyIsWrongLength)
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

TEST(SolidSyslogOpenSslAesGcmPolicySeal, OpenFailsClosedWhenKeyUnavailable)
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

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealReportsNonceFailure)
{
    ErrorHandlerFake_Install(nullptr);
    OpenSslFake_SetRandBytesFails(true);

    CHECK_FALSE(seal());
    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_ERROR,
        SOLIDSYSLOG_CAT_SECURITY_POLICY_SEAL_FAILED,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_NONCE_FAILED
    );
}

/* Seal threads every EVP return through an && chain; any non-1 must fail closed
 * and report ENCRYPT_FAILED. One test per call pins each step's false branch. */
TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealReportsErrorWhenContextAllocationFails)
{
    CHECK_SEAL_REPORTS_ENCRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_CTX_NEW);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealReportsErrorWhenCipherInitFails)
{
    CHECK_SEAL_REPORTS_ENCRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_INIT_CIPHER);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealReportsErrorWhenSettingNonceLengthFails)
{
    CHECK_SEAL_REPORTS_ENCRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_SET_IVLEN);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealReportsErrorWhenKeyInitFails)
{
    CHECK_SEAL_REPORTS_ENCRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_INIT_KEY);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealReportsErrorWhenAuthenticatingHeaderFails)
{
    CHECK_SEAL_REPORTS_ENCRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_UPDATE_AAD);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealReportsErrorWhenEncryptingBodyFails)
{
    CHECK_SEAL_REPORTS_ENCRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_UPDATE_BODY);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealReportsErrorWhenFinalisingFails)
{
    CHECK_SEAL_REPORTS_ENCRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_FINAL);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealReportsErrorWhenReadingTheTagFails)
{
    CHECK_SEAL_REPORTS_ENCRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_GET_TAG);
}

/* Open's setup chain (everything up to and including SET_TAG) reports
 * DECRYPT_FAILED on any non-1. The DecryptFinal verdict is separate - that
 * fail-closed-but-silent path is OpenReturnsFalseWithoutReporting... above. */
TEST(SolidSyslogOpenSslAesGcmPolicySeal, OpenReportsErrorWhenContextAllocationFails)
{
    CHECK_OPEN_REPORTS_DECRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_CTX_NEW);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, OpenReportsErrorWhenCipherInitFails)
{
    CHECK_OPEN_REPORTS_DECRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_INIT_CIPHER);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, OpenReportsErrorWhenSettingNonceLengthFails)
{
    CHECK_OPEN_REPORTS_DECRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_SET_IVLEN);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, OpenReportsErrorWhenKeyInitFails)
{
    CHECK_OPEN_REPORTS_DECRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_INIT_KEY);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, OpenReportsErrorWhenAuthenticatingHeaderFails)
{
    CHECK_OPEN_REPORTS_DECRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_UPDATE_AAD);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, OpenReportsErrorWhenDecryptingBodyFails)
{
    CHECK_OPEN_REPORTS_DECRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_UPDATE_BODY);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, OpenReportsErrorWhenSettingExpectedTagFails)
{
    CHECK_OPEN_REPORTS_DECRYPT_FAILURE_AT(OPENSSLFAKE_GCM_STEP_SET_TAG);
}

TEST(SolidSyslogOpenSslAesGcmPolicySeal, SealWipesTheKeyBufferAfterUse)
{
    CHECK_TRUE(seal());

    LONGS_EQUAL(1, OpenSslFake_CleanseCallCount());
    POINTERS_EQUAL(lastGetKeyBuffer, OpenSslFake_LastCleanseBuf());
    LONGS_EQUAL(lastGetKeyCapacity, OpenSslFake_LastCleanseLen());
}
