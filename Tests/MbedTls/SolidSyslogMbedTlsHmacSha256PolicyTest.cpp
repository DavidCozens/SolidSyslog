#include <cstring>

#include "CppUTest/TestHarness.h"

extern "C"
{
#include "ConfigLockFake.h"
#include "ErrorHandlerFake.h"
#include "MbedTlsFake.h"
#include "SolidSyslogMbedTlsHmacSha256Policy.h"
#include "SolidSyslogMbedTlsHmacSha256PolicyErrors.h"
#include "SolidSyslogNullSecurityPolicy.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogSecurityPolicyDefinition.h"
#include "SolidSyslogTunables.h"
}

#include <mbedtls/md.h>

#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogSecurityPolicyCategories.h"
#include "TestUtils.h"

using namespace CososoTesting;

enum
{
    HMAC_SHA256_TAG_SIZE = 32,
    TEST_KEY_SIZE = 32,
    TEST_KEY_BYTE = 0x2B
};

/* Record bytes a seal/verify test runs through the policy. Non-const because the
 * vtable's content parameter is non-const (an AEAD policy mutates it); HMAC does
 * not. */
static uint8_t TEST_RECORD[] = {0x10, 0x20, 0x30, 0x40};

/* The buffer + capacity the policy handed to GetKey on the most recent fetch -
 * lets a test assert the key buffer is wiped at exactly that pointer and size. */
static const uint8_t* lastGetKeyBuffer = nullptr;
static size_t lastGetKeyCapacity = 0;

/* The key length GetKey reports on the next fetch. Defaults to a full-strength
 * TEST_KEY_SIZE key; a test lowers it to drive the sub-minimum-key path. */
static size_t testKeyLength = TEST_KEY_SIZE;

/* A key accessor: writes a fixed TEST_KEY_BYTE key. The policy fetches this on
 * every seal and verify; expectedTagFor() mirrors it so tests can predict the
 * fake's deterministic tag. `context` points at a bool the test can clear to
 * simulate the key being unavailable (GetKey returns false). */
static bool TestGetKey(void* context, uint8_t* keyOut, size_t capacity, size_t* keyLengthOut)
{
    lastGetKeyBuffer = keyOut;
    lastGetKeyCapacity = capacity;
    const bool* available = static_cast<const bool*>(context);
    if ((available != nullptr) && !*available)
    {
        return false;
    }
    size_t written = (capacity < testKeyLength) ? capacity : testKeyLength;
    memset(keyOut, TEST_KEY_BYTE, written);
    *keyLengthOut = testKeyLength;
    return true;
}

/* Asserts exactly one error of (severity, code) was reported from this policy's source. */
#define CHECK_REPORTED_ERROR(severity, expectedCategory, code) \
    CHECK_ERROR_REPORTED_ONCE((severity), &SolidSyslogMbedTlsHmacSha256PolicyErrorSource, (expectedCategory), (code))

#define CHECK_IS_NULL_FALLBACK(handle) POINTERS_EQUAL(SolidSyslogNullSecurityPolicy_Get(), (handle))

// clang-format off
TEST_BASE(MbedTlsHmacSha256PolicyTestBase)
{
    struct SolidSyslogMbedTlsHmacSha256PolicyConfig config = {};
    bool keyAvailable = true;

    void armConfig()
    {
        MbedTlsFake_Reset();
        lastGetKeyBuffer  = nullptr;
        lastGetKeyCapacity = 0;
        testKeyLength     = TEST_KEY_SIZE;
        config.GetKey     = TestGetKey;
        config.KeyContext = &keyAvailable;
    }
};

TEST_GROUP_BASE(SolidSyslogMbedTlsHmacSha256Policy, MbedTlsHmacSha256PolicyTestBase)
{
    struct SolidSyslogSecurityPolicy* pooled[SOLIDSYSLOG_HMAC_SHA256_POLICY_POOL_SIZE] = {};
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
                SolidSyslogMbedTlsHmacSha256Policy_Destroy(handle);
            }
        }
        if (overflow != nullptr)
        {
            SolidSyslogMbedTlsHmacSha256Policy_Destroy(overflow);
        }
        ConfigLockFake_Uninstall();
    }

    void FillPool()
    {
        for (auto*& slot : pooled)
        {
            slot = SolidSyslogMbedTlsHmacSha256Policy_Create(&config);
        }
    }
};

TEST_GROUP_BASE(SolidSyslogMbedTlsHmacSha256PolicySeal, MbedTlsHmacSha256PolicyTestBase)
{
    struct SolidSyslogSecurityPolicy* policy = nullptr;

    void setup() override
    {
        armConfig();
        policy = SolidSyslogMbedTlsHmacSha256Policy_Create(&config);
    }

    void teardown() override
    {
        SolidSyslogMbedTlsHmacSha256Policy_Destroy(policy);
        ConfigLockFake_Uninstall();
    }

    bool seal(uint8_t* content, size_t length, uint8_t* tag) const
    {
        struct SolidSyslogSecurityRecord rec = {content, (uint16_t) length, 0, tag};
        return policy->SealRecord(policy, &rec);
    }

    bool verify(uint8_t* content, size_t length, uint8_t* tag) const
    {
        struct SolidSyslogSecurityRecord rec = {content, (uint16_t) length, 0, tag};
        return policy->OpenRecord(policy, &rec);
    }

    static void expectedTagFor(const uint8_t* record, size_t length, uint8_t* tagOut)
    {
        uint8_t key[TEST_KEY_SIZE];
        memset(key, TEST_KEY_BYTE, sizeof key);
        MbedTlsFake_ComputeExpectedTag(key, TEST_KEY_SIZE, record, length, tagOut);
    }
};

// clang-format on

TEST(SolidSyslogMbedTlsHmacSha256Policy, CreateReturnsHandleDistinctFromFallback)
{
    struct SolidSyslogSecurityPolicy* handle = SolidSyslogMbedTlsHmacSha256Policy_Create(&config);

    CHECK_TEXT(handle != nullptr, "Create returned nullptr");
    CHECK_TEXT(handle != SolidSyslogNullSecurityPolicy_Get(), "Create returned the Null fallback");

    SolidSyslogMbedTlsHmacSha256Policy_Destroy(handle);
}

TEST(SolidSyslogMbedTlsHmacSha256Policy, TrailerSizeIsThirtyTwo)
{
    struct SolidSyslogSecurityPolicy* handle = SolidSyslogMbedTlsHmacSha256Policy_Create(&config);

    LONGS_EQUAL(HMAC_SHA256_TAG_SIZE, handle->TrailerSize);

    SolidSyslogMbedTlsHmacSha256Policy_Destroy(handle);
}

TEST(SolidSyslogMbedTlsHmacSha256Policy, FillingPoolThenOverflowReturnsNullFallback)
{
    FillPool();

    overflow = SolidSyslogMbedTlsHmacSha256Policy_Create(&config);

    CHECK_IS_NULL_FALLBACK(overflow);
}

TEST(SolidSyslogMbedTlsHmacSha256Policy, ExhaustedCreateReportsError)
{
    ErrorHandlerFake_Install(nullptr);
    FillPool();

    overflow = SolidSyslogMbedTlsHmacSha256Policy_Create(&config);

    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_POOL_EXHAUSTED
    );
}

TEST(SolidSyslogMbedTlsHmacSha256Policy, NullConfigReturnsNullFallback)
{
    CHECK_IS_NULL_FALLBACK(SolidSyslogMbedTlsHmacSha256Policy_Create(nullptr));
}

TEST(SolidSyslogMbedTlsHmacSha256Policy, NullGetKeyReturnsNullFallback)
{
    config.GetKey = nullptr;

    CHECK_IS_NULL_FALLBACK(SolidSyslogMbedTlsHmacSha256Policy_Create(&config));
}

TEST(SolidSyslogMbedTlsHmacSha256Policy, BadConfigReportsError)
{
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogMbedTlsHmacSha256Policy_Create(nullptr);

    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_BAD_CONFIG
    );
}

TEST(SolidSyslogMbedTlsHmacSha256Policy, CreateAcquiresAndReleasesConfigLockOnFirstFreeSlot)
{
    ConfigLockFake_Install();

    pooled[0] = SolidSyslogMbedTlsHmacSha256Policy_Create(&config);

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogMbedTlsHmacSha256Policy, DestroyOfPooledHandleLocksOnce)
{
    pooled[0] = SolidSyslogMbedTlsHmacSha256Policy_Create(&config);
    ConfigLockFake_Install();

    SolidSyslogMbedTlsHmacSha256Policy_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CALLED_FAKE(ConfigLockFake_Lock, ONCE);
    CALLED_FAKE(ConfigLockFake_Unlock, ONCE);
}

TEST(SolidSyslogMbedTlsHmacSha256Policy, DestroyOfUnknownHandleReportsWarning)
{
    ErrorHandlerFake_Install(nullptr);
    struct SolidSyslogSecurityPolicy stranger = {};

    SolidSyslogMbedTlsHmacSha256Policy_Destroy(&stranger);

    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_WARNING,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogMbedTlsHmacSha256Policy, DestroyOfStaleHandleReportsWarning)
{
    pooled[0] = SolidSyslogMbedTlsHmacSha256Policy_Create(&config);
    SolidSyslogMbedTlsHmacSha256Policy_Destroy(pooled[0]);
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogMbedTlsHmacSha256Policy_Destroy(pooled[0]);
    pooled[0] = nullptr;

    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_WARNING,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogMbedTlsHmacSha256PolicySeal, SealRecordHmacsTheRecordWithTheFetchedKey)
{
    uint8_t expectedKey[TEST_KEY_SIZE];
    memset(expectedKey, TEST_KEY_BYTE, sizeof expectedKey);
    uint8_t tag[HMAC_SHA256_TAG_SIZE] = {};

    seal(TEST_RECORD, sizeof TEST_RECORD, tag);

    LONGS_EQUAL(1, MbedTlsFake_MdHmacCallCount());
    LONGS_EQUAL(MBEDTLS_MD_SHA256, MbedTlsFake_LastMdInfoType());
    LONGS_EQUAL(TEST_KEY_SIZE, MbedTlsFake_LastMdHmacKeyLen());
    MEMCMP_EQUAL(expectedKey, MbedTlsFake_LastMdHmacKey(), TEST_KEY_SIZE);
    LONGS_EQUAL(sizeof TEST_RECORD, MbedTlsFake_LastMdHmacInputLen());
    MEMCMP_EQUAL(TEST_RECORD, MbedTlsFake_LastMdHmacInput(), sizeof TEST_RECORD);
}

TEST(SolidSyslogMbedTlsHmacSha256PolicySeal, SealRecordWritesTheTagIntoTheTrailer)
{
    uint8_t expected[HMAC_SHA256_TAG_SIZE];
    expectedTagFor(TEST_RECORD, sizeof TEST_RECORD, expected);
    uint8_t tag[HMAC_SHA256_TAG_SIZE] = {};

    seal(TEST_RECORD, sizeof TEST_RECORD, tag);

    MEMCMP_EQUAL(expected, tag, HMAC_SHA256_TAG_SIZE);
}

TEST(SolidSyslogMbedTlsHmacSha256PolicySeal, SealRecordReportsHmacFailure)
{
    ErrorHandlerFake_Install(nullptr);
    MbedTlsFake_SetMdHmacReturn(-1);
    uint8_t tag[HMAC_SHA256_TAG_SIZE] = {};

    bool sealed = seal(TEST_RECORD, sizeof TEST_RECORD, tag);

    CHECK_FALSE(sealed);
    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_ERROR,
        SOLIDSYSLOG_CAT_SECURITY_POLICY_SEAL_FAILED,
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_HMAC_FAILED
    );
}

TEST(SolidSyslogMbedTlsHmacSha256PolicySeal, SealRecordReportsKeyUnavailable)
{
    ErrorHandlerFake_Install(nullptr);
    keyAvailable = false;
    uint8_t tag[HMAC_SHA256_TAG_SIZE] = {};

    bool sealed = seal(TEST_RECORD, sizeof TEST_RECORD, tag);

    CHECK_FALSE(sealed);
    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_ERROR,
        SOLIDSYSLOG_CAT_SECURITY_POLICY_KEY_UNAVAILABLE,
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_KEY_UNAVAILABLE
    );
}

TEST(SolidSyslogMbedTlsHmacSha256PolicySeal, SealRecordFailsClosedWhenKeyBelowMinimum)
{
    testKeyLength = 16;
    uint8_t tag[HMAC_SHA256_TAG_SIZE] = {};

    bool sealed = seal(TEST_RECORD, sizeof TEST_RECORD, tag);

    CHECK_FALSE(sealed);
}

TEST(SolidSyslogMbedTlsHmacSha256PolicySeal, SealRecordReportsKeyTooShort)
{
    ErrorHandlerFake_Install(nullptr);
    testKeyLength = 16;
    uint8_t tag[HMAC_SHA256_TAG_SIZE] = {};

    bool sealed = seal(TEST_RECORD, sizeof TEST_RECORD, tag);

    CHECK_FALSE(sealed);
    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_ERROR,
        SOLIDSYSLOG_CAT_SECURITY_POLICY_KEY_UNAVAILABLE,
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_KEY_TOO_SHORT
    );
}

// A key longer than the buffer GetKey was handed is a contract violation; reject
// it too rather than passing an out-of-range length to mbedtls_md_hmac.
TEST(SolidSyslogMbedTlsHmacSha256PolicySeal, SealRecordFailsClosedWhenKeyExceedsCapacity)
{
    testKeyLength = SOLIDSYSLOG_MAX_HMAC_KEY_SIZE + 1U;
    uint8_t tag[HMAC_SHA256_TAG_SIZE] = {};

    CHECK_FALSE(seal(TEST_RECORD, sizeof TEST_RECORD, tag));
}

TEST(SolidSyslogMbedTlsHmacSha256PolicySeal, OpenRecordFailsClosedWhenKeyBelowMinimum)
{
    uint8_t tag[HMAC_SHA256_TAG_SIZE] = {};
    seal(TEST_RECORD, sizeof TEST_RECORD, tag);
    testKeyLength = 16;

    CHECK_FALSE(verify(TEST_RECORD, sizeof TEST_RECORD, tag));
}

TEST(SolidSyslogMbedTlsHmacSha256PolicySeal, SealRecordWipesTheKeyBufferAfterUse)
{
    uint8_t tag[HMAC_SHA256_TAG_SIZE] = {};

    seal(TEST_RECORD, sizeof TEST_RECORD, tag);

    LONGS_EQUAL(1, MbedTlsFake_PlatformZeroizeCallCount());
    POINTERS_EQUAL(lastGetKeyBuffer, MbedTlsFake_LastPlatformZeroizeBuf());
    LONGS_EQUAL(lastGetKeyCapacity, MbedTlsFake_LastPlatformZeroizeLen());
}

TEST(SolidSyslogMbedTlsHmacSha256PolicySeal, OpenRecordAcceptsATagItProduced)
{
    uint8_t tag[HMAC_SHA256_TAG_SIZE] = {};
    seal(TEST_RECORD, sizeof TEST_RECORD, tag);

    CHECK_TRUE(verify(TEST_RECORD, sizeof TEST_RECORD, tag));
}

TEST(SolidSyslogMbedTlsHmacSha256PolicySeal, OpenRecordRejectsAModifiedTag)
{
    uint8_t tag[HMAC_SHA256_TAG_SIZE] = {};
    seal(TEST_RECORD, sizeof TEST_RECORD, tag);
    tag[0] ^= 0xFFU;

    CHECK_FALSE(verify(TEST_RECORD, sizeof TEST_RECORD, tag));
}

TEST(SolidSyslogMbedTlsHmacSha256PolicySeal, OpenRecordFailsClosedWhenKeyUnavailable)
{
    uint8_t tag[HMAC_SHA256_TAG_SIZE] = {};
    seal(TEST_RECORD, sizeof TEST_RECORD, tag);
    keyAvailable = false;

    CHECK_FALSE(verify(TEST_RECORD, sizeof TEST_RECORD, tag));
}

// An HMAC computation failure during verify is an OPEN failure, not a SEAL
// failure - the same ComputeTag helper serves both paths, so the category must
// be chosen by the caller.
TEST(SolidSyslogMbedTlsHmacSha256PolicySeal, OpenRecordReportsHmacFailureAsOpenFailed)
{
    uint8_t tag[HMAC_SHA256_TAG_SIZE] = {};
    seal(TEST_RECORD, sizeof TEST_RECORD, tag);
    ErrorHandlerFake_Install(nullptr);
    MbedTlsFake_SetMdHmacReturn(-1);

    bool verified = verify(TEST_RECORD, sizeof TEST_RECORD, tag);

    CHECK_FALSE(verified);
    CHECK_REPORTED_ERROR(
        SOLIDSYSLOG_SEVERITY_ERROR,
        SOLIDSYSLOG_CAT_SECURITY_POLICY_OPEN_FAILED,
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_HMAC_FAILED
    );
}
