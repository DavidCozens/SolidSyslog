#include <cstdint>
#include <cstring>

#include "SolidSyslogTlsFingerprint.h"
#include "CppUTest/TestHarness.h"

// clang-format off
TEST_GROUP(SolidSyslogTlsFingerprint)
{
};

// clang-format on

/* Names what every malformed-pin test asserts. A macro rather than a function
   so a failure reports the calling test's line. */
#define CHECK_PIN_REJECTED(text)                                            \
    {                                                                       \
        struct SolidSyslogTlsFingerprint fingerprint = {};                  \
        CHECK_FALSE(SolidSyslogTlsFingerprint_Parse((text), &fingerprint)); \
    }

TEST(SolidSyslogTlsFingerprint, ParsesTheRfc5425ExampleSha1Fingerprint)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_TRUE(SolidSyslogTlsFingerprint_Parse(
        "sha-1:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D",
        &fingerprint
    ));

    LONGS_EQUAL(SOLIDSYSLOG_TLS_HASH_SHA1, fingerprint.Algorithm);
    LONGS_EQUAL(20, fingerprint.Length);
    BYTES_EQUAL(0xE1, fingerprint.Digest[0]);
    BYTES_EQUAL(0x9D, fingerprint.Digest[19]);
}

TEST(SolidSyslogTlsFingerprint, ParsesASha256Fingerprint)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_TRUE(SolidSyslogTlsFingerprint_Parse(
        "sha-256:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:"
        "0F:1E:2D:3C:4B:5A:69:78:87:96:A5:B4:C3:D2:E1:F0",
        &fingerprint
    ));

    LONGS_EQUAL(SOLIDSYSLOG_TLS_HASH_SHA256, fingerprint.Algorithm);
    LONGS_EQUAL(32, fingerprint.Length);
    BYTES_EQUAL(0x00, fingerprint.Digest[0]);
    BYTES_EQUAL(0xFF, fingerprint.Digest[15]);
    BYTES_EQUAL(0xF0, fingerprint.Digest[31]);
}

/* Every hex digit, in the high nibble and then in the low, so no digit's
   conversion rests on another's. */
TEST(SolidSyslogTlsFingerprint, ParsesEveryHexDigitInTheHighNibble)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};
    static const uint8_t expected[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45,
                                         0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
                                         0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

    CHECK_TRUE(SolidSyslogTlsFingerprint_Parse(
        "sha-256:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:"
        "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF",
        &fingerprint
    ));

    MEMCMP_EQUAL(expected, fingerprint.Digest, sizeof(expected));
}

TEST(SolidSyslogTlsFingerprint, ParsesEveryHexDigitInTheLowNibble)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};
    static const uint8_t expected[32] = {0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54,
                                         0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA,
                                         0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE};

    CHECK_TRUE(SolidSyslogTlsFingerprint_Parse(
        "sha-256:10:32:54:76:98:BA:DC:FE:10:32:54:76:98:BA:DC:FE:"
        "10:32:54:76:98:BA:DC:FE:10:32:54:76:98:BA:DC:FE",
        &fingerprint
    ));

    MEMCMP_EQUAL(expected, fingerprint.Digest, sizeof(expected));
}

/* The characters either side of each accepted run, where an off-by-one in a
   range check would land. */
TEST(SolidSyslogTlsFingerprint, RejectsTheCharactersAdjacentToTheHexRanges)
{
    static const char* const adjacent[] = {"/", ":", "@", "G", "`", "g"};

    for (const char* character : adjacent)
    {
        struct SolidSyslogTlsFingerprint fingerprint = {};
        char text[80] = "sha-1:XX:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D";
        text[6] = character[0];

        CHECK_FALSE_TEXT(SolidSyslogTlsFingerprint_Parse(text, &fingerprint), character);
    }
}

TEST(SolidSyslogTlsFingerprint, RejectsAnUnknownHashLabel)
{
    CHECK_PIN_REJECTED("md5:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF");
}

TEST(SolidSyslogTlsFingerprint, RejectsALabelWithNoColonAfterIt)
{
    CHECK_PIN_REJECTED("sha-1");
}

TEST(SolidSyslogTlsFingerprint, RejectsALabelThatOnlyBeginsLikeASupportedOne)
{
    CHECK_PIN_REJECTED("sha-10:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D");
}

TEST(SolidSyslogTlsFingerprint, RejectsADigestShorterThanTheAlgorithmProduces)
{
    CHECK_PIN_REJECTED("sha-1:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E");
}

TEST(SolidSyslogTlsFingerprint, RejectsADigestLongerThanTheAlgorithmProduces)
{
    CHECK_PIN_REJECTED("sha-1:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D:00");
}

/* RFC 5425 4.2.2 publishes a fingerprint in uppercase, but one reaches this
   library through an engineer transcribing it, so either case is accepted. */
TEST(SolidSyslogTlsFingerprint, ParsesLowercaseHexPairs)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_TRUE(SolidSyslogTlsFingerprint_Parse(
        "sha-1:e1:2d:53:2b:7c:6b:8a:29:a2:76:c8:64:36:0b:08:4b:7a:f1:9e:9d",
        &fingerprint
    ));

    BYTES_EQUAL(0xE1, fingerprint.Digest[0]);
    BYTES_EQUAL(0x9D, fingerprint.Digest[19]);
}

TEST(SolidSyslogTlsFingerprint, ParsesHexPairsOfMixedCase)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_TRUE(SolidSyslogTlsFingerprint_Parse(
        "sha-1:e1:2D:53:2b:7C:6b:8A:29:a2:76:C8:64:36:0B:08:4b:7A:f1:9E:9d",
        &fingerprint
    ));

    BYTES_EQUAL(0xE1, fingerprint.Digest[0]);
    BYTES_EQUAL(0x9D, fingerprint.Digest[19]);
}

TEST(SolidSyslogTlsFingerprint, ParsesEveryLowercaseHexDigit)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};
    static const uint8_t expected[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x32, 0x54,
                                         0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
                                         0xCD, 0xEF, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE};

    CHECK_TRUE(SolidSyslogTlsFingerprint_Parse(
        "sha-256:01:23:45:67:89:ab:cd:ef:10:32:54:76:98:ba:dc:fe:"
        "01:23:45:67:89:ab:cd:ef:10:32:54:76:98:ba:dc:fe",
        &fingerprint
    ));

    MEMCMP_EQUAL(expected, fingerprint.Digest, sizeof(expected));
}

TEST(SolidSyslogTlsFingerprint, RejectsACharacterThatIsNotHex)
{
    CHECK_PIN_REJECTED("sha-1:G1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D");
}

TEST(SolidSyslogTlsFingerprint, RejectsPunctuationWhereADigitIsExpected)
{
    CHECK_PIN_REJECTED("sha-1:*1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D");
}

TEST(SolidSyslogTlsFingerprint, RejectsASeparatorThatIsNotAColon)
{
    CHECK_PIN_REJECTED("sha-1:E1-2D-53-2B-7C-6B-8A-29-A2-76-C8-64-36-0B-08-4B-7A-F1-9E-9D");
}

TEST(SolidSyslogTlsFingerprint, RejectsASingleDigitPair)
{
    CHECK_PIN_REJECTED("sha-1:E:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D:00");
}

struct DigestFake
{
    bool Available;
    enum SolidSyslogTlsHashAlgorithm AlgorithmAsked;
    uint8_t Digest[SOLIDSYSLOG_TLS_FINGERPRINT_DIGEST_MAX];
    size_t Length;
};

static bool DigestFake_Digest(
    void* context,
    enum SolidSyslogTlsHashAlgorithm algorithm,
    uint8_t* digest,
    size_t* length
)
{
    auto* fake = static_cast<struct DigestFake*>(context);
    fake->AlgorithmAsked = algorithm;
    memcpy(digest, fake->Digest, fake->Length);
    *length = fake->Length;
    return fake->Available;
}

// clang-format off
TEST_GROUP(SolidSyslogTlsFingerprintAuthorise)
{
    struct DigestFake fake;

    void setup() override
    {
        fake.Available = true;
        GivePeerADigestOfLength(20);
    }

    /* An ascending pattern, matching the pins written out in the tests. */
    void GivePeerADigestOfLength(size_t length)
    {
        uint8_t* digest = fake.Digest;
        fake.Length = length;
        for (size_t i = 0; i < length; i++)
        {
            digest[i] = static_cast<uint8_t>(i);
        }
    }

    enum SolidSyslogTlsAuthorisation Authorise(const char* const* fingerprints, size_t count)
    {
        return SolidSyslogTlsFingerprint_Authorise(fingerprints, count, DigestFake_Digest, &fake);
    }
};

// clang-format on

TEST(SolidSyslogTlsFingerprintAuthorise, MatchesAPinEqualToThePeerDigest)
{
    const char* pins[] = {"sha-1:00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13"};

    LONGS_EQUAL(SOLIDSYSLOG_TLS_AUTHORISATION_MATCHED, Authorise(pins, 1));
}

TEST(SolidSyslogTlsFingerprintAuthorise, AsksForTheDigestThePinNames)
{
    const char* pins[] = {"sha-256:00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:"
                          "10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F"};
    GivePeerADigestOfLength(32);

    LONGS_EQUAL(SOLIDSYSLOG_TLS_AUTHORISATION_MATCHED, Authorise(pins, 1));
    LONGS_EQUAL(SOLIDSYSLOG_TLS_HASH_SHA256, fake.AlgorithmAsked);
}

TEST(SolidSyslogTlsFingerprintAuthorise, DoesNotMatchAPinDifferingInItsLastByte)
{
    const char* pins[] = {"sha-1:00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:14"};

    LONGS_EQUAL(SOLIDSYSLOG_TLS_AUTHORISATION_NO_MATCH, Authorise(pins, 1));
}

TEST(SolidSyslogTlsFingerprintAuthorise, DoesNotMatchADigestOfAnotherLength)
{
    const char* pins[] = {"sha-1:00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13"};
    fake.Length = 19;

    LONGS_EQUAL(SOLIDSYSLOG_TLS_AUTHORISATION_NO_MATCH, Authorise(pins, 1));
}

TEST(SolidSyslogTlsFingerprintAuthorise, AnyOnePinAuthorises)
{
    const char* pins[] = {
        "sha-1:FF:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13",
        "sha-1:00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13",
    };

    LONGS_EQUAL(SOLIDSYSLOG_TLS_AUTHORISATION_MATCHED, Authorise(pins, 2));
}

TEST(SolidSyslogTlsFingerprintAuthorise, AnEmptyListAuthorisesNothing)
{
    LONGS_EQUAL(SOLIDSYSLOG_TLS_AUTHORISATION_NO_MATCH, Authorise(nullptr, 0));
}

TEST(SolidSyslogTlsFingerprintAuthorise, ReportsAMalformedPinWhereItStopsTheWalk)
{
    const char* pins[] = {
        "sha-1:FF:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13",
        "sha-1:not a fingerprint",
        "sha-1:00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13",
    };

    LONGS_EQUAL(SOLIDSYSLOG_TLS_AUTHORISATION_MALFORMED, Authorise(pins, 3));
}

TEST(SolidSyslogTlsFingerprintAuthorise, ReportsADigestThePeerCannotSupply)
{
    const char* pins[] = {"sha-1:00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13"};
    fake.Available = false;

    LONGS_EQUAL(SOLIDSYSLOG_TLS_AUTHORISATION_DIGEST_UNAVAILABLE, Authorise(pins, 1));
}

TEST(SolidSyslogTlsFingerprint, AListOfSha256PinsIsWellFormed)
{
    const char* pins[] = {
        "sha-256:00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:"
        "10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F",
    };

    LONGS_EQUAL(SOLIDSYSLOG_TLS_FINGERPRINT_LIST_WELL_FORMED, SolidSyslogTlsFingerprint_InspectList(pins, 1));
}

TEST(SolidSyslogTlsFingerprint, AListWithASha1PinSaysSo)
{
    const char* pins[] = {
        "sha-256:00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:"
        "10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F",
        "sha-1:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D",
    };

    LONGS_EQUAL(SOLIDSYSLOG_TLS_FINGERPRINT_LIST_USES_SHA1, SolidSyslogTlsFingerprint_InspectList(pins, 2));
}

TEST(SolidSyslogTlsFingerprint, AMalformedPinOutweighsASha1One)
{
    const char* pins[] = {
        "sha-1:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D",
        "sha-256:not a fingerprint",
    };

    LONGS_EQUAL(SOLIDSYSLOG_TLS_FINGERPRINT_LIST_MALFORMED, SolidSyslogTlsFingerprint_InspectList(pins, 2));
}

TEST(SolidSyslogTlsFingerprint, AnEmptyListIsWellFormed)
{
    LONGS_EQUAL(SOLIDSYSLOG_TLS_FINGERPRINT_LIST_WELL_FORMED, SolidSyslogTlsFingerprint_InspectList(nullptr, 0));
}

TEST(SolidSyslogTlsFingerprint, ParsingAMissingFingerprintFails)
{
    CHECK_PIN_REJECTED(nullptr);
}

TEST(SolidSyslogTlsFingerprint, AListThatIsMissingWhereOneWasCountedIsMalformed)
{
    LONGS_EQUAL(SOLIDSYSLOG_TLS_FINGERPRINT_LIST_MALFORMED, SolidSyslogTlsFingerprint_InspectList(nullptr, 1));
}

TEST(SolidSyslogTlsFingerprint, AMissingPinInTheListIsMalformed)
{
    const char* pins[] = {nullptr};

    LONGS_EQUAL(SOLIDSYSLOG_TLS_FINGERPRINT_LIST_MALFORMED, SolidSyslogTlsFingerprint_InspectList(pins, 1));
}

TEST(SolidSyslogTlsFingerprintAuthorise, AListThatIsMissingWhereOneWasCountedIsMalformed)
{
    LONGS_EQUAL(SOLIDSYSLOG_TLS_AUTHORISATION_MALFORMED, Authorise(nullptr, 1));
}

TEST(SolidSyslogTlsFingerprintAuthorise, AMissingPinInTheListIsMalformed)
{
    const char* pins[] = {nullptr};

    LONGS_EQUAL(SOLIDSYSLOG_TLS_AUTHORISATION_MALFORMED, Authorise(pins, 1));
}

TEST(SolidSyslogTlsFingerprint, AnEmptyListIsPresent)
{
    CHECK_TRUE(SolidSyslogTlsFingerprint_ListIsPresent(nullptr, 0));
}

TEST(SolidSyslogTlsFingerprint, AListBehindItsCountIsPresent)
{
    const char* pins[] = {"sha-256:AA", "sha-256:BB"};

    CHECK_TRUE(SolidSyslogTlsFingerprint_ListIsPresent(pins, 2));
}

TEST(SolidSyslogTlsFingerprint, ACountWithNoListBehindItIsNotPresent)
{
    CHECK_FALSE(SolidSyslogTlsFingerprint_ListIsPresent(nullptr, 1));
}

TEST(SolidSyslogTlsFingerprint, AListWithAMissingPinIsNotPresent)
{
    const char* pins[] = {"sha-256:AA", nullptr};

    CHECK_FALSE(SolidSyslogTlsFingerprint_ListIsPresent(pins, 2));
}
