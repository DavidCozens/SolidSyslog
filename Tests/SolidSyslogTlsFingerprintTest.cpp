#include <cstring>

#include "SolidSyslogTlsFingerprint.h"
#include "CppUTest/TestHarness.h"

// clang-format off
TEST_GROUP(SolidSyslogTlsFingerprint)
{
};

// clang-format on

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

TEST(SolidSyslogTlsFingerprint, RejectsAnUnknownHashLabel)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_FALSE(SolidSyslogTlsFingerprint_Parse("md5:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF", &fingerprint));
}

TEST(SolidSyslogTlsFingerprint, RejectsALabelWithNoColonAfterIt)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_FALSE(SolidSyslogTlsFingerprint_Parse("sha-1", &fingerprint));
}

TEST(SolidSyslogTlsFingerprint, RejectsALabelThatOnlyBeginsLikeASupportedOne)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_FALSE(SolidSyslogTlsFingerprint_Parse(
        "sha-10:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D",
        &fingerprint
    ));
}

TEST(SolidSyslogTlsFingerprint, RejectsADigestShorterThanTheAlgorithmProduces)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_FALSE(
        SolidSyslogTlsFingerprint_Parse("sha-1:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E", &fingerprint)
    );
}

TEST(SolidSyslogTlsFingerprint, RejectsADigestLongerThanTheAlgorithmProduces)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_FALSE(SolidSyslogTlsFingerprint_Parse(
        "sha-1:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D:00",
        &fingerprint
    ));
}

TEST(SolidSyslogTlsFingerprint, RejectsLowercaseHexPairs)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_FALSE(SolidSyslogTlsFingerprint_Parse(
        "sha-1:e1:2d:53:2b:7c:6b:8a:29:a2:76:c8:64:36:0b:08:4b:7a:f1:9e:9d",
        &fingerprint
    ));
}

TEST(SolidSyslogTlsFingerprint, RejectsACharacterThatIsNotHex)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_FALSE(SolidSyslogTlsFingerprint_Parse(
        "sha-1:G1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D",
        &fingerprint
    ));
}

TEST(SolidSyslogTlsFingerprint, RejectsPunctuationWhereADigitIsExpected)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_FALSE(SolidSyslogTlsFingerprint_Parse(
        "sha-1:*1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D",
        &fingerprint
    ));
}

TEST(SolidSyslogTlsFingerprint, RejectsASeparatorThatIsNotAColon)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_FALSE(SolidSyslogTlsFingerprint_Parse(
        "sha-1:E1-2D-53-2B-7C-6B-8A-29-A2-76-C8-64-36-0B-08-4B-7A-F1-9E-9D",
        &fingerprint
    ));
}

TEST(SolidSyslogTlsFingerprint, RejectsASingleDigitPair)
{
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_FALSE(SolidSyslogTlsFingerprint_Parse(
        "sha-1:E:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D:00",
        &fingerprint
    ));
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
    struct SolidSyslogTlsFingerprint fingerprint = {};

    CHECK_FALSE(SolidSyslogTlsFingerprint_Parse(nullptr, &fingerprint));
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
