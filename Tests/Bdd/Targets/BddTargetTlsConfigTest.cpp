#include "BddTargetTlsConfig.h"
#include "CppUTest/TestHarness.h"
#include "SolidSyslogEndpoint.h"
#include "SolidSyslogEndpointHost.h"
#include "SolidSyslogEndpointHostPrivate.h"
#include "SolidSyslogFormatter.h"

enum
{
    TEST_HOST_BUFFER_SIZE = 64
};

#define CHECK_CA_PATH(expected) STRCMP_EQUAL(expected, BddTargetTlsConfig_GetCaBundlePath())
#define CHECK_SERVER_NAME(expected) STRCMP_EQUAL(expected, BddTargetTlsConfig_GetServerName())
#define CHECK_PIN_COUNT(expected) UNSIGNED_LONGS_EQUAL(expected, BddTargetTlsConfig_GetPeerFingerprintCount())
#define CHECK_PIN_AT(index, expected) STRCMP_EQUAL(expected, BddTargetTlsConfig_GetPeerFingerprints()[index])

// clang-format off
TEST_GROUP(BddTargetTlsConfig)
{
    void setup() override
    {
        BddTargetTlsConfig_Reset();
    }

    void teardown() override
    {
        BddTargetTlsConfig_Reset();
    }
};

// clang-format on

TEST(BddTargetTlsConfig, TrustsTheTestCaByDefault)
{
    CHECK_CA_PATH("Bdd/syslog-ng/tls/ca.pem");
}

TEST(BddTargetTlsConfig, NoneAsksForNoTrustAnchors)
{
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-ca", "none"));
    POINTERS_EQUAL(NULL, BddTargetTlsConfig_GetCaBundlePath());
}

TEST(BddTargetTlsConfig, ATrustAnchorPathIsUsedAsGiven)
{
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-ca", "Bdd/syslog-ng/tls/ca-b.pem"));
    CHECK_CA_PATH("Bdd/syslog-ng/tls/ca-b.pem");
}

TEST(BddTargetTlsConfig, ServerNameFallsBackToTheHost)
{
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-host", "collector-b"));
    CHECK_SERVER_NAME("collector-b");
}

TEST(BddTargetTlsConfig, ADeclaredNameIsIndependentOfTheHost)
{
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-host", "10.0.2.2"));
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-name", "syslog-ng"));
    CHECK_SERVER_NAME("syslog-ng");
}

TEST(BddTargetTlsConfig, NoneAsksForNoNameAtAll)
{
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-name", "none"));
    POINTERS_EQUAL(NULL, BddTargetTlsConfig_GetServerName());
}

TEST(BddTargetTlsConfig, AnEmptyNameIsTheOptOutRatherThanNoName)
{
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-name", ""));
    CHECK_SERVER_NAME("");
}

TEST(BddTargetTlsConfig, PortIsTheRfc5425DefaultUntilSet)
{
    UNSIGNED_LONGS_EQUAL(6514, BddTargetTlsConfig_GetPort());
}

TEST(BddTargetTlsConfig, PortSelectsTheListener)
{
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-port", "6519"));
    UNSIGNED_LONGS_EQUAL(6519, BddTargetTlsConfig_GetPort());
}

TEST(BddTargetTlsConfig, APortThatIsNotANumberIsRejectedAndChangesNothing)
{
    CHECK_FALSE(BddTargetTlsConfig_SetByName("tls-port", "six-five-one-four"));
    UNSIGNED_LONGS_EQUAL(6514, BddTargetTlsConfig_GetPort());
}

TEST(BddTargetTlsConfig, NoPinsAreConfiguredByDefault)
{
    CHECK_PIN_COUNT(0);
}

TEST(BddTargetTlsConfig, APinIsAppendedToTheList)
{
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-pin", "sha-256:AA:BB"));
    CHECK_PIN_COUNT(1);
    CHECK_PIN_AT(0, "sha-256:AA:BB");
}

TEST(BddTargetTlsConfig, PinsAccumulateSoARenewalCanBeCrossed)
{
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-pin", "sha-256:AA"));
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-pin", "sha-256:BB"));
    CHECK_PIN_COUNT(2);
    CHECK_PIN_AT(0, "sha-256:AA");
    CHECK_PIN_AT(1, "sha-256:BB");
}

TEST(BddTargetTlsConfig, NoneClearsThePinList)
{
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-pin", "sha-256:AA"));
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-pin", "none"));
    CHECK_PIN_COUNT(0);
}

TEST(BddTargetTlsConfig, APinBeyondCapacityIsRejectedAndLeavesTheListIntact)
{
    for (int i = 0; i < BDD_TARGET_TLS_MAX_FINGERPRINTS; i++)
    {
        CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-pin", "sha-256:AA"));
    }
    CHECK_FALSE(BddTargetTlsConfig_SetByName("tls-pin", "sha-256:BB"));
    CHECK_PIN_COUNT(BDD_TARGET_TLS_MAX_FINGERPRINTS);
}

TEST(BddTargetTlsConfig, AnUnknownNameIsNotOurs)
{
    CHECK_FALSE(BddTargetTlsConfig_SetByName("store", "file"));
}

TEST(BddTargetTlsConfig, TheVersionMovesSoTheNextRecordReconnects)
{
    uint32_t before = BddTargetTlsConfig_GetStreamVersion(NULL);
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-ca", "Bdd/syslog-ng/tls/ca-b.pem"));
    CHECK_COMPARE(BddTargetTlsConfig_GetStreamVersion(NULL), !=, before);
}

TEST(BddTargetTlsConfig, TheEndpointVersionMovesWithIt)
{
    uint32_t before = BddTargetTlsConfig_GetEndpointVersion(NULL);
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-port", "6521"));
    CHECK_COMPARE(BddTargetTlsConfig_GetEndpointVersion(NULL), !=, before);
}

TEST(BddTargetTlsConfig, ARejectedSetLeavesTheVersionAlone)
{
    uint32_t before = BddTargetTlsConfig_GetStreamVersion(NULL);
    CHECK_FALSE(BddTargetTlsConfig_SetByName("tls-port", "not-a-port"));
    UNSIGNED_LONGS_EQUAL(before, BddTargetTlsConfig_GetStreamVersion(NULL));
}

TEST(BddTargetTlsConfig, AnUnknownNameLeavesTheVersionAlone)
{
    uint32_t before = BddTargetTlsConfig_GetStreamVersion(NULL);
    CHECK_FALSE(BddTargetTlsConfig_SetByName("store", "file"));
    UNSIGNED_LONGS_EQUAL(before, BddTargetTlsConfig_GetStreamVersion(NULL));
}

TEST(BddTargetTlsConfig, TheEndpointCarriesTheHostAndPort)
{
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-host", "collector-b"));
    CHECK_TRUE(BddTargetTlsConfig_SetByName("tls-port", "6521"));

    SolidSyslogFormatterStorage storage[SOLIDSYSLOG_FORMATTER_STORAGE_SIZE(TEST_HOST_BUFFER_SIZE)];
    struct SolidSyslogFormatter* formatter = SolidSyslogFormatter_Create(storage, TEST_HOST_BUFFER_SIZE);
    struct SolidSyslogEndpointHost hostSink{};
    SolidSyslogEndpointHost_FromFormatter(&hostSink, formatter);

    struct SolidSyslogEndpoint endpoint{};
    endpoint.Host = &hostSink;
    BddTargetTlsConfig_GetEndpoint(&endpoint, NULL);

    STRCMP_EQUAL("collector-b", SolidSyslogFormatter_AsFormattedBuffer(formatter));
    UNSIGNED_LONGS_EQUAL(6521, endpoint.Port);
}
