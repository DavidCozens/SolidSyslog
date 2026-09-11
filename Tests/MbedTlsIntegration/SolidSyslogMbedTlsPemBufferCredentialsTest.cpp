/* The credential window is only observable through the ssl_config Install
 * writes to, and through the source's own parsed state - both of which mbedTLS
 * and this pack keep private. This is the documented way in. */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "CppUTest/TestHarness.h"

extern "C"
{
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>

#include "MbedTlsTestCert.h"
#include "SolidSyslogError.h"
#include "SolidSyslogMbedTlsCredentialsDefinition.h"
#include "SolidSyslogMbedTlsNullCredentials.h"
#include "SolidSyslogMbedTlsPemBufferCredentials.h"
#include "SolidSyslogMbedTlsPemBufferCredentialsErrors.h"
#include "SolidSyslogMbedTlsPemBufferCredentialsPrivate.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogTlsCredentialsInstalled.h"
#include "SolidSyslogTunables.h"
}

#include "SolidSyslogErrorCategory.h"

namespace
{
constexpr size_t PEM_BUFFER_BYTES = 4096;
} // namespace

/* This suite links no ErrorHandlerFake - it builds against the real libmbedtls,
 * as the rest of Tests/MbedTlsIntegration does, and capturing the last event
 * directly is enough to pin which code a real fault produces. */
static int PemBufferCapturedErrorCount;
static struct SolidSyslogErrorEvent PemBufferLastCapturedError;

static void CapturePemBufferError(void* context, const struct SolidSyslogErrorEvent* event)
{
    (void) context;
    PemBufferCapturedErrorCount++;
    PemBufferLastCapturedError = *event;
}

#define CHECK_PEM_BUFFER_ERROR_REPORTED(expectedSeverity, expectedCategory, expectedCode)                      \
    {                                                                                                          \
        LONGS_EQUAL(1, PemBufferCapturedErrorCount);                                                           \
        LONGS_EQUAL((expectedSeverity), PemBufferLastCapturedError.Severity);                                  \
        POINTERS_EQUAL(&SolidSyslogMbedTlsPemBufferCredentialsErrorSource, PemBufferLastCapturedError.Source); \
        UNSIGNED_LONGS_EQUAL((expectedCategory), PemBufferLastCapturedError.Category);                         \
        LONGS_EQUAL((expectedCode), PemBufferLastCapturedError.Detail);                                        \
    }

/* Nothing parsed is still held: Mbed TLS leaves a freed chain and a freed key
 * in the state an init produces, so an empty slot is what a released source
 * looks like. */
static bool HoldsNoMaterial(struct SolidSyslogMbedTlsCredentials* base)
{
    const auto* self = reinterpret_cast<const struct SolidSyslogMbedTlsPemBufferCredentials*>(base);
    return (self->CaChain.raw.p == nullptr) && (self->ClientCertChain.raw.p == nullptr) &&
           (mbedtls_pk_get_type(&self->ClientKey) == MBEDTLS_PK_NONE);
}

// clang-format off
TEST_GROUP(SolidSyslogMbedTlsPemBufferCredentials)
{
    mbedtls_entropy_context entropy = {};
    mbedtls_ctr_drbg_context rng = {};
    mbedtls_ssl_config conf = {};

    struct MbedTlsTestCert ca = {};
    struct MbedTlsTestCert clientCert = {};
    unsigned char caPem[PEM_BUFFER_BYTES] = {};
    unsigned char clientCertPem[PEM_BUFFER_BYTES] = {};
    unsigned char clientKeyPem[PEM_BUFFER_BYTES] = {};

    struct SolidSyslogMbedTlsPemBufferCredentialsConfig config = {};
    struct SolidSyslogMbedTlsCredentials* credentials = nullptr;
    struct SolidSyslogTlsCredentialsInstalled installed = {};

    void setup() override
    {
        PemBufferCapturedErrorCount = 0;
        PemBufferLastCapturedError = {};
        SolidSyslog_SetErrorHandler(CapturePemBufferError, nullptr);

        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&rng);
        const unsigned char pers[] = "mbedtls-pem-buffer-test";
        mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy, pers, sizeof(pers) - 1U);
        mbedtls_ssl_config_init(&conf);

        struct MbedTlsTestCertConfig caConfig = {};
        caConfig.SubjectName = "CN=Test Root CA";
        caConfig.IsCa = 1;
        MbedTlsTestCert_Create(&caConfig, &ca, &rng);

        struct MbedTlsTestCertConfig leafConfig = {};
        leafConfig.SubjectName = "CN=solidsyslog-test-client";
        leafConfig.Issuer = &ca;
        MbedTlsTestCert_Create(&leafConfig, &clientCert, &rng);

        config.Rng = &rng;
        config.CaPem.Bytes = caPem;
        config.CaPem.Length = MbedTlsTestCert_WriteCertPem(&ca, caPem, sizeof(caPem));
    }

    void teardown() override
    {
        SolidSyslog_SetErrorHandler(nullptr, nullptr);
        if (credentials != nullptr)
        {
            SolidSyslogMbedTlsPemBufferCredentials_Destroy(credentials);
        }
        mbedtls_ssl_config_free(&conf);
        MbedTlsTestCert_Destroy(&clientCert);
        MbedTlsTestCert_Destroy(&ca);
        mbedtls_ctr_drbg_free(&rng);
        mbedtls_entropy_free(&entropy);
    }

    void GiveAClientCredential()
    {
        config.ClientCertPem.Bytes = clientCertPem;
        config.ClientCertPem.Length =
            MbedTlsTestCert_WriteCertPem(&clientCert, clientCertPem, sizeof(clientCertPem));
        config.ClientKeyPem.Bytes = clientKeyPem;
        config.ClientKeyPem.Length = MbedTlsTestCert_WriteKeyPem(&clientCert, clientKeyPem, sizeof(clientKeyPem));
    }
};

// clang-format on

TEST(SolidSyslogMbedTlsPemBufferCredentials, CreateReturnsAPooledHandle)
{
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    CHECK_TRUE(credentials != SolidSyslogMbedTlsNullCredentials_Get());
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallParsesTheTrustAnchorsAndReportsThem)
{
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    CHECK_TRUE(credentials->Install(credentials, &conf, &installed));

    CHECK_TRUE(installed.TrustAnchorsInstalled);
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, CreateWithNullConfigReturnsTheNullCredentials)
{
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(nullptr);

    POINTERS_EQUAL(SolidSyslogMbedTlsNullCredentials_Get(), credentials);
    credentials = nullptr;
    CHECK_PEM_BUFFER_ERROR_REPORTED(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_NULL_CONFIG
    );
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, CreateWithoutAnRngReturnsTheNullCredentials)
{
    config.Rng = nullptr;

    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    POINTERS_EQUAL(SolidSyslogMbedTlsNullCredentials_Get(), credentials);
    credentials = nullptr;
    CHECK_PEM_BUFFER_ERROR_REPORTED(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_NULL_RNG
    );
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, CreateBeyondThePoolReportsExhaustion)
{
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    struct SolidSyslogMbedTlsCredentials* overflow = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    POINTERS_EQUAL(SolidSyslogMbedTlsNullCredentials_Get(), overflow);
    CHECK_PEM_BUFFER_ERROR_REPORTED(
        SOLIDSYSLOG_POOL_EXHAUSTED_SEVERITY,
        SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_POOL_EXHAUSTED
    );
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, DestroyingAHandleThePoolDoesNotOwnIsReported)
{
    struct SolidSyslogMbedTlsCredentials stranger = {};

    SolidSyslogMbedTlsPemBufferCredentials_Destroy(&stranger);

    CHECK_PEM_BUFFER_ERROR_REPORTED(
        SOLIDSYSLOG_UNKNOWN_DESTROY_SEVERITY,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallWiresTheParsedChainAsTheConfigurationsTrustAnchors)
{
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    CHECK_TRUE(conf.MBEDTLS_PRIVATE(ca_chain) != nullptr);
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallPassesTheConfiguredPeerFingerprintsThrough)
{
    const char* pins[] = {"sha-256:AA", "sha-256:BB"};
    config.PeerFingerprints = pins;
    config.PeerFingerprintCount = 2;
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    POINTERS_EQUAL(pins, installed.Fingerprints);
    UNSIGNED_LONGS_EQUAL(2, installed.FingerprintCount);
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, CreateWithAPinCountButNoPinListReturnsTheNullCredentials)
{
    config.PeerFingerprintCount = 1;

    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    POINTERS_EQUAL(SolidSyslogMbedTlsNullCredentials_Get(), credentials);
    credentials = nullptr;
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, CreateWithAMissingPinInTheListReportsBadConfig)
{
    const char* pins[] = {"sha-256:AA", nullptr};
    config.PeerFingerprints = pins;
    config.PeerFingerprintCount = 2;

    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    CHECK_PEM_BUFFER_ERROR_REPORTED(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_NULL_PEER_FINGERPRINT
    );
    POINTERS_EQUAL(SolidSyslogMbedTlsNullCredentials_Get(), credentials);
    credentials = nullptr;
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallWithoutPeerFingerprintsReportsNone)
{
    const char* pin = "sha-256:AA";
    installed.Fingerprints = &pin;
    installed.FingerprintCount = 1;
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    POINTERS_EQUAL(nullptr, installed.Fingerprints);
    UNSIGNED_LONGS_EQUAL(0, installed.FingerprintCount);
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallWithoutTrustAnchorsParsesNothingAndStillSucceeds)
{
    config.CaPem.Bytes = nullptr;
    config.CaPem.Length = 0;
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    CHECK_TRUE(credentials->Install(credentials, &conf, &installed));

    CHECK_FALSE(installed.TrustAnchorsInstalled);
    LONGS_EQUAL(0, PemBufferCapturedErrorCount);
}

/* The classic mistake: a length of strlen rather than strlen + 1. Mbed TLS
 * would read the buffer as DER and fail as "not a certificate", so the fault is
 * named here instead. */
TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallReportsATrustAnchorBufferThatIsNotTerminated)
{
    config.CaPem.Length -= 1U;
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    CHECK_FALSE(credentials->Install(credentials, &conf, &installed));

    CHECK_PEM_BUFFER_ERROR_REPORTED(
        SOLIDSYSLOG_SEVERITY_ERROR,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_PEM_NOT_TERMINATED
    );
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallReportsTrustAnchorsItCannotParse)
{
    caPem[20] = 'X'; /* corrupt the base64 body, leaving the terminator alone */
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    CHECK_FALSE(credentials->Install(credentials, &conf, &installed));

    CHECK_PEM_BUFFER_ERROR_REPORTED(
        SOLIDSYSLOG_SEVERITY_ERROR,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_TRUST_ANCHORS_NOT_PARSED
    );
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallPresentsAParsedClientCredential)
{
    GiveAClientCredential();
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    CHECK_TRUE(conf.MBEDTLS_PRIVATE(key_cert) != nullptr);
    LONGS_EQUAL(0, PemBufferCapturedErrorCount);
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallWithoutAClientCredentialPresentsNone)
{
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    POINTERS_EQUAL(nullptr, conf.MBEDTLS_PRIVATE(key_cert));
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallReportsAHalfSuppliedClientCredential)
{
    GiveAClientCredential();
    config.ClientKeyPem.Bytes = nullptr;
    config.ClientKeyPem.Length = 0;
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    CHECK_PEM_BUFFER_ERROR_REPORTED(
        SOLIDSYSLOG_SEVERITY_WARNING,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_INCOMPLETE
    );
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallReportsAClientKeyItCannotParse)
{
    GiveAClientCredential();
    clientKeyPem[40] = 'X';
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    CHECK_PEM_BUFFER_ERROR_REPORTED(
        SOLIDSYSLOG_SEVERITY_WARNING,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_NOT_PARSED
    );
}

/* No fault in our own credential stops delivery - the connection continues
 * server-authenticated and the collector decides whether to accept it. */
TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallStillSucceedsWhenTheClientCredentialIsFaulty)
{
    GiveAClientCredential();
    clientKeyPem[40] = 'X';
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    CHECK_TRUE(credentials->Install(credentials, &conf, &installed));

    POINTERS_EQUAL(nullptr, conf.MBEDTLS_PRIVATE(key_cert));
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallReportsAClientKeyThatDoesNotMatchItsCertificate)
{
    struct MbedTlsTestCert stranger = {};
    struct MbedTlsTestCertConfig strangerConfig = {};
    strangerConfig.SubjectName = "CN=someone-else";
    strangerConfig.Issuer = &ca;
    MbedTlsTestCert_Create(&strangerConfig, &stranger, &rng);

    GiveAClientCredential();
    config.ClientKeyPem.Length = MbedTlsTestCert_WriteKeyPem(&stranger, clientKeyPem, sizeof(clientKeyPem));
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    CHECK_PEM_BUFFER_ERROR_REPORTED(
        SOLIDSYSLOG_SEVERITY_WARNING,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_MISMATCHED
    );
    POINTERS_EQUAL(nullptr, conf.MBEDTLS_PRIVATE(key_cert));

    MbedTlsTestCert_Destroy(&stranger);
}

/* The custody claim: what Install parsed is gone once the connection ends. */
TEST(SolidSyslogMbedTlsPemBufferCredentials, ReleaseLetsGoOfEverythingItParsed)
{
    GiveAClientCredential();
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);
    credentials->Install(credentials, &conf, &installed);

    credentials->Release(credentials);

    CHECK_TRUE(HoldsNoMaterial(credentials));
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, ReleaseWithoutAnInstallIsSafe)
{
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    credentials->Release(credentials);

    CHECK_TRUE(HoldsNoMaterial(credentials));
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, ASecondInstallParsesAgainAfterARelease)
{
    GiveAClientCredential();
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);
    credentials->Install(credentials, &conf, &installed);
    credentials->Release(credentials);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_config_init(&conf);

    CHECK_TRUE(credentials->Install(credentials, &conf, &installed));

    CHECK_TRUE(installed.TrustAnchorsInstalled);
    CHECK_TRUE(conf.MBEDTLS_PRIVATE(key_cert) != nullptr);
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallReportsATrustAnchorBufferWithNoExtent)
{
    config.CaPem.Length = 0;
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    CHECK_FALSE(credentials->Install(credentials, &conf, &installed));

    CHECK_PEM_BUFFER_ERROR_REPORTED(
        SOLIDSYSLOG_SEVERITY_ERROR,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_PEM_NOT_TERMINATED
    );
}

/* The same off-by-one on the client half must name the same fault the trust
 * anchor path names, or the code exists on one path only. */
TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallReportsAClientCertificateThatIsNotTerminated)
{
    GiveAClientCredential();
    config.ClientCertPem.Length -= 1U;
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    CHECK_PEM_BUFFER_ERROR_REPORTED(
        SOLIDSYSLOG_SEVERITY_WARNING,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_PEM_NOT_TERMINATED
    );
}

TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallReportsAClientKeyThatIsNotTerminated)
{
    GiveAClientCredential();
    config.ClientKeyPem.Length -= 1U;
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    CHECK_PEM_BUFFER_ERROR_REPORTED(
        SOLIDSYSLOG_SEVERITY_WARNING,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_PEM_NOT_TERMINATED
    );
}

/* A pointer with no extent is a mistake, not a decision to go without: read as
 * absent it would leave the integrator believing mutual TLS was in force. */
TEST(SolidSyslogMbedTlsPemBufferCredentials, InstallReportsAClientCredentialWithNoExtent)
{
    GiveAClientCredential();
    config.ClientCertPem.Length = 0;
    config.ClientKeyPem.Length = 0;
    credentials = SolidSyslogMbedTlsPemBufferCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    CHECK_PEM_BUFFER_ERROR_REPORTED(
        SOLIDSYSLOG_SEVERITY_WARNING,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_PEM_NOT_TERMINATED
    );
}
