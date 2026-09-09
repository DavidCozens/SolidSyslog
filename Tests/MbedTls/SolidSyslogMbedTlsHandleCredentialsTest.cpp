#include "CppUTest/TestHarness.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"

extern "C"
{
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>

#include "ErrorHandlerFake.h"
#include "MbedTlsFake.h"
#include "SolidSyslogError.h"
#include "SolidSyslogMbedTlsCredentialsDefinition.h"
#include "SolidSyslogMbedTlsHandleCredentials.h"
#include "SolidSyslogMbedTlsHandleCredentialsErrors.h"
#include "SolidSyslogMbedTlsNullCredentials.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogTlsCredentialsInstalled.h"
#include "SolidSyslogTunables.h"
}

#include "SolidSyslogErrorCategory.h"
#include "TestUtils.h"

using namespace CososoTesting;

// clang-format off
TEST_GROUP(SolidSyslogMbedTlsHandleCredentials)
{
    mbedtls_ctr_drbg_context rng = {};
    mbedtls_x509_crt caChain = {};
    mbedtls_x509_crt clientCert = {};
    mbedtls_pk_context clientKey = {};
    mbedtls_ssl_config conf = {};
    struct SolidSyslogTlsCredentialsInstalled installed = {};
    struct SolidSyslogMbedTlsHandleCredentialsConfig config = {};
    struct SolidSyslogMbedTlsCredentials* credentials = nullptr;
    struct SolidSyslogMbedTlsCredentials* pooled[SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE] = {};
    struct SolidSyslogMbedTlsCredentials* overflow = nullptr;

    void setup() override
    {
        MbedTlsFake_Reset();
        config.Rng = &rng;
        config.CaChain = &caChain;
    }

    void teardown() override
    {
        if (credentials != nullptr)
        {
            SolidSyslogMbedTlsHandleCredentials_Destroy(credentials);
        }
        for (auto* slot : pooled)
        {
            if (slot != nullptr)
            {
                SolidSyslogMbedTlsHandleCredentials_Destroy(slot);
            }
        }
        if (overflow != nullptr)
        {
            SolidSyslogMbedTlsHandleCredentials_Destroy(overflow);
        }
    }

    /* Wires a client credential - either half may be null. */
    void GiveAClientCredential()
    {
        config.ClientCertChain = &clientCert;
        config.ClientKey = &clientKey;
    }

    void FillPool()
    {
        for (auto*& slot : pooled)
        {
            slot = SolidSyslogMbedTlsHandleCredentials_Create(&config);
        }
    }
};

// clang-format on

TEST(SolidSyslogMbedTlsHandleCredentials, CreateReturnsAPooledHandle)
{
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    CHECK_TRUE(credentials != SolidSyslogMbedTlsNullCredentials_Get());
}

TEST(SolidSyslogMbedTlsHandleCredentials, CreateWithNullConfigReturnsTheNullCredentials)
{
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(nullptr);

    POINTERS_EQUAL(SolidSyslogMbedTlsNullCredentials_Get(), credentials);
    credentials = nullptr;
}

TEST(SolidSyslogMbedTlsHandleCredentials, CreateWithNullConfigReportsBadConfig)
{
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogMbedTlsHandleCredentials_Create(nullptr);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogMbedTlsHandleCredentialsErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_NULL_CONFIG
    );
}

TEST(SolidSyslogMbedTlsHandleCredentials, CreateWithoutAnRngReturnsTheNullCredentials)
{
    config.Rng = nullptr;

    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    POINTERS_EQUAL(SolidSyslogMbedTlsNullCredentials_Get(), credentials);
    credentials = nullptr;
}

TEST(SolidSyslogMbedTlsHandleCredentials, CreateWithoutAnRngReportsBadConfig)
{
    config.Rng = nullptr;
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogMbedTlsHandleCredentials_Create(&config);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogMbedTlsHandleCredentialsErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_NULL_RNG
    );
}

TEST(SolidSyslogMbedTlsHandleCredentials, CreateBeyondThePoolReturnsTheNullCredentials)
{
    FillPool();

    overflow = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    POINTERS_EQUAL(SolidSyslogMbedTlsNullCredentials_Get(), overflow);
    overflow = nullptr;
}

TEST(SolidSyslogMbedTlsHandleCredentials, CreateBeyondThePoolReportsExhaustion)
{
    FillPool();
    ErrorHandlerFake_Install(nullptr);

    overflow = SolidSyslogMbedTlsHandleCredentials_Create(&config);
    overflow = nullptr;

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_POOL_EXHAUSTED_SEVERITY,
        &SolidSyslogMbedTlsHandleCredentialsErrorSource,
        SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_POOL_EXHAUSTED
    );
}

TEST(SolidSyslogMbedTlsHandleCredentials, DestroyingAHandleThePoolDoesNotOwnIsReported)
{
    struct SolidSyslogMbedTlsCredentials stranger = {};
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogMbedTlsHandleCredentials_Destroy(&stranger);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_UNKNOWN_DESTROY_SEVERITY,
        &SolidSyslogMbedTlsHandleCredentialsErrorSource,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallWiresTheConfiguredCaChainWithNoRevocationList)
{
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    LONGS_EQUAL(1, MbedTlsFake_SslConfCaChainCallCount());
    POINTERS_EQUAL(&conf, MbedTlsFake_LastSslConfCaChainConfigArg());
    POINTERS_EQUAL(&caChain, MbedTlsFake_LastSslConfCaChainArg());
    POINTERS_EQUAL(nullptr, MbedTlsFake_LastSslConfCaChainCrlArg());
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallReportsTheTrustAnchorsItInstalled)
{
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    CHECK_TRUE(installed.TrustAnchorsInstalled);
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallSucceeds)
{
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    CHECK_TRUE(credentials->Install(credentials, &conf, &installed));
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallWithoutACaChainWiresNoTrustAnchors)
{
    config.CaChain = nullptr;
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    LONGS_EQUAL(0, MbedTlsFake_SslConfCaChainCallCount());
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallWithoutACaChainReportsNoTrustAnchors)
{
    config.CaChain = nullptr;
    installed.TrustAnchorsInstalled = true;
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    CHECK_FALSE(installed.TrustAnchorsInstalled);
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallPassesTheConfiguredPeerFingerprintsThrough)
{
    const char* pins[] = {"sha-256:AA", "sha-256:BB"};
    config.PeerFingerprints = pins;
    config.PeerFingerprintCount = 2;
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    POINTERS_EQUAL(pins, installed.Fingerprints);
    UNSIGNED_LONGS_EQUAL(2, installed.FingerprintCount);
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallWithoutPeerFingerprintsReportsNone)
{
    const char* pin = "sha-256:AA";
    installed.Fingerprints = &pin;
    installed.FingerprintCount = 1;
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    POINTERS_EQUAL(nullptr, installed.Fingerprints);
    UNSIGNED_LONGS_EQUAL(0, installed.FingerprintCount);
}

TEST(SolidSyslogMbedTlsHandleCredentials, CreateWithAPinCountButNoPinListReturnsTheNullCredentials)
{
    config.PeerFingerprintCount = 1;

    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    POINTERS_EQUAL(SolidSyslogMbedTlsNullCredentials_Get(), credentials);
    credentials = nullptr;
}

TEST(SolidSyslogMbedTlsHandleCredentials, CreateWithAPinCountButNoPinListReportsBadConfig)
{
    ErrorHandlerFake_Install(nullptr);
    config.PeerFingerprintCount = 1;

    SolidSyslogMbedTlsHandleCredentials_Create(&config);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogMbedTlsHandleCredentialsErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_NULL_PEER_FINGERPRINT
    );
}

TEST(SolidSyslogMbedTlsHandleCredentials, CreateWithAMissingPinInTheListReturnsTheNullCredentials)
{
    const char* pins[] = {"sha-256:AA", nullptr};
    config.PeerFingerprints = pins;
    config.PeerFingerprintCount = 2;

    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    POINTERS_EQUAL(SolidSyslogMbedTlsNullCredentials_Get(), credentials);
    credentials = nullptr;
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallPresentsTheConfiguredClientCredential)
{
    GiveAClientCredential();
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    LONGS_EQUAL(1, MbedTlsFake_SslConfOwnCertCallCount());
    POINTERS_EQUAL(&conf, MbedTlsFake_LastSslConfOwnCertConfigArg());
    POINTERS_EQUAL(&clientCert, MbedTlsFake_LastSslConfOwnCertCertArg());
    POINTERS_EQUAL(&clientKey, MbedTlsFake_LastSslConfOwnCertKeyArg());
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallChecksTheClientKeyAgainstItsCertificate)
{
    GiveAClientCredential();
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    LONGS_EQUAL(1, MbedTlsFake_PkCheckPairCallCount());
    POINTERS_EQUAL(&clientCert.pk, MbedTlsFake_LastPkCheckPairPublicKeyArg());
    POINTERS_EQUAL(&clientKey, MbedTlsFake_LastPkCheckPairPrivateKeyArg());
    POINTERS_EQUAL((void*) mbedtls_ctr_drbg_random, (void*) MbedTlsFake_LastPkCheckPairRngFuncArg());
    POINTERS_EQUAL(&rng, MbedTlsFake_LastPkCheckPairRngContextArg());
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallWithoutAClientCredentialPresentsNone)
{
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    LONGS_EQUAL(0, MbedTlsFake_SslConfOwnCertCallCount());
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallWithOnlyAClientCertificatePresentsNone)
{
    config.ClientCertChain = &clientCert;
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);

    credentials->Install(credentials, &conf, &installed);

    LONGS_EQUAL(0, MbedTlsFake_SslConfOwnCertCallCount());
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallReportsAHalfSuppliedClientCredential)
{
    config.ClientCertChain = &clientCert;
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);
    ErrorHandlerFake_Install(nullptr);

    credentials->Install(credentials, &conf, &installed);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogMbedTlsHandleCredentialsErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_INCOMPLETE
    );
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallReportsAHalfSuppliedClientKey)
{
    config.ClientKey = &clientKey;
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);
    ErrorHandlerFake_Install(nullptr);

    credentials->Install(credentials, &conf, &installed);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogMbedTlsHandleCredentialsErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_INCOMPLETE
    );
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallReportsAClientKeyThatDoesNotMatchItsCertificate)
{
    GiveAClientCredential();
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);
    MbedTlsFake_SetPkCheckPairReturn(MBEDTLS_ERR_PK_TYPE_MISMATCH);
    ErrorHandlerFake_Install(nullptr);

    credentials->Install(credentials, &conf, &installed);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogMbedTlsHandleCredentialsErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_MISMATCHED
    );
}

/* A credential the collector would reject at CertificateVerify is worse than
 * none: it moves the diagnosis to the far end. */
TEST(SolidSyslogMbedTlsHandleCredentials, InstallDoesNotPresentAClientKeyThatDoesNotMatchItsCertificate)
{
    GiveAClientCredential();
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);
    MbedTlsFake_SetPkCheckPairReturn(MBEDTLS_ERR_PK_TYPE_MISMATCH);

    credentials->Install(credentials, &conf, &installed);

    LONGS_EQUAL(0, MbedTlsFake_SslConfOwnCertCallCount());
}

TEST(SolidSyslogMbedTlsHandleCredentials, InstallReportsAClientCredentialThatWillNotInstall)
{
    GiveAClientCredential();
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);
    MbedTlsFake_SetSslConfOwnCertReturn(MBEDTLS_ERR_SSL_ALLOC_FAILED);
    ErrorHandlerFake_Install(nullptr);

    credentials->Install(credentials, &conf, &installed);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogMbedTlsHandleCredentialsErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_NOT_INSTALLED
    );
}

/* No fault in our own credential stops delivery - the connection continues
 * server-authenticated. */
TEST(SolidSyslogMbedTlsHandleCredentials, InstallStillSucceedsWhenTheClientCredentialIsFaulty)
{
    GiveAClientCredential();
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);
    MbedTlsFake_SetSslConfOwnCertReturn(MBEDTLS_ERR_SSL_ALLOC_FAILED);

    CHECK_TRUE(credentials->Install(credentials, &conf, &installed));
}

TEST(SolidSyslogMbedTlsHandleCredentials, ReleaseDoesNotCrash)
{
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&config);
    credentials->Install(credentials, &conf, &installed);

    credentials->Release(credentials);
}
