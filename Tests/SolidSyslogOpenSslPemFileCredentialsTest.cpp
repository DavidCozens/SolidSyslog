#include "CppUTest/TestHarness.h"

extern "C"
{
#include "ErrorHandlerFake.h"
#include "OpenSslFake.h"
#include "SolidSyslogOpenSslCredentialsDefinition.h"
#include "SolidSyslogOpenSslNullCredentials.h"
#include "SolidSyslogTlsCredentialsInstalled.h"
#include "SolidSyslogOpenSslPemFileCredentials.h"
#include "SolidSyslogOpenSslPemFileCredentialsErrors.h"
#include "SolidSyslogError.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogTunables.h"
}

#include "SolidSyslogErrorCategory.h"
#include "TestUtils.h"

using namespace CososoTesting;

// clang-format off
TEST_GROUP(SolidSyslogOpenSslPemFileCredentials)
{
    struct SolidSyslogOpenSslPemFileCredentialsConfig config = {};
    struct SolidSyslogOpenSslCredentials* credentials = nullptr;
    struct SolidSyslogOpenSslCredentials* pooled[SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE] = {};
    struct SolidSyslogOpenSslCredentials* overflow = nullptr;

    struct SolidSyslogTlsCredentialsInstalled installed = {};
    int ctxStorage = 0;
    struct ssl_ctx_st* ctx = nullptr;

    void setup() override
    {
        OpenSslFake_Reset();
        config.CaBundlePath = "ca.pem";
        ctx = reinterpret_cast<struct ssl_ctx_st*>(&ctxStorage);
    }

    void teardown() override
    {
        if (credentials != nullptr)
        {
            SolidSyslogOpenSslPemFileCredentials_Destroy(credentials);
        }
        for (auto* slot : pooled)
        {
            if (slot != nullptr)
            {
                SolidSyslogOpenSslPemFileCredentials_Destroy(slot);
            }
        }
        if (overflow != nullptr)
        {
            SolidSyslogOpenSslPemFileCredentials_Destroy(overflow);
        }
    }

    void GiveAClientCredential()
    {
        config.ClientCertChainPath = "client.pem";
        config.ClientKeyPath = "client.key";
    }

    void FillPool()
    {
        for (auto*& slot : pooled)
        {
            slot = SolidSyslogOpenSslPemFileCredentials_Create(&config);
        }
    }
};

// clang-format on

TEST(SolidSyslogOpenSslPemFileCredentials, CreateReturnsAPooledHandle)
{
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    CHECK_TRUE(credentials != SolidSyslogOpenSslNullCredentials_Get());
}

TEST(SolidSyslogOpenSslPemFileCredentials, CreateWithNullConfigReturnsTheNullCredentials)
{
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(nullptr);

    POINTERS_EQUAL(SolidSyslogOpenSslNullCredentials_Get(), credentials);
    credentials = nullptr;
}

TEST(SolidSyslogOpenSslPemFileCredentials, CreateWithNullConfigReportsBadConfig)
{
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogOpenSslPemFileCredentials_Create(nullptr);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogOpenSslPemFileCredentialsErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_NULL_CONFIG
    );
}

TEST(SolidSyslogOpenSslPemFileCredentials, CreateBeyondThePoolReturnsTheNullCredentials)
{
    FillPool();

    overflow = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    POINTERS_EQUAL(SolidSyslogOpenSslNullCredentials_Get(), overflow);
    overflow = nullptr;
}

TEST(SolidSyslogOpenSslPemFileCredentials, CreateBeyondThePoolReportsExhaustion)
{
    FillPool();
    ErrorHandlerFake_Install(nullptr);

    overflow = SolidSyslogOpenSslPemFileCredentials_Create(&config);
    overflow = nullptr;

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_POOL_EXHAUSTED_SEVERITY,
        &SolidSyslogOpenSslPemFileCredentialsErrorSource,
        SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_POOL_EXHAUSTED
    );
}

TEST(SolidSyslogOpenSslPemFileCredentials, DestroyingAHandleThePoolDoesNotOwnIsReported)
{
    struct SolidSyslogOpenSslCredentials stranger = {};
    ErrorHandlerFake_Install(nullptr);

    SolidSyslogOpenSslPemFileCredentials_Destroy(&stranger);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_UNKNOWN_DESTROY_SEVERITY,
        &SolidSyslogOpenSslPemFileCredentialsErrorSource,
        SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_UNKNOWN_DESTROY
    );
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallLoadsTheConfiguredTrustAnchors)
{
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    credentials->Install(credentials, ctx, &installed);

    POINTERS_EQUAL(ctx, OpenSslFake_LastLoadVerifyLocationsCtxArg());
    STRCMP_EQUAL("ca.pem", OpenSslFake_LastCaBundlePath());
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallReportsTheTrustAnchorsItInstalled)
{
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    credentials->Install(credentials, ctx, &installed);

    CHECK_TRUE(installed.TrustAnchorsInstalled);
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallSucceeds)
{
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    CHECK_TRUE(credentials->Install(credentials, ctx, &installed));
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallWithoutATrustAnchorPathLoadsNothing)
{
    config.CaBundlePath = nullptr;
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    credentials->Install(credentials, ctx, &installed);

    POINTERS_EQUAL(nullptr, OpenSslFake_LastLoadVerifyLocationsCtxArg());
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallWithoutATrustAnchorPathReportsNoTrustAnchors)
{
    config.CaBundlePath = nullptr;
    installed.TrustAnchorsInstalled = true;
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    credentials->Install(credentials, ctx, &installed);

    CHECK_FALSE(installed.TrustAnchorsInstalled);
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallPassesTheConfiguredPeerFingerprintsThrough)
{
    const char* pins[] = {"sha-256:AA", "sha-256:BB"};
    config.PeerFingerprints = pins;
    config.PeerFingerprintCount = 2;
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    credentials->Install(credentials, ctx, &installed);

    POINTERS_EQUAL(pins, installed.Fingerprints);
    UNSIGNED_LONGS_EQUAL(2, installed.FingerprintCount);
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallWithoutPeerFingerprintsReportsNone)
{
    const char* pin = "sha-256:AA";
    installed.Fingerprints = &pin;
    installed.FingerprintCount = 1;
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    credentials->Install(credentials, ctx, &installed);

    POINTERS_EQUAL(nullptr, installed.Fingerprints);
    UNSIGNED_LONGS_EQUAL(0, installed.FingerprintCount);
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallFailsWhenTheTrustAnchorsWillNotLoad)
{
    OpenSslFake_SetLoadVerifyLocationsFails(true);
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    CHECK_FALSE(credentials->Install(credentials, ctx, &installed));
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallReportsTrustAnchorsThatWillNotLoad)
{
    OpenSslFake_SetLoadVerifyLocationsFails(true);
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);
    ErrorHandlerFake_Install(nullptr);

    credentials->Install(credentials, ctx, &installed);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_ERROR,
        &SolidSyslogOpenSslPemFileCredentialsErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_TRUST_ANCHORS_NOT_LOADED
    );
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallPresentsTheConfiguredClientCredential)
{
    GiveAClientCredential();
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    credentials->Install(credentials, ctx, &installed);

    STRCMP_EQUAL("client.pem", OpenSslFake_LastClientCertChainPath());
    STRCMP_EQUAL("client.key", OpenSslFake_LastClientKeyPath());
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallWithoutAClientCredentialPresentsNone)
{
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    credentials->Install(credentials, ctx, &installed);

    LONGS_EQUAL(0, OpenSslFake_UseCertChainFileCallCount());
    LONGS_EQUAL(0, OpenSslFake_UsePrivateKeyFileCallCount());
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallReportsAHalfSuppliedClientCredential)
{
    config.ClientCertChainPath = "client.pem";
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);
    ErrorHandlerFake_Install(nullptr);

    credentials->Install(credentials, ctx, &installed);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogOpenSslPemFileCredentialsErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_INCOMPLETE
    );
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallReportsAClientCredentialThatWillNotLoad)
{
    GiveAClientCredential();
    OpenSslFake_SetUseCertChainFileFails(true);
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);
    ErrorHandlerFake_Install(nullptr);

    credentials->Install(credentials, ctx, &installed);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogOpenSslPemFileCredentialsErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_NOT_INSTALLED
    );
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallReportsAClientKeyThatDoesNotMatchItsCertificate)
{
    GiveAClientCredential();
    OpenSslFake_SetCheckPrivateKeyFails(true);
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);
    ErrorHandlerFake_Install(nullptr);

    credentials->Install(credentials, ctx, &installed);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogOpenSslPemFileCredentialsErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_MISMATCHED
    );
}

TEST(SolidSyslogOpenSslPemFileCredentials, InstallStillSucceedsWhenTheClientCredentialIsFaulty)
{
    GiveAClientCredential();
    OpenSslFake_SetUseCertChainFileFails(true);
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    CHECK_TRUE(credentials->Install(credentials, ctx, &installed));
}

TEST(SolidSyslogOpenSslPemFileCredentials, ReleaseDoesNotCrash)
{
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);
    credentials->Install(credentials, ctx, &installed);

    credentials->Release(credentials);
}

TEST(SolidSyslogOpenSslPemFileCredentials, CreateWithAPinCountButNoPinListReturnsTheNullCredentials)
{
    config.PeerFingerprintCount = 1;

    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    POINTERS_EQUAL(SolidSyslogOpenSslNullCredentials_Get(), credentials);
    credentials = nullptr;
}

TEST(SolidSyslogOpenSslPemFileCredentials, CreateWithAPinCountButNoPinListReportsBadConfig)
{
    ErrorHandlerFake_Install(nullptr);
    config.PeerFingerprintCount = 1;

    SolidSyslogOpenSslPemFileCredentials_Create(&config);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogOpenSslPemFileCredentialsErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_NULL_PEER_FINGERPRINT
    );
}

TEST(SolidSyslogOpenSslPemFileCredentials, CreateWithAMissingPinInTheListReturnsTheNullCredentials)
{
    const char* pins[] = {"sha-256:AA", nullptr};
    config.PeerFingerprints = pins;
    config.PeerFingerprintCount = 2;

    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&config);

    POINTERS_EQUAL(SolidSyslogOpenSslNullCredentials_Get(), credentials);
    credentials = nullptr;
}

TEST(SolidSyslogOpenSslPemFileCredentials, CreateWithAMissingPinInTheListReportsBadConfig)
{
    const char* pins[] = {"sha-256:AA", nullptr};
    ErrorHandlerFake_Install(nullptr);
    config.PeerFingerprints = pins;
    config.PeerFingerprintCount = 2;

    SolidSyslogOpenSslPemFileCredentials_Create(&config);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        &SolidSyslogOpenSslPemFileCredentialsErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_NULL_PEER_FINGERPRINT
    );
}
