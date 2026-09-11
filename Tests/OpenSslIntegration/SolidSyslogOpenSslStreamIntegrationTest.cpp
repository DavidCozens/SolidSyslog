#include <openssl/err.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <string>

#include "BioPairStream.h"
#include "AddressFake.h"
#include "SolidSyslogError.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogTlsStreamCategories.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogOpenSslPemFileCredentials.h"
#include "SolidSyslogOpenSslPemFileCredentialsErrors.h"
#include "SolidSyslogOpenSslStream.h"
#include "SolidSyslogOpenSslStreamErrors.h"
#include "TlsTestCert.h"
#include "TlsTestServer.h"
#include "CppUTest/TestHarness.h"

/* BioPairStream pumps synchronously - SSL_connect completes in one call so
 * the handshake retry loop never sleeps. Provide a NoOp to satisfy the
 * required config field without taking a platform dependency on the
 * integration tests (these run on both POSIX and Windows). */
/* What the scenario under construction wants the connection made with. Held per
 * test on the fixture and reached through ProfileContext, so nothing leaks
 * between tests. */
struct IntegrationProfileValues
{
    const char* ServerName;
    const char* CipherList;
};

static void IntegrationProfile(struct SolidSyslogOpenSslProfile* profile, void* context)
{
    const auto* values = static_cast<const struct IntegrationProfileValues*>(context);
    profile->ServerName = values->ServerName;
    profile->CipherList = values->CipherList;
}

static void NoOpSleep(int milliseconds)
{
    (void) milliseconds;
}

/* This suite links no ErrorHandlerFake - that is the unit executable's, and this
 * one builds against the real libssl. Capturing the last event directly is
 * enough to pin which code a real fault produces. */
static int CapturedErrorCount;
static struct SolidSyslogErrorEvent LastCapturedError;

static void CaptureError(void* context, const struct SolidSyslogErrorEvent* event)
{
    (void) context;
    CapturedErrorCount++;
    LastCapturedError = *event;
}

/* Pins a refused handshake to the check that refused it, against the real
 * libssl rather than the fake's canned verdict. */
#define CHECK_REFUSAL_REPORTED(expectedCode)                                                           \
    {                                                                                                  \
        LONGS_EQUAL(1, CapturedErrorCount);                                                            \
        LONGS_EQUAL(SOLIDSYSLOG_SEVERITY_ERROR, LastCapturedError.Severity);                           \
        POINTERS_EQUAL(&SolidSyslogOpenSslStreamErrorSource, LastCapturedError.Source);                \
        UNSIGNED_LONGS_EQUAL(SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED, LastCapturedError.Category); \
        LONGS_EQUAL((expectedCode), LastCapturedError.Detail);                                         \
    }

static const char* const LOCALHOST_SANS[] = {"localhost", nullptr};

// clang-format off
TEST_GROUP(OpenSslStreamIntegration)
{
    struct TlsTestCert                cert           = {};
    struct TlsTestCert                clientCa       = {};
    struct TlsTestCert                clientCert     = {};
    /* Throwaway certificates a single test substitutes for real material.
       Fixture members rather than locals so a failing assertion, which
       abandons the test body, still releases them. */
    struct TlsTestCert                untrusted      = {};
    struct TlsTestCert                untrustedCa    = {};
    struct TlsTestCert                strayCert      = {};
    struct TlsTestCert                stranger       = {};
    struct TlsTestServer*             server         = nullptr;
    struct SolidSyslogStream*         transport      = nullptr;
    struct SolidSyslogOpenSslStreamConfig tlsConfig      = {};
    struct SolidSyslogOpenSslPemFileCredentialsConfig credsConfig = {};
    struct SolidSyslogOpenSslCredentials* credentials   = nullptr;
    
    struct SolidSyslogStream*         tlsStream      = nullptr;
    struct SolidSyslogAddress*        addr           = nullptr;
    char                              caPath[256]     = {};
    /* Set before buildScenario. A label pins the server's own certificate with
       that hash; a literal pins whatever it says. */
    const struct TlsTestCert*         serverIssuer    = nullptr;
    const char*                       pinLabel        = nullptr;
    const char*                       pinLiteral      = nullptr;
    bool                              installTrustAnchors = true;
    char                              pinText[160]    = {};
    const char*                       pins[1]         = {};
    struct IntegrationProfileValues   profileValues   = {};
    char                              clientCertPath[256] = {};
    char                              clientKeyPath[256]  = {};

    void setup() override
    {
        addr = AddressFake_Get();
        CapturedErrorCount = 0;
        LastCapturedError = {};
        SolidSyslog_SetErrorHandler(CaptureError, nullptr);
    }

    void teardown() override
    {
        SolidSyslog_SetErrorHandler(nullptr, nullptr);
        if (tlsStream != nullptr)         { SolidSyslogOpenSslStream_Destroy(tlsStream); }
        if (credentials != nullptr)       { SolidSyslogOpenSslPemFileCredentials_Destroy(credentials); }
        if (transport != nullptr)         { BioPairStream_Destroy(transport); }
        if (server != nullptr)            { TlsTestServer_Destroy(server); }
        if (cert.cert != nullptr)         { TlsTestCert_Destroy(&cert); }
        if (clientCert.cert != nullptr)   { TlsTestCert_Destroy(&clientCert); }
        if (clientCa.cert != nullptr)     { TlsTestCert_Destroy(&clientCa); }
        if (untrusted.cert != nullptr)    { TlsTestCert_Destroy(&untrusted); }
        if (untrustedCa.cert != nullptr)  { TlsTestCert_Destroy(&untrustedCa); }
        if (strayCert.cert != nullptr)    { TlsTestCert_Destroy(&strayCert); }
        if (stranger.cert != nullptr)     { TlsTestCert_Destroy(&stranger); }
        if (caPath[0] != '\0')            { (void) std::remove(caPath); }
        if (clientCertPath[0] != '\0')    { (void) std::remove(clientCertPath); }
        if (clientKeyPath[0] != '\0')     { (void) std::remove(clientKeyPath); }
    }

    template <std::size_t N>
    static void makeTempFile(char (&out)[N])
    {
        namespace fs = std::filesystem;
        static std::atomic<unsigned> counter{0};
        const std::string path = (fs::temp_directory_path() /
                                  ("solidsyslog_mtls_" + std::to_string(counter++) + ".tmp")).string();
        CHECK_TRUE(path.size() + 1 <= N);
        std::memcpy(out, path.c_str(), path.size() + 1);
        std::ofstream touch(out, std::ios::binary | std::ios::trunc);
        CHECK_TRUE(touch.is_open());
    }

    void buildScenario(const struct TlsTestCertConfig& certConfig,
                       const char*                     clientServerName = "localhost",
                       const struct TlsTestCert*       serverClientCa   = nullptr)
    {
        TlsTestCert_Create(&certConfig, &cert);
        makeTempFile(caPath);
        TlsTestCert_WritePemToFile(&cert, caPath);

        struct TlsTestServerConfig serverConfig = {};
        serverConfig.IssuerCert   = serverIssuer;
        serverConfig.ServerCert   = &cert;
        serverConfig.ClientCaCert = serverClientCa;
        server                    = TlsTestServer_Create(&serverConfig);

        transport = BioPairStream_Create(TlsTestServer_ClientSideBio(server));
        BioPairStream_SetPump(transport, TlsTestServer_Pump, server);

        if (installTrustAnchors)
        {
            credsConfig.CaBundlePath = caPath;
        }
        applyPinPolicy();
        credentials              = SolidSyslogOpenSslPemFileCredentials_Create(&credsConfig);

        tlsConfig.Transport    = transport;
        tlsConfig.Sleep        = NoOpSleep;
        tlsConfig.Credentials  = credentials;
        profileValues.ServerName  = clientServerName;
        tlsConfig.Profile         = IntegrationProfile;
        tlsConfig.ProfileContext  = &profileValues;
        tlsStream              = SolidSyslogOpenSslStream_Create(&tlsConfig);
    }

    void applyPinPolicy()
    {
        if (pinLabel != nullptr)
        {
            TlsTestCert_WriteFingerprint(&cert, pinLabel, pinText, sizeof(pinText));
            pins[0] = pinText;
        }
        else if (pinLiteral != nullptr)
        {
            pins[0] = pinLiteral;
        }
        if (pins[0] != nullptr)
        {
            credsConfig.PeerFingerprints    = pins;
            credsConfig.PeerFingerprintCount = 1;
        }
    }

    /* Creates the client-side mTLS material and writes it to disk.
     * `signingCa` signs the client leaf cert. Pass `&clientCa` for the happy
     * path (server-trusted), or a separately-created throwaway CA to drive
     * the "client cert not trusted by server" scenario. */
    void stageClientIdentity(const struct TlsTestCert* signingCa)
    {
        struct TlsTestCertConfig leafConfig = {};
        leafConfig.commonName               = "solidsyslog-test-client";
        leafConfig.issuer                   = signingCa;
        TlsTestCert_Create(&leafConfig, &clientCert);

        makeTempFile(clientCertPath);
        makeTempFile(clientKeyPath);
        TlsTestCert_WritePemToFile(&clientCert, clientCertPath);
        TlsTestCert_WritePrivateKeyPemToFile(&clientCert, clientKeyPath);

        credsConfig.ClientCertChainPath = clientCertPath;
        credsConfig.ClientKeyPath       = clientKeyPath;
    }

    /* A collector certificate issued by a CA, which the server then presents
       alongside the leaf. `clientCa` doubles as the issuer here. */
    void givenAnIssuedServerCertificate()
    {
        struct TlsTestCertConfig caConfig = {};
        caConfig.commonName               = "SolidSyslog Test Collector CA";
        TlsTestCert_Create(&caConfig, &clientCa);
        serverIssuer = &clientCa;
    }

    [[nodiscard]] struct TlsTestCertConfig issuedCertConfig() const
    {
        struct TlsTestCertConfig certConfig = {};
        certConfig.commonName         = "localhost";
        certConfig.subjectAltDnsNames = LOCALHOST_SANS;
        certConfig.issuer             = &clientCa;
        return certConfig;
    }

    void createClientCa()
    {
        struct TlsTestCertConfig caConfig = {};
        caConfig.commonName               = "SolidSyslog Test Client CA";
        TlsTestCert_Create(&caConfig, &clientCa);
    }
};

// clang-format on

TEST(OpenSslStreamIntegration, HandshakeSucceedsAgainstTrustedServerCert)
{
    struct TlsTestCertConfig certConfig = {};
    certConfig.commonName = "localhost";
    certConfig.subjectAltDnsNames = LOCALHOST_SANS;
    buildScenario(certConfig);

    CHECK_TRUE(SolidSyslogStream_Open(tlsStream, addr));
}

TEST(OpenSslStreamIntegration, HandshakeRejectedWhenServerCertIsExpired)
{
    struct TlsTestCertConfig certConfig = {};
    certConfig.commonName = "localhost";
    certConfig.subjectAltDnsNames = LOCALHOST_SANS;
    certConfig.notBefore = std::time(nullptr) - 7200;
    certConfig.notAfter = std::time(nullptr) - 3600;
    buildScenario(certConfig);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_EXPIRED);
}

TEST(OpenSslStreamIntegration, HandshakeRejectedWhenServerCertIsNotYetValid)
{
    struct TlsTestCertConfig certConfig = {};
    certConfig.commonName = "localhost";
    certConfig.subjectAltDnsNames = LOCALHOST_SANS;
    certConfig.notBefore = std::time(nullptr) + 3600;
    certConfig.notAfter = std::time(nullptr) + 7200;
    buildScenario(certConfig);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_NOT_YET_VALID);
}

TEST(OpenSslStreamIntegration, HandshakeRejectedWhenServerCertHostnameDoesNotMatch)
{
    static const char* const otherSans[] = {"someone-else.example", nullptr};
    struct TlsTestCertConfig certConfig = {};
    certConfig.commonName = "someone-else.example";
    certConfig.subjectAltDnsNames = otherSans;
    buildScenario(certConfig); /* the profile's ServerName defaults to "localhost" */

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_NAME_MISMATCHED);
}

TEST(OpenSslStreamIntegration, HandshakeRejectedWhenClientDoesNotTrustServerCert)
{
    struct TlsTestCertConfig certConfig = {};
    certConfig.commonName = "localhost";
    certConfig.subjectAltDnsNames = LOCALHOST_SANS;
    buildScenario(certConfig);

    /* Overwrite the client's trust file with an unrelated self-signed cert
     * so the server's cert is no longer anchored in the trust store. The CA
     * file is loaded on Open, so this replacement takes effect for the next
     * handshake attempt. */
    struct TlsTestCertConfig untrustedConfig = {};
    untrustedConfig.commonName = "some-other-entity.example";
    TlsTestCert_Create(&untrustedConfig, &untrusted);
    TlsTestCert_WritePemToFile(&untrusted, caPath);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_UNTRUSTED);
}

TEST(OpenSslStreamIntegration, HandshakeRejectedWhenCipherListIsUnsupported)
{
    struct TlsTestCertConfig certConfig = {};
    certConfig.commonName = "localhost";
    certConfig.subjectAltDnsNames = LOCALHOST_SANS;
    profileValues.CipherList = "NOT-A-REAL-CIPHER";
    buildScenario(certConfig);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
}

/* -------------------------------------------------------------------------
 * Mutual TLS - client cert + private key (S03.09).
 * ------------------------------------------------------------------------- */

TEST(OpenSslStreamIntegration, MutualTlsHandshakeSucceedsWithClientCertSignedByTrustedCa)
{
    createClientCa();
    stageClientIdentity(&clientCa);

    struct TlsTestCertConfig serverCertConfig = {};
    serverCertConfig.commonName = "localhost";
    serverCertConfig.subjectAltDnsNames = LOCALHOST_SANS;
    buildScenario(serverCertConfig, "localhost", &clientCa);

    bool opened = SolidSyslogStream_Open(tlsStream, addr);
    if (!opened)
    {
        ERR_print_errors_fp(stderr);
    }
    CHECK_TRUE(opened);
}

TEST(OpenSslStreamIntegration, MutualTlsHandshakeRejectedWhenClientSendsNoCert)
{
    createClientCa();
    /* Client config intentionally leaves clientCertChainPath / clientKeyPath NULL. */

    struct TlsTestCertConfig serverCertConfig = {};
    serverCertConfig.commonName = "localhost";
    serverCertConfig.subjectAltDnsNames = LOCALHOST_SANS;
    buildScenario(serverCertConfig, "localhost", &clientCa);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
}

TEST(OpenSslStreamIntegration, MutualTlsConnectsServerAuthenticatedWhenClientKeyDoesNotMatchCert)
{
    createClientCa();
    stageClientIdentity(&clientCa);

    /* Overwrite the key file with an unrelated private key. OpenSSL refuses the
     * pairing, so no client credential is installed and none is presented - the
     * fault is reported and the connection continues server-authenticated. The
     * server here does not ask for a client certificate; one that does refuses
     * the handshake, which MutualTlsHandshakeRejectedWhenClientSendsNoCert
     * covers. */
    struct TlsTestCertConfig strayConfig = {};
    strayConfig.commonName = "unrelated";
    TlsTestCert_Create(&strayConfig, &strayCert);
    TlsTestCert_WritePrivateKeyPemToFile(&strayCert, clientKeyPath);

    struct TlsTestCertConfig serverCertConfig = {};
    serverCertConfig.commonName = "localhost";
    serverCertConfig.subjectAltDnsNames = LOCALHOST_SANS;
    buildScenario(serverCertConfig, "localhost");

    CHECK_TRUE(SolidSyslogStream_Open(tlsStream, addr));
    LONGS_EQUAL(1, CapturedErrorCount);
    LONGS_EQUAL(SOLIDSYSLOG_SEVERITY_WARNING, LastCapturedError.Severity);
    /* The credential source raises this now, not the stream: the fault is in
     * where the material came from rather than in the stream that asked. */
    POINTERS_EQUAL(&SolidSyslogOpenSslPemFileCredentialsErrorSource, LastCapturedError.Source);
    UNSIGNED_LONGS_EQUAL(SOLIDSYSLOG_CAT_BAD_CONFIG, LastCapturedError.Category);
    /* NOT_INSTALLED rather than MISMATCHED: both test certs are RSA, so OpenSSL
     * refuses the pair inside SSL_CTX_use_PrivateKey_file and never reaches the
     * explicit pairing check. */
    LONGS_EQUAL(SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_NOT_INSTALLED, LastCapturedError.Detail);
}

TEST(OpenSslStreamIntegration, MutualTlsHandshakeRejectedWhenClientCertSignedByUntrustedCa)
{
    createClientCa();

    /* Client cert is signed by a throwaway CA that the server never learns
     * about - the server's trust store only has `clientCa`. */
    struct TlsTestCertConfig untrustedCaConfig = {};
    untrustedCaConfig.commonName = "Untrusted Client CA";
    TlsTestCert_Create(&untrustedCaConfig, &untrustedCa);
    stageClientIdentity(&untrustedCa);

    struct TlsTestCertConfig serverCertConfig = {};
    serverCertConfig.commonName = "localhost";
    serverCertConfig.subjectAltDnsNames = LOCALHOST_SANS;
    buildScenario(serverCertConfig, "localhost", &clientCa);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
}

/* -------------------------------------------------------------------------
 * Certificate fingerprint authorisation (RFC 5425 4.2.2).
 * ------------------------------------------------------------------------- */

/* A pin no certificate will ever match. */
static const char* const UNMATCHABLE_PIN = "sha-256:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
                                           "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";

TEST(OpenSslStreamIntegration, HandshakeSucceedsWhenAPinIsTheOnlyThingAuthorisingTheServer)
{
    struct TlsTestCertConfig certConfig = {};
    certConfig.commonName = "localhost";
    certConfig.subjectAltDnsNames = LOCALHOST_SANS;
    pinLabel = "sha-256";
    installTrustAnchors = false;
    buildScenario(certConfig);

    CHECK_TRUE(SolidSyslogStream_Open(tlsStream, addr));
    LONGS_EQUAL(0, CapturedErrorCount);
}

TEST(OpenSslStreamIntegration, HandshakeRejectedWhenTheServerCertMatchesNoPin)
{
    struct TlsTestCertConfig certConfig = {};
    certConfig.commonName = "localhost";
    certConfig.subjectAltDnsNames = LOCALHOST_SANS;
    pinLiteral = UNMATCHABLE_PIN;
    installTrustAnchors = false;
    buildScenario(certConfig);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_FINGERPRINT_MISMATCHED);
}

TEST(OpenSslStreamIntegration, HandshakeRejectedWhenTheServerCertIsExpiredEvenThoughItsPinMatches)
{
    struct TlsTestCertConfig certConfig = {};
    certConfig.commonName = "localhost";
    certConfig.subjectAltDnsNames = LOCALHOST_SANS;
    certConfig.notBefore = std::time(nullptr) - 7200;
    certConfig.notAfter = std::time(nullptr) - 3600;
    pinLabel = "sha-256";
    installTrustAnchors = false;
    buildScenario(certConfig);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_EXPIRED);
}

TEST(OpenSslStreamIntegration, HandshakeSucceedsWhenTrustAnchorsAndAMatchingPinAgree)
{
    struct TlsTestCertConfig certConfig = {};
    certConfig.commonName = "localhost";
    certConfig.subjectAltDnsNames = LOCALHOST_SANS;
    pinLabel = "sha-256";
    buildScenario(certConfig);

    CHECK_TRUE(SolidSyslogStream_Open(tlsStream, addr));
}

TEST(OpenSslStreamIntegration, HandshakeRejectedWhenTheChainIsTrustedButNoPinMatches)
{
    struct TlsTestCertConfig certConfig = {};
    certConfig.commonName = "localhost";
    certConfig.subjectAltDnsNames = LOCALHOST_SANS;
    pinLiteral = UNMATCHABLE_PIN;
    buildScenario(certConfig);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_FINGERPRINT_MISMATCHED);
}

TEST(OpenSslStreamIntegration, HandshakeSucceedsAgainstASha1PinAndWarnsOfIt)
{
    struct TlsTestCertConfig certConfig = {};
    certConfig.commonName = "localhost";
    certConfig.subjectAltDnsNames = LOCALHOST_SANS;
    pinLabel = "sha-1";
    installTrustAnchors = false;
    buildScenario(certConfig);

    CHECK_TRUE(SolidSyslogStream_Open(tlsStream, addr));
    LONGS_EQUAL(1, CapturedErrorCount);
    LONGS_EQUAL(SOLIDSYSLOG_SEVERITY_WARNING, LastCapturedError.Severity);
    POINTERS_EQUAL(&SolidSyslogOpenSslStreamErrorSource, LastCapturedError.Source);
    UNSIGNED_LONGS_EQUAL(SOLIDSYSLOG_CAT_BAD_CONFIG, LastCapturedError.Category);
    LONGS_EQUAL(SOLIDSYSLOG_TLS_STREAM_ERROR_FINGERPRINT_SHA1, LastCapturedError.Detail);
}

TEST(OpenSslStreamIntegration, OpenFailsWhenAPinIsMalformed)
{
    struct TlsTestCertConfig certConfig = {};
    certConfig.commonName = "localhost";
    certConfig.subjectAltDnsNames = LOCALHOST_SANS;
    pinLiteral = "sha-256:not-a-fingerprint";
    buildScenario(certConfig);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    LONGS_EQUAL(1, CapturedErrorCount);
    LONGS_EQUAL(SOLIDSYSLOG_SEVERITY_ERROR, LastCapturedError.Severity);
    POINTERS_EQUAL(&SolidSyslogOpenSslStreamErrorSource, LastCapturedError.Source);
    UNSIGNED_LONGS_EQUAL(SOLIDSYSLOG_CAT_BAD_CONFIG, LastCapturedError.Category);
    LONGS_EQUAL(SOLIDSYSLOG_TLS_STREAM_ERROR_FINGERPRINT_MALFORMED, LastCapturedError.Detail);
}

/* A collector that presents its issuer alongside its leaf is the ordinary
   case, and puts the chain-trust failure above the leaf. */
TEST(OpenSslStreamIntegration, HandshakeSucceedsWhenAPinAuthorisesALeafPresentedWithItsIssuer)
{
    givenAnIssuedServerCertificate();
    pinLabel = "sha-256";
    installTrustAnchors = false;
    buildScenario(issuedCertConfig());

    CHECK_TRUE(SolidSyslogStream_Open(tlsStream, addr));
}

/* Waiving the chain above the leaf must not let the leaf itself through. */
TEST(OpenSslStreamIntegration, HandshakeRejectedWhenALeafPresentedWithItsIssuerMatchesNoPin)
{
    givenAnIssuedServerCertificate();
    pinLiteral = UNMATCHABLE_PIN;
    installTrustAnchors = false;
    buildScenario(issuedCertConfig());

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_FINGERPRINT_MISMATCHED);
}

/* The waiver is for a peer authorised by pin alone. Where trust anchors are
   configured as well, the chain must still validate against them. */
TEST(OpenSslStreamIntegration, HandshakeRejectedWhenTrustAnchorsAreConfiguredAndTheChainDoesNotReachThem)
{
    givenAnIssuedServerCertificate();
    pinLabel = "sha-256";
    buildScenario(issuedCertConfig());

    /* The trust file holds an unrelated self-signed certificate, so the anchors
       are installed but the presented chain reaches none of them. */
    struct TlsTestCertConfig strangerConfig = {};
    strangerConfig.commonName = "some-other-entity.example";
    TlsTestCert_Create(&strangerConfig, &stranger);
    TlsTestCert_WritePemToFile(&stranger, caPath);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_UNTRUSTED);
}
