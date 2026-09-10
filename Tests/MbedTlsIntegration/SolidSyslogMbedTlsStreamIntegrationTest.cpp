#include "CppUTest/TestHarness.h"

extern "C"
{
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/version.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "MbedTlsTestCert.h"
#include "MbedTlsTestServer.h"
#include "SocketStream.h"
#include "SolidSyslogError.h"
#include "SolidSyslogMbedTlsCredentialsDefinition.h"
#include "SolidSyslogMbedTlsHandleCredentials.h"
#include "SolidSyslogMbedTlsStream.h"
#include "SolidSyslogMbedTlsStreamErrors.h"
#include "SolidSyslogPrival.h"
#include "AddressFake.h"
#include "SolidSyslogStream.h"
}

#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogTlsStreamCategories.h"

namespace
{
constexpr const char* TEST_SERVER_HOSTNAME = "syslog.example.com";
constexpr const char* TEST_CA_SUBJECT = "CN=Test Root CA";
constexpr const char* TEST_SERVER_SUBJECT = "CN=syslog.example.com";

void NoOpSleep(int milliseconds)
{
    (void) milliseconds;
}
} // namespace

/* This suite links no ErrorHandlerFake - that is the unit executable's, and this
 * one builds against the real libmbedtls. Capturing the last event directly is
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
 * libmbedtls rather than the fake's canned verdict. */
#define CHECK_REFUSAL_REPORTED(expectedCode)                                                           \
    {                                                                                                  \
        LONGS_EQUAL(1, CapturedErrorCount);                                                            \
        LONGS_EQUAL(SOLIDSYSLOG_SEVERITY_ERROR, LastCapturedError.Severity);                           \
        POINTERS_EQUAL(&SolidSyslogMbedTlsStreamErrorSource, LastCapturedError.Source);                \
        UNSIGNED_LONGS_EQUAL(SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED, LastCapturedError.Category); \
        LONGS_EQUAL((expectedCode), LastCapturedError.Detail);                                         \
    }

// clang-format off
/* What the scenario under construction wants the connection made with. Held per
 * test on the fixture and reached through ProfileContext, so nothing leaks
 * between tests. */
struct IntegrationProfileValues
{
    const char* ServerName;
    const int*  CipherSuites;
};

static void IntegrationProfile(struct SolidSyslogMbedTlsProfile* profile, void* context)
{
    const auto* values   = static_cast<const struct IntegrationProfileValues*>(context);
    profile->ServerName   = values->ServerName;
    profile->CipherSuites = values->CipherSuites;
}

TEST_GROUP(SolidSyslogMbedTlsStreamIntegration)
{
    struct IntegrationProfileValues profileValues = {};
    mbedtls_entropy_context  entropy            = {};
    mbedtls_ctr_drbg_context rng                = {};
    int                      fds[2]             = {-1, -1};
    struct MbedTlsTestCert   trustedCa          = {};
    struct MbedTlsTestCert   serverCert         = {};
    struct MbedTlsTestServer* server            = nullptr;
    struct SolidSyslogStream* clientTransport   = nullptr;
    struct SolidSyslogStream* tlsStream         = nullptr;
    struct SolidSyslogMbedTlsHandleCredentialsConfig credsConfig = {};
    char pinText[160] = {};
    const char* pins[1] = {};
    struct SolidSyslogMbedTlsCredentials* credentials = nullptr;
    struct SolidSyslogAddress* addr             = nullptr;

    void setup() override
    {
        addr = AddressFake_Get();
        CapturedErrorCount = 0;
        LastCapturedError = {};
        SolidSyslog_SetErrorHandler(CaptureError, nullptr);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&rng);
        const unsigned char pers[] = "mbedtls-integration-test";
        mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy, pers, sizeof(pers) - 1U);

        socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
        /* Bound both sides' blocking recv to 5s. The OpenSSL integration
         * tests use an in-memory BIO pair that never blocks; our socketpair
         * harness inherently can deadlock on negative-path handshakes (one
         * side waits for a message the other won't send). The cap matches
         * the production handshake retry budget - generous for any real
         * handshake (sub-second), tight enough that a stuck test fails fast. */
        struct timeval rcvTimeout = {5, 0};
        setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &rcvTimeout, sizeof(rcvTimeout));
        setsockopt(fds[1], SOL_SOCKET, SO_RCVTIMEO, &rcvTimeout, sizeof(rcvTimeout));

        struct MbedTlsTestCertConfig caConfig = {};
        caConfig.SubjectName = TEST_CA_SUBJECT;
        caConfig.IsCa = 1;
        MbedTlsTestCert_Create(&caConfig, &trustedCa, &rng);

        struct MbedTlsTestCertConfig serverConfig = {};
        serverConfig.SubjectName = TEST_SERVER_SUBJECT;
        serverConfig.SubjectAltDns = TEST_SERVER_HOSTNAME;
        serverConfig.IsCa = 0;
        serverConfig.Issuer = &trustedCa;
        MbedTlsTestCert_Create(&serverConfig, &serverCert, &rng);
    }

    void teardown() override
    {
        SolidSyslog_SetErrorHandler(nullptr, nullptr);
        if (tlsStream != nullptr)
        {
            SolidSyslogMbedTlsStream_Destroy(tlsStream);
        }
        if (credentials != nullptr)
        {
            SolidSyslogMbedTlsHandleCredentials_Destroy(credentials);
        }
        if (clientTransport != nullptr)
        {
            SocketStream_Destroy(clientTransport);
        }
        if (server != nullptr)
        {
            MbedTlsTestServer_Destroy(server);
        }
        MbedTlsTestCert_Destroy(&serverCert);
        MbedTlsTestCert_Destroy(&trustedCa);
        mbedtls_ctr_drbg_free(&rng);
        mbedtls_entropy_free(&entropy);
    }

    struct SolidSyslogStream* StartServerWithCert(const struct MbedTlsTestCert* cert)
    {
        return StartServerRequiringClientCa(cert, nullptr);
    }

    /* mTLS variant: server requires + verifies a client cert against
     * `trustedClientCa`. Passing nullptr behaves like StartServerWithCert. */
    // NOLINTBEGIN(bugprone-easily-swappable-parameters) -- both args are MbedTlsTestCert by domain; the function name distinguishes their roles
    struct SolidSyslogStream* StartServerRequiringClientCa(
        const struct MbedTlsTestCert* cert,
        const struct MbedTlsTestCert* trustedClientCa
    )
    // NOLINTEND(bugprone-easily-swappable-parameters)
    {
        struct MbedTlsTestServerConfig serverConfig = {};
        serverConfig.ServerFd = fds[1];
        serverConfig.ServerCert = cert;
        serverConfig.Rng = &rng;
        serverConfig.TrustedClientCa = trustedClientCa;
        server = MbedTlsTestServer_Create(&serverConfig);
        clientTransport = SocketStream_Create(fds[0]);
        return clientTransport;
    }

    /* Build a CA + leaf-cert pair signed by it, for the per-test mTLS
     * material. Both outputs must be MbedTlsTestCert_Destroy'd by the
     * test body before it returns. */
    void CreateClientIdentitySignedBy(
        const struct MbedTlsTestCert* signingCa,
        struct MbedTlsTestCert* outClientCert
    )
    {
        struct MbedTlsTestCertConfig leafConfig = {};
        leafConfig.SubjectName = "CN=solidsyslog-test-client";
        leafConfig.IsCa = 0;
        leafConfig.Issuer = signingCa;
        MbedTlsTestCert_Create(&leafConfig, outClientCert, &rng);
    }

    /* Build a server cert valid only between the two "YYYYMMDDHHMMSS" instants,
     * identical to setup()'s in every other respect. The test body must
     * MbedTlsTestCert_Destroy the result before it returns. */
    void CreateServerCertValidBetween(const char* from, const char* to, struct MbedTlsTestCert* outCert)
    {
        struct MbedTlsTestCertConfig certConfig = {};
        certConfig.SubjectName = TEST_SERVER_SUBJECT;
        certConfig.SubjectAltDns = TEST_SERVER_HOSTNAME;
        certConfig.Issuer = &trustedCa;
        certConfig.ValidityFrom = from;
        certConfig.ValidityTo = to;
        MbedTlsTestCert_Create(&certConfig, outCert, &rng);
    }

    /* Common wiring used by every integration test: transport, sleep,
     * fixture-owned DRBG, and the hostname built in setup(). The material -
     * trust anchors here, plus ClientCertChain / ClientKey where a test wants
     * mTLS - goes on credsConfig, which CreateTlsStream turns into the
     * credentials the stream asks at Open. Per-test tweaks overlay onto either
     * struct before CreateTlsStream. */
    struct SolidSyslogMbedTlsStreamConfig BuildBaseConfig(struct SolidSyslogStream* transport)
    {
        credsConfig = {};
        credsConfig.Rng = &rng;
        credsConfig.CaChain = &trustedCa.Cert;

        struct SolidSyslogMbedTlsStreamConfig cfg = {};
        cfg.Transport = transport;
        cfg.Sleep = NoOpSleep;
        cfg.Rng = &rng;
        profileValues.ServerName = TEST_SERVER_HOSTNAME;
        cfg.Profile = IntegrationProfile;
        cfg.ProfileContext = &profileValues;
        return cfg;
    }

    /* Pin the certificate the server will present, with the named hash. */
    void PinCertificate(const struct MbedTlsTestCert* cert, const char* label)
    {
        MbedTlsTestCert_WriteFingerprint(cert, label, pinText, sizeof(pinText));
        pins[0] = pinText;
        credsConfig.PeerFingerprints = pins;
        credsConfig.PeerFingerprintCount = 1;
    }

    void PinLiterally(const char* pin)
    {
        pins[0] = pin;
        credsConfig.PeerFingerprints = pins;
        credsConfig.PeerFingerprintCount = 1;
    }

    /* Start a server that presents its leaf together with the CA that issued
       it, as a correctly configured collector does. */
    struct SolidSyslogStream* StartServerPresentingItsIssuer(const struct MbedTlsTestCert* cert)
    {
        struct MbedTlsTestServerConfig serverConfig = {};
        serverConfig.ServerFd = fds[1];
        serverConfig.ServerCert = cert;
        serverConfig.IssuerCert = &trustedCa;
        serverConfig.Rng = &rng;
        server = MbedTlsTestServer_Create(&serverConfig);
        clientTransport = SocketStream_Create(fds[0]);
        return clientTransport;
    }

    struct SolidSyslogStream* CreateTlsStream(struct SolidSyslogMbedTlsStreamConfig* cfg)
    {
        credentials = SolidSyslogMbedTlsHandleCredentials_Create(&credsConfig);
        cfg->Credentials = credentials;
        return SolidSyslogMbedTlsStream_Create(cfg);
    }
};

// clang-format on

TEST(SolidSyslogMbedTlsStreamIntegration, HandshakeSucceedsWhenServerCertSignedByTrustedCaAndHostnameMatches)

{
    struct SolidSyslogStream* transport = StartServerWithCert(&serverCert);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    tlsStream = CreateTlsStream(&config);

    bool opened = SolidSyslogStream_Open(tlsStream, addr);

    CHECK_TRUE_TEXT(opened, "client-side Open (incl. handshake) should succeed against a trusted server");
    CHECK_TRUE_TEXT(
        MbedTlsTestServer_JoinAndHandshakeSucceeded(server),
        "server-side handshake should mirror the client's success"
    );
}

TEST(SolidSyslogMbedTlsStreamIntegration, HandshakeFailsWhenServerCertSignedByUntrustedCa)

{
    /* Trust an unrelated CA: we hand the *client* a different CA chain than
     * the one that signed the server's cert, so the chain validation fails. */
    struct MbedTlsTestCert untrustedCa = {};
    struct MbedTlsTestCertConfig untrustedConfig = {};
    untrustedConfig.SubjectName = "CN=Wrong Root CA";
    untrustedConfig.IsCa = 1;
    MbedTlsTestCert_Create(&untrustedConfig, &untrustedCa, &rng);

    struct SolidSyslogStream* transport = StartServerWithCert(&serverCert);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    credsConfig.CaChain = &untrustedCa.Cert;
    tlsStream = CreateTlsStream(&config);

    bool opened = SolidSyslogStream_Open(tlsStream, addr);

    CHECK_FALSE_TEXT(opened, "client-side handshake must fail when the server cert chains to an untrusted CA");
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_UNTRUSTED);

    MbedTlsTestCert_Destroy(&untrustedCa);
}

TEST(SolidSyslogMbedTlsStreamIntegration, HandshakeFailsWhenServerNameDoesNotMatchCert)

{
    struct SolidSyslogStream* transport = StartServerWithCert(&serverCert);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    profileValues.ServerName = "wrong-host.example.com"; /* server cert has SAN syslog.example.com */
    tlsStream = CreateTlsStream(&config);

    bool opened = SolidSyslogStream_Open(tlsStream, addr);

    CHECK_FALSE_TEXT(opened, "client-side handshake must fail when ServerName does not match the cert's SAN");
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_NAME_MISMATCHED);
}

/* No trust anchors and no pinned fingerprint: nothing authorises the peer, so
 * the connection stops before the handshake rather than reaching a collector
 * this stream cannot identify. */
TEST(SolidSyslogMbedTlsStreamIntegration, OpenFailsWhenNothingAuthorisesThePeer)

{
    struct SolidSyslogStream* transport = StartServerWithCert(&serverCert);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    credsConfig.CaChain = nullptr;
    tlsStream = CreateTlsStream(&config);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    LONGS_EQUAL(1, CapturedErrorCount);
    LONGS_EQUAL(SOLIDSYSLOG_SEVERITY_ERROR, LastCapturedError.Severity);
    POINTERS_EQUAL(&SolidSyslogMbedTlsStreamErrorSource, LastCapturedError.Source);
    UNSIGNED_LONGS_EQUAL(SOLIDSYSLOG_CAT_BAD_CONFIG, LastCapturedError.Category);
    LONGS_EQUAL(SOLIDSYSLOG_TLS_STREAM_ERROR_NO_PEER_AUTHORISATION, LastCapturedError.Detail);
}

TEST(SolidSyslogMbedTlsStreamIntegration, HandshakeFailsWhenServerCertHasExpired)

{
    struct MbedTlsTestCert expiredCert = {};
    CreateServerCertValidBetween("20240101000000", "20240102000000", &expiredCert);

    struct SolidSyslogStream* transport = StartServerWithCert(&expiredCert);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    tlsStream = CreateTlsStream(&config);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_EXPIRED);

    MbedTlsTestCert_Destroy(&expiredCert);
}

TEST(SolidSyslogMbedTlsStreamIntegration, HandshakeFailsWhenServerCertIsNotYetValid)

{
    struct MbedTlsTestCert futureCert = {};
    CreateServerCertValidBetween("20980101000000", "20990101000000", &futureCert);

    struct SolidSyslogStream* transport = StartServerWithCert(&futureCert);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    tlsStream = CreateTlsStream(&config);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_NOT_YET_VALID);

    MbedTlsTestCert_Destroy(&futureCert);
}

TEST(SolidSyslogMbedTlsStreamIntegration, MutualTlsHandshakeSucceedsWithClientCertSignedByTrustedCa)

{
    /* Build per-test mTLS material: a client CA + a leaf cert signed by it.
     * Server is told to require + verify client certs against this CA. */
    struct MbedTlsTestCert clientCa = {};
    struct MbedTlsTestCertConfig clientCaConfig = {};
    clientCaConfig.SubjectName = "CN=Test Client CA";
    clientCaConfig.IsCa = 1;
    MbedTlsTestCert_Create(&clientCaConfig, &clientCa, &rng);
    struct MbedTlsTestCert clientCert = {};
    CreateClientIdentitySignedBy(&clientCa, &clientCert);

    struct SolidSyslogStream* transport = StartServerRequiringClientCa(&serverCert, &clientCa);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    credsConfig.ClientCertChain = &clientCert.Cert;
    credsConfig.ClientKey = &clientCert.Key;
    tlsStream = CreateTlsStream(&config);

    bool opened = SolidSyslogStream_Open(tlsStream, addr);

    CHECK_TRUE_TEXT(opened, "client-side mTLS Open should succeed against a server trusting the client CA");
    CHECK_TRUE_TEXT(
        MbedTlsTestServer_JoinAndHandshakeSucceeded(server),
        "server-side mTLS handshake should mirror the client's success"
    );

    MbedTlsTestCert_Destroy(&clientCert);
    MbedTlsTestCert_Destroy(&clientCa);
}

TEST(SolidSyslogMbedTlsStreamIntegration, MutualTlsHandshakeRejectedWhenClientSendsNoCert)

{
    /* Server requires a client cert but the integrator hasn't opted in to
     * mTLS - ClientCertChain / ClientKey are NULL. Server-side verify must
     * fail and the client's Open must return false. */
    struct MbedTlsTestCert clientCa = {};
    struct MbedTlsTestCertConfig clientCaConfig = {};
    clientCaConfig.SubjectName = "CN=Test Client CA";
    clientCaConfig.IsCa = 1;
    MbedTlsTestCert_Create(&clientCaConfig, &clientCa, &rng);

    struct SolidSyslogStream* transport = StartServerRequiringClientCa(&serverCert, &clientCa);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    tlsStream = CreateTlsStream(&config);

    bool opened = SolidSyslogStream_Open(tlsStream, addr);

    CHECK_FALSE_TEXT(opened, "mTLS handshake must fail when the client does not present a cert");

    MbedTlsTestCert_Destroy(&clientCa);
}

TEST(SolidSyslogMbedTlsStreamIntegration, MutualTlsHandshakeRejectedWhenClientCertSignedByUntrustedCa)

{
    /* Client cert is signed by a CA the server doesn't trust. Server-side
     * chain validation fails and Open returns false on the client. */
    struct MbedTlsTestCert trustedClientCa = {};
    struct MbedTlsTestCertConfig trustedConfig = {};
    trustedConfig.SubjectName = "CN=Trusted Client CA";
    trustedConfig.IsCa = 1;
    MbedTlsTestCert_Create(&trustedConfig, &trustedClientCa, &rng);

    struct MbedTlsTestCert untrustedClientCa = {};
    struct MbedTlsTestCertConfig untrustedConfig = {};
    untrustedConfig.SubjectName = "CN=Untrusted Client CA";
    untrustedConfig.IsCa = 1;
    MbedTlsTestCert_Create(&untrustedConfig, &untrustedClientCa, &rng);

    /* Client cert is signed by the *untrusted* CA - server only trusts
     * trustedClientCa, so verify will reject this chain. */
    struct MbedTlsTestCert clientCert = {};
    CreateClientIdentitySignedBy(&untrustedClientCa, &clientCert);

    struct SolidSyslogStream* transport = StartServerRequiringClientCa(&serverCert, &trustedClientCa);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    credsConfig.ClientCertChain = &clientCert.Cert;
    credsConfig.ClientKey = &clientCert.Key;
    tlsStream = CreateTlsStream(&config);

    bool opened = SolidSyslogStream_Open(tlsStream, addr);

    CHECK_FALSE_TEXT(opened, "mTLS handshake must fail when the client cert chains to an untrusted CA");

    MbedTlsTestCert_Destroy(&clientCert);
    MbedTlsTestCert_Destroy(&untrustedClientCa);
    MbedTlsTestCert_Destroy(&trustedClientCa);
}

TEST(SolidSyslogMbedTlsStreamIntegration, BinaryLinksAgainstRealLibMbedTls)

{
    /* mbedtls_version_get_number() is a constant, side-effect-free symbol
     * present in every mbedTLS build - a successful link plus a return
     * value matching the expected major version (3.x) confirms the
     * integration scaffold pulls in the real library, not a fake. */
    const unsigned int major = (mbedtls_version_get_number() >> 24) & 0xFFU;
    LONGS_EQUAL(3, major);
}

/* -------------------------------------------------------------------------
 * Certificate fingerprint authorisation (RFC 5425 4.2.2).
 * ------------------------------------------------------------------------- */

/* A pin no certificate will ever match. */
static const char* const UNMATCHABLE_PIN = "sha-256:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
                                           "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";

TEST(SolidSyslogMbedTlsStreamIntegration, HandshakeSucceedsWhenAPinIsTheOnlyThingAuthorisingTheServer)
{
    struct SolidSyslogStream* transport = StartServerWithCert(&serverCert);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    credsConfig.CaChain = nullptr;
    PinCertificate(&serverCert, "sha-256");
    tlsStream = CreateTlsStream(&config);

    CHECK_TRUE(SolidSyslogStream_Open(tlsStream, addr));
}

TEST(SolidSyslogMbedTlsStreamIntegration, HandshakeRejectedWhenTheServerCertMatchesNoPin)
{
    struct SolidSyslogStream* transport = StartServerWithCert(&serverCert);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    credsConfig.CaChain = nullptr;
    PinLiterally(UNMATCHABLE_PIN);
    tlsStream = CreateTlsStream(&config);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_FINGERPRINT_MISMATCHED);
}

TEST(SolidSyslogMbedTlsStreamIntegration, HandshakeRejectedWhenTheServerCertIsExpiredEvenThoughItsPinMatches)
{
    struct MbedTlsTestCert expiredCert = {};
    CreateServerCertValidBetween("20200101000000", "20200102000000", &expiredCert);

    struct SolidSyslogStream* transport = StartServerWithCert(&expiredCert);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    credsConfig.CaChain = nullptr;
    PinCertificate(&expiredCert, "sha-256");
    tlsStream = CreateTlsStream(&config);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_EXPIRED);

    MbedTlsTestCert_Destroy(&expiredCert);
}

/* Mbed TLS merges every certificate's flags into one verdict, so the chain
   objection raised above the leaf must be cleared there too. */
TEST(SolidSyslogMbedTlsStreamIntegration, HandshakeSucceedsWhenAPinAuthorisesALeafPresentedWithItsIssuer)
{
    struct SolidSyslogStream* transport = StartServerPresentingItsIssuer(&serverCert);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    credsConfig.CaChain = nullptr;
    PinCertificate(&serverCert, "sha-256");
    tlsStream = CreateTlsStream(&config);

    CHECK_TRUE(SolidSyslogStream_Open(tlsStream, addr));
}

TEST(SolidSyslogMbedTlsStreamIntegration, HandshakeRejectedWhenALeafPresentedWithItsIssuerMatchesNoPin)
{
    struct SolidSyslogStream* transport = StartServerPresentingItsIssuer(&serverCert);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    credsConfig.CaChain = nullptr;
    PinLiterally(UNMATCHABLE_PIN);
    tlsStream = CreateTlsStream(&config);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_FINGERPRINT_MISMATCHED);
}

TEST(SolidSyslogMbedTlsStreamIntegration, HandshakeSucceedsWhenTrustAnchorsAndAMatchingPinAgree)
{
    struct SolidSyslogStream* transport = StartServerWithCert(&serverCert);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    PinCertificate(&serverCert, "sha-256");
    tlsStream = CreateTlsStream(&config);

    CHECK_TRUE(SolidSyslogStream_Open(tlsStream, addr));
}

TEST(SolidSyslogMbedTlsStreamIntegration, HandshakeRejectedWhenTheChainIsTrustedButNoPinMatches)
{
    struct SolidSyslogStream* transport = StartServerWithCert(&serverCert);
    struct SolidSyslogMbedTlsStreamConfig config = BuildBaseConfig(transport);
    PinLiterally(UNMATCHABLE_PIN);
    tlsStream = CreateTlsStream(&config);

    CHECK_FALSE(SolidSyslogStream_Open(tlsStream, addr));
    CHECK_REFUSAL_REPORTED(SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_FINGERPRINT_MISMATCHED);
}
