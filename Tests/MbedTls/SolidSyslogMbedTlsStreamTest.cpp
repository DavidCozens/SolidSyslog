#include "CppUTest/TestHarness.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"

extern "C"
{
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <stdint.h>

#include "ErrorHandlerFake.h"
#include "MbedTlsCredentialsFake.h"
#include "MbedTlsFake.h"
#include "SolidSyslogMbedTlsCredentialsDefinition.h"
#include "SolidSyslogMbedTlsStream.h"
#include "SolidSyslogMbedTlsStreamErrors.h"
#include "SolidSyslogPrival.h"
#include "AddressFake.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogTunables.h"
#include "StreamFake.h"
}

#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogTlsStreamCategories.h"
#include "TestUtils.h"

using namespace CososoTesting;

#define CHECK_OPEN_UNWOUND_WITH_SEVERITY(transport, expectedSeverity, expectedCategory, expectedCode) \
    {                                                                                                 \
        LONGS_EQUAL(1, StreamFake_CloseCallCount(transport));                                         \
        LONGS_EQUAL(1, MbedTlsFake_SslFreeCallCount());                                               \
        LONGS_EQUAL(1, MbedTlsFake_SslConfigFreeCallCount());                                         \
        CHECK_ERROR_REPORTED_ONCE(                                                                    \
            (expectedSeverity),                                                                       \
            &SolidSyslogMbedTlsStreamErrorSource,                                                     \
            (expectedCategory),                                                                       \
            (expectedCode)                                                                            \
        );                                                                                            \
    }

#define CHECK_OPEN_UNWOUND_WITH_ERROR(transport, expectedCategory, expectedCode) \
    CHECK_OPEN_UNWOUND_WITH_SEVERITY(transport, SOLIDSYSLOG_SEVERITY_ERROR, expectedCategory, expectedCode)

/* Records what mbedTLS had already done by the time the credentials were told
   the window had closed. */
static int SslConfigFreesSeenAtRelease;

extern "C" void CaptureSslConfigFreesAtRelease(void)
{
    SslConfigFreesSeenAtRelease = MbedTlsFake_SslConfigFreeCallCount();
}

static const unsigned char TEST_SHA256_DIGEST[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                                                     0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                                     0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

/* One RFC 5425 4.2.2 pin and the digest that matches it. */
static const char* const TEST_SHA256_PINS[] = {
    "sha-256:00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F"
};

static int NoOpSleepCallCount;
static int g_lastSleepMs;

static void NoOpSleep(int milliseconds)
{
    NoOpSleepCallCount++;
    g_lastSleepMs = milliseconds;
}

namespace
{
int FakeGetHandshakeTimeoutMs_CallCount = 0;
void* FakeGetHandshakeTimeoutMs_LastContext = nullptr;
uint32_t FakeGetHandshakeTimeoutMs_ReturnValue = SOLIDSYSLOG_TLS_HANDSHAKE_TIMEOUT_MS;

void FakeGetHandshakeTimeoutMs_Reset()
{
    FakeGetHandshakeTimeoutMs_CallCount = 0;
    FakeGetHandshakeTimeoutMs_LastContext = reinterpret_cast<void*>(0x1U); /* sentinel - overwritten on first call */
    FakeGetHandshakeTimeoutMs_ReturnValue = SOLIDSYSLOG_TLS_HANDSHAKE_TIMEOUT_MS;
}

extern "C" uint32_t FakeGetHandshakeTimeoutMs(void* context)
{
    FakeGetHandshakeTimeoutMs_CallCount++;
    FakeGetHandshakeTimeoutMs_LastContext = context;
    return FakeGetHandshakeTimeoutMs_ReturnValue;
}

/* Stands in for whatever the integrator bumps when the credentials or the
 * expected peer name change. */
uint32_t FakeVersion_ReturnValue = 0;
void* FakeVersion_LastContext = nullptr;

void FakeVersion_Reset()
{
    FakeVersion_ReturnValue = 0;
    FakeVersion_LastContext = reinterpret_cast<void*>(0x1U); /* sentinel - overwritten on first call */
}

extern "C" uint32_t FakeVersion(void* context)
{
    FakeVersion_LastContext = context;
    return FakeVersion_ReturnValue;
}

/* The TLS profile the stream pulls at Open. Tests set the fields they care
 * about; anything left alone is what an integrator would leave to the library. */
struct SolidSyslogMbedTlsProfile FakeProfile_Value;
int FakeProfile_CallCount = 0;
void* FakeProfile_LastContext = nullptr;

void FakeProfile_Reset()
{
    FakeProfile_Value = {};
    FakeProfile_CallCount = 0;
    FakeProfile_LastContext = reinterpret_cast<void*>(0x1U); /* sentinel - overwritten on first call */
}

extern "C" void FakeProfile(struct SolidSyslogMbedTlsProfile* profile, void* context)
{
    FakeProfile_CallCount++;
    FakeProfile_LastContext = context;
    *profile = FakeProfile_Value;
}
} // namespace

// clang-format off
TEST_GROUP(SolidSyslogMbedTlsStream)
{
    mbedtls_ctr_drbg_context             rng       = {};
    struct SolidSyslogStream*            transport = nullptr;
    struct SolidSyslogStream*            handle    = nullptr;
    struct SolidSyslogMbedTlsStreamConfig config   = {};
    struct SolidSyslogAddress*           addr      = nullptr;

    void setup() override
    {
        MbedTlsFake_Reset();
        MbedTlsCredentialsFake_Reset();
        ErrorHandlerFake_Install(nullptr);
        FakeGetHandshakeTimeoutMs_Reset();
        FakeVersion_Reset();
        FakeProfile_Reset();
        NoOpSleepCallCount = 0;
        g_lastSleepMs = 0;
        transport = StreamFake_Create();
        config.Transport = transport;
        config.Sleep = NoOpSleep;
        config.Rng = &rng;
        config.Credentials = MbedTlsCredentialsFake_Get();
        config.Profile = FakeProfile;
        handle = SolidSyslogMbedTlsStream_Create(&config);
        addr = AddressFake_Get();
    }

    /* Pin the peer with a digest that matches the pin. Trust anchors are
       installed unless a test clears them. */
    static void GivenAPinnedPeer()
    {
        MbedTlsCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);
        MbedTlsFake_SetDigest(TEST_SHA256_DIGEST, sizeof(TEST_SHA256_DIGEST));
    }

    /* The same peer, authorised by its pin alone. */
    static void GivenAPinnedPeerWithoutTrustAnchors()
    {
        MbedTlsCredentialsFake_SetTrustAnchorsInstalled(false);
        GivenAPinnedPeer();
    }

    /* Drive the verify callback for the certificate at `depth`, starting from
       `flags`, and return what the callback left there. The callback always
       reports success; what it decides is in the flags. */
    [[nodiscard]] uint32_t OpenThenVerifyAt(int depth, uint32_t flags) const
    {
        SolidSyslogStream_Open(handle, addr);
        auto* verify = MbedTlsFake_LastSslConfVerifyCallback();
        CHECK_TRUE_TEXT(verify != nullptr, "the stream registered no verify callback");
        if (verify != nullptr)
        {
            LONGS_EQUAL(0, verify(handle, MbedTlsFake_Certificate(), depth, &flags));
        }
        return flags;
    }

    /* Replaces the default Null-getter handle with one that uses the fake
     * handshake-timeout getter. Each test sets only the fake-getter return
     * value (or context) it needs different from the defaults restored in
     * setup(). */
    void RecreateHandleWithFakeHandshakeGetter()
    {
        SolidSyslogMbedTlsStream_Destroy(handle);
        config.GetHandshakeTimeoutMs = FakeGetHandshakeTimeoutMs;
        handle                        = SolidSyslogMbedTlsStream_Create(&config);
    }

    void teardown() override
    {
        SolidSyslogMbedTlsStream_Destroy(handle);
        StreamFake_Destroy(transport);
    }

    /* Tests needing config tweaks (Rng, ServerName, Credentials, ...) call this
     * to release setup()'s pool slot, mutate `config`, then re-Create.
     * Fully resets the fixture (transport, MbedTls fake counters, error
     * handler) so the test body observes counts from this Open onwards
     * only - matters for assertions like CHECK_OPEN_UNWOUND_WITH_ERROR
     * that pin counts at == 1. */
    void ReCreateHandleWithUpdatedConfig()
    {
        SolidSyslogMbedTlsStream_Destroy(handle);
        StreamFake_Destroy(transport);
        MbedTlsFake_Reset();
        MbedTlsCredentialsFake_Reset();
        ErrorHandlerFake_Install(nullptr);
        transport = StreamFake_Create();
        config.Transport = transport;
        handle = SolidSyslogMbedTlsStream_Create(&config);
    }

    /* Arrange mbedtls_ssl_handshake to first emit `wantError`, then succeed on
     * the next call - exercises the bounded handshake retry loop's progress
     * path. mbedTLS returns the error code directly (no get_error indirection). */
    static void ArrangeHandshakeRetryThenSucceed(int wantError)
    {
        int seq[] = {wantError, 0};
        MbedTlsFake_SetSslHandshakeReturnSequence(seq, 2);
    }

    /* Arrange mbedtls_ssl_handshake to fail with `errorCode` on every call -
     * used both for the persistent-WANT (budget-exhausted) and hard-error paths. */
    static void ArrangePersistentHandshakeError(int errorCode)
    {
        int seq[] = {errorCode};
        MbedTlsFake_SetSslHandshakeReturnSequence(seq, 1);
    }

    /* Arrange a peer whose certificate mbedTLS refused for `flags`. ServerName is
     * set so the refusal is the only error source - a NULL one would also emit
     * the unverified-peer WARNING. */
    void ArrangeCertificateVerificationFailure(uint32_t flags)
    {
        FakeProfile_Value.ServerName = "syslog.example.com";
        ReCreateHandleWithUpdatedConfig();
        ArrangePersistentHandshakeError(MBEDTLS_ERR_X509_CERT_VERIFY_FAILED);
        MbedTlsFake_SetSslVerifyResult(flags);
    }
};

// clang-format on

TEST(SolidSyslogMbedTlsStream, OpenDelegatesToInjectedTransport)

{
    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(1, StreamFake_OpenCallCount(transport));
    POINTERS_EQUAL(addr, StreamFake_LastOpenAddr(transport));
}

TEST(SolidSyslogMbedTlsStream, CreateInitialisesSslConfigForSafeFree)

{
    /* Init happens eagerly in Create (via SolidSyslogMbedTlsStream_Initialise) so the
     * symmetric *_free in Close is always safe - whether Open was reached,
     * whether it succeeded, or whether Close is called more than once. */
    LONGS_EQUAL(1, MbedTlsFake_SslConfigInitCallCount());
}

TEST(SolidSyslogMbedTlsStream, OpenAppliesClientStreamDefaultsToSslConfig)

{
    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(1, MbedTlsFake_SslConfigDefaultsCallCount());
    POINTERS_EQUAL(MbedTlsFake_LastSslConfigInitArg(), MbedTlsFake_LastSslConfigDefaultsConfigArg());
    LONGS_EQUAL(MBEDTLS_SSL_IS_CLIENT, MbedTlsFake_LastSslConfigDefaultsEndpoint());
    LONGS_EQUAL(MBEDTLS_SSL_TRANSPORT_STREAM, MbedTlsFake_LastSslConfigDefaultsTransport());
    LONGS_EQUAL(MBEDTLS_SSL_PRESET_DEFAULT, MbedTlsFake_LastSslConfigDefaultsPreset());
}

TEST(SolidSyslogMbedTlsStream, CreateInitialisesSslContextForSafeFree)

{
    /* Same eager-init invariant as the SslConfig case above. */
    LONGS_EQUAL(1, MbedTlsFake_SslInitCallCount());
}

TEST(SolidSyslogMbedTlsStream, OpenBindsContextToConfig)

{
    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(1, MbedTlsFake_SslSetupCallCount());
    POINTERS_EQUAL(MbedTlsFake_LastSslInitArg(), MbedTlsFake_LastSslSetupContextArg());
    POINTERS_EQUAL(MbedTlsFake_LastSslConfigInitArg(), MbedTlsFake_LastSslSetupConfigArg());
}

TEST(SolidSyslogMbedTlsStream, OpenWiresBioWithNonNullSendRecvAndNullRecvTimeout)

{
    /* mbedTLS's set_bio takes both a recv and a recv_timeout callback;
     * we install the former (non-blocking would-block via WANT_READ) and
     * leave the latter NULL since we manage timeouts via PerformHandshake's
     * Sleep-based budget rather than mbedTLS's internal timer. */
    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(1, MbedTlsFake_SslSetBioCallCount());
    POINTERS_EQUAL(MbedTlsFake_LastSslInitArg(), MbedTlsFake_LastSslSetBioContextArg());
    CHECK(MbedTlsFake_LastSslSetBioPBioArg() != nullptr);
    CHECK(MbedTlsFake_LastSslSetBioSendCallback() != nullptr);
    CHECK(MbedTlsFake_LastSslSetBioRecvCallback() != nullptr);
    POINTERS_EQUAL(nullptr, (void*) MbedTlsFake_LastSslSetBioRecvTimeoutCallback());
}

TEST(SolidSyslogMbedTlsStream, OpenDrivesHandshakeOnTheSslContext)

{
    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(1, MbedTlsFake_SslHandshakeCallCount());
    POINTERS_EQUAL(MbedTlsFake_LastSslInitArg(), MbedTlsFake_LastSslHandshakeArg());
}

TEST(SolidSyslogMbedTlsStream, OpenReturnsTrueWhenHandshakeSucceeds)

{
    MbedTlsFake_SetSslHandshakeReturn(0);

    CHECK_TRUE(SolidSyslogStream_Open(handle, addr));
}

TEST(SolidSyslogMbedTlsStream, OpenReturnsFalseWhenHandshakeFails)

{
    MbedTlsFake_SetSslHandshakeReturn(-1);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
}

/* -------------------------------------------------------------------------
 * Bounded handshake retry loop. mbedtls_ssl_handshake under non-blocking
 * transport will emit MBEDTLS_ERR_SSL_WANT_READ / WANT_WRITE between RTTs;
 * the loop must drive it to completion within a bounded budget so a wedged
 * peer doesn't burn the service thread indefinitely. Mirrors the OpenSSL
 * OpenSslStream pattern (Tests/SolidSyslogOpenSslStreamTest.cpp).
 * ------------------------------------------------------------------------- */

TEST(SolidSyslogMbedTlsStream, OpenRetriesHandshakeOnWantRead)

{
    ArrangeHandshakeRetryThenSucceed(MBEDTLS_ERR_SSL_WANT_READ);

    CHECK_TRUE(SolidSyslogStream_Open(handle, addr));
    CALLED_FAKE(MbedTlsFake_SslHandshake, TWICE);
}

TEST(SolidSyslogMbedTlsStream, OpenSleepsBetweenHandshakeRetries)

{
    ArrangeHandshakeRetryThenSucceed(MBEDTLS_ERR_SSL_WANT_READ);

    SolidSyslogStream_Open(handle, addr);
    CALLED_FUNCTION(NoOpSleep, ONCE);
}

TEST(SolidSyslogMbedTlsStream, OpenRetriesHandshakeOnWantWrite)

{
    /* WANT_WRITE arises when mbedTLS needs to send (e.g. ClientFinished
     * under non-blocking transport with a temporarily-full send buffer).
     * Same retry treatment as WANT_READ. */
    ArrangeHandshakeRetryThenSucceed(MBEDTLS_ERR_SSL_WANT_WRITE);

    CHECK_TRUE(SolidSyslogStream_Open(handle, addr));
    CALLED_FAKE(MbedTlsFake_SslHandshake, TWICE);
}

TEST(SolidSyslogMbedTlsStream, OpenClosesTransportAndFreesSslStateWhenHandshakeBudgetExhausts)

{
    /* ServerName set so the handshake timeout is the only error source (a NULL
     * ServerName would also emit the unverified-peer WARNING).
     * mbedtls_ssl_handshake always returns WANT_READ - handshake never makes
     * progress, so the bounded budget should expire and Open returns false. */
    FakeProfile_Value.ServerName = "syslog.example.com";
    ReCreateHandleWithUpdatedConfig();
    ArrangePersistentHandshakeError(MBEDTLS_ERR_SSL_WANT_READ);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_OPEN_UNWOUND_WITH_SEVERITY(
        transport,
        SOLIDSYSLOG_SEVERITY_WARNING,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_HANDSHAKE_TIMEOUT
    );
}

TEST(SolidSyslogMbedTlsStream, OpenInvokesConfiguredHandshakeTimeoutGetter)

{
    RecreateHandleWithFakeHandshakeGetter();
    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(1, FakeGetHandshakeTimeoutMs_CallCount);
}

TEST(SolidSyslogMbedTlsStream, OpenUsesGetterReturnValueAsHandshakeBudget)

{
    /* 5 ms budget against the 1 ms poll interval -> loop should sleep 5 times
       before declaring HANDSHAKE_TIMEOUT and unwinding. */
    FakeGetHandshakeTimeoutMs_ReturnValue = 5U;
    RecreateHandleWithFakeHandshakeGetter();
    ArrangePersistentHandshakeError(MBEDTLS_ERR_SSL_WANT_READ);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));

    LONGS_EQUAL(5, NoOpSleepCallCount);
}

TEST(SolidSyslogMbedTlsStream, GetterReceivesNullContextWhenContextNotConfigured)

{
    RecreateHandleWithFakeHandshakeGetter();
    SolidSyslogStream_Open(handle, addr);

    POINTERS_EQUAL(nullptr, FakeGetHandshakeTimeoutMs_LastContext);
}

TEST(SolidSyslogMbedTlsStream, SecondOpenAfterFailedFirstOpenSucceeds)

{
    /* The recovery contract that the per-failure-point unwinds enable: once
     * Open's failure tail Closes the transport and frees the SSL state, the
     * next Open is a clean Open-Close-Open cycle on the transport - Connected
     * goes false, StreamSender's next reconnect tick re-enters, and the
     * second handshake completes. Without the unwind, the inner transport
     * would stay open and PosixTcpStream_Open would clobber its fd. */
    int handshakeSequence[] = {MBEDTLS_ERR_SSL_BAD_INPUT_DATA, 0};
    MbedTlsFake_SetSslHandshakeReturnSequence(handshakeSequence, 2);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_TRUE(SolidSyslogStream_Open(handle, addr));
    LONGS_EQUAL(2, StreamFake_OpenCallCount(transport));
    LONGS_EQUAL(1, StreamFake_CloseCallCount(transport));
}

TEST(SolidSyslogMbedTlsStream, OpenClosesTransportAndFreesSslStateWhenHandshakeFailsHard)

{
    /* ServerName set so the handshake hard error is the only error source.
     * Non-WANT error (e.g. a verify/connection failure) is fail-fast - no
     * retry budget burn, no Sleep. */
    FakeProfile_Value.ServerName = "syslog.example.com";
    ReCreateHandleWithUpdatedConfig();
    ArrangePersistentHandshakeError(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CALLED_FAKE(MbedTlsFake_SslHandshake, ONCE);
    CALLED_FUNCTION(NoOpSleep, NEVER);
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_HANDSHAKE_REJECTED
    );
}

TEST(SolidSyslogMbedTlsStream, OpenReportsThatThePeerCertificateHasExpired)
{
    ArrangeCertificateVerificationFailure(MBEDTLS_X509_BADCERT_EXPIRED);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_EXPIRED
    );
}

TEST(SolidSyslogMbedTlsStream, OpenReportsThatThePeerCertificateIsNotYetValid)
{
    ArrangeCertificateVerificationFailure(MBEDTLS_X509_BADCERT_FUTURE);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_NOT_YET_VALID
    );
}

TEST(SolidSyslogMbedTlsStream, OpenReportsThatThePeerNameDidNotMatch)
{
    ArrangeCertificateVerificationFailure(MBEDTLS_X509_BADCERT_CN_MISMATCH);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_NAME_MISMATCHED
    );
}

TEST(SolidSyslogMbedTlsStream, OpenReportsThatThePeerCertificateIsNotTrusted)
{
    ArrangeCertificateVerificationFailure(MBEDTLS_X509_BADCERT_NOT_TRUSTED);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_UNTRUSTED
    );
}

/* mbedTLS accumulates every fault it found into one bitmask, so a compound
 * verdict has to resolve to a single reason. An untrusted chain wins, which is
 * the reason a library that stops at the first failure reaches first - path
 * building runs before any date is examined - so both TLS adapters agree on a
 * compound fault as well as on a single one. */
TEST(SolidSyslogMbedTlsStream, OpenReportsAnUntrustedChainAheadOfTheDatesOnIt)
{
    ArrangeCertificateVerificationFailure(MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_EXPIRED);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_UNTRUSTED
    );
}

/* A verification failure with no name of its own - here a key too weak for the
 * profile - still tells the integrator the certificate is the fault rather than
 * the network, which is the whole point of naming the check. */
TEST(SolidSyslogMbedTlsStream, OpenReportsAVerificationFailureItCannotNameAsUntrusted)
{
    ArrangeCertificateVerificationFailure(MBEDTLS_X509_BADCERT_BAD_KEY);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_UNTRUSTED
    );
}

/* mbedTLS answers 0xFFFFFFFF when it has no verdict to give. Every flag reads as
 * set, so it must be recognised rather than mapped, or a refusal with no
 * certificate behind it would be reported as an untrusted one. */
TEST(SolidSyslogMbedTlsStream, OpenReportsAPlainRejectionWhenNoVerdictIsAvailable)
{
    /* Arranged by hand rather than through ArrangeCertificateVerificationFailure:
     * a verdict is unavailable when certificate verification never ran, which
     * pairs with a handshake that failed for some other reason. */
    FakeProfile_Value.ServerName = "syslog.example.com";
    ReCreateHandleWithUpdatedConfig();
    ArrangePersistentHandshakeError(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    MbedTlsFake_SetSslVerifyResult(0xFFFFFFFFU);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_HANDSHAKE_REJECTED
    );
}

/* -------------------------------------------------------------------------
 * Open failure unwind + error reporting (S26.02). Every failure path after
 * the first allocating operation must close the inner transport, free both
 * mbedTLS structs, and emit the matching typed error code so the integrator
 * sees a protocol-level diagnostic.
 * ------------------------------------------------------------------------- */

TEST(SolidSyslogMbedTlsStream, OpenClosesTransportAndFreesSslStateWhenSslConfigDefaultsFails)

{
    MbedTlsFake_SetSslConfigDefaultsReturn(-1);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_DEFAULTS_NOT_APPLIED
    );
}

TEST(SolidSyslogMbedTlsStream, OpenClosesTransportAndFreesSslStateWhenSslSetupFails)

{
    MbedTlsFake_SetSslSetupReturn(-1);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_SESSION_INIT_FAILED
    );
}

TEST(SolidSyslogMbedTlsStream, OpenClosesTransportAndFreesSslStateWhenSetHostnameFails)

{
    /* ServerName must be set for ConfigureExpectedHostname to invoke
     * mbedtls_ssl_set_hostname - otherwise the helper short-circuits to true. */
    FakeProfile_Value.ServerName = "syslog.example.com";
    ReCreateHandleWithUpdatedConfig();
    MbedTlsFake_SetSslSetHostnameReturn(-1);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_OPEN_UNWOUND_WITH_SEVERITY(
        transport,
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_SERVER_NAME_NOT_SET
    );
}

TEST(SolidSyslogMbedTlsStream, SendForwardsBufferToSslWrite)

{
    const unsigned char payload[] = {0x10, 0x20, 0x30};

    SolidSyslogStream_Send(handle, payload, sizeof(payload));

    LONGS_EQUAL(1, MbedTlsFake_SslWriteCallCount());
    POINTERS_EQUAL(payload, MbedTlsFake_LastSslWriteBufArg());
    LONGS_EQUAL(sizeof(payload), MbedTlsFake_LastSslWriteLenArg());
}

TEST(SolidSyslogMbedTlsStream, SendReturnsTrueWhenSslWriteWritesAllBytes)

{
    const unsigned char payload[] = {0x10, 0x20, 0x30};
    MbedTlsFake_SetSslWriteReturn((int) sizeof(payload));

    CHECK_TRUE(SolidSyslogStream_Send(handle, payload, sizeof(payload)));
}

TEST(SolidSyslogMbedTlsStream, SendReturnsFalseWhenSslWriteWritesPartial)

{
    const unsigned char payload[] = {0x10, 0x20, 0x30};
    MbedTlsFake_SetSslWriteReturn(1);

    CHECK_FALSE(SolidSyslogStream_Send(handle, payload, sizeof(payload)));
}

TEST(SolidSyslogMbedTlsStream, SendReturnsFalseWhenSslWriteFails)

{
    const unsigned char payload[] = {0x10, 0x20, 0x30};
    MbedTlsFake_SetSslWriteReturn(-1);

    CHECK_FALSE(SolidSyslogStream_Send(handle, payload, sizeof(payload)));
}

TEST(SolidSyslogMbedTlsStream, SendClosesSslAndTransportOnWriteFailure)

{
    /* Fail-fast: a TLS-level write failure means the session state is
     * unrecoverable. Mirror the OpenSslStream contract - close internally
     * so the StreamSender reconnect path runs on the next tick. */
    const unsigned char payload[] = {0x10, 0x20, 0x30};
    MbedTlsFake_SetSslWriteReturn(-1);

    SolidSyslogStream_Send(handle, payload, sizeof(payload));

    LONGS_EQUAL(1, MbedTlsFake_SslFreeCallCount());
    LONGS_EQUAL(1, StreamFake_CloseCallCount(transport));
}

TEST(SolidSyslogMbedTlsStream, SendClosesSslAndTransportOnShortWrite)

{
    /* mbedtls_ssl_write returning fewer bytes than requested is treated the
     * same as outright failure - the application boundary requires
     * all-or-nothing writes (syslog framing). */
    const unsigned char payload[] = {0x10, 0x20, 0x30};
    MbedTlsFake_SetSslWriteReturn(2); /* asked for 3, got 2 */

    SolidSyslogStream_Send(handle, payload, sizeof(payload));

    LONGS_EQUAL(1, MbedTlsFake_SslFreeCallCount());
    LONGS_EQUAL(1, StreamFake_CloseCallCount(transport));
}

TEST(SolidSyslogMbedTlsStream, ReadForwardsBufferToSslRead)

{
    unsigned char buffer[8];
    MbedTlsFake_SetSslReadReturn(3);

    SolidSyslogStream_Read(handle, buffer, sizeof(buffer));

    LONGS_EQUAL(1, MbedTlsFake_SslReadCallCount());
    POINTERS_EQUAL(buffer, MbedTlsFake_LastSslReadBufArg());
    LONGS_EQUAL(sizeof(buffer), MbedTlsFake_LastSslReadLenArg());
}

TEST(SolidSyslogMbedTlsStream, ReadReturnsByteCountWhenSslReadReturnsPositive)

{
    unsigned char buffer[8];
    MbedTlsFake_SetSslReadReturn(5);

    LONGS_EQUAL(5, SolidSyslogStream_Read(handle, buffer, sizeof(buffer)));
}

TEST(SolidSyslogMbedTlsStream, ReadReturnsZeroOnWantRead)

{
    unsigned char buffer[8];
    MbedTlsFake_SetSslReadReturn(MBEDTLS_ERR_SSL_WANT_READ);

    LONGS_EQUAL(0, SolidSyslogStream_Read(handle, buffer, sizeof(buffer)));
}

TEST(SolidSyslogMbedTlsStream, ReadReturnsNegativeOnSslReadError)

{
    unsigned char buffer[8];
    MbedTlsFake_SetSslReadReturn(-1);

    CHECK(SolidSyslogStream_Read(handle, buffer, sizeof(buffer)) < 0);
}

TEST(SolidSyslogMbedTlsStream, ReadClosesSslAndTransportOnHardError)

{
    /* Same fail-fast contract as Send: any read result other than positive
     * bytes or WANT_READ (e.g. peer close_notify, fatal alert, transport
     * error) closes internally so the next tick reopens. */
    unsigned char buffer[8];
    MbedTlsFake_SetSslReadReturn(-1);

    SolidSyslogStream_Read(handle, buffer, sizeof(buffer));

    LONGS_EQUAL(1, MbedTlsFake_SslFreeCallCount());
    LONGS_EQUAL(1, StreamFake_CloseCallCount(transport));
}

TEST(SolidSyslogMbedTlsStream, ReadDoesNotCloseOnWantRead)

{
    /* WANT_READ is steady-state would-block, not a connection failure -
     * leave the session intact so the caller can retry. */
    unsigned char buffer[8];
    MbedTlsFake_SetSslReadReturn(MBEDTLS_ERR_SSL_WANT_READ);

    SolidSyslogStream_Read(handle, buffer, sizeof(buffer));

    LONGS_EQUAL(0, MbedTlsFake_SslFreeCallCount());
    LONGS_EQUAL(0, StreamFake_CloseCallCount(transport));
}

TEST(SolidSyslogMbedTlsStream, CloseAfterInternalCloseFromSendFailureDoesNotDoubleFree)

{
    /* Send and Read may close internally on failure; the subsequent Close
     * from the StreamSender reconnect path or Destroy must not crash or
     * double-free. mbedTLS's freed-equivalent zeroed state makes this safe. */
    const unsigned char payload[] = {0x10};
    MbedTlsFake_SetSslWriteReturn(-1);
    SolidSyslogStream_Send(handle, payload, sizeof(payload)); /* internal close */

    SolidSyslogStream_Close(handle); /* second close - must be safe */

    /* Exactly one of each free per real session. The teardown's Destroy
     * will add a third pair when this test ends, but that's outside the
     * assertion window. */
    LONGS_EQUAL(2, MbedTlsFake_SslFreeCallCount());
    LONGS_EQUAL(2, MbedTlsFake_SslConfigFreeCallCount());
}

TEST(SolidSyslogMbedTlsStream, CloseSendsSslCloseNotifyOnTheSslContextFromOpen)

{
    SolidSyslogStream_Open(handle, addr);

    SolidSyslogStream_Close(handle);

    LONGS_EQUAL(1, MbedTlsFake_SslCloseNotifyCallCount());
    POINTERS_EQUAL(MbedTlsFake_LastSslInitArg(), MbedTlsFake_LastSslCloseNotifyArg());
}

TEST(SolidSyslogMbedTlsStream, CloseFreesSslContextAndSslConfigFromOpen)

{
    SolidSyslogStream_Open(handle, addr);

    SolidSyslogStream_Close(handle);

    LONGS_EQUAL(1, MbedTlsFake_SslFreeCallCount());
    POINTERS_EQUAL(MbedTlsFake_LastSslInitArg(), MbedTlsFake_LastSslFreeArg());
    LONGS_EQUAL(1, MbedTlsFake_SslConfigFreeCallCount());
    POINTERS_EQUAL(MbedTlsFake_LastSslConfigInitArg(), MbedTlsFake_LastSslConfigFreeArg());
}

TEST(SolidSyslogMbedTlsStream, CloseDelegatesToInjectedTransport)

{
    SolidSyslogStream_Close(handle);

    LONGS_EQUAL(1, StreamFake_CloseCallCount(transport));
}

TEST(SolidSyslogMbedTlsStream, BioSendCallbackForwardsBufferToTransport)

{
    SolidSyslogStream_Open(handle, addr);
    auto* bioSend = MbedTlsFake_LastSslSetBioSendCallback();
    void* bioContext = MbedTlsFake_LastSslSetBioPBioArg();
    const unsigned char payload[] = {0xAA, 0xBB, 0xCC};

    int rc = bioSend(bioContext, payload, sizeof(payload));

    LONGS_EQUAL((int) sizeof(payload), rc);
    LONGS_EQUAL(1, StreamFake_SendCallCount(transport));
    POINTERS_EQUAL(payload, StreamFake_LastSendBuf(transport));
    LONGS_EQUAL(sizeof(payload), StreamFake_LastSendSize(transport));
}

TEST(SolidSyslogMbedTlsStream, BioRecvCallbackForwardsBufferToTransport)

{
    SolidSyslogStream_Open(handle, addr);
    auto* bioRecv = MbedTlsFake_LastSslSetBioRecvCallback();
    void* bioContext = MbedTlsFake_LastSslSetBioPBioArg();
    unsigned char buffer[16];
    StreamFake_SetReadReturn(transport, 4);

    int rc = bioRecv(bioContext, buffer, sizeof(buffer));

    LONGS_EQUAL(4, rc);
    LONGS_EQUAL(1, StreamFake_ReadCallCount(transport));
    POINTERS_EQUAL(buffer, StreamFake_LastReadBuf(transport));
    LONGS_EQUAL(sizeof(buffer), StreamFake_LastReadSize(transport));
}

TEST(SolidSyslogMbedTlsStream, BioRecvReturnsWantReadWhenTransportWouldBlock)

{
    /* Stream contract: transport Read returns 0 to signal would-block. mbedTLS
     * needs MBEDTLS_ERR_SSL_WANT_READ to drive its retry loop; any other
     * negative is fatal. Returning -1 (or 0) here would abort the handshake
     * on the first non-blocking poll. */
    SolidSyslogStream_Open(handle, addr);
    auto* bioRecv = MbedTlsFake_LastSslSetBioRecvCallback();
    void* bioContext = MbedTlsFake_LastSslSetBioPBioArg();
    unsigned char buffer[16];
    StreamFake_SetReadReturn(transport, 0);

    int rc = bioRecv(bioContext, buffer, sizeof(buffer));

    LONGS_EQUAL(MBEDTLS_ERR_SSL_WANT_READ, rc);
}

TEST(SolidSyslogMbedTlsStream, BioRecvReturnsFatalWhenTransportFails)

{
    /* Stream contract: negative is fatal. mbedTLS treats any negative other
     * than its own WANT_* sentinels as a transport error and aborts. */
    SolidSyslogStream_Open(handle, addr);
    auto* bioRecv = MbedTlsFake_LastSslSetBioRecvCallback();
    void* bioContext = MbedTlsFake_LastSslSetBioPBioArg();
    unsigned char buffer[16];
    StreamFake_SetReadReturn(transport, -1);

    int rc = bioRecv(bioContext, buffer, sizeof(buffer));

    CHECK_TRUE(rc < 0);
    CHECK_FALSE(rc == MBEDTLS_ERR_SSL_WANT_READ);
}

TEST(SolidSyslogMbedTlsStream, OpenSetsAuthmodeRequired)

{
    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(1, MbedTlsFake_SslConfAuthmodeCallCount());
    POINTERS_EQUAL(MbedTlsFake_LastSslConfigInitArg(), MbedTlsFake_LastSslConfAuthmodeConfigArg());
    LONGS_EQUAL(MBEDTLS_SSL_VERIFY_REQUIRED, MbedTlsFake_LastSslConfAuthmodeArg());
}

// Parity with the OpenSSL adapter's explicit TLS 1.2 floor - the mbedTLS default
// preset can otherwise negotiate down to TLS 1.0/1.1 on permissive builds.
TEST(SolidSyslogMbedTlsStream, OpenPinsMinimumTlsVersionToTls12)

{
    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(MBEDTLS_SSL_VERSION_TLS1_2, MbedTlsFake_ConfMinTlsVersion(MbedTlsFake_LastSslConfigInitArg()));
}

TEST(SolidSyslogMbedTlsStream, OpenWiresRngFromConfigUsingCtrDrbgRandom)

{
    static mbedtls_ctr_drbg_context rngMarker;
    config.Rng = &rngMarker;
    ReCreateHandleWithUpdatedConfig();
    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(1, MbedTlsFake_SslConfRngCallCount());
    POINTERS_EQUAL(MbedTlsFake_LastSslConfigInitArg(), MbedTlsFake_LastSslConfRngConfigArg());
    POINTERS_EQUAL((void*) mbedtls_ctr_drbg_random, (void*) MbedTlsFake_LastSslConfRngFuncArg());
    POINTERS_EQUAL(&rngMarker, MbedTlsFake_LastSslConfRngContextArg());
}

TEST(SolidSyslogMbedTlsStream, OpenSetsHostnameWhenServerNameProvided)

{
    FakeProfile_Value.ServerName = "syslog.example.com";
    ReCreateHandleWithUpdatedConfig();
    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(1, MbedTlsFake_SslSetHostnameCallCount());
    POINTERS_EQUAL(MbedTlsFake_LastSslInitArg(), MbedTlsFake_LastSslSetHostnameContextArg());
    STRCMP_EQUAL("syslog.example.com", MbedTlsFake_LastSslSetHostnameNameArg());
}

TEST(SolidSyslogMbedTlsStream, OpenSkipsHostnameWhenServerNameIsNull)

{
    /* The profile leaves ServerName unset. */
    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(0, MbedTlsFake_SslSetHostnameCallCount());
}

TEST(SolidSyslogMbedTlsStream, OpenWarnsWhenServerNameIsNull)

{
    /* The profile leaves ServerName unset - peer identity is unverified, which
     * the library must surface rather than swallow (S12.28). */
    SolidSyslogStream_Open(handle, addr);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogMbedTlsStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_SERVER_NAME_NOT_SET
    );
}

TEST(SolidSyslogMbedTlsStream, OpenStillConnectsWhenServerNameIsNull)

{
    /* The unverified-peer WARNING is observable but non-fatal - the IP-pinned /
     * closed-network use case must still connect. */
    CHECK_TRUE(SolidSyslogStream_Open(handle, addr));
    LONGS_EQUAL(0, StreamFake_CloseCallCount(transport));
}

TEST(SolidSyslogMbedTlsStream, OpenDoesNotWarnWhenServerNameIsEmpty)

{
    /* Empty string is the deliberate opt-out - no diagnostic. */
    FakeProfile_Value.ServerName = "";
    ReCreateHandleWithUpdatedConfig();
    SolidSyslogStream_Open(handle, addr);

    CALLED_FAKE(ErrorHandlerFake_Handle, NEVER);
}

TEST(SolidSyslogMbedTlsStream, OpenSkipsHostnameSetupWhenServerNameIsEmpty)

{
    FakeProfile_Value.ServerName = "";
    ReCreateHandleWithUpdatedConfig();
    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(0, MbedTlsFake_SslSetHostnameCallCount());
}

TEST(SolidSyslogMbedTlsStream, OpenConnectsWhenServerNameIsEmpty)

{
    FakeProfile_Value.ServerName = "";
    ReCreateHandleWithUpdatedConfig();

    CHECK_TRUE(SolidSyslogStream_Open(handle, addr));
}

/* -------------------------------------------------------------------------
 * Credentials. The stream holds no material of its own: it asks its
 * credentials source to install onto the ssl_config once per connection, and
 * tells it when that connection ends.
 * ------------------------------------------------------------------------- */

TEST(SolidSyslogMbedTlsStream, OpenAsksTheCredentialsToInstallOntoItsSslConfig)
{
    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(1, MbedTlsCredentialsFake_InstallCallCount());
    POINTERS_EQUAL(MbedTlsFake_LastSslConfigInitArg(), MbedTlsCredentialsFake_LastInstallConfig());
}

TEST(SolidSyslogMbedTlsStream, OpenInstallsCredentialsBeforeTheHandshake)
{
    ArrangePersistentHandshakeError(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);

    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(1, MbedTlsCredentialsFake_InstallCallCount());
}

TEST(SolidSyslogMbedTlsStream, OpenFailsWhenTheCredentialsCannotInstall)
{
    MbedTlsCredentialsFake_SetInstallSucceeds(false);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
}

TEST(SolidSyslogMbedTlsStream, OpenClosesTransportAndFreesSslStateWhenTheCredentialsCannotInstall)
{
    MbedTlsCredentialsFake_SetInstallSucceeds(false);

    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(1, StreamFake_CloseCallCount(transport));
    LONGS_EQUAL(1, MbedTlsFake_SslFreeCallCount());
    LONGS_EQUAL(1, MbedTlsFake_SslConfigFreeCallCount());
}

TEST(SolidSyslogMbedTlsStream, OpenDoesNotHandshakeWhenTheCredentialsCannotInstall)
{
    MbedTlsCredentialsFake_SetInstallSucceeds(false);

    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(0, MbedTlsFake_SslHandshakeCallCount());
}

/* Nothing vouches for the peer and nothing pins it, so there is no check the
 * handshake could fail - the connection stops rather than reaching a collector
 * this stream cannot identify. */
TEST(SolidSyslogMbedTlsStream, OpenFailsWhenNothingAuthorisesThePeer)
{
    MbedTlsCredentialsFake_SetTrustAnchorsInstalled(false);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
}

TEST(SolidSyslogMbedTlsStream, OpenReportsThatNothingAuthorisesThePeer)
{
    FakeProfile_Value.ServerName = "";
    ReCreateHandleWithUpdatedConfig();
    MbedTlsCredentialsFake_SetTrustAnchorsInstalled(false);

    SolidSyslogStream_Open(handle, addr);

    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NO_PEER_AUTHORISATION
    );
}

/* RFC 5425 4.2.1 makes a pinned certificate fingerprint sufficient on its own,
 * so a peer with no trust anchors behind it is still authorisable. */
TEST(SolidSyslogMbedTlsStream, OpenConnectsWhenOnlyAFingerprintAuthorisesThePeer)
{
    MbedTlsCredentialsFake_SetTrustAnchorsInstalled(false);
    MbedTlsCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);

    CHECK_TRUE(SolidSyslogStream_Open(handle, addr));
}

TEST(SolidSyslogMbedTlsStream, CloseReleasesTheCredentialsItInstalled)
{
    SolidSyslogStream_Open(handle, addr);

    SolidSyslogStream_Close(handle);

    LONGS_EQUAL(1, MbedTlsCredentialsFake_ReleaseCallCount());
}

/* One Release per Install call, whatever that call returned - which is what
 * spares every backend a rollback path of its own. */
TEST(SolidSyslogMbedTlsStream, AFailedInstallIsStillAnsweredByARelease)
{
    MbedTlsCredentialsFake_SetInstallSucceeds(false);

    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(1, MbedTlsCredentialsFake_ReleaseCallCount());
}

TEST(SolidSyslogMbedTlsStream, AnOpenThatFailedLaterIsStillAnsweredByARelease)
{
    ArrangePersistentHandshakeError(MBEDTLS_ERR_SSL_BAD_INPUT_DATA);

    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(1, MbedTlsCredentialsFake_ReleaseCallCount());
}

TEST(SolidSyslogMbedTlsStream, CloseWithoutAnOpenReleasesNothing)
{
    SolidSyslogStream_Close(handle);

    LONGS_EQUAL(0, MbedTlsCredentialsFake_ReleaseCallCount());
}

TEST(SolidSyslogMbedTlsStream, CloseTwiceReleasesOnlyOnce)
{
    SolidSyslogStream_Open(handle, addr);

    SolidSyslogStream_Close(handle);
    SolidSyslogStream_Close(handle);

    LONGS_EQUAL(1, MbedTlsCredentialsFake_ReleaseCallCount());
}

/* The ssl_config holds pointers into the caller's certificates until it is
 * freed, so the credentials are told the window has closed only once mbedTLS
 * has let go of them. */
TEST(SolidSyslogMbedTlsStream, CredentialsAreReleasedAfterTheSslConfigIsFreed)
{
    SslConfigFreesSeenAtRelease = 0;
    MbedTlsCredentialsFake_SetReleaseObserver(CaptureSslConfigFreesAtRelease);
    SolidSyslogStream_Open(handle, addr);

    SolidSyslogStream_Close(handle);

    LONGS_EQUAL(1, SslConfigFreesSeenAtRelease);
}

TEST(SolidSyslogMbedTlsStream, ASecondOpenInstallsTheCredentialsAgain)
{
    SolidSyslogStream_Open(handle, addr);
    SolidSyslogStream_Close(handle);

    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(2, MbedTlsCredentialsFake_InstallCallCount());
}

/* Mbed TLS returns MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED for VERIFY_REQUIRED with
   no CA chain, whatever a verify callback decides, so a peer authorised by pin
   alone has to be verified optionally and judged by this stream instead. */
TEST(SolidSyslogMbedTlsStream, OpenVerifiesOptionallyWhenOnlyAFingerprintAuthorisesThePeer)
{
    MbedTlsCredentialsFake_SetTrustAnchorsInstalled(false);
    MbedTlsCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);

    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(MBEDTLS_SSL_VERIFY_OPTIONAL, MbedTlsFake_LastSslConfAuthmodeArg());
}

TEST(SolidSyslogMbedTlsStream, OpenFailsWhenAPinIsMalformed)
{
    static const char* const pins[] = {"sha-256:AA"};
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateHandleWithUpdatedConfig();
    MbedTlsCredentialsFake_SetFingerprints(pins, 1);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_FINGERPRINT_MALFORMED
    );
}

TEST(SolidSyslogMbedTlsStream, OpenWarnsOfASha1Pin)
{
    static const char* const pins[] = {"sha-1:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D"};
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateHandleWithUpdatedConfig();
    MbedTlsCredentialsFake_SetFingerprints(pins, 1);

    CHECK_TRUE(SolidSyslogStream_Open(handle, addr));
    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogMbedTlsStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_FINGERPRINT_SHA1
    );
}

TEST(SolidSyslogMbedTlsStream, OpenDoesNotWarnOfAMissingServerNameWhenThePeerIsPinned)
{
    /* The profile leaves ServerName unset - a pin names the peer instead. */
    MbedTlsCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);

    CHECK_TRUE(SolidSyslogStream_Open(handle, addr));
    CALLED_FAKE(ErrorHandlerFake_Handle, NEVER);
}

/* Mbed TLS merges each certificate's flags into one verdict, so a chain-trust
   objection raised above the leaf reaches the result even when the leaf itself
   is cleared. A pinned peer with no anchors therefore clears it at every
   depth. */
TEST(SolidSyslogMbedTlsStream, VerifyCallbackClearsAChainTrustFlagAboveTheLeafForAPinnedPeerWithoutTrustAnchors)
{
    GivenAPinnedPeerWithoutTrustAnchors();

    UNSIGNED_LONGS_EQUAL(0, OpenThenVerifyAt(1, MBEDTLS_X509_BADCERT_NOT_TRUSTED));
}

TEST(SolidSyslogMbedTlsStream, VerifyCallbackAcceptsALeafWhoseDigestMatchesAPin)
{
    GivenAPinnedPeerWithoutTrustAnchors();

    UNSIGNED_LONGS_EQUAL(0, OpenThenVerifyAt(0, MBEDTLS_X509_BADCERT_NOT_TRUSTED));
}

TEST(SolidSyslogMbedTlsStream, VerifyCallbackMarksALeafWhoseDigestMatchesNoPin)
{
    static const unsigned char presented[32] = {0xFF};
    GivenAPinnedPeerWithoutTrustAnchors();
    MbedTlsFake_SetDigest(presented, sizeof(presented));

    UNSIGNED_LONGS_EQUAL(MBEDTLS_X509_BADCERT_OTHER, OpenThenVerifyAt(0, 0));
}

TEST(SolidSyslogMbedTlsStream, VerifyCallbackDoesNotClearTheCertificatesOwnValidityForAPinnedPeer)
{
    GivenAPinnedPeerWithoutTrustAnchors();

    UNSIGNED_LONGS_EQUAL(MBEDTLS_X509_BADCERT_EXPIRED, OpenThenVerifyAt(0, MBEDTLS_X509_BADCERT_EXPIRED));
}

TEST(SolidSyslogMbedTlsStream, VerifyCallbackLeavesAChainTrustFlagWhenTrustAnchorsAreInstalled)
{
    GivenAPinnedPeer();

    UNSIGNED_LONGS_EQUAL(MBEDTLS_X509_BADCERT_NOT_TRUSTED, OpenThenVerifyAt(1, MBEDTLS_X509_BADCERT_NOT_TRUSTED));
}

TEST(SolidSyslogMbedTlsStream, VerifyCallbackDigestsWithTheAlgorithmThePinNames)
{
    static const char* const pins[] = {"sha-1:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D"};
    static const unsigned char presented[20] = {0xE1, 0x2D, 0x53, 0x2B, 0x7C, 0x6B, 0x8A, 0x29, 0xA2, 0x76,
                                                0xC8, 0x64, 0x36, 0x0B, 0x08, 0x4B, 0x7A, 0xF1, 0x9E, 0x9D};
    MbedTlsCredentialsFake_SetFingerprints(pins, 1);
    MbedTlsFake_SetDigest(presented, sizeof(presented));

    UNSIGNED_LONGS_EQUAL(0, OpenThenVerifyAt(0, 0));
    LONGS_EQUAL(MBEDTLS_MD_SHA1, MbedTlsFake_LastMdInfoType());
}

/* The Core contract refuses a peer whose pinned algorithm cannot be computed,
   which on this platform is a hash compiled out of Mbed TLS. */
TEST(SolidSyslogMbedTlsStream, VerifyCallbackMarksALeafWhosePinnedAlgorithmIsUnavailable)
{
    MbedTlsCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);
    MbedTlsFake_SetDigestUnavailableFor(MBEDTLS_MD_SHA256);

    UNSIGNED_LONGS_EQUAL(MBEDTLS_X509_BADCERT_OTHER, OpenThenVerifyAt(0, 0));
}

/* Verifying optionally means Mbed TLS completes the handshake and leaves the
   verdict to be read, so the stream is what refuses a peer authorised by pin
   alone whose certificate failed a check of its own. */
TEST(SolidSyslogMbedTlsStream, OpenFailsWhenTheVerdictCarriesAFaultAfterAnOptionalVerification)
{
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateHandleWithUpdatedConfig();
    MbedTlsCredentialsFake_SetTrustAnchorsInstalled(false);
    MbedTlsCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);
    MbedTlsFake_SetSslVerifyResult(MBEDTLS_X509_BADCERT_EXPIRED);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_EXPIRED
    );
}

TEST(SolidSyslogMbedTlsStream, OpenReportsThatThePeerFingerprintDidNotMatch)
{
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateHandleWithUpdatedConfig();
    MbedTlsCredentialsFake_SetTrustAnchorsInstalled(false);
    MbedTlsCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);
    MbedTlsFake_SetSslVerifyResult(MBEDTLS_X509_BADCERT_OTHER | MBEDTLS_X509_BADCERT_NOT_TRUSTED);

    CHECK_FALSE(SolidSyslogStream_Open(handle, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_FINGERPRINT_MISMATCHED
    );
}

TEST(SolidSyslogMbedTlsStream, OpenConnectsWhenTheVerdictIsClean)
{
    MbedTlsCredentialsFake_SetTrustAnchorsInstalled(false);
    MbedTlsCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);
    MbedTlsFake_SetSslVerifyResult(0);

    CHECK_TRUE(SolidSyslogStream_Open(handle, addr));
}

TEST(SolidSyslogMbedTlsStream, VersionReportsTheConfiguredFunctionsValue)
{
    FakeVersion_ReturnValue = 7U;
    config.Version = FakeVersion;
    ReCreateHandleWithUpdatedConfig();

    LONGS_EQUAL(7, SolidSyslogStream_Version(handle));
}

TEST(SolidSyslogMbedTlsStream, VersionFunctionReceivesVersionContext)
{
    int context = 0;
    config.Version = FakeVersion;
    config.VersionContext = &context;
    ReCreateHandleWithUpdatedConfig();

    SolidSyslogStream_Version(handle);

    POINTERS_EQUAL(&context, FakeVersion_LastContext);
}

TEST(SolidSyslogMbedTlsStream, VersionIsZeroWhenNoFunctionIsConfigured)
{
    LONGS_EQUAL(0, SolidSyslogStream_Version(handle));
}

TEST(SolidSyslogMbedTlsStream, OpenAppliesTheProfilesCiphersuites)
{
    static const int suites[] = {MBEDTLS_TLS1_3_AES_256_GCM_SHA384, 0};
    FakeProfile_Value.CipherSuites = suites;

    SolidSyslogStream_Open(handle, addr);

    POINTERS_EQUAL(suites, MbedTlsFake_LastSslConfCiphersuitesArg());
}

TEST(SolidSyslogMbedTlsStream, OpenLeavesCiphersuitesAloneWhenTheProfileSetsNone)
{
    SolidSyslogStream_Open(handle, addr);

    LONGS_EQUAL(0, MbedTlsFake_SslConfCiphersuitesCallCount());
}
