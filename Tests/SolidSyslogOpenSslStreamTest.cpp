#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/prov_ssl.h>
#include <openssl/types.h>
#include <stddef.h>
#include <stdint.h>

#include "AddressFake.h"
#include "CppUTest/TestHarness.h"
#include "ErrorHandlerFake.h"
#include "OpenSslCredentialsFake.h"
#include "OpenSslFake.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogOpenSslStream.h"
#include "SolidSyslogTlsStreamCategories.h"
#include "SolidSyslogOpenSslStreamErrors.h"
#include "SolidSyslogTransport.h"
#include "SolidSyslogTunables.h"
#include "StreamFake.h"
#include "TestUtils.h"

using namespace CososoTesting;

#define CHECK_OPEN_UNWOUND_WITH_SEVERITY(transport, expectedSeverity, expectedCategory, expectedCode) \
    {                                                                                                 \
        LONGS_EQUAL(1, StreamFake_CloseCallCount(transport));                                         \
        CHECK_ERROR_REPORTED_ONCE(                                                                    \
            (expectedSeverity),                                                                       \
            &SolidSyslogOpenSslStreamErrorSource,                                                     \
            (expectedCategory),                                                                       \
            (expectedCode)                                                                            \
        );                                                                                            \
    }

#define CHECK_OPEN_UNWOUND_WITH_ERROR(transport, expectedCategory, expectedCode) \
    CHECK_OPEN_UNWOUND_WITH_SEVERITY(transport, SOLIDSYSLOG_SEVERITY_ERROR, expectedCategory, expectedCode)

class TEST_SolidSyslogOpenSslStream_ReadReturnsNegativeOneOnHardErrorAndClosesSsl_Test;
class TEST_SolidSyslogOpenSslStream_ReadReturnsNegativeOneOnZeroReturnAndClosesSsl_Test;
class TEST_SolidSyslogOpenSslStream_SendClosesTransportOnWriteFailure_Test;

/* One RFC 5425 4.2.2 pin and the digest that matches it. */
static const char* const TEST_SHA256_PINS[] = {
    "sha-256:00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F"
};
static const uint8_t TEST_SHA256_DIGEST[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                                               0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                               0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

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

/* Stands in for whatever the integrator bumps when the credentials, the expected
 * peer name or the cipher list change. */
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
struct SolidSyslogOpenSslProfile FakeProfile_Value;
int FakeProfile_CallCount = 0;
void* FakeProfile_LastContext = nullptr;

void FakeProfile_Reset()
{
    FakeProfile_Value = {};
    FakeProfile_CallCount = 0;
    FakeProfile_LastContext = reinterpret_cast<void*>(0x1U); /* sentinel - overwritten on first call */
}

extern "C" void FakeProfile(struct SolidSyslogOpenSslProfile* profile, void* context)
{
    FakeProfile_CallCount++;
    FakeProfile_LastContext = context;
    *profile = FakeProfile_Value;
}
} // namespace

// clang-format off
TEST_GROUP(SolidSyslogOpenSslStream)
{
    struct SolidSyslogStream*         transport = nullptr;
    struct SolidSyslogOpenSslStreamConfig config    = {};
    struct SolidSyslogStream*         stream    = nullptr;
    struct SolidSyslogAddress*        addr      = nullptr;

    void setup() override
    {
        OpenSslFake_Reset();
        ErrorHandlerFake_Install(nullptr);
        FakeGetHandshakeTimeoutMs_Reset();
        FakeVersion_Reset();
        FakeProfile_Reset();
        NoOpSleepCallCount = 0;
        g_lastSleepMs    = 0;
        transport        = StreamFake_Create();
        config.Transport = transport;
        config.Sleep     = NoOpSleep;
        OpenSslCredentialsFake_Reset();
        config.Credentials = OpenSslCredentialsFake_Get();
        config.Profile     = FakeProfile;
        stream = SolidSyslogOpenSslStream_Create(&config);
        addr = AddressFake_Get();
    }

    /* Replaces the default Null-getter stream with one that uses the fake
     * handshake-timeout getter. Each test sets only the fake-getter return
     * value (or context) it needs different from the defaults restored in
     * setup(). */
    void RecreateStreamWithFakeHandshakeGetter()
    {
        SolidSyslogOpenSslStream_Destroy(stream);
        config.GetHandshakeTimeoutMs    = FakeGetHandshakeTimeoutMs;
        stream                          = SolidSyslogOpenSslStream_Create(&config);
    }

    void teardown() override
    {
        SolidSyslogOpenSslStream_Destroy(stream);
        StreamFake_Destroy(transport);
    }

    /* Tests needing config tweaks (Credentials, Rng, ...)
     * call this to release setup()'s pool slot, mutate `config`, then re-Create.
     * Fully resets the fixture (transport, OpenSslFake counters, error handler)
     * so the test body observes counts from this Open onwards only - matters
     * for assertions like CHECK_OPEN_UNWOUND_WITH_ERROR that pin counts at == 1. */
    void ReCreateStreamWithUpdatedConfig()
    {
        SolidSyslogOpenSslStream_Destroy(stream);
        StreamFake_Destroy(transport);
        OpenSslFake_Reset();
        ErrorHandlerFake_Install(nullptr);
        transport        = StreamFake_Create();
        config.Transport = transport;
        stream           = SolidSyslogOpenSslStream_Create(&config);
    }

    /* Arrange a peer whose certificate OpenSSL refused with `verifyResult`.
     * ServerName is supplied so the refusal is the only error source - an unset one
     * would also emit the unverified-peer WARNING. */
    void ArrangeCertificateVerificationFailure(long verifyResult)
    {
        FakeProfile_Value.ServerName = "logs.example";
        ReCreateStreamWithUpdatedConfig();
        OpenSslFake_SetConnectFails(true);
        OpenSslFake_SetGetErrorReturn(SSL_ERROR_SSL);
        OpenSslFake_SetVerifyResult(verifyResult);
    }

    /* Drive the registered BIO read callback with the given transport return -
       collapses the open + set-return + grab-callback + invoke boilerplate. */
    [[nodiscard]] int InvokeBioReadWithTransportReturn(SolidSyslogSsize transportReturn) const
    {
        SolidSyslogStream_Open(stream, addr);
        StreamFake_SetReadReturn(transport, transportReturn);
        int (*readFn)(BIO*, char*, int) = OpenSslFake_LastBioReadCallback();
        char buf[16];
        return readFn(OpenSslFake_LastBioReturned(), buf, sizeof(buf));
    }

    /* Drive the registered BIO write callback while the underlying transport
       Send is configured to fail. */
    [[nodiscard]] int InvokeBioWriteWithFailingTransport() const
    {
        SolidSyslogStream_Open(stream, addr);
        StreamFake_SetSendFails(transport, true);
        int (*writeFn)(BIO*, const char*, int) = OpenSslFake_LastBioWriteCallback();
        const char msg[]                       = "hi";
        return writeFn(OpenSslFake_LastBioReturned(), msg, (int) sizeof(msg));
    }

    /* Arrange SSL_connect to first emit `wantError`, then succeed on the next
       call - exercises the bounded handshake retry loop's progress path. */
    static void ArrangeHandshakeRetryThenSucceed(int wantError)
    {
        int seq[] = {-1, 1};
        OpenSslFake_SetConnectReturnSequence(seq, 2);
        OpenSslFake_SetGetErrorReturn(wantError);
    }

    /* Arrange SSL_connect to fail with `errorCode` on every call - used both
       for the persistent-WANT (budget-exhausted) and hard-error paths. */
    static void ArrangePersistentHandshakeError(int errorCode)
    {
        int seq[] = {-1};
        OpenSslFake_SetConnectReturnSequence(seq, 1);
        OpenSslFake_SetGetErrorReturn(errorCode);
    }

    /* Open then arrange the next SSL_write to fail - exercises the Send fail-fast
       teardown path that closes the SSL session and the underlying transport. */
    void OpenThenCauseSslWriteFailure() const
    {
        SolidSyslogStream_Open(stream, addr);
        OpenSslFake_SetWriteFails(true);
    }

    /* Open, then drive the verify callback for the leaf certificate, with
       `preverifyOk` as OpenSSL's own verdict on it. */
    [[nodiscard]] int OpenThenVerifyLeaf(int preverifyOk) const
    {
        SolidSyslogStream_Open(stream, addr);
        return OpenSslFake_LastVerifyCallback()(preverifyOk, OpenSslFake_StoreCtx());
    }

    /* Drive the verify callback for a certificate above the leaf, with
       `preverifyOk` as OpenSSL's verdict on it and `error` the objection it
       raised. */
    [[nodiscard]] int OpenThenVerifyIssuer(int preverifyOk, int error) const
    {
        OpenSslFake_SetStoreCtxDepth(1);
        OpenSslFake_SetStoreCtxError(error);
        SolidSyslogStream_Open(stream, addr);
        return OpenSslFake_LastVerifyCallback()(preverifyOk, OpenSslFake_StoreCtx());
    }

    void SendShortMessage() const
    {
        const char msg[] = "hi";
        SolidSyslogStream_Send(stream, msg, sizeof(msg));
    }

    /* Open then arrange SSL_read to return the configured value while
       SSL_get_error reports the configured SSL-level status - together they
       exercise each branch of the Read non-blocking contract. */
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters) -- both ints, but name + comment make role distinct
    [[nodiscard]] SolidSyslogSsize OpenThenReadWithSslReturnAndError(int sslReadReturn, int sslErrorCode) const
    {
        SolidSyslogStream_Open(stream, addr);
        OpenSslFake_SetReadReturn(sslReadReturn);
        OpenSslFake_SetGetErrorReturn(sslErrorCode);
        char buf[16];
        return SolidSyslogStream_Read(stream, buf, sizeof(buf));
    }
};

// clang-format on

#define CHECK_BIO_READ_RETRY_SIGNALLED()            \
    {                                               \
        CALLED_FAKE(OpenSslFake_BioSetFlags, ONCE); \
    }
#define CHECK_BIO_READ_RETRY_NOT_SIGNALLED()         \
    {                                                \
        CALLED_FAKE(OpenSslFake_BioSetFlags, NEVER); \
    }
#define CHECK_BIO_RETRY_FLAGS_CLEARED()               \
    {                                                 \
        CALLED_FAKE(OpenSslFake_BioClearFlags, ONCE); \
    }
#define CHECK_SSL_SESSION_CLOSED()               \
    {                                            \
        CALLED_FAKE(OpenSslFake_Shutdown, ONCE); \
        CALLED_FAKE(OpenSslFake_Free, ONCE);     \
    }
#define CHECK_TRANSPORT_CLOSED_ONCE()                      \
    {                                                      \
        CALLED_FAKE_ON(StreamFake_Close, transport, ONCE); \
    }

TEST(SolidSyslogOpenSslStream, CreateSucceeds)
{
    CHECK_TRUE(stream != nullptr);
}

TEST(SolidSyslogOpenSslStream, OpenOpensTransport)
{
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE_ON(StreamFake_Open, transport, ONCE);
}

TEST(SolidSyslogOpenSslStream, OpenPassesAddressToTransport)
{
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(addr, StreamFake_LastOpenAddr(transport));
}

TEST(SolidSyslogOpenSslStream, OpenCreatesSslContext)
{
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(OpenSslFake_CtxNew, ONCE);
}

TEST(SolidSyslogOpenSslStream, OpenRequiresPeerVerification)
{
    SolidSyslogStream_Open(stream, addr);
    LONGS_EQUAL(SSL_VERIFY_PEER, OpenSslFake_LastVerifyMode());
}

TEST(SolidSyslogOpenSslStream, OpenSetsTls12Floor)
{
    SolidSyslogStream_Open(stream, addr);
    LONGS_EQUAL(TLS1_2_VERSION, OpenSslFake_LastMinProtoVersion());
}

TEST(SolidSyslogOpenSslStream, OpenPassesCipherListToSslCtx)
{
    FakeProfile_Value.CipherList = "ECDHE+AESGCM";
    ReCreateStreamWithUpdatedConfig();
    SolidSyslogStream_Open(stream, addr);
    STRCMP_EQUAL("ECDHE+AESGCM", OpenSslFake_LastCipherList());
}

TEST(SolidSyslogOpenSslStream, OpenSkipsCipherListSetupWhenNotConfigured)
{
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(OpenSslFake_SetCipherList, NEVER);
}

TEST(SolidSyslogOpenSslStream, OpenReturnsFalseWhenCipherListRejected)
{
    FakeProfile_Value.CipherList = "not-a-real-cipher";
    ReCreateStreamWithUpdatedConfig();
    OpenSslFake_SetCipherListFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_CONTEXT_INIT_FAILED
    );
}

TEST(SolidSyslogOpenSslStream, CipherListFailureFreesCtx)
{
    FakeProfile_Value.CipherList = "not-a-real-cipher";
    ReCreateStreamWithUpdatedConfig();
    OpenSslFake_SetCipherListFails(true);
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(OpenSslFake_CtxFree, ONCE);
}

TEST(SolidSyslogOpenSslStream, OpenPassesCipherSuitesToSslCtx)
{
    FakeProfile_Value.CipherSuites = "TLS_AES_256_GCM_SHA384";
    ReCreateStreamWithUpdatedConfig();
    SolidSyslogStream_Open(stream, addr);
    STRCMP_EQUAL("TLS_AES_256_GCM_SHA384", OpenSslFake_LastCipherSuites());
}

TEST(SolidSyslogOpenSslStream, OpenSkipsCipherSuitesSetupWhenNotConfigured)
{
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(OpenSslFake_SetCipherSuites, NEVER);
}

TEST(SolidSyslogOpenSslStream, OpenReturnsFalseWhenCipherSuitesRejected)
{
    FakeProfile_Value.CipherSuites = "NOT-A-REAL-SUITE";
    ReCreateStreamWithUpdatedConfig();
    OpenSslFake_SetCipherSuitesFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_CONTEXT_INIT_FAILED
    );
}

TEST(SolidSyslogOpenSslStream, OpenCreatesSslSession)
{
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(OpenSslFake_SslNew, ONCE);
}

TEST(SolidSyslogOpenSslStream, OpenPassesCtxFromCtxNewToSslNew)
{
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(OpenSslFake_LastCtxReturned(), OpenSslFake_LastSslNewCtxArg());
}

TEST(SolidSyslogOpenSslStream, OpenCreatesBio)
{
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(OpenSslFake_BioNew, ONCE);
}

TEST(SolidSyslogOpenSslStream, OpenSetsBioOnSsl)
{
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(OpenSslFake_SetBio, ONCE);
}

TEST(SolidSyslogOpenSslStream, OpenPassesSslFromNewToSetBio)
{
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(OpenSslFake_LastSslReturned(), OpenSslFake_LastSetBioSslArg());
}

TEST(SolidSyslogOpenSslStream, OpenPassesBioFromNewToSetBio)
{
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(OpenSslFake_LastBioReturned(), OpenSslFake_LastSetBioReadBioArg());
}

TEST(SolidSyslogOpenSslStream, OpenPerformsHandshake)
{
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(OpenSslFake_Connect, ONCE);
}

TEST(SolidSyslogOpenSslStream, OpenPassesSslToConnect)
{
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(OpenSslFake_LastSslReturned(), OpenSslFake_LastConnectSslArg());
}

TEST(SolidSyslogOpenSslStream, OpenSetsSniHostnameFromTheProfile)
{
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateStreamWithUpdatedConfig();
    SolidSyslogStream_Open(stream, addr);
    STRCMP_EQUAL("logs.example", OpenSslFake_LastSniHostname());
}

TEST(SolidSyslogOpenSslStream, OpenSetsExpectedCertHostname)
{
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateStreamWithUpdatedConfig();
    SolidSyslogStream_Open(stream, addr);
    STRCMP_EQUAL("logs.example", OpenSslFake_LastSet1Host());
}

TEST(SolidSyslogOpenSslStream, OpenSkipsHostnameSetupWhenServerNameIsNull)
{
    /* The profile leaves ServerName unset. */
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(NULL, OpenSslFake_LastSet1Host());
}

TEST(SolidSyslogOpenSslStream, OpenWarnsWhenServerNameIsNull)
{
    /* The profile leaves ServerName unset - peer identity is unverified, which the
     * library must surface rather than swallow (S12.28). */
    SolidSyslogStream_Open(stream, addr);
    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogOpenSslStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_SERVER_NAME_NOT_SET
    );
}

TEST(SolidSyslogOpenSslStream, OpenStillConnectsWhenServerNameIsNull)
{
    /* The unverified-peer WARNING is observable but non-fatal - the IP-pinned /
     * closed-network use case must still connect. */
    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
    LONGS_EQUAL(0, StreamFake_CloseCallCount(transport));
}

TEST(SolidSyslogOpenSslStream, OpenDoesNotWarnWhenServerNameIsEmpty)
{
    /* Empty string is the deliberate opt-out - no diagnostic. */
    FakeProfile_Value.ServerName = "";
    ReCreateStreamWithUpdatedConfig();
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(ErrorHandlerFake_Handle, NEVER);
}

TEST(SolidSyslogOpenSslStream, OpenSkipsHostnameSetupWhenServerNameIsEmpty)
{
    FakeProfile_Value.ServerName = "";
    ReCreateStreamWithUpdatedConfig();
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(NULL, OpenSslFake_LastSet1Host());
}

TEST(SolidSyslogOpenSslStream, OpenConnectsWhenServerNameIsEmpty)
{
    FakeProfile_Value.ServerName = "";
    ReCreateStreamWithUpdatedConfig();
    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogOpenSslStream, OpenAttachesTransportAsBioData)
{
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(transport, OpenSslFake_LastSetDataArg());
}

TEST(SolidSyslogOpenSslStream, BioReadCallbackDelegatesToTransportRead)
{
    SolidSyslogStream_Open(stream, addr);
    int (*readFn)(BIO*, char*, int) = OpenSslFake_LastBioReadCallback();
    CHECK_TRUE(readFn != nullptr);
    if (readFn == nullptr)
    {
        return;
    }
    char buf[16];
    readFn(OpenSslFake_LastBioReturned(), buf, sizeof(buf));
    CALLED_FAKE_ON(StreamFake_Read, transport, ONCE);
}

TEST(SolidSyslogOpenSslStream, BioWriteCallbackDelegatesToTransportSend)
{
    SolidSyslogStream_Open(stream, addr);
    int (*writeFn)(BIO*, const char*, int) = OpenSslFake_LastBioWriteCallback();
    CHECK_TRUE(writeFn != nullptr);
    if (writeFn == nullptr)
    {
        return;
    }
    const char msg[] = "hi";
    writeFn(OpenSslFake_LastBioReturned(), msg, (int) sizeof(msg));
    CALLED_FAKE_ON(StreamFake_Send, transport, ONCE);
}

TEST(SolidSyslogOpenSslStream, SendWritesToSsl)
{
    SolidSyslogStream_Open(stream, addr);
    const char msg[] = "hello";
    SolidSyslogStream_Send(stream, msg, sizeof(msg));
    CALLED_FAKE(OpenSslFake_Write, ONCE);
}

TEST(SolidSyslogOpenSslStream, SendPassesBufferToSslWrite)
{
    SolidSyslogStream_Open(stream, addr);
    const char msg[] = "hello";
    SolidSyslogStream_Send(stream, msg, sizeof(msg));
    POINTERS_EQUAL(msg, OpenSslFake_LastWriteBuf());
}

TEST(SolidSyslogOpenSslStream, SendPassesSizeToSslWrite)
{
    SolidSyslogStream_Open(stream, addr);
    const char msg[] = "hello";
    SolidSyslogStream_Send(stream, msg, sizeof(msg));
    LONGS_EQUAL(sizeof(msg), OpenSslFake_LastWriteSize());
}

TEST(SolidSyslogOpenSslStream, SendPassesSslFromNewToWrite)
{
    SolidSyslogStream_Open(stream, addr);
    const char msg[] = "hello";
    SolidSyslogStream_Send(stream, msg, sizeof(msg));
    POINTERS_EQUAL(OpenSslFake_LastSslReturned(), OpenSslFake_LastWriteSslArg());
}

TEST(SolidSyslogOpenSslStream, ReadReadsFromSsl)
{
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogStream_Read(stream, buf, sizeof(buf));
    CALLED_FAKE(OpenSslFake_SslRead, ONCE);
}

TEST(SolidSyslogOpenSslStream, ReadPassesSslFromNewToSslRead)
{
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogStream_Read(stream, buf, sizeof(buf));
    POINTERS_EQUAL(OpenSslFake_LastSslReturned(), OpenSslFake_LastSslReadSslArg());
}

TEST(SolidSyslogOpenSslStream, ReadPassesBufferToSslRead)
{
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogStream_Read(stream, buf, sizeof(buf));
    POINTERS_EQUAL(buf, OpenSslFake_LastSslReadBuf());
}

TEST(SolidSyslogOpenSslStream, ReadPassesSizeToSslRead)
{
    SolidSyslogStream_Open(stream, addr);
    char buf[16];
    SolidSyslogStream_Read(stream, buf, sizeof(buf));
    LONGS_EQUAL(sizeof(buf), OpenSslFake_LastSslReadSize());
}

TEST(SolidSyslogOpenSslStream, CloseShutsDownSsl)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Close(stream);
    CALLED_FAKE(OpenSslFake_Shutdown, ONCE);
}

TEST(SolidSyslogOpenSslStream, CloseFreesSsl)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Close(stream);
    CALLED_FAKE(OpenSslFake_Free, ONCE);
}

TEST(SolidSyslogOpenSslStream, CloseClosesTransport)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Close(stream);
    CALLED_FAKE_ON(StreamFake_Close, transport, ONCE);
}

/* Destroy on a still-Open stream must release the underlying transport,
   otherwise an integrator that omits the explicit Close call leaks the
   transport's socket / fd. Verified before the teardown's Destroy fires
   (which would itself trigger another transport Close). */
TEST(SolidSyslogOpenSslStream, DestroyClosesTransportWhenStillOpen)
{
    SolidSyslogStream_Open(stream, addr);

    SolidSyslogOpenSslStream_Destroy(stream);

    CALLED_FAKE_ON(StreamFake_Close, transport, ONCE);
    /* Re-create so teardown's Destroy targets a live slot rather than a
       stale handle (which would fire SOLIDSYSLOG_TLS_STREAM_ERROR_UNKNOWN_DESTROY). */
    stream = SolidSyslogOpenSslStream_Create(&config);
}

TEST(SolidSyslogOpenSslStream, CloseFreesBioMethod)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Close(stream);
    CALLED_FAKE(OpenSslFake_BioMethFree, ONCE);
}

TEST(SolidSyslogOpenSslStream, DestroyFreesSslContext)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogOpenSslStream_Destroy(stream);
    CALLED_FAKE(OpenSslFake_CtxFree, ONCE);
    /* teardown re-Destroys safely */
}

TEST(SolidSyslogOpenSslStream, DestroyFreesBioMethodWhenCloseNotCalled)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogOpenSslStream_Destroy(stream);
    CALLED_FAKE(OpenSslFake_BioMethFree, ONCE);
    /* teardown re-Destroys safely */
}

TEST(SolidSyslogOpenSslStream, DestroyAfterCloseDoesNotDoubleFreeBioMethod)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Close(stream);
    SolidSyslogOpenSslStream_Destroy(stream);
    CALLED_FAKE(OpenSslFake_BioMethFree, ONCE);
}

TEST(SolidSyslogOpenSslStream, DestroyFreesSslWhenCloseNotCalled)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogOpenSslStream_Destroy(stream);
    CALLED_FAKE(OpenSslFake_Free, ONCE);
}

TEST(SolidSyslogOpenSslStream, DestroyAfterCloseDoesNotDoubleFreeSsl)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Close(stream);
    SolidSyslogOpenSslStream_Destroy(stream);
    CALLED_FAKE(OpenSslFake_Free, ONCE);
}

TEST(SolidSyslogOpenSslStream, ReopenAfterCloseDoesNotLeakSslContext)
{
    /* Each Open rebuilds the SSL_CTX (the cert-rotation contract - a fresh CTX
       per connection picks up trust-store / client-identity changes). The
       fail-fast reconnect model therefore drives Open -> Close -> Open on a
       single stream instance repeatedly; Close must free the CTX so the next
       Open does not leak the previous one. */
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Close(stream);
    SolidSyslogStream_Open(stream, addr);
    LONGS_EQUAL(2, OpenSslFake_CtxNewCallCount());
    LONGS_EQUAL(1, OpenSslFake_CtxFreeCallCount());
}

/* -------------------------------------------------------------------------
 * Pointer-chain assertions: each OpenSSL call must receive the handle
 * returned by the preceding call, not some stale or NULL pointer.
 * ------------------------------------------------------------------------- */

TEST(SolidSyslogOpenSslStream, OpenPassesClientMethodToCtxNew)
{
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(TLS_client_method(), OpenSslFake_LastCtxNewMethodArg());
}

TEST(SolidSyslogOpenSslStream, OpenPassesCtxFromNewToSetVerify)
{
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(OpenSslFake_LastCtxReturned(), OpenSslFake_LastSetVerifyCtxArg());
}

TEST(SolidSyslogOpenSslStream, OpenPassesCtxFromNewToSetMinProtoVersion)
{
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(OpenSslFake_LastCtxReturned(), OpenSslFake_LastSslCtxCtrlCtxArg());
}

TEST(SolidSyslogOpenSslStream, OpenPassesBioMethodFromNewToSetRead)
{
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(OpenSslFake_LastBioMethReturned(), OpenSslFake_LastBioMethSetReadMethodArg());
}

TEST(SolidSyslogOpenSslStream, OpenPassesBioMethodFromNewToSetWrite)
{
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(OpenSslFake_LastBioMethReturned(), OpenSslFake_LastBioMethSetWriteMethodArg());
}

TEST(SolidSyslogOpenSslStream, OpenPassesBioMethodFromNewToBioNew)
{
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(OpenSslFake_LastBioMethReturned(), OpenSslFake_LastBioNewMethodArg());
}

TEST(SolidSyslogOpenSslStream, OpenPassesBioFromNewToSetData)
{
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(OpenSslFake_LastBioReturned(), OpenSslFake_LastSetDataBioArg());
}

TEST(SolidSyslogOpenSslStream, OpenPassesSameBioForReadAndWrite)
{
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(OpenSslFake_LastSetBioReadBioArg(), OpenSslFake_LastSetBioWriteBioArg());
}

TEST(SolidSyslogOpenSslStream, OpenPassesSslToSniCtrl)
{
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateStreamWithUpdatedConfig();
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(OpenSslFake_LastSslReturned(), OpenSslFake_LastSslCtrlSslArg());
}

TEST(SolidSyslogOpenSslStream, OpenPassesSslFromNewToSet1Host)
{
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateStreamWithUpdatedConfig();
    SolidSyslogStream_Open(stream, addr);
    POINTERS_EQUAL(OpenSslFake_LastSslReturned(), OpenSslFake_LastSet1HostSslArg());
}

TEST(SolidSyslogOpenSslStream, BioReadCallbackLooksUpDataOnTheCorrectBio)
{
    SolidSyslogStream_Open(stream, addr);
    int (*readFn)(BIO*, char*, int) = OpenSslFake_LastBioReadCallback();
    char buf[16];
    readFn(OpenSslFake_LastBioReturned(), buf, sizeof(buf));
    POINTERS_EQUAL(OpenSslFake_LastBioReturned(), OpenSslFake_LastGetDataBioArg());
}

TEST(SolidSyslogOpenSslStream, ClosePassesSslFromNewToShutdown)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Close(stream);
    POINTERS_EQUAL(OpenSslFake_LastSslReturned(), OpenSslFake_LastShutdownSslArg());
}

TEST(SolidSyslogOpenSslStream, ClosePassesSslFromNewToFree)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogStream_Close(stream);
    POINTERS_EQUAL(OpenSslFake_LastSslReturned(), OpenSslFake_LastFreeSslArg());
}

TEST(SolidSyslogOpenSslStream, DestroyPassesCtxFromNewToCtxFree)
{
    SolidSyslogStream_Open(stream, addr);
    SolidSyslogOpenSslStream_Destroy(stream);
    POINTERS_EQUAL(OpenSslFake_LastCtxReturned(), OpenSslFake_LastCtxFreeCtxArg());
}

/* -------------------------------------------------------------------------
 * Error paths.
 * ------------------------------------------------------------------------- */

TEST(SolidSyslogOpenSslStream, OpenReturnsTrueOnHappyPath)
{
    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogOpenSslStream, OpenReturnsFalseWhenHandshakeFails)
{
    /* ServerName set so the handshake stage is the only error source (a NULL
     * ServerName would also emit the unverified-peer WARNING). Default
     * OpenSslFake_SetConnectFails(true) returns -1 from SSL_connect and
     * SSL_get_error reports SSL_ERROR_SSL (the default for SetGetErrorReturn) -
     * a non-retryable hard error, which is the HANDSHAKE_REJECTED branch. */
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateStreamWithUpdatedConfig();
    OpenSslFake_SetConnectFails(true);
    OpenSslFake_SetGetErrorReturn(SSL_ERROR_SSL);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_HANDSHAKE_REJECTED
    );
}

TEST(SolidSyslogOpenSslStream, OpenReportsThatThePeerCertificateHasExpired)
{
    ArrangeCertificateVerificationFailure(X509_V_ERR_CERT_HAS_EXPIRED);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_EXPIRED
    );
}

TEST(SolidSyslogOpenSslStream, OpenReportsThatThePeerCertificateIsNotYetValid)
{
    ArrangeCertificateVerificationFailure(X509_V_ERR_CERT_NOT_YET_VALID);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_NOT_YET_VALID
    );
}

TEST(SolidSyslogOpenSslStream, OpenReportsThatThePeerNameDidNotMatch)
{
    ArrangeCertificateVerificationFailure(X509_V_ERR_HOSTNAME_MISMATCH);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_NAME_MISMATCHED
    );
}

TEST(SolidSyslogOpenSslStream, OpenReportsThatThePeerAddressDidNotMatch)
{
    ArrangeCertificateVerificationFailure(X509_V_ERR_IP_ADDRESS_MISMATCH);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_NAME_MISMATCHED
    );
}

TEST(SolidSyslogOpenSslStream, OpenReportsThatThePeerCertificateIsNotTrusted)
{
    ArrangeCertificateVerificationFailure(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_UNTRUSTED
    );
}

TEST(SolidSyslogOpenSslStream, OpenReturnsFalseWhenSet1HostFails)
{
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateStreamWithUpdatedConfig();
    OpenSslFake_SetSet1HostFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_SEVERITY(
        transport,
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_SERVER_NAME_NOT_SET
    );
}

TEST(SolidSyslogOpenSslStream, OpenReturnsFalseWhenSniHostnameSetupFails)
{
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateStreamWithUpdatedConfig();
    OpenSslFake_SetSniHostnameFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_SEVERITY(
        transport,
        SOLIDSYSLOG_SEVERITY_CRITICAL,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_SERVER_NAME_NOT_SET
    );
}

TEST(SolidSyslogOpenSslStream, OpenReturnsFalseWhenCtxNewFails)
{
    OpenSslFake_SetCtxNewFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_CONTEXT_INIT_FAILED
    );
}

TEST(SolidSyslogOpenSslStream, OpenReturnsFalseWhenSslNewFails)
{
    OpenSslFake_SetSslNewFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_SESSION_INIT_FAILED
    );
}

/* The context is built before the credentials are asked for, so a credentials
 * source that cannot produce its material must not leak it. */
TEST(SolidSyslogOpenSslStream, CredentialsInstallFailureFreesCtx)
{
    OpenSslCredentialsFake_SetInstallSucceeds(false);
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(OpenSslFake_CtxFree, ONCE);
}

TEST(SolidSyslogOpenSslStream, OpenReturnsFalseWhenMinProtoVersionFails)
{
    OpenSslFake_SetMinProtoVersionFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_CONTEXT_INIT_FAILED
    );
}

TEST(SolidSyslogOpenSslStream, MinProtoVersionFailureFreesCtx)
{
    OpenSslFake_SetMinProtoVersionFails(true);
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(OpenSslFake_CtxFree, ONCE);
}

TEST(SolidSyslogOpenSslStream, OpenReturnsFalseWhenBioMethNewFails)
{
    OpenSslFake_SetBioMethNewFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_SESSION_INIT_FAILED
    );
}

TEST(SolidSyslogOpenSslStream, OpenReturnsFalseWhenBioNewFails)
{
    OpenSslFake_SetBioNewFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_SESSION_INIT_FAILED
    );
}

TEST(SolidSyslogOpenSslStream, BioNewFailureFreesBioMethodInline)
{
    OpenSslFake_SetBioNewFails(true);
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(OpenSslFake_BioMethFree, ONCE);
    /* teardown re-Destroys safely - bioMethod already cleared */
}

TEST(SolidSyslogOpenSslStream, SendReturnsTrueOnHappyPath)
{
    SolidSyslogStream_Open(stream, addr);
    const char msg[] = "hi";
    CHECK_TRUE(SolidSyslogStream_Send(stream, msg, sizeof(msg)));
}

TEST(SolidSyslogOpenSslStream, SendReturnsFalseWhenWriteFails)
{
    SolidSyslogStream_Open(stream, addr);
    OpenSslFake_SetWriteFails(true);
    const char msg[] = "hi";
    CHECK_FALSE(SolidSyslogStream_Send(stream, msg, sizeof(msg)));
}

TEST(SolidSyslogOpenSslStream, OpenReturnsFalseWhenTransportOpenFails)
{
    StreamFake_SetOpenFails(transport, true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogOpenSslStream, OpenSkipsSslSetupWhenTransportOpenFails)
{
    StreamFake_SetOpenFails(transport, true);
    SolidSyslogStream_Open(stream, addr);
    CALLED_FAKE(OpenSslFake_CtxNew, NEVER);
}

TEST(SolidSyslogOpenSslStream, OpenWiresBioCtrlCallback)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(OpenSslFake_LastBioCtrlCallback() != nullptr);
}

TEST(SolidSyslogOpenSslStream, OpenWiresBioCreateCallback)
{
    SolidSyslogStream_Open(stream, addr);
    CHECK_TRUE(OpenSslFake_LastBioCreateCallback() != nullptr);
}

TEST(SolidSyslogOpenSslStream, BioCtrlCallbackReturnsSuccessForFlush)
{
    SolidSyslogStream_Open(stream, addr);
    auto ctrlFn = OpenSslFake_LastBioCtrlCallback();
    LONGS_EQUAL(1, ctrlFn(OpenSslFake_LastBioReturned(), BIO_CTRL_FLUSH, 0, nullptr));
}

TEST(SolidSyslogOpenSslStream, BioCtrlCallbackReturnsSuccessForPushPopDup)
{
    SolidSyslogStream_Open(stream, addr);
    auto ctrlFn = OpenSslFake_LastBioCtrlCallback();
    BIO* bio = OpenSslFake_LastBioReturned();
    LONGS_EQUAL(1, ctrlFn(bio, BIO_CTRL_PUSH, 0, nullptr));
    LONGS_EQUAL(1, ctrlFn(bio, BIO_CTRL_POP, 0, nullptr));
    LONGS_EQUAL(1, ctrlFn(bio, BIO_CTRL_DUP, 0, nullptr));
}

TEST(SolidSyslogOpenSslStream, BioCtrlCallbackReturnsFailureForUnknownCommand)
{
    SolidSyslogStream_Open(stream, addr);
    auto ctrlFn = OpenSslFake_LastBioCtrlCallback();
    LONGS_EQUAL(0, ctrlFn(OpenSslFake_LastBioReturned(), /* arbitrary unsupported cmd */ 9999, 0, nullptr));
}

TEST(SolidSyslogOpenSslStream, BioCreateCallbackMarksBioInitialised)
{
    SolidSyslogStream_Open(stream, addr);
    auto createFn = OpenSslFake_LastBioCreateCallback();
    createFn(OpenSslFake_LastBioReturned());
    LONGS_EQUAL(1, OpenSslFake_LastSetInitArg());
}

TEST(SolidSyslogOpenSslStream, DefaultPortMatchesRfc5425)
{
    LONGS_EQUAL(6514, SOLIDSYSLOG_TLS_DEFAULT_PORT);
}

/* -------------------------------------------------------------------------
 * Non-blocking BIO read translation. Under the new transport contract a
 * 0 return means "would-block, retry"; without BIO_set_retry_read OpenSSL
 * would treat that as EOF and abort the handshake on the first poll.
 * ------------------------------------------------------------------------- */

TEST(SolidSyslogOpenSslStream, BioReadCallbackSignalsRetryWhenTransportWouldBlock)
{
    LONGS_EQUAL(-1, InvokeBioReadWithTransportReturn(0));
    CHECK_BIO_READ_RETRY_SIGNALLED();
}

TEST(SolidSyslogOpenSslStream, BioReadCallbackClearsRetryOnHardError)
{
    LONGS_EQUAL(-1, InvokeBioReadWithTransportReturn(-1));
    CHECK_BIO_RETRY_FLAGS_CLEARED();
}

TEST(SolidSyslogOpenSslStream, BioReadCallbackReturnsBytesWhenTransportHasData)
{
    LONGS_EQUAL(7, InvokeBioReadWithTransportReturn(7));
    /* No retry signal needed: positive return is the success path. */
    CHECK_BIO_READ_RETRY_NOT_SIGNALLED();
}

TEST(SolidSyslogOpenSslStream, BioWriteCallbackClearsRetryOnTransportFailure)
{
    /* When the transport's fail-fast Send returns false the BIO must clear
       any stale retry flag and return -1 so OpenSSL surfaces SSL_ERROR_SYSCALL
       rather than spinning on a closed transport. */
    LONGS_EQUAL(-1, InvokeBioWriteWithFailingTransport());
    CHECK_BIO_RETRY_FLAGS_CLEARED();
}

/* -------------------------------------------------------------------------
 * Bounded handshake retry loop. SSL_connect under non-blocking transport
 * will emit WANT_READ/WANT_WRITE between RTTs; the loop must drive it to
 * completion within HANDSHAKE_TIMEOUT_MILLISECONDS.
 * ------------------------------------------------------------------------- */

TEST(SolidSyslogOpenSslStream, OpenRetriesHandshakeOnWantRead)
{
    ArrangeHandshakeRetryThenSucceed(SSL_ERROR_WANT_READ);
    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
    CALLED_FAKE(OpenSslFake_Connect, TWICE);
}

TEST(SolidSyslogOpenSslStream, OpenSleepsBetweenHandshakeRetries)
{
    ArrangeHandshakeRetryThenSucceed(SSL_ERROR_WANT_READ);
    SolidSyslogStream_Open(stream, addr);
    CALLED_FUNCTION(NoOpSleep, ONCE);
}

TEST(SolidSyslogOpenSslStream, OpenRetriesHandshakeOnWantWrite)
{
    /* WANT_WRITE arises when SSL needs to send (e.g. during the handshake
       finished message under non-blocking transport with a temporarily-full
       send buffer). Same retry treatment as WANT_READ. */
    ArrangeHandshakeRetryThenSucceed(SSL_ERROR_WANT_WRITE);
    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
    CALLED_FAKE(OpenSslFake_Connect, TWICE);
}

TEST(SolidSyslogOpenSslStream, OpenFailsWhenHandshakeNeverCompletes)
{
    /* ServerName set so the handshake timeout is the only error source.
       SSL_connect always returns -1 with WANT_READ - handshake never makes
       progress, so the bounded budget should expire and Open returns false. */
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateStreamWithUpdatedConfig();
    ArrangePersistentHandshakeError(SSL_ERROR_WANT_READ);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_SEVERITY(
        transport,
        SOLIDSYSLOG_SEVERITY_WARNING,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_HANDSHAKE_TIMEOUT
    );
}

TEST(SolidSyslogOpenSslStream, OpenInvokesConfiguredHandshakeTimeoutGetter)
{
    RecreateStreamWithFakeHandshakeGetter();
    SolidSyslogStream_Open(stream, addr);

    LONGS_EQUAL(1, FakeGetHandshakeTimeoutMs_CallCount);
}

TEST(SolidSyslogOpenSslStream, OpenUsesGetterReturnValueAsHandshakeBudget)
{
    /* 5 ms budget against the 1 ms poll interval -> loop should sleep 5 times
       before declaring HANDSHAKE_TIMEOUT and unwinding. */
    FakeGetHandshakeTimeoutMs_ReturnValue = 5U;
    RecreateStreamWithFakeHandshakeGetter();
    ArrangePersistentHandshakeError(SSL_ERROR_WANT_READ);

    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));

    LONGS_EQUAL(5, NoOpSleepCallCount);
}

TEST(SolidSyslogOpenSslStream, GetterReceivesNullContextWhenContextNotConfigured)
{
    RecreateStreamWithFakeHandshakeGetter();
    SolidSyslogStream_Open(stream, addr);

    POINTERS_EQUAL(nullptr, FakeGetHandshakeTimeoutMs_LastContext);
}

TEST(SolidSyslogOpenSslStream, OpenFailsImmediatelyOnHardSslError)
{
    /* ServerName set so the handshake hard error is the only error source.
       Non-WANT error (e.g. SSL_ERROR_SSL) is fail-fast - no retry budget burn. */
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateStreamWithUpdatedConfig();
    ArrangePersistentHandshakeError(SSL_ERROR_SSL);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CALLED_FAKE(OpenSslFake_Connect, ONCE);
    CALLED_FUNCTION(NoOpSleep, NEVER);
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_HANDSHAKE_REJECTED
    );
}

TEST(SolidSyslogOpenSslStream, SecondOpenAfterFailedFirstOpenSucceeds)
{
    /* The recovery contract that the per-failure-point unwinds enable: once
     * Open's failure tail Closes the transport and releases the SSL state, the
     * next Open is a clean Open-Close-Open cycle on the transport. Without the
     * unwind, the inner transport would stay open and PosixTcpStream_Open would
     * clobber its fd on the next StreamSender reconnect tick. */
    int handshakeSequence[] = {-1, 1};
    OpenSslFake_SetConnectReturnSequence(handshakeSequence, 2);
    OpenSslFake_SetGetErrorReturn(SSL_ERROR_SSL); /* first call: hard error, fail-fast */

    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    OpenSslFake_SetGetErrorReturn(0); /* second call: handshake succeeds, no error lookup */
    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
    LONGS_EQUAL(2, StreamFake_OpenCallCount(transport));
    LONGS_EQUAL(1, StreamFake_CloseCallCount(transport));
}

/* -------------------------------------------------------------------------
 * Send fail-fast: any non-success closes the SSL session and the underlying
 * transport so the StreamSender's reconnect path runs on the next tick.
 * ------------------------------------------------------------------------- */

TEST(SolidSyslogOpenSslStream, SendClosesSslOnWriteFailure)
{
    OpenThenCauseSslWriteFailure();
    SendShortMessage();
    CHECK_SSL_SESSION_CLOSED();
}

TEST(SolidSyslogOpenSslStream, SendClosesTransportOnWriteFailure)
{
    OpenThenCauseSslWriteFailure();
    SendShortMessage();
    CHECK_TRANSPORT_CLOSED_ONCE();
}

TEST(SolidSyslogOpenSslStream, SendReturnsFalseOnShortWrite)
{
    SolidSyslogStream_Open(stream, addr);
    OpenSslFake_SetWriteReturn(3);
    const char msg[] = "hello";
    CHECK_FALSE(SolidSyslogStream_Send(stream, msg, sizeof(msg)));
}

/* -------------------------------------------------------------------------
 * Read non-blocking contract.
 * ------------------------------------------------------------------------- */

TEST(SolidSyslogOpenSslStream, ReadReturnsZeroOnWantRead)
{
    LONGS_EQUAL(0, OpenThenReadWithSslReturnAndError(-1, SSL_ERROR_WANT_READ));
}

TEST(SolidSyslogOpenSslStream, ReadReturnsNegativeOneOnHardErrorAndClosesSsl)
{
    LONGS_EQUAL(-1, OpenThenReadWithSslReturnAndError(-1, SSL_ERROR_SSL));
    CHECK_SSL_SESSION_CLOSED();
    CHECK_TRANSPORT_CLOSED_ONCE();
}

TEST(SolidSyslogOpenSslStream, ReadReturnsNegativeOneOnZeroReturnAndClosesSsl)
{
    /* SSL_read returns 0 -> SSL_ERROR_ZERO_RETURN (clean shutdown by peer). */
    LONGS_EQUAL(-1, OpenThenReadWithSslReturnAndError(0, SSL_ERROR_ZERO_RETURN));
    CHECK_SSL_SESSION_CLOSED();
    CHECK_TRANSPORT_CLOSED_ONCE();
}

/* -------------------------------------------------------------------------
 * Close idempotency. Send/Read may close internally on failure; subsequent
 * Close from the StreamSender's reconnect path or Destroy must not crash
 * or double-free.
 * ------------------------------------------------------------------------- */

TEST(SolidSyslogOpenSslStream, CloseAfterInternalCloseFromSendFailureDoesNotDoubleFree)
{
    OpenThenCauseSslWriteFailure();
    SendShortMessage(); /* internal close */
    SolidSyslogStream_Close(stream); /* second close - must be safe */
    CHECK_SSL_SESSION_CLOSED();
}

/* -------------------------------------------------------------------------
 * The credentials role - the stream asks for material per connection, and
 * says when it has finished with it.
 * ------------------------------------------------------------------------- */

TEST(SolidSyslogOpenSslStream, OpenInstallsTheCredentialsOnTheContextItBuilt)
{
    SolidSyslogStream_Open(stream, addr);

    LONGS_EQUAL(1, OpenSslCredentialsFake_InstallCallCount());
    POINTERS_EQUAL(OpenSslFake_LastCtxReturned(), OpenSslCredentialsFake_LastInstallCtx());
}

TEST(SolidSyslogOpenSslStream, OpenFailsWhenTheCredentialsCannotBeInstalled)
{
    OpenSslCredentialsFake_SetInstallSucceeds(false);

    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogOpenSslStream, OpenUnwindsWhenTheCredentialsCannotBeInstalled)
{
    OpenSslCredentialsFake_SetInstallSucceeds(false);

    SolidSyslogStream_Open(stream, addr);

    LONGS_EQUAL(1, StreamFake_CloseCallCount(transport));
}

TEST(SolidSyslogOpenSslStream, OpenFailsWhenNothingAuthorisesThePeer)
{
    OpenSslCredentialsFake_SetTrustAnchorsInstalled(false);

    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
}

TEST(SolidSyslogOpenSslStream, OpenReportsThatNothingAuthorisesThePeer)
{
    OpenSslCredentialsFake_SetTrustAnchorsInstalled(false);

    SolidSyslogStream_Open(stream, addr);

    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_ERROR,
        &SolidSyslogOpenSslStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NO_PEER_AUTHORISATION
    );
}

TEST(SolidSyslogOpenSslStream, OpenSucceedsWhenFingerprintsAuthoriseThePeerWithoutTrustAnchors)
{
    OpenSslCredentialsFake_SetTrustAnchorsInstalled(false);
    OpenSslCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);

    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
}

/* The verify mode must be set whether or not trust anchors were installed -
 * this is the one place in the change that could fail open rather than closed. */
TEST(SolidSyslogOpenSslStream, OpenRequiresPeerVerificationWithoutTrustAnchors)
{
    OpenSslCredentialsFake_SetTrustAnchorsInstalled(false);
    OpenSslCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);

    SolidSyslogStream_Open(stream, addr);

    LONGS_EQUAL(SSL_VERIFY_PEER, OpenSslFake_LastVerifyMode());
}

TEST(SolidSyslogOpenSslStream, CloseReleasesTheCredentials)
{
    SolidSyslogStream_Open(stream, addr);

    SolidSyslogStream_Close(stream);

    LONGS_EQUAL(1, OpenSslCredentialsFake_ReleaseCallCount());
}

TEST(SolidSyslogOpenSslStream, AFailedOpenStillReleasesTheCredentials)
{
    OpenSslCredentialsFake_SetInstallSucceeds(false);

    SolidSyslogStream_Open(stream, addr);

    LONGS_EQUAL(1, OpenSslCredentialsFake_ReleaseCallCount());
}

TEST(SolidSyslogOpenSslStream, CloseWithoutAnOpenReleasesNothing)
{
    SolidSyslogStream_Close(stream);

    LONGS_EQUAL(0, OpenSslCredentialsFake_ReleaseCallCount());
}

TEST(SolidSyslogOpenSslStream, ASecondCloseDoesNotReleaseTheCredentialsAgain)
{
    SolidSyslogStream_Open(stream, addr);

    SolidSyslogStream_Close(stream);
    SolidSyslogStream_Close(stream);

    LONGS_EQUAL(1, OpenSslCredentialsFake_ReleaseCallCount());
}

TEST(SolidSyslogOpenSslStream, OpenFailsWhenAPinIsMalformed)
{
    static const char* const pins[] = {"sha-256:AA"};
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateStreamWithUpdatedConfig();
    OpenSslCredentialsFake_SetFingerprints(pins, 1);

    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_FINGERPRINT_MALFORMED
    );
}

TEST(SolidSyslogOpenSslStream, OpenWarnsOfASha1Pin)
{
    static const char* const pins[] = {"sha-1:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D"};
    FakeProfile_Value.ServerName = "logs.example";
    ReCreateStreamWithUpdatedConfig();
    OpenSslCredentialsFake_SetFingerprints(pins, 1);

    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
    CHECK_ERROR_REPORTED_ONCE(
        SOLIDSYSLOG_SEVERITY_WARNING,
        &SolidSyslogOpenSslStreamErrorSource,
        SOLIDSYSLOG_CAT_BAD_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_FINGERPRINT_SHA1
    );
}

TEST(SolidSyslogOpenSslStream, OpenDoesNotWarnOfAMissingServerNameWhenThePeerIsPinned)
{
    /* The profile leaves ServerName unset. */
    OpenSslCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);

    CHECK_TRUE(SolidSyslogStream_Open(stream, addr));
    CALLED_FAKE(ErrorHandlerFake_Handle, NEVER);
}

TEST(SolidSyslogOpenSslStream, OpenInstallsAVerifyCallback)
{
    SolidSyslogStream_Open(stream, addr);

    CHECK_TRUE(OpenSslFake_LastVerifyCallback() != nullptr);
}

TEST(SolidSyslogOpenSslStream, OpenAttachesTheStreamToTheSessionForTheVerifyCallback)
{
    SolidSyslogStream_Open(stream, addr);

    LONGS_EQUAL(0, OpenSslFake_LastSslExDataIndex());
    POINTERS_EQUAL(stream, OpenSslFake_LastSslExData());
}

TEST(SolidSyslogOpenSslStream, OpenFailsWhenTheSessionCannotCarryTheStream)
{
    OpenSslFake_SetSslExDataFails(true);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_SESSION_INIT_FAILED
    );
}

TEST(SolidSyslogOpenSslStream, VerifyCallbackRefusesAPinnedPeerWhoseFingerprintMatchesNone)
{
    static const uint8_t presented[32] = {0xFF};
    OpenSslCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);
    OpenSslFake_SetCertDigest(presented, sizeof(presented));

    LONGS_EQUAL(0, OpenThenVerifyLeaf(1));
    LONGS_EQUAL(X509_V_ERR_APPLICATION_VERIFICATION, OpenSslFake_StoreCtxError());
}

TEST(SolidSyslogOpenSslStream, VerifyCallbackAcceptsAPinnedPeerWhoseFingerprintMatches)
{
    OpenSslCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);
    OpenSslFake_SetCertDigest(TEST_SHA256_DIGEST, sizeof(TEST_SHA256_DIGEST));

    LONGS_EQUAL(1, OpenThenVerifyLeaf(1));
    LONGS_EQUAL(X509_V_OK, OpenSslFake_StoreCtxError());
    POINTERS_EQUAL(EVP_sha256(), OpenSslFake_LastDigestMd());
}

TEST(SolidSyslogOpenSslStream, VerifyCallbackDigestsWithSha1ForASha1Pin)
{
    static const char* const pins[] = {"sha-1:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D"};
    static const uint8_t presented[20] = {0xE1, 0x2D, 0x53, 0x2B, 0x7C, 0x6B, 0x8A, 0x29, 0xA2, 0x76,
                                          0xC8, 0x64, 0x36, 0x0B, 0x08, 0x4B, 0x7A, 0xF1, 0x9E, 0x9D};
    OpenSslCredentialsFake_SetFingerprints(pins, 1);
    OpenSslFake_SetCertDigest(presented, sizeof(presented));

    LONGS_EQUAL(1, OpenThenVerifyLeaf(1));
    POINTERS_EQUAL(EVP_sha1(), OpenSslFake_LastDigestMd());
}

TEST(SolidSyslogOpenSslStream, VerifyCallbackRefusesAPinnedPeerWhoseCertificateWillNotDigest)
{
    OpenSslCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);
    OpenSslFake_SetDigestFails(true);

    LONGS_EQUAL(0, OpenThenVerifyLeaf(1));
    LONGS_EQUAL(X509_V_ERR_APPLICATION_VERIFICATION, OpenSslFake_StoreCtxError());
}

TEST(SolidSyslogOpenSslStream, VerifyCallbackLeavesAnIssuerCertificateToOpenSsl)
{
    OpenSslCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);
    OpenSslFake_SetStoreCtxDepth(1);

    LONGS_EQUAL(1, OpenThenVerifyLeaf(1));
    POINTERS_EQUAL(nullptr, OpenSslFake_LastDigestMd());
}

TEST(SolidSyslogOpenSslStream, VerifyCallbackLeavesAnUnpinnedPeerToOpenSsl)
{
    LONGS_EQUAL(0, OpenThenVerifyLeaf(0));
    POINTERS_EQUAL(nullptr, OpenSslFake_LastDigestMd());
}

TEST(SolidSyslogOpenSslStream, VerifyCallbackWaivesChainTrustForAPinnedPeerWithoutTrustAnchors)
{
    OpenSslCredentialsFake_SetTrustAnchorsInstalled(false);
    OpenSslCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);
    OpenSslFake_SetCertDigest(TEST_SHA256_DIGEST, sizeof(TEST_SHA256_DIGEST));
    OpenSslFake_SetStoreCtxError(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);

    LONGS_EQUAL(1, OpenThenVerifyLeaf(0));
}

TEST(SolidSyslogOpenSslStream, VerifyCallbackWaivesEveryObjectionAMissingTrustAnchorRaises)
{
    static const int chainTrustErrors[] = {
        X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
        X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
        X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
        X509_V_ERR_CERT_UNTRUSTED,
    };
    OpenSslCredentialsFake_SetTrustAnchorsInstalled(false);
    OpenSslCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);
    OpenSslFake_SetCertDigest(TEST_SHA256_DIGEST, sizeof(TEST_SHA256_DIGEST));
    SolidSyslogStream_Open(stream, addr);

    for (int error : chainTrustErrors)
    {
        OpenSslFake_SetStoreCtxError(error);
        LONGS_EQUAL_TEXT(
            1,
            OpenSslFake_LastVerifyCallback()(0, OpenSslFake_StoreCtx()),
            StringFrom(error).asCharString()
        );
    }
}

TEST(SolidSyslogOpenSslStream, VerifyCallbackDoesNotWaiveTheCertificatesOwnValidityForAPinnedPeer)
{
    OpenSslCredentialsFake_SetTrustAnchorsInstalled(false);
    OpenSslCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);
    OpenSslFake_SetCertDigest(TEST_SHA256_DIGEST, sizeof(TEST_SHA256_DIGEST));
    OpenSslFake_SetStoreCtxError(X509_V_ERR_CERT_HAS_EXPIRED);

    LONGS_EQUAL(0, OpenThenVerifyLeaf(0));
    LONGS_EQUAL(X509_V_ERR_CERT_HAS_EXPIRED, OpenSslFake_StoreCtxError());
}

TEST(SolidSyslogOpenSslStream, VerifyCallbackRequiresTheChainTooWhenTrustAnchorsAreInstalled)
{
    OpenSslCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);
    OpenSslFake_SetCertDigest(TEST_SHA256_DIGEST, sizeof(TEST_SHA256_DIGEST));
    OpenSslFake_SetStoreCtxError(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);

    LONGS_EQUAL(0, OpenThenVerifyLeaf(0));
    LONGS_EQUAL(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, OpenSslFake_StoreCtxError());
}

TEST(SolidSyslogOpenSslStream, OpenReportsThatThePeerFingerprintDidNotMatch)
{
    ArrangeCertificateVerificationFailure(X509_V_ERR_APPLICATION_VERIFICATION);
    CHECK_FALSE(SolidSyslogStream_Open(stream, addr));
    CHECK_OPEN_UNWOUND_WITH_ERROR(
        transport,
        SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_FINGERPRINT_MISMATCHED
    );
}

/* Returning zero above the leaf stops OpenSSL before the leaf is reached, so a
   collector presenting its issuer would never have its pin consulted. */
TEST(SolidSyslogOpenSslStream, VerifyCallbackWaivesAChainTrustErrorAboveTheLeafForAPinnedPeerWithoutTrustAnchors)
{
    OpenSslCredentialsFake_SetTrustAnchorsInstalled(false);
    OpenSslCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);

    LONGS_EQUAL(1, OpenThenVerifyIssuer(0, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
    POINTERS_EQUAL(nullptr, OpenSslFake_LastDigestMd());
}

TEST(SolidSyslogOpenSslStream, VerifyCallbackDoesNotWaiveAboveTheLeafWhenTrustAnchorsAreInstalled)
{
    OpenSslCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);

    LONGS_EQUAL(0, OpenThenVerifyIssuer(0, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
}

TEST(SolidSyslogOpenSslStream, VerifyCallbackDoesNotWaiveTheCertificatesOwnValidityAboveTheLeaf)
{
    OpenSslCredentialsFake_SetTrustAnchorsInstalled(false);
    OpenSslCredentialsFake_SetFingerprints(TEST_SHA256_PINS, 1);

    LONGS_EQUAL(0, OpenThenVerifyIssuer(0, X509_V_ERR_CERT_HAS_EXPIRED));
}

TEST(SolidSyslogOpenSslStream, VerifyCallbackLeavesAnIssuerToOpenSslWhenNoPeerIsPinned)
{
    LONGS_EQUAL(0, OpenThenVerifyIssuer(0, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
}

TEST(SolidSyslogOpenSslStream, VersionReportsTheConfiguredFunctionsValue)
{
    FakeVersion_ReturnValue = 7U;
    config.Version = FakeVersion;
    ReCreateStreamWithUpdatedConfig();

    LONGS_EQUAL(7, SolidSyslogStream_Version(stream));
}

TEST(SolidSyslogOpenSslStream, VersionFunctionReceivesVersionContext)
{
    int context = 0;
    config.Version = FakeVersion;
    config.VersionContext = &context;
    ReCreateStreamWithUpdatedConfig();

    SolidSyslogStream_Version(stream);

    POINTERS_EQUAL(&context, FakeVersion_LastContext);
}

TEST(SolidSyslogOpenSslStream, VersionIsZeroWhenNoFunctionIsConfigured)
{
    LONGS_EQUAL(0, SolidSyslogStream_Version(stream));
}

TEST(SolidSyslogOpenSslStream, OpenPullsTheProfile)
{
    config.Profile = FakeProfile;
    ReCreateStreamWithUpdatedConfig();

    SolidSyslogStream_Open(stream, addr);

    LONGS_EQUAL(1, FakeProfile_CallCount);
}
