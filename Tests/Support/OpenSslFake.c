#include "OpenSslFake.h"

#include <openssl/ssl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* -------------------------------------------------------------------------
 * Captured state - one section per OpenSSL API call. Tests read these via
 * accessors below; production reaches libssl through the link-interposed
 * functions at the bottom of the file.
 * ------------------------------------------------------------------------- */

/* Sentinel storage for opaque OpenSSL types - our fake returns stable
 * pointers to these so tests can assert pointer-chain plumbing with
 * POINTERS_EQUAL. */
static char fakeCtxStorage;
static char fakeMethodStorage;
static char fakeSslStorage;
static char fakeBioMethStorage;
static char fakeSha256Storage;

/* HMAC / EVP_sha256 / OPENSSL_cleanse capture - backs the at-rest
 * HMAC-SHA256 SecurityPolicy tests. */
enum
{
    OPENSSLFAKE_MAX_KEY = 64,
    OPENSSLFAKE_MAX_INPUT = 256
};

static int hmacCallCount;
static const void* lastHmacMd;
static uint8_t lastHmacKey[OPENSSLFAKE_MAX_KEY];
static int lastHmacKeyLen;
static uint8_t lastHmacInput[OPENSSLFAKE_MAX_INPUT];
static size_t lastHmacInputLen;
static bool hmacFails;

static int cleanseCallCount;
static const void* lastCleanseBuf;
static size_t lastCleanseLen;

/* AES-256-GCM fake - a capture-and-canned-return test double, NOT a cipher. The
 * production policy is a thin adapter that shuttles bytes through the EVP_*
 * sequence; the unit tests verify that wiring (which key, nonce, AAD and
 * plaintext reach OpenSSL, in what order, and how success/failure propagate).
 * The EVP calls therefore capture their arguments and return canned results:
 * Encrypt/DecryptUpdate copy input to output unchanged, GET_TAG writes a fixed
 * tag, and DecryptFinal returns a settable verdict. Genuine AES-256-GCM
 * correctness - round-trip, tamper detection, wrong-key rejection - is owned by
 * the OpenSslIntegration suite against real libcrypto. */
enum
{
    FAKE_GCM_KEY_SIZE = 32,
    FAKE_GCM_NONCE_SIZE = 12,
    FAKE_GCM_TAG_SIZE = 16,
    FAKE_GCM_MAX_AAD = 16,
    FAKE_GCM_MAX_BODY = 256
};

/* A single direction flag is all the state the double needs: the production code
 * allocates one EVP context per seal or open, uses it, and frees it before the
 * next - never two at once. The flag lets Update capture the plaintext only on
 * encrypt. The handle is a char sentinel (like the SSL/BIO fakes). */
static bool fakeGcmEncrypting;
static char fakeGcmCtxStorage;
static char fakeAesGcmCipherStorage;

static int gcmSealCount; /* GET_TAG calls */
static int gcmOpenCount; /* DecryptFinal calls */
static uint8_t lastGcmKey[FAKE_GCM_KEY_SIZE];
static uint8_t lastGcmNonce[FAKE_GCM_NONCE_SIZE];
static uint8_t lastGcmAad[FAKE_GCM_MAX_AAD];
static size_t lastGcmAadLen;
static uint8_t lastGcmPlaintext[FAKE_GCM_MAX_BODY];
static size_t lastGcmPlaintextLen;

/* Which step of the EVP seal/open sequence the double should fail. The adapter
 * threads every EVP return through an && chain, so failing any one step lets a
 * test pin that step's error path. Default OPENSSLFAKE_GCM_STEP_NONE = all
 * succeed. */
static enum OpenSslFakeGcmStep gcmFailStep;

static int randCallCount;
static const void* lastRandBuf;
static int lastRandLen;
static bool randFails;

/* Pool of fake BIOs. Each slot is independent so callers can exercise
 * multiple BIOs without aliasing. The address of `slot` is the BIO handle
 * returned from BIO_new; `data` is the per-BIO storage that backs
 * BIO_set_data / BIO_get_data. */
typedef struct
{
    char slot;
    void* data;
} FakeBio;

enum
{
    FAKE_BIO_POOL_SIZE = 4
};

static FakeBio fakeBios[FAKE_BIO_POOL_SIZE];
static int fakeBioCount;

/* SSL_CTX_new */
static int ctxNewCallCount;
static const SSL_METHOD* lastCtxNewMethodArg;
static bool ctxNewFails;

/* SSL_CTX_load_verify_locations */
static SSL_CTX* lastLoadVerifyLocationsCtxArg;
static const char* lastCaBundlePath;
static bool loadVerifyLocationsFails;

/* SSL_CTX_set_verify */
static SSL_CTX* lastSetVerifyCtxArg;
static int lastVerifyMode;
static SSL_verify_cb lastVerifyCallback;

/* SSL ex_data / X509_STORE_CTX / X509_digest */
enum
{
    FAKE_SSL_STORE_CTX_IDX = 7,
    FAKE_DIGEST_MAX = 64
};

static int lastSslExDataIndex;
static void* lastSslExData;
static bool sslExDataFails;
static int fakeStoreCtxStorage;
static int fakeCertStorage;
static int storeCtxDepth;
static int storeCtxError;
static uint8_t certDigest[FAKE_DIGEST_MAX];
static size_t certDigestLength;
static bool digestFails;
static const EVP_MD* lastDigestMd;
static int fakeSha1Storage;

/* SSL_CTX_ctrl (SET_MIN_PROTO_VERSION) */
static SSL_CTX* lastSslCtxCtrlCtxArg;
static long lastMinProtoVersion;
static bool minProtoVersionFails;

/* SSL_CTX_set_cipher_list */
static int setCipherListCallCount;
static SSL_CTX* lastSetCipherListCtxArg;
static const char* lastCipherList;
static bool setCipherListFails;

/* SSL_CTX_set_ciphersuites */
static int setCipherSuitesCallCount;
static const char* lastCipherSuites;
static bool setCipherSuitesFails;

/* SSL_new */
static int sslNewCallCount;
static SSL_CTX* lastSslNewCtxArg;
static bool sslNewFails;

/* BIO_meth_new */
static bool bioMethNewFails;

/* BIO_meth_free */
static int bioMethFreeCallCount;
static BIO_METHOD* lastBioMethFreeArg;

/* BIO_meth_set_read / BIO_meth_set_write */
static BIO_METHOD* lastBioMethSetReadMethodArg;
static int (*lastBioReadCallback)(BIO*, char*, int);
static long (*lastBioCtrlCallback)(BIO*, int, long, void*);
static int (*lastBioCreateCallback)(BIO*);
static int lastSetInitArg;
static BIO_METHOD* lastBioMethSetWriteMethodArg;
static int (*lastBioWriteCallback)(BIO*, const char*, int);

/* BIO_new */
static int bioNewCallCount;
static const BIO_METHOD* lastBioNewMethodArg;
static bool bioNewFails;

/* BIO_set_data / BIO_get_data */
static BIO* lastSetDataBioArg;
static void* lastSetDataArg;
static BIO* lastGetDataBioArg;

/* SSL_set_bio */
static int setBioCallCount;
static SSL* lastSetBioSslArg;
static BIO* lastSetBioReadBioArg;
static BIO* lastSetBioWriteBioArg;

/* SSL_ctrl (SET_TLSEXT_HOSTNAME) */
static SSL* lastSslCtrlSslArg;
static const char* lastSniHostname;
static bool sniHostnameFails;

/* SSL_set1_host */
static SSL* lastSet1HostSslArg;
static const char* lastSet1Host;
static bool set1HostFails;

/* SSL_connect */
static int connectCallCount;
static SSL* lastConnectSslArg;
static bool connectFails;
static int connectReturnSequence[OPENSSLFAKE_MAX_CONNECT_RETURNS];
static int connectReturnSequenceLen;

/* SSL_write */
static int writeCallCount;
static SSL* lastWriteSslArg;
static const void* lastWriteBuf;
static int lastWriteSize;
static bool writeFails;
static bool writeReturnOverride;
static int writeReturnValue;

/* SSL_read */
static int sslReadCallCount;
static SSL* lastSslReadSslArg;
static void* lastSslReadBuf;
static int lastSslReadSize;
static bool readReturnOverride;
static int readReturnValue;

/* SSL_get_error */
static int getErrorCallCount;
static int getErrorReturnValue;

/* SSL_get_verify_result */
static long verifyResultValue;

/* BIO_set_flags / BIO_clear_flags */
static int bioSetFlagsCallCount;
static int lastBioSetFlags;
static int bioClearFlagsCallCount;

/* SSL_shutdown */
static int shutdownCallCount;
static SSL* lastShutdownSslArg;

/* SSL_free */
static int freeCallCount;
static SSL* lastFreeSslArg;

/* SSL_CTX_free */
static int ctxFreeCallCount;
static SSL_CTX* lastCtxFreeCtxArg;

/* SSL_CTX_use_certificate_chain_file */
static int useCertChainFileCallCount;
static SSL_CTX* lastUseCertChainFileCtxArg;
static const char* lastClientCertChainPath;
static bool useCertChainFileFails;

/* SSL_CTX_use_PrivateKey_file */
static int usePrivateKeyFileCallCount;
static SSL_CTX* lastUsePrivateKeyFileCtxArg;
static const char* lastClientKeyPath;
static int lastClientKeyFileType;
static bool usePrivateKeyFileFails;

/* SSL_CTX_check_private_key */
static int checkPrivateKeyCallCount;
static SSL_CTX* lastCheckPrivateKeyCtxArg;
static bool checkPrivateKeyFails;

/* -------------------------------------------------------------------------
 * Reset - zero every captured value.
 * ------------------------------------------------------------------------- */

void OpenSslFake_Reset(void)
{
    ctxNewCallCount = 0;
    lastCtxNewMethodArg = NULL;
    ctxNewFails = false;
    lastLoadVerifyLocationsCtxArg = NULL;
    lastCaBundlePath = NULL;
    loadVerifyLocationsFails = false;
    lastSetVerifyCtxArg = NULL;
    lastVerifyMode = 0;
    lastVerifyCallback = NULL;
    lastSslExDataIndex = -1;
    lastSslExData = NULL;
    sslExDataFails = false;
    storeCtxDepth = 0;
    storeCtxError = X509_V_OK;
    certDigestLength = 0;
    digestFails = false;
    lastDigestMd = NULL;
    lastSslCtxCtrlCtxArg = NULL;
    lastMinProtoVersion = 0;
    minProtoVersionFails = false;
    setCipherListCallCount = 0;
    lastSetCipherListCtxArg = NULL;
    lastCipherList = NULL;
    setCipherListFails = false;
    setCipherSuitesCallCount = 0;
    lastCipherSuites = NULL;
    setCipherSuitesFails = false;
    sslNewCallCount = 0;
    lastSslNewCtxArg = NULL;
    sslNewFails = false;
    bioMethNewFails = false;
    bioMethFreeCallCount = 0;
    lastBioMethFreeArg = NULL;
    lastBioMethSetReadMethodArg = NULL;
    lastBioReadCallback = NULL;
    lastBioCtrlCallback = NULL;
    lastBioCreateCallback = NULL;
    lastSetInitArg = 0;
    lastBioMethSetWriteMethodArg = NULL;
    lastBioWriteCallback = NULL;
    bioNewCallCount = 0;
    lastBioNewMethodArg = NULL;
    bioNewFails = false;
    fakeBioCount = 0;
    for (int i = 0; i < FAKE_BIO_POOL_SIZE; i++)
    {
        fakeBios[i].data = NULL;
    }
    lastSetDataBioArg = NULL;
    lastSetDataArg = NULL;
    lastGetDataBioArg = NULL;
    setBioCallCount = 0;
    lastSetBioSslArg = NULL;
    lastSetBioReadBioArg = NULL;
    lastSetBioWriteBioArg = NULL;
    lastSslCtrlSslArg = NULL;
    lastSniHostname = NULL;
    sniHostnameFails = false;
    lastSet1HostSslArg = NULL;
    lastSet1Host = NULL;
    set1HostFails = false;
    connectCallCount = 0;
    lastConnectSslArg = NULL;
    connectFails = false;
    connectReturnSequenceLen = 0;
    for (int i = 0; i < OPENSSLFAKE_MAX_CONNECT_RETURNS; i++)
    {
        connectReturnSequence[i] = 0;
    }
    writeCallCount = 0;
    lastWriteSslArg = NULL;
    lastWriteBuf = NULL;
    lastWriteSize = 0;
    writeFails = false;
    writeReturnOverride = false;
    writeReturnValue = 0;
    sslReadCallCount = 0;
    lastSslReadSslArg = NULL;
    lastSslReadBuf = NULL;
    lastSslReadSize = 0;
    readReturnOverride = false;
    readReturnValue = 0;
    getErrorCallCount = 0;
    getErrorReturnValue = 0;
    verifyResultValue = X509_V_OK;
    bioSetFlagsCallCount = 0;
    lastBioSetFlags = 0;
    bioClearFlagsCallCount = 0;
    shutdownCallCount = 0;
    lastShutdownSslArg = NULL;
    freeCallCount = 0;
    lastFreeSslArg = NULL;
    ctxFreeCallCount = 0;
    lastCtxFreeCtxArg = NULL;
    useCertChainFileCallCount = 0;
    lastUseCertChainFileCtxArg = NULL;
    lastClientCertChainPath = NULL;
    useCertChainFileFails = false;
    usePrivateKeyFileCallCount = 0;
    lastUsePrivateKeyFileCtxArg = NULL;
    lastClientKeyPath = NULL;
    lastClientKeyFileType = 0;
    usePrivateKeyFileFails = false;
    checkPrivateKeyCallCount = 0;
    lastCheckPrivateKeyCtxArg = NULL;
    checkPrivateKeyFails = false;
    hmacCallCount = 0;
    lastHmacMd = NULL;
    lastHmacKeyLen = 0;
    lastHmacInputLen = 0;
    hmacFails = false;
    memset(lastHmacKey, 0, sizeof lastHmacKey);
    memset(lastHmacInput, 0, sizeof lastHmacInput);
    cleanseCallCount = 0;
    lastCleanseBuf = NULL;
    lastCleanseLen = 0;
    fakeGcmEncrypting = false;
    gcmSealCount = 0;
    gcmOpenCount = 0;
    gcmFailStep = OPENSSLFAKE_GCM_STEP_NONE;
    lastGcmAadLen = 0;
    lastGcmPlaintextLen = 0;
    memset(lastGcmKey, 0, sizeof lastGcmKey);
    memset(lastGcmNonce, 0, sizeof lastGcmNonce);
    memset(lastGcmAad, 0, sizeof lastGcmAad);
    memset(lastGcmPlaintext, 0, sizeof lastGcmPlaintext);
    randCallCount = 0;
    lastRandBuf = NULL;
    lastRandLen = 0;
    randFails = false;
}

/* -------------------------------------------------------------------------
 * Accessors - grouped by the OpenSSL function they describe.
 * ------------------------------------------------------------------------- */

int OpenSslFake_CtxNewCallCount(void)
{
    return ctxNewCallCount;
}

const SSL_METHOD* OpenSslFake_LastCtxNewMethodArg(void)
{
    return lastCtxNewMethodArg;
}

SSL_CTX* OpenSslFake_LastCtxReturned(void)
{
    return (SSL_CTX*) &fakeCtxStorage;
}

SSL_CTX* OpenSslFake_LastLoadVerifyLocationsCtxArg(void)
{
    return lastLoadVerifyLocationsCtxArg;
}

const char* OpenSslFake_LastCaBundlePath(void)
{
    return lastCaBundlePath;
}

SSL_CTX* OpenSslFake_LastSetVerifyCtxArg(void)
{
    return lastSetVerifyCtxArg;
}

int OpenSslFake_LastVerifyMode(void)
{
    return lastVerifyMode;
}

SSL_CTX* OpenSslFake_LastSslCtxCtrlCtxArg(void)
{
    return lastSslCtxCtrlCtxArg;
}

long OpenSslFake_LastMinProtoVersion(void)
{
    return lastMinProtoVersion;
}

int OpenSslFake_SslNewCallCount(void)
{
    return sslNewCallCount;
}

SSL_CTX* OpenSslFake_LastSslNewCtxArg(void)
{
    return lastSslNewCtxArg;
}

SSL* OpenSslFake_LastSslReturned(void)
{
    return (SSL*) &fakeSslStorage;
}

BIO_METHOD* OpenSslFake_LastBioMethReturned(void)
{
    return (BIO_METHOD*) &fakeBioMethStorage;
}

BIO_METHOD* OpenSslFake_LastBioMethSetReadMethodArg(void)
{
    return lastBioMethSetReadMethodArg;
}

int (*OpenSslFake_LastBioReadCallback(void))(BIO*, char*, int)
{
    return lastBioReadCallback;
}

long (*OpenSslFake_LastBioCtrlCallback(void))(BIO*, int, long, void*)
{
    return lastBioCtrlCallback;
}

int (*OpenSslFake_LastBioCreateCallback(void))(BIO*)
{
    return lastBioCreateCallback;
}

int OpenSslFake_LastSetInitArg(void)
{
    return lastSetInitArg;
}

BIO_METHOD* OpenSslFake_LastBioMethSetWriteMethodArg(void)
{
    return lastBioMethSetWriteMethodArg;
}

int (*OpenSslFake_LastBioWriteCallback(void))(BIO*, const char*, int)
{
    return lastBioWriteCallback;
}

int OpenSslFake_BioNewCallCount(void)
{
    return bioNewCallCount;
}

const BIO_METHOD* OpenSslFake_LastBioNewMethodArg(void)
{
    return lastBioNewMethodArg;
}

BIO* OpenSslFake_LastBioReturned(void)
{
    return fakeBioCount > 0 ? (BIO*) &fakeBios[fakeBioCount - 1].slot : NULL;
}

BIO* OpenSslFake_LastSetDataBioArg(void)
{
    return lastSetDataBioArg;
}

void* OpenSslFake_LastSetDataArg(void)
{
    return lastSetDataArg;
}

BIO* OpenSslFake_LastGetDataBioArg(void)
{
    return lastGetDataBioArg;
}

int OpenSslFake_SetBioCallCount(void)
{
    return setBioCallCount;
}

SSL* OpenSslFake_LastSetBioSslArg(void)
{
    return lastSetBioSslArg;
}

BIO* OpenSslFake_LastSetBioReadBioArg(void)
{
    return lastSetBioReadBioArg;
}

BIO* OpenSslFake_LastSetBioWriteBioArg(void)
{
    return lastSetBioWriteBioArg;
}

SSL* OpenSslFake_LastSslCtrlSslArg(void)
{
    return lastSslCtrlSslArg;
}

const char* OpenSslFake_LastSniHostname(void)
{
    return lastSniHostname;
}

SSL* OpenSslFake_LastSet1HostSslArg(void)
{
    return lastSet1HostSslArg;
}

const char* OpenSslFake_LastSet1Host(void)
{
    return lastSet1Host;
}

int OpenSslFake_ConnectCallCount(void)
{
    return connectCallCount;
}

SSL* OpenSslFake_LastConnectSslArg(void)
{
    return lastConnectSslArg;
}

int OpenSslFake_WriteCallCount(void)
{
    return writeCallCount;
}

SSL* OpenSslFake_LastWriteSslArg(void)
{
    return lastWriteSslArg;
}

const void* OpenSslFake_LastWriteBuf(void)
{
    return lastWriteBuf;
}

int OpenSslFake_LastWriteSize(void)
{
    return lastWriteSize;
}

int OpenSslFake_SslReadCallCount(void)
{
    return sslReadCallCount;
}

SSL* OpenSslFake_LastSslReadSslArg(void)
{
    return lastSslReadSslArg;
}

void* OpenSslFake_LastSslReadBuf(void)
{
    return lastSslReadBuf;
}

int OpenSslFake_LastSslReadSize(void)
{
    return lastSslReadSize;
}

int OpenSslFake_ShutdownCallCount(void)
{
    return shutdownCallCount;
}

SSL* OpenSslFake_LastShutdownSslArg(void)
{
    return lastShutdownSslArg;
}

int OpenSslFake_FreeCallCount(void)
{
    return freeCallCount;
}

SSL* OpenSslFake_LastFreeSslArg(void)
{
    return lastFreeSslArg;
}

int OpenSslFake_CtxFreeCallCount(void)
{
    return ctxFreeCallCount;
}

SSL_CTX* OpenSslFake_LastCtxFreeCtxArg(void)
{
    return lastCtxFreeCtxArg;
}

/* -------------------------------------------------------------------------
 * Link-time substitution for OpenSSL - replaces libssl symbols in the test
 * binary. Production links real libssl; tests never link -lssl.
 * Each function records its args for test assertion. Return values are
 * plausible-success stubs; where behaviour needs switching for failure-path
 * tests, add a setter (e.g. OpenSslFake_SetConnectFails) in a later cycle.
 * ------------------------------------------------------------------------- */

const SSL_METHOD* TLS_client_method(void)
{
    return (const SSL_METHOD*) &fakeMethodStorage;
}

SSL_CTX* SSL_CTX_new(const SSL_METHOD* method)
{
    ctxNewCallCount++;
    lastCtxNewMethodArg = method;
    return ctxNewFails ? NULL : (SSL_CTX*) &fakeCtxStorage;
}

void OpenSslFake_SetCtxNewFails(bool fails)
{
    ctxNewFails = fails;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters) -- signature fixed by OpenSSL API
int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* CAfile, const char* CApath)
{
    (void) CApath;
    lastLoadVerifyLocationsCtxArg = ctx;
    lastCaBundlePath = CAfile;
    return loadVerifyLocationsFails ? 0 : 1;
}

void OpenSslFake_SetLoadVerifyLocationsFails(bool fails)
{
    loadVerifyLocationsFails = fails;
}

void SSL_CTX_set_verify(SSL_CTX* ctx, int mode, SSL_verify_cb verify_callback)
{
    lastSetVerifyCtxArg = ctx;
    lastVerifyMode = mode;
    lastVerifyCallback = verify_callback;
}

SSL_verify_cb OpenSslFake_LastVerifyCallback(void)
{
    return lastVerifyCallback;
}

int SSL_set_ex_data(SSL* ssl, int idx, void* data)
{
    (void) ssl;
    lastSslExDataIndex = idx;
    lastSslExData = data;
    return sslExDataFails ? 0 : 1;
}

void* SSL_get_ex_data(const SSL* ssl, int idx)
{
    (void) ssl;
    return (idx == lastSslExDataIndex) ? lastSslExData : NULL;
}

int OpenSslFake_LastSslExDataIndex(void)
{
    return lastSslExDataIndex;
}

void* OpenSslFake_LastSslExData(void)
{
    return lastSslExData;
}

void OpenSslFake_SetSslExDataFails(bool fails)
{
    sslExDataFails = fails;
}

int SSL_get_ex_data_X509_STORE_CTX_idx(void)
{
    return FAKE_SSL_STORE_CTX_IDX;
}

void* X509_STORE_CTX_get_ex_data(const X509_STORE_CTX* ctx, int idx)
{
    (void) ctx;
    return (idx == FAKE_SSL_STORE_CTX_IDX) ? (void*) &fakeSslStorage : NULL;
}

int X509_STORE_CTX_get_error_depth(const X509_STORE_CTX* ctx)
{
    (void) ctx;
    return storeCtxDepth;
}

int X509_STORE_CTX_get_error(const X509_STORE_CTX* ctx)
{
    (void) ctx;
    return storeCtxError;
}

void X509_STORE_CTX_set_error(X509_STORE_CTX* ctx, int s)
{
    (void) ctx;
    storeCtxError = s;
}

X509* X509_STORE_CTX_get_current_cert(const X509_STORE_CTX* ctx)
{
    (void) ctx;
    return (X509*) &fakeCertStorage;
}

int X509_digest(const X509* data, const EVP_MD* type, unsigned char* md, unsigned int* len)
{
    (void) data;
    lastDigestMd = type;
    memcpy(md, certDigest, certDigestLength);
    *len = (unsigned int) certDigestLength;
    return digestFails ? 0 : 1;
}

const EVP_MD* EVP_sha1(void)
{
    return (const EVP_MD*) &fakeSha1Storage;
}

X509_STORE_CTX* OpenSslFake_StoreCtx(void)
{
    return (X509_STORE_CTX*) &fakeStoreCtxStorage;
}

void OpenSslFake_SetStoreCtxDepth(int depth)
{
    storeCtxDepth = depth;
}

void OpenSslFake_SetStoreCtxError(int error)
{
    storeCtxError = error;
}

int OpenSslFake_StoreCtxError(void)
{
    return storeCtxError;
}

void OpenSslFake_SetCertDigest(const uint8_t* digest, size_t length)
{
    memcpy(certDigest, digest, length);
    certDigestLength = length;
}

void OpenSslFake_SetDigestFails(bool fails)
{
    digestFails = fails;
}

const void* OpenSslFake_LastDigestMd(void)
{
    return lastDigestMd;
}

/* SSL_CTX_set_min_proto_version is a macro forwarding to SSL_CTX_ctrl; fake
 * intercepts the ctrl call for the min-proto command only. */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters) -- signature fixed by OpenSSL API
long SSL_CTX_ctrl(SSL_CTX* ctx, int cmd, long larg, void* parg)
{
    (void) parg;
    lastSslCtxCtrlCtxArg = ctx;
    if (cmd == SSL_CTRL_SET_MIN_PROTO_VERSION)
    {
        lastMinProtoVersion = larg;
        return minProtoVersionFails ? 0 : 1;
    }
    return 1;
}

void OpenSslFake_SetMinProtoVersionFails(bool fails)
{
    minProtoVersionFails = fails;
}

int SSL_CTX_set_cipher_list(SSL_CTX* ctx, const char* str)
{
    setCipherListCallCount++;
    lastSetCipherListCtxArg = ctx;
    lastCipherList = str;
    return setCipherListFails ? 0 : 1;
}

void OpenSslFake_SetCipherListFails(bool fails)
{
    setCipherListFails = fails;
}

int OpenSslFake_SetCipherListCallCount(void)
{
    return setCipherListCallCount;
}

SSL_CTX* OpenSslFake_LastSetCipherListCtxArg(void)
{
    return lastSetCipherListCtxArg;
}

const char* OpenSslFake_LastCipherList(void)
{
    return lastCipherList;
}

int SSL_CTX_set_ciphersuites(SSL_CTX* ctx, const char* str)
{
    (void) ctx;
    setCipherSuitesCallCount++;
    lastCipherSuites = str;
    return setCipherSuitesFails ? 0 : 1;
}

void OpenSslFake_SetCipherSuitesFails(bool fails)
{
    setCipherSuitesFails = fails;
}

int OpenSslFake_SetCipherSuitesCallCount(void)
{
    return setCipherSuitesCallCount;
}

const char* OpenSslFake_LastCipherSuites(void)
{
    return lastCipherSuites;
}

SSL* SSL_new(SSL_CTX* ctx)
{
    sslNewCallCount++;
    lastSslNewCtxArg = ctx;
    return sslNewFails ? NULL : (SSL*) &fakeSslStorage;
}

void OpenSslFake_SetSslNewFails(bool fails)
{
    sslNewFails = fails;
}

BIO_METHOD* BIO_meth_new(int type, const char* name)
{
    (void) type;
    (void) name;
    return bioMethNewFails ? NULL : (BIO_METHOD*) &fakeBioMethStorage;
}

void OpenSslFake_SetBioMethNewFails(bool fails)
{
    bioMethNewFails = fails;
}

void BIO_meth_free(BIO_METHOD* biom)
{
    bioMethFreeCallCount++;
    lastBioMethFreeArg = biom;
}

int OpenSslFake_BioMethFreeCallCount(void)
{
    return bioMethFreeCallCount;
}

BIO_METHOD* OpenSslFake_LastBioMethFreeArg(void)
{
    return lastBioMethFreeArg;
}

int BIO_meth_set_read(BIO_METHOD* biom, int (*read)(BIO*, char*, int))
{
    lastBioMethSetReadMethodArg = biom;
    lastBioReadCallback = read;
    return 1;
}

int BIO_meth_set_write(BIO_METHOD* biom, int (*write)(BIO*, const char*, int))
{
    lastBioMethSetWriteMethodArg = biom;
    lastBioWriteCallback = write;
    return 1;
}

int BIO_meth_set_ctrl(BIO_METHOD* biom, long (*ctrl)(BIO*, int, long, void*))
{
    (void) biom;
    lastBioCtrlCallback = ctrl;
    return 1;
}

int BIO_meth_set_create(BIO_METHOD* biom, int (*create)(BIO*))
{
    (void) biom;
    lastBioCreateCallback = create;
    return 1;
}

void BIO_set_init(BIO* a, int init)
{
    (void) a;
    lastSetInitArg = init;
}

BIO* BIO_new(const BIO_METHOD* type)
{
    bioNewCallCount++;
    lastBioNewMethodArg = type;
    BIO* bio = NULL;
    if (!bioNewFails && fakeBioCount < FAKE_BIO_POOL_SIZE)
    {
        bio = (BIO*) &fakeBios[fakeBioCount].slot;
        fakeBioCount++;
    }
    return bio;
}

void OpenSslFake_SetBioNewFails(bool fails)
{
    bioNewFails = fails;
}

void BIO_set_data(BIO* a, void* ptr)
{
    lastSetDataBioArg = a;
    lastSetDataArg = ptr;
    for (int i = 0; i < fakeBioCount; i++)
    {
        if ((BIO*) &fakeBios[i].slot == a)
        {
            fakeBios[i].data = ptr;
        }
    }
}

void* BIO_get_data(BIO* a)
{
    lastGetDataBioArg = a;
    void* result = NULL;
    for (int i = 0; i < fakeBioCount; i++)
    {
        if ((BIO*) &fakeBios[i].slot == a)
        {
            result = fakeBios[i].data;
        }
    }
    return result;
}

void SSL_set_bio(SSL* ssl, BIO* rbio, BIO* wbio)
{
    setBioCallCount++;
    lastSetBioSslArg = ssl;
    lastSetBioReadBioArg = rbio;
    lastSetBioWriteBioArg = wbio;
}

/* SSL_set_tlsext_host_name is a macro forwarding to SSL_ctrl; fake intercepts
 * the SET_TLSEXT_HOSTNAME command and captures the hostname pointer. */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters) -- signature fixed by OpenSSL API
long SSL_ctrl(SSL* ssl, int cmd, long larg, void* parg)
{
    (void) larg;
    lastSslCtrlSslArg = ssl;
    if (cmd == SSL_CTRL_SET_TLSEXT_HOSTNAME)
    {
        lastSniHostname = (const char*) parg;
        return sniHostnameFails ? 0 : 1;
    }
    return 1;
}

void OpenSslFake_SetSniHostnameFails(bool fails)
{
    sniHostnameFails = fails;
}

int SSL_set1_host(SSL* ssl, const char* hostname)
{
    lastSet1HostSslArg = ssl;
    lastSet1Host = hostname;
    return set1HostFails ? 0 : 1;
}

void OpenSslFake_SetSet1HostFails(bool fails)
{
    set1HostFails = fails;
}

int SSL_connect(SSL* ssl)
{
    int rc = connectFails ? -1 : 1;
    int callIndex = connectCallCount;
    connectCallCount++;
    lastConnectSslArg = ssl;
    if (connectReturnSequenceLen > 0)
    {
        int idx = (callIndex < connectReturnSequenceLen) ? callIndex : (connectReturnSequenceLen - 1);
        rc = connectReturnSequence[idx];
    }
    return rc;
}

void OpenSslFake_SetConnectFails(bool fails)
{
    connectFails = fails;
}

void OpenSslFake_SetConnectReturnSequence(const int* values, int count)
{
    int safe = (count < OPENSSLFAKE_MAX_CONNECT_RETURNS) ? count : OPENSSLFAKE_MAX_CONNECT_RETURNS;
    for (int i = 0; i < safe; i++)
    {
        connectReturnSequence[i] = values[i];
    }
    connectReturnSequenceLen = safe;
}

int SSL_write(SSL* ssl, const void* buf, int num)
{
    writeCallCount++;
    lastWriteSslArg = ssl;
    lastWriteBuf = buf;
    lastWriteSize = num;
    if (writeReturnOverride)
    {
        return writeReturnValue;
    }
    return writeFails ? -1 : num;
}

void OpenSslFake_SetWriteFails(bool fails)
{
    writeFails = fails;
}

void OpenSslFake_SetWriteReturn(int value)
{
    writeReturnOverride = true;
    writeReturnValue = value;
}

int SSL_read(SSL* ssl, void* buf, int num)
{
    sslReadCallCount++;
    lastSslReadSslArg = ssl;
    lastSslReadBuf = buf;
    lastSslReadSize = num;
    if (readReturnOverride)
    {
        return readReturnValue;
    }
    return num;
}

void OpenSslFake_SetReadReturn(int value)
{
    readReturnOverride = true;
    readReturnValue = value;
}

int SSL_get_error(const SSL* ssl, int ret)
{
    (void) ssl;
    (void) ret;
    getErrorCallCount++;
    return getErrorReturnValue;
}

void OpenSslFake_SetGetErrorReturn(int err)
{
    getErrorReturnValue = err;
}

int OpenSslFake_GetErrorCallCount(void)
{
    return getErrorCallCount;
}

long SSL_get_verify_result(const SSL* ssl)
{
    (void) ssl;
    return verifyResultValue;
}

void OpenSslFake_SetVerifyResult(long value)
{
    verifyResultValue = value;
}

/* BIO_set_flags / BIO_clear_flags are macros in OpenSSL that forward to these
 * non-inline functions. Faking the underlying calls lets the production code
 * use the standard idioms (BIO_set_retry_read, BIO_clear_retry_flags) while
 * tests observe whether retry semantics were signalled. */
void BIO_set_flags(BIO* bio, int flags)
{
    (void) bio;
    bioSetFlagsCallCount++;
    lastBioSetFlags = flags;
}

void BIO_clear_flags(BIO* bio, int flags)
{
    (void) bio;
    (void) flags;
    bioClearFlagsCallCount++;
}

int OpenSslFake_BioSetFlagsCallCount(void)
{
    return bioSetFlagsCallCount;
}

int OpenSslFake_LastBioSetFlags(void)
{
    return lastBioSetFlags;
}

int OpenSslFake_BioClearFlagsCallCount(void)
{
    return bioClearFlagsCallCount;
}

int SSL_shutdown(SSL* ssl)
{
    shutdownCallCount++;
    lastShutdownSslArg = ssl;
    return 1;
}

void SSL_free(SSL* ssl)
{
    freeCallCount++;
    lastFreeSslArg = ssl;
}

void SSL_CTX_free(SSL_CTX* ctx)
{
    ctxFreeCallCount++;
    lastCtxFreeCtxArg = ctx;
}

int SSL_CTX_use_certificate_chain_file(SSL_CTX* ctx, const char* file)
{
    useCertChainFileCallCount++;
    lastUseCertChainFileCtxArg = ctx;
    lastClientCertChainPath = file;
    return useCertChainFileFails ? 0 : 1;
}

int OpenSslFake_UseCertChainFileCallCount(void)
{
    return useCertChainFileCallCount;
}

SSL_CTX* OpenSslFake_LastUseCertChainFileCtxArg(void)
{
    return lastUseCertChainFileCtxArg;
}

const char* OpenSslFake_LastClientCertChainPath(void)
{
    return lastClientCertChainPath;
}

void OpenSslFake_SetUseCertChainFileFails(bool fails)
{
    useCertChainFileFails = fails;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters) -- signature fixed by OpenSSL API
int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int type)
{
    usePrivateKeyFileCallCount++;
    lastUsePrivateKeyFileCtxArg = ctx;
    lastClientKeyPath = file;
    lastClientKeyFileType = type;
    return usePrivateKeyFileFails ? 0 : 1;
}

int OpenSslFake_UsePrivateKeyFileCallCount(void)
{
    return usePrivateKeyFileCallCount;
}

SSL_CTX* OpenSslFake_LastUsePrivateKeyFileCtxArg(void)
{
    return lastUsePrivateKeyFileCtxArg;
}

const char* OpenSslFake_LastClientKeyPath(void)
{
    return lastClientKeyPath;
}

int OpenSslFake_LastClientKeyFileType(void)
{
    return lastClientKeyFileType;
}

void OpenSslFake_SetUsePrivateKeyFileFails(bool fails)
{
    usePrivateKeyFileFails = fails;
}

int SSL_CTX_check_private_key(const SSL_CTX* ctx)
{
    checkPrivateKeyCallCount++;
    lastCheckPrivateKeyCtxArg = (SSL_CTX*) ctx;
    return checkPrivateKeyFails ? 0 : 1;
}

int OpenSslFake_CheckPrivateKeyCallCount(void)
{
    return checkPrivateKeyCallCount;
}

SSL_CTX* OpenSslFake_LastCheckPrivateKeyCtxArg(void)
{
    return lastCheckPrivateKeyCtxArg;
}

void OpenSslFake_SetCheckPrivateKeyFails(bool fails)
{
    checkPrivateKeyFails = fails;
}

/* Deterministic, NON-cryptographic tag: an FNV-1a fold over the key then the
 * input then each output position. Sensitive to key, input, and position so a
 * changed key, tampered data, or tampered tag all produce a different value -
 * enough to exercise the policy's round-trip / tamper / wrong-key paths without
 * linking real libcrypto. */
void OpenSslFake_ComputeExpectedTag(
    const uint8_t* key,
    size_t keyLength,
    const uint8_t* input,
    size_t inputLength,
    uint8_t* tagOut
)
{
    uint32_t hash = 2166136261U;
    for (size_t index = 0; index < keyLength; index++)
    {
        hash = (hash ^ key[index]) * 16777619U;
    }
    for (size_t index = 0; index < inputLength; index++)
    {
        hash = (hash ^ input[index]) * 16777619U;
    }
    for (size_t index = 0; index < 32U; index++)
    {
        hash = (hash ^ (uint32_t) index) * 16777619U;
        tagOut[index] = (uint8_t) (hash >> 24U);
    }
}

const EVP_MD* EVP_sha256(void)
{
    return (const EVP_MD*) &fakeSha256Storage;
}

unsigned char* HMAC(
    const EVP_MD* evp_md,
    const void* key,
    int key_len,
    const unsigned char* d,
    size_t n,
    unsigned char* md,
    unsigned int* md_len
)
{
    hmacCallCount++;
    lastHmacMd = evp_md;
    lastHmacKeyLen = key_len;
    size_t keyCopyLen = ((size_t) key_len < sizeof lastHmacKey) ? (size_t) key_len : sizeof lastHmacKey;
    memcpy(lastHmacKey, key, keyCopyLen);
    lastHmacInputLen = n;
    size_t inputCopyLen = (n < sizeof lastHmacInput) ? n : sizeof lastHmacInput;
    memcpy(lastHmacInput, d, inputCopyLen);
    if (hmacFails)
    {
        return NULL;
    }
    OpenSslFake_ComputeExpectedTag((const uint8_t*) key, (size_t) key_len, d, n, md);
    if (md_len != NULL)
    {
        *md_len = 32U;
    }
    return md;
}

void OPENSSL_cleanse(void* ptr, size_t len)
{
    cleanseCallCount++;
    lastCleanseBuf = ptr;
    lastCleanseLen = len;
    memset(ptr, 0, len);
}

int OpenSslFake_HmacCallCount(void)
{
    return hmacCallCount;
}

const void* OpenSslFake_LastHmacMd(void)
{
    return lastHmacMd;
}

const uint8_t* OpenSslFake_LastHmacKey(void)
{
    return lastHmacKey;
}

int OpenSslFake_LastHmacKeyLen(void)
{
    return lastHmacKeyLen;
}

const uint8_t* OpenSslFake_LastHmacInput(void)
{
    return lastHmacInput;
}

size_t OpenSslFake_LastHmacInputLen(void)
{
    return lastHmacInputLen;
}

void OpenSslFake_SetHmacFails(bool fails)
{
    hmacFails = fails;
}

int OpenSslFake_CleanseCallCount(void)
{
    return cleanseCallCount;
}

const void* OpenSslFake_LastCleanseBuf(void)
{
    return lastCleanseBuf;
}

size_t OpenSslFake_LastCleanseLen(void)
{
    return lastCleanseLen;
}

/* -------------------------------------------------------------------------
 * AES-256-GCM - link-interposed EVP cipher + RAND_bytes.
 * ------------------------------------------------------------------------- */

static int FakeGcm_Init(const EVP_CIPHER* cipher, const unsigned char* key, const unsigned char* iv, bool encrypting)
{
    fakeGcmEncrypting = encrypting;
    /* Production sets the cipher first (cipher != NULL, key/iv NULL), then the
     * key/iv on a second call (cipher NULL). Each call is a distinct failable
     * step; capture whichever arrives. */
    if (key != NULL)
    {
        memcpy(lastGcmKey, key, FAKE_GCM_KEY_SIZE);
    }
    if (iv != NULL)
    {
        memcpy(lastGcmNonce, iv, FAKE_GCM_NONCE_SIZE);
    }
    enum OpenSslFakeGcmStep step = (cipher != NULL) ? OPENSSLFAKE_GCM_STEP_INIT_CIPHER : OPENSSLFAKE_GCM_STEP_INIT_KEY;
    return (gcmFailStep == step) ? 0 : 1;
}

static int FakeGcm_Update(unsigned char* out, int* outl, const unsigned char* in, int inl)
{
    size_t length = (size_t) inl;
    enum OpenSslFakeGcmStep step = OPENSSLFAKE_GCM_STEP_UPDATE_BODY;
    if (out == NULL)
    {
        /* Associated data - captured, never transformed. */
        lastGcmAadLen = length;
        memcpy(lastGcmAad, in, (length < sizeof lastGcmAad) ? length : sizeof lastGcmAad);
        step = OPENSSLFAKE_GCM_STEP_UPDATE_AAD;
    }
    else
    {
        /* Body. The double does not encrypt: it copies input to output unchanged
         * so the in-place buffer stays defined. On encrypt it also captures the
         * plaintext so a test can assert the body region production handed to
         * EVP. (memmove, not memcpy: production passes out == in.) */
        if (fakeGcmEncrypting)
        {
            lastGcmPlaintextLen = length;
            memcpy(lastGcmPlaintext, in, (length < sizeof lastGcmPlaintext) ? length : sizeof lastGcmPlaintext);
        }
        memmove(out, in, length);
    }
    *outl = inl;
    return (gcmFailStep == step) ? 0 : 1;
}

const EVP_CIPHER* EVP_aes_256_gcm(void)
{
    return (const EVP_CIPHER*) &fakeAesGcmCipherStorage;
}

EVP_CIPHER_CTX* EVP_CIPHER_CTX_new(void)
{
    fakeGcmEncrypting = false;
    return (gcmFailStep == OPENSSLFAKE_GCM_STEP_CTX_NEW) ? NULL : (EVP_CIPHER_CTX*) &fakeGcmCtxStorage;
}

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* ctx)
{
    (void) ctx;
}

int EVP_EncryptInit_ex(
    EVP_CIPHER_CTX* ctx,
    const EVP_CIPHER* cipher,
    ENGINE* impl,
    const unsigned char* key,
    const unsigned char* iv
)
{
    (void) ctx;
    (void) impl;
    return FakeGcm_Init(cipher, key, iv, true);
}

int EVP_DecryptInit_ex(
    EVP_CIPHER_CTX* ctx,
    const EVP_CIPHER* cipher,
    ENGINE* impl,
    const unsigned char* key,
    const unsigned char* iv
)
{
    (void) ctx;
    (void) impl;
    return FakeGcm_Init(cipher, key, iv, false);
}

int EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)
{
    (void) ctx;
    return FakeGcm_Update(out, outl, in, inl);
}

int EVP_DecryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)
{
    (void) ctx;
    return FakeGcm_Update(out, outl, in, inl);
}

// NOLINTNEXTLINE(readability-non-const-parameter) -- signature fixed by OpenSSL API
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl)
{
    (void) ctx;
    (void) out;
    *outl = 0;
    return (gcmFailStep == OPENSSLFAKE_GCM_STEP_FINAL) ? 0 : 1;
}

// NOLINTNEXTLINE(readability-non-const-parameter) -- signature fixed by OpenSSL API
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)
{
    (void) ctx;
    (void) outm;
    *outl = 0;
    gcmOpenCount++;
    /* Canned authentication verdict - real tag verification is the integration
     * suite's job. A FINAL-step failure drives the tamper-rejected path
     * (DecryptFinal returns 0), which the adapter must surface silently. */
    return (gcmFailStep == OPENSSLFAKE_GCM_STEP_FINAL) ? 0 : 1;
}

int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr)
{
    (void) ctx;
    (void) arg;
    int result = 1;
    if (type == EVP_CTRL_GCM_GET_TAG)
    {
        gcmSealCount++;
        /* Canned tag - the adapter only forwards these bytes into the trailer; it
         * never inspects them and no unit test asserts their value. */
        memset(ptr, 0, FAKE_GCM_TAG_SIZE);
        result = (gcmFailStep == OPENSSLFAKE_GCM_STEP_GET_TAG) ? 0 : 1;
    }
    else if (type == EVP_CTRL_GCM_SET_TAG)
    {
        result = (gcmFailStep == OPENSSLFAKE_GCM_STEP_SET_TAG) ? 0 : 1;
    }
    else if (type == EVP_CTRL_GCM_SET_IVLEN)
    {
        result = (gcmFailStep == OPENSSLFAKE_GCM_STEP_SET_IVLEN) ? 0 : 1;
    }
    else
    {
        /* Any other control: accepted, no-op. */
    }
    return result;
}

int RAND_bytes(unsigned char* buf, int num)
{
    randCallCount++;
    lastRandBuf = buf;
    lastRandLen = num;
    if (randFails)
    {
        return 0;
    }
    for (int index = 0; index < num; index++)
    {
        buf[index] = (unsigned char) (0xA0 + index);
    }
    return 1;
}

int OpenSslFake_GcmSealCount(void)
{
    return gcmSealCount;
}

int OpenSslFake_GcmOpenCount(void)
{
    return gcmOpenCount;
}

const uint8_t* OpenSslFake_LastGcmKey(void)
{
    return lastGcmKey;
}

const uint8_t* OpenSslFake_LastGcmNonce(void)
{
    return lastGcmNonce;
}

const uint8_t* OpenSslFake_LastGcmAad(void)
{
    return lastGcmAad;
}

size_t OpenSslFake_LastGcmAadLen(void)
{
    return lastGcmAadLen;
}

const uint8_t* OpenSslFake_LastGcmPlaintext(void)
{
    return lastGcmPlaintext;
}

size_t OpenSslFake_LastGcmPlaintextLen(void)
{
    return lastGcmPlaintextLen;
}

void OpenSslFake_SetGcmStepFails(enum OpenSslFakeGcmStep step)
{
    gcmFailStep = step;
}

int OpenSslFake_RandBytesCallCount(void)
{
    return randCallCount;
}

const void* OpenSslFake_LastRandBytesBuf(void)
{
    return lastRandBuf;
}

int OpenSslFake_LastRandBytesLen(void)
{
    return lastRandLen;
}

void OpenSslFake_SetRandBytesFails(bool fails)
{
    randFails = fails;
}
