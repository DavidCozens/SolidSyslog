#include "MbedTlsFake.h"

#include <mbedtls/cipher.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ssl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/x509_crt.h"

enum
{
    MBEDTLSFAKE_MAX_KEY = 64,
    MBEDTLSFAKE_MAX_INPUT = 256
};

/* AES-256-GCM capture double - see header. */
enum
{
    MBEDTLSFAKE_GCM_KEY_SIZE = 32,
    MBEDTLSFAKE_GCM_NONCE_SIZE = 12,
    MBEDTLSFAKE_GCM_MAX_AAD = 16,
    MBEDTLSFAKE_GCM_MAX_BODY = 256
};

static int gcmSealCount;
static int gcmOpenCount;
static unsigned int lastGcmKeyBits;
static int lastGcmCipher;
static uint8_t lastGcmKey[MBEDTLSFAKE_GCM_KEY_SIZE];
static uint8_t lastGcmNonce[MBEDTLSFAKE_GCM_NONCE_SIZE];
static uint8_t lastGcmAad[MBEDTLSFAKE_GCM_MAX_AAD];
static size_t lastGcmAadLen;
static uint8_t lastGcmPlaintext[MBEDTLSFAKE_GCM_MAX_BODY];
static size_t lastGcmPlaintextLen;
static enum MbedTlsFakeGcmStep gcmFailStep;
static bool gcmAuthFails;

/* mbedtls_ctr_drbg_random capture */
static int ctrDrbgRandomCallCount;
static const void* lastCtrDrbgRandomContext;
static const void* lastCtrDrbgRandomBuf;
static size_t lastCtrDrbgRandomLen;
static bool ctrDrbgRandomFails;

/* mbedtls_md_info_from_type / mbedtls_md_hmac */
static int mdHmacCallCount;
static int lastMdInfoType;
static uint8_t lastMdHmacKey[MBEDTLSFAKE_MAX_KEY];
static size_t lastMdHmacKeyLen;
static uint8_t lastMdHmacInput[MBEDTLSFAKE_MAX_INPUT];
static size_t lastMdHmacInputLen;
static int mdHmacReturn;

/* mbedtls_ssl_conf_verify / mbedtls_md over a certificate */
enum
{
    MBEDTLSFAKE_MAX_DER = 512,
    MBEDTLSFAKE_MAX_DIGEST = 64
};

static int (*lastSslConfVerifyCallback)(void*, mbedtls_x509_crt*, int, uint32_t*);
static void* lastSslConfVerifyContext;
static mbedtls_x509_crt fakeCertificate;
static unsigned char fakeCertificateDer[MBEDTLSFAKE_MAX_DER];
static unsigned char fakeDigest[MBEDTLSFAKE_MAX_DIGEST];
static size_t fakeDigestLength;
static int digestUnavailableMdType = -1;

/* mbedtls_platform_zeroize */
static int platformZeroizeCallCount;
static const void* lastPlatformZeroizeBuf;
static size_t lastPlatformZeroizeLen;

/* -------------------------------------------------------------------------
 * Captured state - one section per mbedTLS API call. Tests read these via
 * accessors below; production reaches libmbedtls through the link-interposed
 * functions at the bottom of the file.
 * ------------------------------------------------------------------------- */

/* mbedtls_ssl_config_init */
static int sslConfigInitCallCount;
static mbedtls_ssl_config* lastSslConfigInitArg;

/* mbedtls_ssl_config_defaults */
static int sslConfigDefaultsCallCount;
static mbedtls_ssl_config* lastSslConfigDefaultsConfigArg;
static int lastSslConfigDefaultsEndpoint;
static int lastSslConfigDefaultsTransport;
static int lastSslConfigDefaultsPreset;
static int sslConfigDefaultsReturn;

/* mbedtls_ssl_init */
static int sslInitCallCount;
static mbedtls_ssl_context* lastSslInitArg;

/* mbedtls_ssl_setup */
static int sslSetupCallCount;
static mbedtls_ssl_context* lastSslSetupContextArg;
static const mbedtls_ssl_config* lastSslSetupConfigArg;
static int sslSetupReturn;

/* mbedtls_ssl_set_bio */
static int sslSetBioCallCount;
static mbedtls_ssl_context* lastSslSetBioContextArg;
static void* lastSslSetBioPBioArg;
static mbedtls_ssl_send_t* lastSslSetBioSendCallback;
static mbedtls_ssl_recv_t* lastSslSetBioRecvCallback;
static mbedtls_ssl_recv_timeout_t* lastSslSetBioRecvTimeoutCallback;

/* mbedtls_ssl_handshake */
enum
{
    MBEDTLSFAKE_MAX_HANDSHAKE_RETURNS = 8
};

static int sslHandshakeCallCount;
static mbedtls_ssl_context* lastSslHandshakeArg;
static int sslHandshakeReturn;
static uint32_t sslVerifyResult;
static int sslHandshakeReturnSequence[MBEDTLSFAKE_MAX_HANDSHAKE_RETURNS];
static int sslHandshakeReturnSequenceLen;

/* mbedtls_ssl_write */
static int sslWriteCallCount;
static mbedtls_ssl_context* lastSslWriteContextArg;
static const unsigned char* lastSslWriteBufArg;
static size_t lastSslWriteLenArg;
static int sslWriteReturn;
static bool sslWriteReturnSet;

/* mbedtls_ssl_read */
static int sslReadCallCount;
static mbedtls_ssl_context* lastSslReadContextArg;
static unsigned char* lastSslReadBufArg;
static size_t lastSslReadLenArg;
static int sslReadReturn;

/* mbedtls_ssl_close_notify */
static int sslCloseNotifyCallCount;
static mbedtls_ssl_context* lastSslCloseNotifyArg;

/* mbedtls_ssl_free */
static int sslFreeCallCount;
static mbedtls_ssl_context* lastSslFreeArg;

/* mbedtls_ssl_config_free */
static int sslConfigFreeCallCount;
static mbedtls_ssl_config* lastSslConfigFreeArg;

/* mbedtls_ssl_conf_authmode */
static int sslConfAuthmodeCallCount;
static mbedtls_ssl_config* lastSslConfAuthmodeConfigArg;
static int lastSslConfAuthmodeArg;

/* mbedtls_ssl_conf_ca_chain */
static int sslConfCaChainCallCount;
static mbedtls_ssl_config* lastSslConfCaChainConfigArg;
static mbedtls_x509_crt* lastSslConfCaChainArg;
static mbedtls_x509_crl* lastSslConfCaChainCrlArg;

/* mbedtls_ssl_conf_rng */
static int sslConfRngCallCount;
static mbedtls_ssl_config* lastSslConfRngConfigArg;
static int (*lastSslConfRngFuncArg)(void*, unsigned char*, size_t);
static void* lastSslConfRngContextArg;

/* mbedtls_ssl_set_hostname */
static int sslSetHostnameCallCount;
static mbedtls_ssl_context* lastSslSetHostnameContextArg;
static const char* lastSslSetHostnameNameArg;
static int sslSetHostnameReturn;

/* mbedtls_ssl_conf_own_cert */
static int sslConfOwnCertCallCount;
static mbedtls_ssl_config* lastSslConfOwnCertConfigArg;
static mbedtls_x509_crt* lastSslConfOwnCertCertArg;
static mbedtls_pk_context* lastSslConfOwnCertKeyArg;
static int sslConfOwnCertReturn;

/* mbedtls_pk_check_pair */
static int pkCheckPairCallCount;
static const mbedtls_pk_context* lastPkCheckPairPublicKeyArg;
static const mbedtls_pk_context* lastPkCheckPairPrivateKeyArg;
static int (*lastPkCheckPairRngFuncArg)(void*, unsigned char*, size_t);
static void* lastPkCheckPairRngContextArg;
static int pkCheckPairReturn;

/* -------------------------------------------------------------------------
 * Test accessors.
 * ------------------------------------------------------------------------- */

void MbedTlsFake_Reset(void)
{
    lastSslConfVerifyCallback = NULL;
    lastSslConfVerifyContext = NULL;
    fakeCertificate.raw.p = NULL;
    fakeCertificate.raw.len = 0;
    fakeDigestLength = 0;
    digestUnavailableMdType = -1;
    lastMdInfoType = 0;
    sslConfigInitCallCount = 0;
    lastSslConfigInitArg = NULL;
    sslConfigDefaultsCallCount = 0;
    lastSslConfigDefaultsConfigArg = NULL;
    lastSslConfigDefaultsEndpoint = 0;
    lastSslConfigDefaultsTransport = 0;
    lastSslConfigDefaultsPreset = 0;
    sslConfigDefaultsReturn = 0;
    sslInitCallCount = 0;
    lastSslInitArg = NULL;
    sslSetupCallCount = 0;
    lastSslSetupContextArg = NULL;
    lastSslSetupConfigArg = NULL;
    sslSetupReturn = 0;
    sslSetBioCallCount = 0;
    lastSslSetBioContextArg = NULL;
    lastSslSetBioPBioArg = NULL;
    lastSslSetBioSendCallback = NULL;
    lastSslSetBioRecvCallback = NULL;
    lastSslSetBioRecvTimeoutCallback = NULL;
    sslHandshakeCallCount = 0;
    lastSslHandshakeArg = NULL;
    sslHandshakeReturn = 0;
    sslVerifyResult = 0;
    sslHandshakeReturnSequenceLen = 0;
    sslWriteCallCount = 0;
    lastSslWriteContextArg = NULL;
    lastSslWriteBufArg = NULL;
    lastSslWriteLenArg = 0;
    sslWriteReturn = 0;
    sslWriteReturnSet = false;
    sslReadCallCount = 0;
    lastSslReadContextArg = NULL;
    lastSslReadBufArg = NULL;
    lastSslReadLenArg = 0;
    sslReadReturn = 0;
    sslCloseNotifyCallCount = 0;
    lastSslCloseNotifyArg = NULL;
    sslFreeCallCount = 0;
    lastSslFreeArg = NULL;
    sslConfigFreeCallCount = 0;
    lastSslConfigFreeArg = NULL;
    sslConfAuthmodeCallCount = 0;
    lastSslConfAuthmodeConfigArg = NULL;
    lastSslConfAuthmodeArg = 0;
    sslConfCaChainCallCount = 0;
    lastSslConfCaChainConfigArg = NULL;
    lastSslConfCaChainArg = NULL;
    lastSslConfCaChainCrlArg = NULL;
    sslConfRngCallCount = 0;
    lastSslConfRngConfigArg = NULL;
    lastSslConfRngFuncArg = NULL;
    lastSslConfRngContextArg = NULL;
    sslSetHostnameCallCount = 0;
    lastSslSetHostnameContextArg = NULL;
    lastSslSetHostnameNameArg = NULL;
    sslSetHostnameReturn = 0;
    sslConfOwnCertCallCount = 0;
    lastSslConfOwnCertConfigArg = NULL;
    lastSslConfOwnCertCertArg = NULL;
    lastSslConfOwnCertKeyArg = NULL;
    pkCheckPairCallCount = 0;
    lastPkCheckPairPublicKeyArg = NULL;
    lastPkCheckPairPrivateKeyArg = NULL;
    lastPkCheckPairRngFuncArg = NULL;
    lastPkCheckPairRngContextArg = NULL;
    pkCheckPairReturn = 0;
    sslConfOwnCertReturn = 0;
    mdHmacCallCount = 0;
    lastMdInfoType = 0;
    lastMdHmacKeyLen = 0;
    lastMdHmacInputLen = 0;
    mdHmacReturn = 0;
    memset(lastMdHmacKey, 0, sizeof lastMdHmacKey);
    memset(lastMdHmacInput, 0, sizeof lastMdHmacInput);
    platformZeroizeCallCount = 0;
    lastPlatformZeroizeBuf = NULL;
    lastPlatformZeroizeLen = 0;
    gcmSealCount = 0;
    gcmOpenCount = 0;
    lastGcmKeyBits = 0;
    lastGcmCipher = 0;
    lastGcmAadLen = 0;
    lastGcmPlaintextLen = 0;
    gcmFailStep = MBEDTLSFAKE_GCM_STEP_NONE;
    gcmAuthFails = false;
    memset(lastGcmKey, 0, sizeof lastGcmKey);
    memset(lastGcmNonce, 0, sizeof lastGcmNonce);
    memset(lastGcmAad, 0, sizeof lastGcmAad);
    memset(lastGcmPlaintext, 0, sizeof lastGcmPlaintext);
    ctrDrbgRandomCallCount = 0;
    lastCtrDrbgRandomContext = NULL;
    lastCtrDrbgRandomBuf = NULL;
    lastCtrDrbgRandomLen = 0;
    ctrDrbgRandomFails = false;
}

int MbedTlsFake_SslConfigInitCallCount(void)
{
    return sslConfigInitCallCount;
}

mbedtls_ssl_config* MbedTlsFake_LastSslConfigInitArg(void)
{
    return lastSslConfigInitArg;
}

int MbedTlsFake_SslConfigDefaultsCallCount(void)
{
    return sslConfigDefaultsCallCount;
}

mbedtls_ssl_config* MbedTlsFake_LastSslConfigDefaultsConfigArg(void)
{
    return lastSslConfigDefaultsConfigArg;
}

int MbedTlsFake_LastSslConfigDefaultsEndpoint(void)
{
    return lastSslConfigDefaultsEndpoint;
}

int MbedTlsFake_LastSslConfigDefaultsTransport(void)
{
    return lastSslConfigDefaultsTransport;
}

int MbedTlsFake_LastSslConfigDefaultsPreset(void)
{
    return lastSslConfigDefaultsPreset;
}

void MbedTlsFake_SetSslConfigDefaultsReturn(int value)
{
    sslConfigDefaultsReturn = value;
}

int MbedTlsFake_SslInitCallCount(void)
{
    return sslInitCallCount;
}

mbedtls_ssl_context* MbedTlsFake_LastSslInitArg(void)
{
    return lastSslInitArg;
}

int MbedTlsFake_SslSetupCallCount(void)
{
    return sslSetupCallCount;
}

mbedtls_ssl_context* MbedTlsFake_LastSslSetupContextArg(void)
{
    return lastSslSetupContextArg;
}

const mbedtls_ssl_config* MbedTlsFake_LastSslSetupConfigArg(void)
{
    return lastSslSetupConfigArg;
}

void MbedTlsFake_SetSslSetupReturn(int value)
{
    sslSetupReturn = value;
}

int MbedTlsFake_SslSetBioCallCount(void)
{
    return sslSetBioCallCount;
}

mbedtls_ssl_context* MbedTlsFake_LastSslSetBioContextArg(void)
{
    return lastSslSetBioContextArg;
}

void* MbedTlsFake_LastSslSetBioPBioArg(void)
{
    return lastSslSetBioPBioArg;
}

mbedtls_ssl_send_t* MbedTlsFake_LastSslSetBioSendCallback(void)
{
    return lastSslSetBioSendCallback;
}

mbedtls_ssl_recv_t* MbedTlsFake_LastSslSetBioRecvCallback(void)
{
    return lastSslSetBioRecvCallback;
}

mbedtls_ssl_recv_timeout_t* MbedTlsFake_LastSslSetBioRecvTimeoutCallback(void)
{
    return lastSslSetBioRecvTimeoutCallback;
}

int MbedTlsFake_SslHandshakeCallCount(void)
{
    return sslHandshakeCallCount;
}

mbedtls_ssl_context* MbedTlsFake_LastSslHandshakeArg(void)
{
    return lastSslHandshakeArg;
}

uint32_t mbedtls_ssl_get_verify_result(const mbedtls_ssl_context* ssl)
{
    (void) ssl;
    return sslVerifyResult;
}

void MbedTlsFake_SetSslVerifyResult(uint32_t flags)
{
    sslVerifyResult = flags;
}

void MbedTlsFake_SetSslHandshakeReturn(int value)
{
    sslHandshakeReturn = value;
}

void MbedTlsFake_SetSslHandshakeReturnSequence(const int* values, int count)
{
    int safe = (count < MBEDTLSFAKE_MAX_HANDSHAKE_RETURNS) ? count : MBEDTLSFAKE_MAX_HANDSHAKE_RETURNS;
    for (int i = 0; i < safe; i++)
    {
        sslHandshakeReturnSequence[i] = values[i];
    }
    sslHandshakeReturnSequenceLen = safe;
}

int MbedTlsFake_SslWriteCallCount(void)
{
    return sslWriteCallCount;
}

mbedtls_ssl_context* MbedTlsFake_LastSslWriteContextArg(void)
{
    return lastSslWriteContextArg;
}

const unsigned char* MbedTlsFake_LastSslWriteBufArg(void)
{
    return lastSslWriteBufArg;
}

size_t MbedTlsFake_LastSslWriteLenArg(void)
{
    return lastSslWriteLenArg;
}

void MbedTlsFake_SetSslWriteReturn(int value)
{
    sslWriteReturn = value;
    sslWriteReturnSet = true;
}

int MbedTlsFake_SslReadCallCount(void)
{
    return sslReadCallCount;
}

mbedtls_ssl_context* MbedTlsFake_LastSslReadContextArg(void)
{
    return lastSslReadContextArg;
}

unsigned char* MbedTlsFake_LastSslReadBufArg(void)
{
    return lastSslReadBufArg;
}

size_t MbedTlsFake_LastSslReadLenArg(void)
{
    return lastSslReadLenArg;
}

void MbedTlsFake_SetSslReadReturn(int value)
{
    sslReadReturn = value;
}

int MbedTlsFake_SslCloseNotifyCallCount(void)
{
    return sslCloseNotifyCallCount;
}

mbedtls_ssl_context* MbedTlsFake_LastSslCloseNotifyArg(void)
{
    return lastSslCloseNotifyArg;
}

int MbedTlsFake_SslFreeCallCount(void)
{
    return sslFreeCallCount;
}

mbedtls_ssl_context* MbedTlsFake_LastSslFreeArg(void)
{
    return lastSslFreeArg;
}

int MbedTlsFake_SslConfigFreeCallCount(void)
{
    return sslConfigFreeCallCount;
}

mbedtls_ssl_config* MbedTlsFake_LastSslConfigFreeArg(void)
{
    return lastSslConfigFreeArg;
}

int MbedTlsFake_SslConfAuthmodeCallCount(void)
{
    return sslConfAuthmodeCallCount;
}

mbedtls_ssl_config* MbedTlsFake_LastSslConfAuthmodeConfigArg(void)
{
    return lastSslConfAuthmodeConfigArg;
}

int MbedTlsFake_LastSslConfAuthmodeArg(void)
{
    return lastSslConfAuthmodeArg;
}

int MbedTlsFake_ConfMinTlsVersion(const mbedtls_ssl_config* conf)
{
    return (int) conf->MBEDTLS_PRIVATE(min_tls_version);
}

int MbedTlsFake_SslConfCaChainCallCount(void)
{
    return sslConfCaChainCallCount;
}

mbedtls_ssl_config* MbedTlsFake_LastSslConfCaChainConfigArg(void)
{
    return lastSslConfCaChainConfigArg;
}

mbedtls_x509_crt* MbedTlsFake_LastSslConfCaChainArg(void)
{
    return lastSslConfCaChainArg;
}

mbedtls_x509_crl* MbedTlsFake_LastSslConfCaChainCrlArg(void)
{
    return lastSslConfCaChainCrlArg;
}

int MbedTlsFake_SslConfRngCallCount(void)
{
    return sslConfRngCallCount;
}

mbedtls_ssl_config* MbedTlsFake_LastSslConfRngConfigArg(void)
{
    return lastSslConfRngConfigArg;
}

int (*MbedTlsFake_LastSslConfRngFuncArg(void))(void*, unsigned char*, size_t)
{
    return lastSslConfRngFuncArg;
}

void* MbedTlsFake_LastSslConfRngContextArg(void)
{
    return lastSslConfRngContextArg;
}

int MbedTlsFake_SslSetHostnameCallCount(void)
{
    return sslSetHostnameCallCount;
}

mbedtls_ssl_context* MbedTlsFake_LastSslSetHostnameContextArg(void)
{
    return lastSslSetHostnameContextArg;
}

const char* MbedTlsFake_LastSslSetHostnameNameArg(void)
{
    return lastSslSetHostnameNameArg;
}

void MbedTlsFake_SetSslSetHostnameReturn(int value)
{
    sslSetHostnameReturn = value;
}

int MbedTlsFake_SslConfOwnCertCallCount(void)
{
    return sslConfOwnCertCallCount;
}

mbedtls_ssl_config* MbedTlsFake_LastSslConfOwnCertConfigArg(void)
{
    return lastSslConfOwnCertConfigArg;
}

mbedtls_x509_crt* MbedTlsFake_LastSslConfOwnCertCertArg(void)
{
    return lastSslConfOwnCertCertArg;
}

void MbedTlsFake_SetSslConfOwnCertReturn(int value)
{
    sslConfOwnCertReturn = value;
}

mbedtls_pk_context* MbedTlsFake_LastSslConfOwnCertKeyArg(void)
{
    return lastSslConfOwnCertKeyArg;
}

int MbedTlsFake_PkCheckPairCallCount(void)
{
    return pkCheckPairCallCount;
}

const mbedtls_pk_context* MbedTlsFake_LastPkCheckPairPublicKeyArg(void)
{
    return lastPkCheckPairPublicKeyArg;
}

const mbedtls_pk_context* MbedTlsFake_LastPkCheckPairPrivateKeyArg(void)
{
    return lastPkCheckPairPrivateKeyArg;
}

int (*MbedTlsFake_LastPkCheckPairRngFuncArg(void))(void*, unsigned char*, size_t)
{
    return lastPkCheckPairRngFuncArg;
}

void* MbedTlsFake_LastPkCheckPairRngContextArg(void)
{
    return lastPkCheckPairRngContextArg;
}

void MbedTlsFake_SetPkCheckPairReturn(int value)
{
    pkCheckPairReturn = value;
}

/* -------------------------------------------------------------------------
 * Link-interposed mbedTLS symbols. The test executable does not link
 * libmbedtls; the production code's calls to mbedtls_* resolve here.
 * ------------------------------------------------------------------------- */

void mbedtls_ssl_config_init(mbedtls_ssl_config* conf)
{
    sslConfigInitCallCount++;
    lastSslConfigInitArg = conf;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters) -- signature fixed by mbedTLS API
int mbedtls_ssl_config_defaults(mbedtls_ssl_config* conf, int endpoint, int transport, int preset)
{
    sslConfigDefaultsCallCount++;
    lastSslConfigDefaultsConfigArg = conf;
    lastSslConfigDefaultsEndpoint = endpoint;
    lastSslConfigDefaultsTransport = transport;
    lastSslConfigDefaultsPreset = preset;
    return sslConfigDefaultsReturn;
}

void mbedtls_ssl_init(mbedtls_ssl_context* ssl)
{
    sslInitCallCount++;
    lastSslInitArg = ssl;
}

int mbedtls_ssl_setup(mbedtls_ssl_context* ssl, const mbedtls_ssl_config* conf)
{
    sslSetupCallCount++;
    lastSslSetupContextArg = ssl;
    lastSslSetupConfigArg = conf;
    return sslSetupReturn;
}

void mbedtls_ssl_set_bio(
    mbedtls_ssl_context* ssl,
    void* p_bio,
    mbedtls_ssl_send_t* f_send,
    mbedtls_ssl_recv_t* f_recv,
    mbedtls_ssl_recv_timeout_t* f_recv_timeout
)
{
    sslSetBioCallCount++;
    lastSslSetBioContextArg = ssl;
    lastSslSetBioPBioArg = p_bio;
    lastSslSetBioSendCallback = f_send;
    lastSslSetBioRecvCallback = f_recv;
    lastSslSetBioRecvTimeoutCallback = f_recv_timeout;
}

int mbedtls_ssl_handshake(mbedtls_ssl_context* ssl)
{
    int callIndex = sslHandshakeCallCount;
    sslHandshakeCallCount++;
    lastSslHandshakeArg = ssl;
    int rc = sslHandshakeReturn;
    if (sslHandshakeReturnSequenceLen > 0)
    {
        int idx = (callIndex < sslHandshakeReturnSequenceLen) ? callIndex : (sslHandshakeReturnSequenceLen - 1);
        rc = sslHandshakeReturnSequence[idx];
    }
    return rc;
}

int mbedtls_ssl_write(mbedtls_ssl_context* ssl, const unsigned char* buf, size_t len)
{
    sslWriteCallCount++;
    lastSslWriteContextArg = ssl;
    lastSslWriteBufArg = buf;
    lastSslWriteLenArg = len;
    /* Default: write succeeds fully (returns len). Tests can override via SetSslWriteReturn. */
    return sslWriteReturnSet ? sslWriteReturn : (int) len;
}

int mbedtls_ssl_read(mbedtls_ssl_context* ssl, unsigned char* buf, size_t len)
{
    sslReadCallCount++;
    lastSslReadContextArg = ssl;
    lastSslReadBufArg = buf;
    lastSslReadLenArg = len;
    return sslReadReturn;
}

int mbedtls_ssl_close_notify(mbedtls_ssl_context* ssl)
{
    sslCloseNotifyCallCount++;
    lastSslCloseNotifyArg = ssl;
    return 0;
}

void mbedtls_ssl_free(mbedtls_ssl_context* ssl)
{
    sslFreeCallCount++;
    lastSslFreeArg = ssl;
}

void mbedtls_ssl_config_free(mbedtls_ssl_config* conf)
{
    sslConfigFreeCallCount++;
    lastSslConfigFreeArg = conf;
}

void mbedtls_ssl_conf_authmode(mbedtls_ssl_config* conf, int authmode)
{
    sslConfAuthmodeCallCount++;
    lastSslConfAuthmodeConfigArg = conf;
    lastSslConfAuthmodeArg = authmode;
}

void mbedtls_ssl_conf_ca_chain(mbedtls_ssl_config* conf, mbedtls_x509_crt* ca_chain, mbedtls_x509_crl* ca_crl)
{
    sslConfCaChainCallCount++;
    lastSslConfCaChainConfigArg = conf;
    lastSslConfCaChainArg = ca_chain;
    lastSslConfCaChainCrlArg = ca_crl;
}

int mbedtls_ssl_conf_own_cert(mbedtls_ssl_config* conf, mbedtls_x509_crt* own_cert, mbedtls_pk_context* pk_key)
{
    sslConfOwnCertCallCount++;
    lastSslConfOwnCertConfigArg = conf;
    lastSslConfOwnCertCertArg = own_cert;
    lastSslConfOwnCertKeyArg = pk_key;
    return sslConfOwnCertReturn;
}

int mbedtls_pk_check_pair(
    const mbedtls_pk_context* pub,
    const mbedtls_pk_context* prv,
    int (*f_rng)(void*, unsigned char*, size_t),
    void* p_rng
)
{
    pkCheckPairCallCount++;
    lastPkCheckPairPublicKeyArg = pub;
    lastPkCheckPairPrivateKeyArg = prv;
    lastPkCheckPairRngFuncArg = f_rng;
    lastPkCheckPairRngContextArg = p_rng;
    return pkCheckPairReturn;
}

void mbedtls_ssl_conf_rng(mbedtls_ssl_config* conf, int (*f_rng)(void*, unsigned char*, size_t), void* p_rng)
{
    sslConfRngCallCount++;
    lastSslConfRngConfigArg = conf;
    lastSslConfRngFuncArg = f_rng;
    lastSslConfRngContextArg = p_rng;
}

/* Capture double - two callers. The TLS stream wires this by address into
 * mbedtls_ssl_conf_rng and never invokes it at test time; the AES-GCM policy
 * calls it directly to fill each record's nonce. Captures its arguments and
 * fills a deterministic 0xA0, 0xA1, ... pattern (mirrors the OpenSslFake
 * RAND_bytes double) so a seal test can assert the nonce reached the trailer. */
int mbedtls_ctr_drbg_random(void* p_rng, unsigned char* output, size_t output_len)
{
    ctrDrbgRandomCallCount++;
    lastCtrDrbgRandomContext = p_rng;
    lastCtrDrbgRandomBuf = output;
    lastCtrDrbgRandomLen = output_len;
    if (ctrDrbgRandomFails)
    {
        return -1;
    }
    for (size_t index = 0; index < output_len; index++)
    {
        output[index] = (unsigned char) (0xA0U + index);
    }
    return 0;
}

int mbedtls_ssl_set_hostname(mbedtls_ssl_context* ssl, const char* hostname)
{
    sslSetHostnameCallCount++;
    lastSslSetHostnameContextArg = ssl;
    lastSslSetHostnameNameArg = hostname;
    return sslSetHostnameReturn;
}

int MbedTlsFake_MdHmacCallCount(void)
{
    return mdHmacCallCount;
}

int MbedTlsFake_LastMdInfoType(void)
{
    return lastMdInfoType;
}

const uint8_t* MbedTlsFake_LastMdHmacKey(void)
{
    return lastMdHmacKey;
}

size_t MbedTlsFake_LastMdHmacKeyLen(void)
{
    return lastMdHmacKeyLen;
}

const uint8_t* MbedTlsFake_LastMdHmacInput(void)
{
    return lastMdHmacInput;
}

size_t MbedTlsFake_LastMdHmacInputLen(void)
{
    return lastMdHmacInputLen;
}

void MbedTlsFake_SetMdHmacReturn(int value)
{
    mdHmacReturn = value;
}

int MbedTlsFake_PlatformZeroizeCallCount(void)
{
    return platformZeroizeCallCount;
}

const void* MbedTlsFake_LastPlatformZeroizeBuf(void)
{
    return lastPlatformZeroizeBuf;
}

size_t MbedTlsFake_LastPlatformZeroizeLen(void)
{
    return lastPlatformZeroizeLen;
}

/* Deterministic, NON-cryptographic tag: an FNV-1a fold over the key then the
 * input then each output position. Sensitive to key, input, and position so a
 * changed key, tampered data, or tampered tag all produce a different value -
 * enough to exercise the policy's round-trip / tamper / wrong-key paths without
 * linking real libmbedcrypto. */
void MbedTlsFake_ComputeExpectedTag(
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

const mbedtls_md_info_t* mbedtls_md_info_from_type(mbedtls_md_type_t md_type)
{
    static const int mdInfoSentinel = 0;
    lastMdInfoType = (int) md_type;
    return ((int) md_type == digestUnavailableMdType) ? NULL : (const mbedtls_md_info_t*) &mdInfoSentinel;
}

int mbedtls_md(const mbedtls_md_info_t* md_info, const unsigned char* input, size_t ilen, unsigned char* output)
{
    (void) md_info;
    (void) input;
    (void) ilen;
    memcpy(output, fakeDigest, fakeDigestLength);
    return 0;
}

unsigned char mbedtls_md_get_size(const mbedtls_md_info_t* md_info)
{
    (void) md_info;
    return (unsigned char) fakeDigestLength;
}

void mbedtls_ssl_conf_verify(
    mbedtls_ssl_config* conf,
    int (*f_vrfy)(void*, mbedtls_x509_crt*, int, uint32_t*),
    void* p_vrfy
)
{
    (void) conf;
    lastSslConfVerifyCallback = f_vrfy;
    lastSslConfVerifyContext = p_vrfy;
}

int (*MbedTlsFake_LastSslConfVerifyCallback(void))(void*, mbedtls_x509_crt*, int, uint32_t*)
{
    return lastSslConfVerifyCallback;
}

void* MbedTlsFake_LastSslConfVerifyContext(void)
{
    return lastSslConfVerifyContext;
}

mbedtls_x509_crt* MbedTlsFake_Certificate(void)
{
    return &fakeCertificate;
}

void MbedTlsFake_SetCertificateDer(const unsigned char* der, size_t length)
{
    memcpy(fakeCertificateDer, der, length);
    fakeCertificate.raw.p = fakeCertificateDer;
    fakeCertificate.raw.len = length;
}

void MbedTlsFake_SetDigest(const unsigned char* digest, size_t length)
{
    memcpy(fakeDigest, digest, length);
    fakeDigestLength = length;
}

void MbedTlsFake_SetDigestUnavailableFor(int mdType)
{
    digestUnavailableMdType = mdType;
}

int MbedTlsFake_LastDigestMdType(void)
{
    return lastMdInfoType;
}

int mbedtls_md_hmac(
    const mbedtls_md_info_t* md_info,
    const unsigned char* key,
    size_t keylen,
    const unsigned char* input,
    size_t ilen,
    unsigned char* output
)
{
    (void) md_info;
    mdHmacCallCount++;
    lastMdHmacKeyLen = keylen;
    memcpy(lastMdHmacKey, key, (keylen < sizeof lastMdHmacKey) ? keylen : sizeof lastMdHmacKey);
    lastMdHmacInputLen = ilen;
    memcpy(lastMdHmacInput, input, (ilen < sizeof lastMdHmacInput) ? ilen : sizeof lastMdHmacInput);
    MbedTlsFake_ComputeExpectedTag(key, keylen, input, ilen, output);
    return mdHmacReturn;
}

void mbedtls_platform_zeroize(void* buf, size_t len)
{
    platformZeroizeCallCount++;
    lastPlatformZeroizeBuf = buf;
    lastPlatformZeroizeLen = len;
    memset(buf, 0, len);
}

/* -------------------------------------------------------------------------
 * AES-256-GCM - link-interposed mbedtls_gcm_* + the CTR-DRBG nonce source.
 * Capture-and-canned-return, NOT a cipher (see header).
 * ------------------------------------------------------------------------- */

void mbedtls_gcm_init(mbedtls_gcm_context* ctx)
{
    (void) ctx;
}

void mbedtls_gcm_free(mbedtls_gcm_context* ctx)
{
    (void) ctx;
}

int mbedtls_gcm_setkey(
    mbedtls_gcm_context* ctx,
    mbedtls_cipher_id_t cipher,
    const unsigned char* key,
    unsigned int keybits
)
{
    (void) ctx;
    lastGcmCipher = (int) cipher;
    lastGcmKeyBits = keybits;
    size_t keyBytes = keybits / 8U;
    memcpy(lastGcmKey, key, (keyBytes < sizeof lastGcmKey) ? keyBytes : sizeof lastGcmKey);
    return (gcmFailStep == MBEDTLSFAKE_GCM_STEP_SETKEY) ? -1 : 0;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters) -- signature fixed by the mbedTLS API
int mbedtls_gcm_crypt_and_tag(
    mbedtls_gcm_context* ctx,
    int mode,
    size_t length,
    const unsigned char* iv,
    size_t iv_len,
    const unsigned char* add,
    size_t add_len,
    const unsigned char* input,
    unsigned char* output,
    size_t tag_len,
    unsigned char* tag
)
{
    (void) ctx;
    (void) mode;
    gcmSealCount++;
    memcpy(lastGcmNonce, iv, (iv_len < sizeof lastGcmNonce) ? iv_len : sizeof lastGcmNonce);
    /* Report only what was actually captured - a reader walking LastGcmAad() /
     * LastGcmPlaintext() up to the reported length then never runs past the
     * capture buffer if a test exceeds its capacity. */
    lastGcmAadLen = (add_len < sizeof lastGcmAad) ? add_len : sizeof lastGcmAad;
    memcpy(lastGcmAad, add, lastGcmAadLen);
    lastGcmPlaintextLen = (length < sizeof lastGcmPlaintext) ? length : sizeof lastGcmPlaintext;
    memcpy(lastGcmPlaintext, input, lastGcmPlaintextLen);
    /* The double does not encrypt: copy input to output unchanged so the
     * in-place buffer stays defined (memmove - production passes output == input)
     * and write a canned all-zero tag the adapter only forwards into the trailer. */
    memmove(output, input, length);
    memset(tag, 0, tag_len);
    return (gcmFailStep == MBEDTLSFAKE_GCM_STEP_CRYPT_AND_TAG) ? -1 : 0;
}

int mbedtls_gcm_auth_decrypt(
    mbedtls_gcm_context* ctx,
    size_t length,
    const unsigned char* iv,
    size_t iv_len,
    const unsigned char* add,
    size_t add_len,
    const unsigned char* tag,
    size_t tag_len,
    const unsigned char* input,
    unsigned char* output
)
{
    (void) ctx;
    (void) tag;
    (void) tag_len;
    gcmOpenCount++;
    memcpy(lastGcmNonce, iv, (iv_len < sizeof lastGcmNonce) ? iv_len : sizeof lastGcmNonce);
    lastGcmAadLen = (add_len < sizeof lastGcmAad) ? add_len : sizeof lastGcmAad;
    memcpy(lastGcmAad, add, lastGcmAadLen);
    memmove(output, input, length);
    /* Canned verdict - real tag verification is the integration suite's job.
     * SetGcmAuthFails drives the tamper / wrong-key rejection (silent false);
     * the AUTH_DECRYPT step drives a genuine error (reported DECRYPT_FAILED). */
    int result = 0;
    if (gcmAuthFails)
    {
        result = MBEDTLS_ERR_GCM_AUTH_FAILED;
    }
    else if (gcmFailStep == MBEDTLSFAKE_GCM_STEP_AUTH_DECRYPT)
    {
        result = -1;
    }
    else
    {
        /* Authentic. */
    }
    return result;
}

int MbedTlsFake_GcmSealCount(void)
{
    return gcmSealCount;
}

int MbedTlsFake_GcmOpenCount(void)
{
    return gcmOpenCount;
}

const uint8_t* MbedTlsFake_LastGcmKey(void)
{
    return lastGcmKey;
}

unsigned int MbedTlsFake_LastGcmKeyBits(void)
{
    return lastGcmKeyBits;
}

int MbedTlsFake_LastGcmCipher(void)
{
    return lastGcmCipher;
}

const uint8_t* MbedTlsFake_LastGcmNonce(void)
{
    return lastGcmNonce;
}

const uint8_t* MbedTlsFake_LastGcmAad(void)
{
    return lastGcmAad;
}

size_t MbedTlsFake_LastGcmAadLen(void)
{
    return lastGcmAadLen;
}

const uint8_t* MbedTlsFake_LastGcmPlaintext(void)
{
    return lastGcmPlaintext;
}

size_t MbedTlsFake_LastGcmPlaintextLen(void)
{
    return lastGcmPlaintextLen;
}

void MbedTlsFake_SetGcmStepFails(enum MbedTlsFakeGcmStep step)
{
    gcmFailStep = step;
}

void MbedTlsFake_SetGcmAuthFails(bool fails)
{
    gcmAuthFails = fails;
}

int MbedTlsFake_CtrDrbgRandomCallCount(void)
{
    return ctrDrbgRandomCallCount;
}

const void* MbedTlsFake_LastCtrDrbgRandomContext(void)
{
    return lastCtrDrbgRandomContext;
}

const void* MbedTlsFake_LastCtrDrbgRandomBuf(void)
{
    return lastCtrDrbgRandomBuf;
}

size_t MbedTlsFake_LastCtrDrbgRandomLen(void)
{
    return lastCtrDrbgRandomLen;
}

void MbedTlsFake_SetCtrDrbgRandomFails(bool fails)
{
    ctrDrbgRandomFails = fails;
}
