#ifndef MBEDTLSFAKE_H
#define MBEDTLSFAKE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogExternC.h"

struct mbedtls_ssl_config;
struct mbedtls_ssl_context;
struct mbedtls_x509_crt;
struct mbedtls_x509_crl;
struct mbedtls_ctr_drbg_context;

SOLIDSYSLOG_EXTERN_C_BEGIN

    /* Resets every counter and captured-arg field to its initial state.
     * Call from TEST_GROUP::setup() so each test starts from a clean slate. */
    void MbedTlsFake_Reset(void);

    int MbedTlsFake_SslConfigInitCallCount(void);
    struct mbedtls_ssl_config* MbedTlsFake_LastSslConfigInitArg(void);

    int MbedTlsFake_SslConfigDefaultsCallCount(void);
    struct mbedtls_ssl_config* MbedTlsFake_LastSslConfigDefaultsConfigArg(void);
    int MbedTlsFake_LastSslConfigDefaultsEndpoint(void);
    int MbedTlsFake_LastSslConfigDefaultsTransport(void);
    int MbedTlsFake_LastSslConfigDefaultsPreset(void);
    void MbedTlsFake_SetSslConfigDefaultsReturn(int value);

    int MbedTlsFake_SslInitCallCount(void);
    struct mbedtls_ssl_context* MbedTlsFake_LastSslInitArg(void);

    int MbedTlsFake_SslSetupCallCount(void);
    struct mbedtls_ssl_context* MbedTlsFake_LastSslSetupContextArg(void);
    const struct mbedtls_ssl_config* MbedTlsFake_LastSslSetupConfigArg(void);
    void MbedTlsFake_SetSslSetupReturn(int value);

    int MbedTlsFake_SslSetBioCallCount(void);
    struct mbedtls_ssl_context* MbedTlsFake_LastSslSetBioContextArg(void);
    void* MbedTlsFake_LastSslSetBioPBioArg(void);
    int (*MbedTlsFake_LastSslSetBioSendCallback(void))(void*, const unsigned char*, size_t);
    int (*MbedTlsFake_LastSslSetBioRecvCallback(void))(void*, unsigned char*, size_t);
    int (*MbedTlsFake_LastSslSetBioRecvTimeoutCallback(void))(void*, unsigned char*, size_t, uint32_t);

    int MbedTlsFake_SslHandshakeCallCount(void);
    struct mbedtls_ssl_context* MbedTlsFake_LastSslHandshakeArg(void);
    void MbedTlsFake_SetSslHandshakeReturn(int value);
    /* Per-call return sequence - each handshake invocation gets the next
     * value in `values`; once exhausted, every subsequent call returns the
     * last entry. Used to drive WANT_READ/WANT_WRITE retry loops. Capped
     * at MBEDTLSFAKE_MAX_HANDSHAKE_RETURNS (silently truncated). */
    void MbedTlsFake_SetSslHandshakeReturnSequence(const int* values, int count);

    /* mbedtls_ssl_get_verify_result - the accumulated MBEDTLS_X509_BADCERT_*
     * flags the adapter reads after a refused handshake. Resets to 0, which is
     * what mbedTLS reports when verification found nothing wrong. */
    void MbedTlsFake_SetSslVerifyResult(uint32_t flags);

    int MbedTlsFake_SslWriteCallCount(void);
    struct mbedtls_ssl_context* MbedTlsFake_LastSslWriteContextArg(void);
    const unsigned char* MbedTlsFake_LastSslWriteBufArg(void);
    size_t MbedTlsFake_LastSslWriteLenArg(void);
    void MbedTlsFake_SetSslWriteReturn(int value);

    int MbedTlsFake_SslReadCallCount(void);
    struct mbedtls_ssl_context* MbedTlsFake_LastSslReadContextArg(void);
    unsigned char* MbedTlsFake_LastSslReadBufArg(void);
    size_t MbedTlsFake_LastSslReadLenArg(void);
    void MbedTlsFake_SetSslReadReturn(int value);

    int MbedTlsFake_SslCloseNotifyCallCount(void);
    struct mbedtls_ssl_context* MbedTlsFake_LastSslCloseNotifyArg(void);

    int MbedTlsFake_SslFreeCallCount(void);
    struct mbedtls_ssl_context* MbedTlsFake_LastSslFreeArg(void);

    int MbedTlsFake_SslConfigFreeCallCount(void);
    struct mbedtls_ssl_config* MbedTlsFake_LastSslConfigFreeArg(void);

    int MbedTlsFake_SslConfAuthmodeCallCount(void);
    struct mbedtls_ssl_config* MbedTlsFake_LastSslConfAuthmodeConfigArg(void);
    int MbedTlsFake_LastSslConfAuthmodeArg(void);

    /* mbedtls_ssl_conf_verify - the callback the stream registers, and one
     * certificate to pass it. The digest is whatever MbedTlsFake_SetDigest
     * configured, so the certificate carries no bytes of its own. */
    int (*MbedTlsFake_LastSslConfVerifyCallback(void))(void*, struct mbedtls_x509_crt*, int, uint32_t*);
    void* MbedTlsFake_LastSslConfVerifyContext(void);
    struct mbedtls_x509_crt* MbedTlsFake_Certificate(void);

    /* mbedtls_md - the digest the stream takes over a certificate. Reports the
     * bytes a test configures, and NULL from mbedtls_md_info_from_type stands
     * for a hash compiled out of the library. Which algorithm was asked for
     * reads back through MbedTlsFake_LastMdInfoType. */
    void MbedTlsFake_SetDigest(const unsigned char* digest, size_t length);
    void MbedTlsFake_SetDigestUnavailableFor(int mdType);

    /* mbedtls_ssl_conf_min_tls_version is a static-inline setter in <mbedtls/ssl.h>
     * (it writes conf->min_tls_version directly), so it cannot be intercepted at
     * link time like the other conf_* doubles. This reader exposes the field the
     * production inline call set, so a test can assert the negotiated floor. */
    int MbedTlsFake_ConfMinTlsVersion(const struct mbedtls_ssl_config* conf);

    int MbedTlsFake_SslConfCaChainCallCount(void);
    struct mbedtls_ssl_config* MbedTlsFake_LastSslConfCaChainConfigArg(void);
    struct mbedtls_x509_crt* MbedTlsFake_LastSslConfCaChainArg(void);
    struct mbedtls_x509_crl* MbedTlsFake_LastSslConfCaChainCrlArg(void);

    int MbedTlsFake_SslConfRngCallCount(void);
    struct mbedtls_ssl_config* MbedTlsFake_LastSslConfRngConfigArg(void);
    int (*MbedTlsFake_LastSslConfRngFuncArg(void))(void*, unsigned char*, size_t);
    void* MbedTlsFake_LastSslConfRngContextArg(void);

    int MbedTlsFake_SslSetHostnameCallCount(void);
    struct mbedtls_ssl_context* MbedTlsFake_LastSslSetHostnameContextArg(void);
    const char* MbedTlsFake_LastSslSetHostnameNameArg(void);
    void MbedTlsFake_SetSslSetHostnameReturn(int value);

    /* mbedtls_ssl_conf_own_cert (mTLS client identity wiring) */
    int MbedTlsFake_SslConfOwnCertCallCount(void);
    struct mbedtls_ssl_config* MbedTlsFake_LastSslConfOwnCertConfigArg(void);
    struct mbedtls_x509_crt* MbedTlsFake_LastSslConfOwnCertCertArg(void);
    struct mbedtls_pk_context* MbedTlsFake_LastSslConfOwnCertKeyArg(void);
    void MbedTlsFake_SetSslConfOwnCertReturn(int value);

    /* mbedtls_pk_check_pair (client key against its certificate) */
    int MbedTlsFake_PkCheckPairCallCount(void);
    const struct mbedtls_pk_context* MbedTlsFake_LastPkCheckPairPublicKeyArg(void);
    const struct mbedtls_pk_context* MbedTlsFake_LastPkCheckPairPrivateKeyArg(void);
    int (*MbedTlsFake_LastPkCheckPairRngFuncArg(void))(void*, unsigned char*, size_t);
    void* MbedTlsFake_LastPkCheckPairRngContextArg(void);
    void MbedTlsFake_SetPkCheckPairReturn(int value);

    int MbedTlsFake_MdHmacCallCount(void);
    int MbedTlsFake_LastMdInfoType(void);
    const uint8_t* MbedTlsFake_LastMdHmacKey(void);
    size_t MbedTlsFake_LastMdHmacKeyLen(void);
    const uint8_t* MbedTlsFake_LastMdHmacInput(void);
    size_t MbedTlsFake_LastMdHmacInputLen(void);
    void MbedTlsFake_SetMdHmacReturn(int value);

    /* Computes the same deterministic, non-cryptographic 32-byte tag the fake's
     * mbedtls_md_hmac writes - derived from (key, input) so tests can predict the
     * tag and exercise round-trip / tamper / wrong-key behaviour. NOT a real HMAC. */
    void MbedTlsFake_ComputeExpectedTag(
        const uint8_t* key,
        size_t keyLength,
        const uint8_t* input,
        size_t inputLength,
        uint8_t* tagOut
    );

    int MbedTlsFake_PlatformZeroizeCallCount(void);
    const void* MbedTlsFake_LastPlatformZeroizeBuf(void);
    size_t MbedTlsFake_LastPlatformZeroizeLen(void);

    /* AES-256-GCM (mbedtls_gcm_*) + CTR-DRBG nonce source - drive the at-rest
     * AES-GCM SecurityPolicy without linking real libmbedcrypto. A
     * capture-and-canned-return double, NOT a cipher: mbedtls_gcm_crypt_and_tag /
     * mbedtls_gcm_auth_decrypt capture their arguments, copy the body through
     * unchanged, and return canned results. It verifies the adapter's wiring;
     * genuine AES-256-GCM correctness (round-trip, tamper, wrong-key) is the
     * MbedTlsIntegration suite's job. */
    int MbedTlsFake_GcmSealCount(void); /* mbedtls_gcm_crypt_and_tag calls (seals) */
    int MbedTlsFake_GcmOpenCount(void); /* mbedtls_gcm_auth_decrypt calls (opens) */
    const uint8_t* MbedTlsFake_LastGcmKey(void); /* 32 bytes, from setkey */
    unsigned int MbedTlsFake_LastGcmKeyBits(void); /* keybits arg to setkey */
    int MbedTlsFake_LastGcmCipher(void); /* mbedtls_cipher_id_t arg to setkey */
    const uint8_t* MbedTlsFake_LastGcmNonce(void); /* 12 bytes */
    const uint8_t* MbedTlsFake_LastGcmAad(void);
    size_t MbedTlsFake_LastGcmAadLen(void);
    const uint8_t* MbedTlsFake_LastGcmPlaintext(void); /* body bytes handed to encrypt */
    size_t MbedTlsFake_LastGcmPlaintextLen(void);

    /* Step of the seal/open sequence to fail, so a test can pin the error path of
     * each fallible mbedTLS GCM call: setkey, crypt_and_tag (seal), auth_decrypt
     * (open, genuine error - distinct from the tamper verdict below). */
    enum MbedTlsFakeGcmStep
    {
        MBEDTLSFAKE_GCM_STEP_NONE = 0,
        MBEDTLSFAKE_GCM_STEP_SETKEY,
        MBEDTLSFAKE_GCM_STEP_CRYPT_AND_TAG,
        MBEDTLSFAKE_GCM_STEP_AUTH_DECRYPT
    };

    void MbedTlsFake_SetGcmStepFails(enum MbedTlsFakeGcmStep step);
    /* Makes mbedtls_gcm_auth_decrypt return MBEDTLS_ERR_GCM_AUTH_FAILED - the
     * tamper / wrong-key verdict the adapter must surface silently (no report). */
    void MbedTlsFake_SetGcmAuthFails(bool fails);

    /* mbedtls_ctr_drbg_random - the policy's per-record nonce source. */
    int MbedTlsFake_CtrDrbgRandomCallCount(void);
    const void* MbedTlsFake_LastCtrDrbgRandomContext(void);
    const void* MbedTlsFake_LastCtrDrbgRandomBuf(void);
    size_t MbedTlsFake_LastCtrDrbgRandomLen(void);
    void MbedTlsFake_SetCtrDrbgRandomFails(bool fails);

SOLIDSYSLOG_EXTERN_C_END

#endif /* MBEDTLSFAKE_H */
