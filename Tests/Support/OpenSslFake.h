#ifndef OPENSSLFAKE_H
#define OPENSSLFAKE_H

#include "SolidSyslogExternC.h"

#include <stdbool.h> // IWYU pragma: keep - dual-use header (C and C++ TUs); IWYU only sees the C++ side and would drop this.
#include <stddef.h>
#include <stdint.h>

/* Forward-declared OpenSSL types - full definitions live in <openssl/ssl.h>. */
struct ssl_ctx_st;
struct ssl_st;
struct ssl_method_st;
struct bio_st;
struct bio_method_st;
struct x509_store_ctx_st;

SOLIDSYSLOG_EXTERN_C_BEGIN

    void OpenSslFake_Reset(void);

    void OpenSslFake_SetConnectFails(bool fails);
    void OpenSslFake_SetWriteFails(bool fails);
    void OpenSslFake_SetSet1HostFails(bool fails);
    void OpenSslFake_SetSniHostnameFails(bool fails);
    void OpenSslFake_SetCtxNewFails(bool fails);
    void OpenSslFake_SetSslNewFails(bool fails);
    void OpenSslFake_SetLoadVerifyLocationsFails(bool fails);
    void OpenSslFake_SetMinProtoVersionFails(bool fails);
    void OpenSslFake_SetBioMethNewFails(bool fails);
    void OpenSslFake_SetBioNewFails(bool fails);
    void OpenSslFake_SetCipherListFails(bool fails);

    /* SSL return-value injection - drive non-blocking I/O paths */
    enum
    {
        OPENSSLFAKE_MAX_CONNECT_RETURNS = 8
    };

    void OpenSslFake_SetConnectReturnSequence(const int* values, int count);
    void OpenSslFake_SetWriteReturn(int value);
    void OpenSslFake_SetReadReturn(int value);
    void OpenSslFake_SetGetErrorReturn(int err);
    int OpenSslFake_GetErrorCallCount(void);

    /* SSL_get_verify_result - the certification-path verdict the adapter reads
     * after a refused handshake. Resets to X509_V_OK, which is what OpenSSL
     * reports when verification never ran or found nothing wrong. */
    void OpenSslFake_SetVerifyResult(long value);

    int OpenSslFake_BioSetFlagsCallCount(void);
    int OpenSslFake_LastBioSetFlags(void);
    int OpenSslFake_BioClearFlagsCallCount(void);

    int OpenSslFake_CtxNewCallCount(void);
    const struct ssl_method_st* OpenSslFake_LastCtxNewMethodArg(void);
    struct ssl_ctx_st* OpenSslFake_LastCtxReturned(void);

    struct ssl_ctx_st* OpenSslFake_LastLoadVerifyLocationsCtxArg(void);
    const char* OpenSslFake_LastCaBundlePath(void);

    struct ssl_ctx_st* OpenSslFake_LastSetVerifyCtxArg(void);
    int OpenSslFake_LastVerifyMode(void);
    int (*OpenSslFake_LastVerifyCallback(void))(int, struct x509_store_ctx_st*);

    /* SSL_set_ex_data / SSL_get_ex_data - one slot, which is all
     * SSL_set_app_data uses. */
    int OpenSslFake_LastSslExDataIndex(void);
    void* OpenSslFake_LastSslExData(void);
    void OpenSslFake_SetSslExDataFails(bool fails);

    /* One X509_STORE_CTX for driving a captured verify callback. Its ex_data
     * at the SSL index resolves to the SSL the fake last handed out, as
     * OpenSSL's own does mid-handshake; depth, error and the leaf's digest
     * are what a test sets. X509_digest reports the configured bytes, or
     * fails when told to. */
    struct x509_store_ctx_st* OpenSslFake_StoreCtx(void);
    void OpenSslFake_SetStoreCtxDepth(int depth);
    void OpenSslFake_SetStoreCtxError(int error);
    int OpenSslFake_StoreCtxError(void);
    void OpenSslFake_SetCertDigest(const uint8_t* digest, size_t length);
    void OpenSslFake_SetDigestFails(bool fails);
    const void* OpenSslFake_LastDigestMd(void); /* compare against EVP_sha1() / EVP_sha256() */

    /* SSL_CTX_ctrl (SET_MIN_PROTO_VERSION path) */
    struct ssl_ctx_st* OpenSslFake_LastSslCtxCtrlCtxArg(void);
    long OpenSslFake_LastMinProtoVersion(void);

    int OpenSslFake_SetCipherListCallCount(void);
    struct ssl_ctx_st* OpenSslFake_LastSetCipherListCtxArg(void);
    const char* OpenSslFake_LastCipherList(void);

    int OpenSslFake_SslNewCallCount(void);
    struct ssl_ctx_st* OpenSslFake_LastSslNewCtxArg(void);
    struct ssl_st* OpenSslFake_LastSslReturned(void);

    struct bio_method_st* OpenSslFake_LastBioMethReturned(void);

    int OpenSslFake_BioMethFreeCallCount(void);
    struct bio_method_st* OpenSslFake_LastBioMethFreeArg(void);

    struct bio_method_st* OpenSslFake_LastBioMethSetReadMethodArg(void);
    int (*OpenSslFake_LastBioReadCallback(void))(struct bio_st*, char*, int);
    long (*OpenSslFake_LastBioCtrlCallback(void))(struct bio_st*, int, long, void*);
    int (*OpenSslFake_LastBioCreateCallback(void))(struct bio_st*);
    int OpenSslFake_LastSetInitArg(void);

    struct bio_method_st* OpenSslFake_LastBioMethSetWriteMethodArg(void);
    int (*OpenSslFake_LastBioWriteCallback(void))(struct bio_st*, const char*, int);

    int OpenSslFake_BioNewCallCount(void);
    const struct bio_method_st* OpenSslFake_LastBioNewMethodArg(void);
    struct bio_st* OpenSslFake_LastBioReturned(void);

    struct bio_st* OpenSslFake_LastSetDataBioArg(void);
    void* OpenSslFake_LastSetDataArg(void);

    /* BIO_get_data (arg capture for BIO-callback introspection) */
    struct bio_st* OpenSslFake_LastGetDataBioArg(void);

    int OpenSslFake_SetBioCallCount(void);
    struct ssl_st* OpenSslFake_LastSetBioSslArg(void);
    struct bio_st* OpenSslFake_LastSetBioReadBioArg(void);
    struct bio_st* OpenSslFake_LastSetBioWriteBioArg(void);

    /* SSL_ctrl (SET_TLSEXT_HOSTNAME path - SNI) */
    struct ssl_st* OpenSslFake_LastSslCtrlSslArg(void);
    const char* OpenSslFake_LastSniHostname(void);

    struct ssl_st* OpenSslFake_LastSet1HostSslArg(void);
    const char* OpenSslFake_LastSet1Host(void);

    int OpenSslFake_ConnectCallCount(void);
    struct ssl_st* OpenSslFake_LastConnectSslArg(void);

    int OpenSslFake_WriteCallCount(void);
    struct ssl_st* OpenSslFake_LastWriteSslArg(void);
    const void* OpenSslFake_LastWriteBuf(void);
    int OpenSslFake_LastWriteSize(void);

    int OpenSslFake_SslReadCallCount(void);
    struct ssl_st* OpenSslFake_LastSslReadSslArg(void);
    void* OpenSslFake_LastSslReadBuf(void);
    int OpenSslFake_LastSslReadSize(void);

    int OpenSslFake_ShutdownCallCount(void);
    struct ssl_st* OpenSslFake_LastShutdownSslArg(void);

    int OpenSslFake_FreeCallCount(void);
    struct ssl_st* OpenSslFake_LastFreeSslArg(void);

    int OpenSslFake_CtxFreeCallCount(void);
    struct ssl_ctx_st* OpenSslFake_LastCtxFreeCtxArg(void);

    int OpenSslFake_UseCertChainFileCallCount(void);
    struct ssl_ctx_st* OpenSslFake_LastUseCertChainFileCtxArg(void);
    const char* OpenSslFake_LastClientCertChainPath(void);
    void OpenSslFake_SetUseCertChainFileFails(bool fails);

    int OpenSslFake_UsePrivateKeyFileCallCount(void);
    struct ssl_ctx_st* OpenSslFake_LastUsePrivateKeyFileCtxArg(void);
    const char* OpenSslFake_LastClientKeyPath(void);
    int OpenSslFake_LastClientKeyFileType(void);
    void OpenSslFake_SetUsePrivateKeyFileFails(bool fails);

    int OpenSslFake_CheckPrivateKeyCallCount(void);
    struct ssl_ctx_st* OpenSslFake_LastCheckPrivateKeyCtxArg(void);
    void OpenSslFake_SetCheckPrivateKeyFails(bool fails);

    /* HMAC / EVP_sha256 / OPENSSL_cleanse - drive the at-rest HMAC-SHA256
     * SecurityPolicy without linking real libcrypto. */
    int OpenSslFake_HmacCallCount(void);
    const void* OpenSslFake_LastHmacMd(void); /* compare against EVP_sha256() to assert SHA-256 was selected */
    const uint8_t* OpenSslFake_LastHmacKey(void);
    int OpenSslFake_LastHmacKeyLen(void);
    const uint8_t* OpenSslFake_LastHmacInput(void);
    size_t OpenSslFake_LastHmacInputLen(void);
    void OpenSslFake_SetHmacFails(bool fails);

    /* Computes the same deterministic, non-cryptographic 32-byte tag the fake's
     * HMAC writes - derived from (key, input) so tests can predict the tag and
     * exercise round-trip / tamper / wrong-key behaviour. NOT a real HMAC. */
    void OpenSslFake_ComputeExpectedTag(
        const uint8_t* key,
        size_t keyLength,
        const uint8_t* input,
        size_t inputLength,
        uint8_t* tagOut
    );

    int OpenSslFake_CleanseCallCount(void);
    const void* OpenSslFake_LastCleanseBuf(void);
    size_t OpenSslFake_LastCleanseLen(void);

    /* AES-256-GCM EVP cipher + RAND_bytes - drive the at-rest AES-GCM
     * SecurityPolicy without linking real libcrypto. A capture-and-canned-return
     * double, NOT a cipher: the EVP calls capture their arguments, copy the body
     * through unchanged, and return canned results. It verifies the adapter's
     * wiring; genuine AES-256-GCM correctness (round-trip, tamper, wrong-key) is
     * the OpenSslIntegration suite's job. */
    int OpenSslFake_GcmSealCount(void); /* EVP_CTRL_GCM_GET_TAG calls (seals) */
    int OpenSslFake_GcmOpenCount(void); /* EVP_DecryptFinal_ex calls (opens) */
    const uint8_t* OpenSslFake_LastGcmKey(void); /* 32 bytes */
    const uint8_t* OpenSslFake_LastGcmNonce(void); /* 12 bytes */
    const uint8_t* OpenSslFake_LastGcmAad(void);
    size_t OpenSslFake_LastGcmAadLen(void);
    const uint8_t* OpenSslFake_LastGcmPlaintext(void); /* body bytes handed to encrypt */
    size_t OpenSslFake_LastGcmPlaintextLen(void);

    /* Step of the EVP seal/open sequence to fail, so a test can pin the error
     * path of each OpenSSL crypto call the adapter makes. The names match the
     * production && chain: CTX_NEW -> INIT_CIPHER -> SET_IVLEN -> INIT_KEY ->
     * UPDATE_AAD -> UPDATE_BODY -> (encrypt: FINAL -> GET_TAG) / (decrypt: SET_TAG ->
     * FINAL). A FINAL failure on open is the tamper/auth-reject verdict. */
    enum OpenSslFakeGcmStep
    {
        OPENSSLFAKE_GCM_STEP_NONE = 0,
        OPENSSLFAKE_GCM_STEP_CTX_NEW,
        OPENSSLFAKE_GCM_STEP_INIT_CIPHER,
        OPENSSLFAKE_GCM_STEP_SET_IVLEN,
        OPENSSLFAKE_GCM_STEP_INIT_KEY,
        OPENSSLFAKE_GCM_STEP_UPDATE_AAD,
        OPENSSLFAKE_GCM_STEP_UPDATE_BODY,
        OPENSSLFAKE_GCM_STEP_FINAL,
        OPENSSLFAKE_GCM_STEP_GET_TAG,
        OPENSSLFAKE_GCM_STEP_SET_TAG
    };

    void OpenSslFake_SetGcmStepFails(enum OpenSslFakeGcmStep step);

    int OpenSslFake_RandBytesCallCount(void);
    const void* OpenSslFake_LastRandBytesBuf(void);
    int OpenSslFake_LastRandBytesLen(void);
    void OpenSslFake_SetRandBytesFails(bool fails);

SOLIDSYSLOG_EXTERN_C_END

#endif /* OPENSSLFAKE_H */
