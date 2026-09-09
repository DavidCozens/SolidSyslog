/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogOpenSslStream.h"

#include <openssl/bio.h>
#include <openssl/prov_ssl.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogNullStream.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogStreamDefinition.h"
#include "SolidSyslogOpenSslCredentialsDefinition.h"
#include "SolidSyslogTlsCredentialsInstalled.h"
#include "SolidSyslogTlsFingerprint.h"
#include "SolidSyslogTlsStreamCategories.h"
#include "SolidSyslogOpenSslStreamErrors.h"
#include "SolidSyslogOpenSslStreamPrivate.h"
#include "SolidSyslogTunables.h"

const struct SolidSyslogErrorSource SolidSyslogOpenSslStreamErrorSource = {"OpenSslStream"};

enum
{
    HANDSHAKE_POLL_INTERVAL_MILLISECONDS = 1
};

static uint32_t OpenSslStream_NullHandshakeTimeoutGetter(void* context);
static uint32_t OpenSslStream_NullVersion(void* context);
static inline bool OpenSslStream_ConfigProvidesHandshakeGetter(const struct SolidSyslogOpenSslStreamConfig* config);
static inline bool OpenSslStream_ConfigProvidesVersion(const struct SolidSyslogOpenSslStreamConfig* config);
static inline uint32_t OpenSslStream_ResolveHandshakeTimeoutMs(struct SolidSyslogOpenSslStream* self);

struct SolidSyslogAddress;

static inline struct SolidSyslogOpenSslStream* OpenSslStream_SelfFromBase(struct SolidSyslogStream* base);

static inline bool OpenSslStream_AttachTransportBio(struct SolidSyslogOpenSslStream* self);
static inline void OpenSslStream_Close(struct SolidSyslogStream* base);
static uint32_t OpenSslStream_Version(struct SolidSyslogStream* base);
static inline bool OpenSslStream_ConfigureCipherList(SSL_CTX* ctx, const char* cipherList);
static inline bool OpenSslStream_ConfigureExpectedHostname(struct SolidSyslogOpenSslStream* self);
static inline bool OpenSslStream_ConfigureProtocolFloor(SSL_CTX* ctx);
static inline bool OpenSslStream_ConfigureSslContext(SSL_CTX* ctx, const struct SolidSyslogOpenSslStreamConfig* config);
static inline SSL_CTX* OpenSslStream_CreateSslContext(const struct SolidSyslogOpenSslStreamConfig* config);
static inline BIO* OpenSslStream_CreateTransportBio(struct SolidSyslogOpenSslStream* self);
static inline BIO_METHOD* OpenSslStream_CreateTransportBioMethod(void);
static inline bool OpenSslStream_InitSslContext(struct SolidSyslogOpenSslStream* self);
static inline bool OpenSslStream_InstallCredentials(struct SolidSyslogOpenSslStream* self);
static inline bool OpenSslStream_PeerIsAuthorisable(const struct SolidSyslogTlsCredentialsInstalled* installed);
static inline bool OpenSslStream_FingerprintsAreUsable(const struct SolidSyslogTlsCredentialsInstalled* installed);
static inline void OpenSslStream_ReleaseCredentials(struct SolidSyslogOpenSslStream* self);
static inline bool OpenSslStream_RequirePeerVerification(SSL_CTX* ctx);
static int OpenSslStream_VerifyPeer(int preverifyOk, X509_STORE_CTX* storeCtx);
static inline struct SolidSyslogOpenSslStream* OpenSslStream_SelfFromStoreCtx(X509_STORE_CTX* storeCtx);
static inline int OpenSslStream_VerifyPinnedLeaf(
    struct SolidSyslogOpenSslStream* self,
    int preverifyOk,
    X509_STORE_CTX* storeCtx
);
static inline bool OpenSslStream_LeafMatchesAPin(struct SolidSyslogOpenSslStream* self, X509_STORE_CTX* storeCtx);
static inline const EVP_MD* OpenSslStream_DigestFor(enum SolidSyslogTlsHashAlgorithm algorithm);
static bool OpenSslStream_DigestCertificate(
    void* context,
    enum SolidSyslogTlsHashAlgorithm algorithm,
    uint8_t* digest,
    size_t* length
);
static inline bool OpenSslStream_IsChainTrustWaived(
    const struct SolidSyslogOpenSslStream* self,
    const X509_STORE_CTX* storeCtx
);
static inline bool OpenSslStream_IsChainTrustError(int error);
static inline bool OpenSslStream_InitSslSession(struct SolidSyslogOpenSslStream* self);
static inline bool OpenSslStream_Open(struct SolidSyslogStream* base, const struct SolidSyslogAddress* addr);
static inline bool OpenSslStream_PerformHandshake(struct SolidSyslogOpenSslStream* self);
static inline enum SolidSyslogOpenSslStreamErrors OpenSslStream_RefusalDetail(struct SolidSyslogOpenSslStream* self);
static inline SolidSyslogSsize OpenSslStream_Read(struct SolidSyslogStream* base, void* buffer, size_t size);
static inline void OpenSslStream_ReleaseBioMethod(struct SolidSyslogOpenSslStream* self);
static inline void OpenSslStream_ReleaseHandshakeState(struct SolidSyslogOpenSslStream* self);
static inline void OpenSslStream_ReleaseSsl(struct SolidSyslogOpenSslStream* self);
static inline void OpenSslStream_ReleaseSslContext(struct SolidSyslogOpenSslStream* self);
static inline bool OpenSslStream_Send(struct SolidSyslogStream* base, const void* buffer, size_t size);
static inline int OpenSslStream_TransportBioCreate(BIO* bio);
static inline long OpenSslStream_TransportBioCtrl(BIO* bio, int cmd, long larg, void* parg);
static inline int OpenSslStream_TransportBioRead(BIO* bio, char* buffer, int size);
static inline int OpenSslStream_TransportBioWrite(BIO* bio, const char* buffer, int size);

void SolidSyslogOpenSslStream_Initialise(
    struct SolidSyslogStream* base,
    const struct SolidSyslogOpenSslStreamConfig* config
)
{
    struct SolidSyslogOpenSslStream* self = OpenSslStream_SelfFromBase(base);
    self->Base.Open = OpenSslStream_Open;
    self->Base.Send = OpenSslStream_Send;
    self->Base.Read = OpenSslStream_Read;
    self->Base.Close = OpenSslStream_Close;
    self->Base.Version = OpenSslStream_Version;
    self->Config = *config;
    if (OpenSslStream_ConfigProvidesHandshakeGetter(config) == false)
    {
        /* Substitute the Null Object so the bounded-handshake loop has a
         * single code path regardless of whether the integrator wired
         * runtime tuning. */
        self->Config.GetHandshakeTimeoutMs = OpenSslStream_NullHandshakeTimeoutGetter;
        self->Config.HandshakeTimeoutContext = NULL;
    }
    if (OpenSslStream_ConfigProvidesVersion(config) == false)
    {
        self->Config.Version = OpenSslStream_NullVersion;
        self->Config.VersionContext = NULL;
    }
    self->Ctx = NULL;
    self->Ssl = NULL;
    self->BioMethod = NULL;
    self->CredentialsInstalled = false;
}

static inline struct SolidSyslogOpenSslStream* OpenSslStream_SelfFromBase(struct SolidSyslogStream* base)
{
    return (struct SolidSyslogOpenSslStream*) base;
}

void SolidSyslogOpenSslStream_Cleanup(struct SolidSyslogStream* base)
{
    /* Close first so an integrator who destroys a still-Open stream doesn't
     * leak the underlying transport. Close now releases the SSL, BIO_METHOD
     * and SSL_CTX, and is idempotent (the TLS-side teardown guards on Ssl /
     * Ctx != NULL; transport Close is itself idempotent on every Stream
     * impl), so the normal Open -> Close -> Destroy lifecycle is unaffected. */
    OpenSslStream_Close(base);
    /* Overwrite the abstract base with the shared NullStream vtable so
     * use-after-destroy is a safe no-op rather than a NULL-fn-pointer crash. */
    *base = *SolidSyslogNullStream_Get();
}

/* Idempotent: Send/Read may close internally on failure, after which the
 * StreamSender's reconnect path or the caller's Destroy may call Close
 * again. Skipping when ssl is already NULL keeps that safe. */
static inline void OpenSslStream_Close(struct SolidSyslogStream* base)
{
    struct SolidSyslogOpenSslStream* self = OpenSslStream_SelfFromBase(base);
    if (self->Ssl != NULL)
    {
        SSL_shutdown(self->Ssl);
        OpenSslStream_ReleaseHandshakeState(self);
    }
    /* Each Open rebuilds the CTX (cert-rotation contract), so Close must free
       the current one or the fail-fast Open -> Close -> Open reconnect cycle
       leaks an SSL_CTX every round. NULL-guarded, so the Open-failure tail and
       Cleanup that also call it stay double-free safe. */
    OpenSslStream_ReleaseSslContext(self);
    OpenSslStream_ReleaseCredentials(self);
    SolidSyslogStream_Close(self->Config.Transport);
}

static uint32_t OpenSslStream_Version(struct SolidSyslogStream* base)
{
    struct SolidSyslogOpenSslStream* self = OpenSslStream_SelfFromBase(base);
    return self->Config.Version(self->Config.VersionContext);
}

static inline void OpenSslStream_ReleaseHandshakeState(struct SolidSyslogOpenSslStream* self)
{
    OpenSslStream_ReleaseSsl(self);
    OpenSslStream_ReleaseBioMethod(self);
}

static inline void OpenSslStream_ReleaseSsl(struct SolidSyslogOpenSslStream* self)
{
    if (self->Ssl != NULL)
    {
        SSL_free(self->Ssl);
        self->Ssl = NULL;
    }
}

static inline void OpenSslStream_ReleaseBioMethod(struct SolidSyslogOpenSslStream* self)
{
    if (self->BioMethod != NULL)
    {
        BIO_meth_free(self->BioMethod);
        self->BioMethod = NULL;
    }
}

static inline void OpenSslStream_ReleaseSslContext(struct SolidSyslogOpenSslStream* self)
{
    if (self->Ctx != NULL)
    {
        SSL_CTX_free(self->Ctx);
        self->Ctx = NULL;
    }
}

static inline bool OpenSslStream_Open(struct SolidSyslogStream* base, const struct SolidSyslogAddress* addr)
{
    struct SolidSyslogOpenSslStream* self = OpenSslStream_SelfFromBase(base);
    bool ok = SolidSyslogStream_Open(self->Config.Transport, addr) && OpenSslStream_InitSslContext(self) &&
              OpenSslStream_InstallCredentials(self) && OpenSslStream_InitSslSession(self) &&
              OpenSslStream_AttachTransportBio(self) && OpenSslStream_ConfigureExpectedHostname(self) &&
              OpenSslStream_PerformHandshake(self);
    if (!ok)
    {
        OpenSslStream_Close(base);
    }
    return ok;
}

static inline bool OpenSslStream_InitSslContext(struct SolidSyslogOpenSslStream* self)
{
    self->Ctx = OpenSslStream_CreateSslContext(&self->Config);
    bool ok = self->Ctx != NULL;
    if (!ok)
    {
        OpenSslStream_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
            SOLIDSYSLOG_OPENSSL_STREAM_ERROR_CONTEXT_INIT_FAILED
        );
    }
    return ok;
}

/* Asked once per connection, after the context exists and before the handshake,
 * so material is fetched only for a connection actually being made. The flag is
 * set before the call rather than after it: the contract is one Release per
 * Install call whatever that call returned, which is what spares every backend
 * a rollback path of its own. */
static inline bool OpenSslStream_InstallCredentials(struct SolidSyslogOpenSslStream* self)
{
    self->Installed.TrustAnchorsInstalled = false;
    self->Installed.Fingerprints = NULL;
    self->Installed.FingerprintCount = 0U;
    self->CredentialsInstalled = true;
    bool ok = self->Config.Credentials->Install(self->Config.Credentials, self->Ctx, &self->Installed);
    if (ok && !OpenSslStream_PeerIsAuthorisable(&self->Installed))
    {
        OpenSslStream_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_OPENSSL_STREAM_ERROR_NO_PEER_AUTHORISATION
        );
        ok = false;
    }
    if (ok)
    {
        ok = OpenSslStream_FingerprintsAreUsable(&self->Installed);
    }
    return ok;
}

/* A peer is authorised by a chain to trust anchors or by a pinned certificate
 * fingerprint, and RFC 5425 4.2.1 makes the second sufficient on its own. With
 * neither, there is nothing to check the peer against, so the connection stops
 * rather than reaching a peer this stream cannot identify. */
static inline bool OpenSslStream_PeerIsAuthorisable(const struct SolidSyslogTlsCredentialsInstalled* installed)
{
    return installed->TrustAnchorsInstalled || (installed->FingerprintCount > 0U);
}

/* Inspected before the handshake, so a pin that cannot match is reported as
 * bad configuration rather than as a refused peer. */
static inline bool OpenSslStream_FingerprintsAreUsable(const struct SolidSyslogTlsCredentialsInstalled* installed)
{
    bool ok = true;
    enum SolidSyslogTlsFingerprintListState state =
        SolidSyslogTlsFingerprint_InspectList(installed->Fingerprints, installed->FingerprintCount);
    if (state == SOLIDSYSLOG_TLS_FINGERPRINT_LIST_MALFORMED)
    {
        OpenSslStream_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_OPENSSL_STREAM_ERROR_FINGERPRINT_MALFORMED
        );
        ok = false;
    }
    else if (state == SOLIDSYSLOG_TLS_FINGERPRINT_LIST_USES_SHA1)
    {
        OpenSslStream_Report(
            SOLIDSYSLOG_SEVERITY_WARNING,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_OPENSSL_STREAM_ERROR_FINGERPRINT_SHA1
        );
    }
    else
    {
        /* Well formed, or no pins at all. */
    }
    return ok;
}

/* Answers every Install, so the integrator is always told when the credential
 * window has closed - including on the paths where Open failed part way. */
static inline void OpenSslStream_ReleaseCredentials(struct SolidSyslogOpenSslStream* self)
{
    if (self->CredentialsInstalled)
    {
        self->CredentialsInstalled = false;
        self->Config.Credentials->Release(self->Config.Credentials);
    }
}

static inline SSL_CTX* OpenSslStream_CreateSslContext(const struct SolidSyslogOpenSslStreamConfig* config)
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if ((ctx != NULL) && !OpenSslStream_ConfigureSslContext(ctx, config))
    {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

static inline bool OpenSslStream_ConfigureSslContext(SSL_CTX* ctx, const struct SolidSyslogOpenSslStreamConfig* config)
{
    return OpenSslStream_RequirePeerVerification(ctx) && OpenSslStream_ConfigureProtocolFloor(ctx) &&
           OpenSslStream_ConfigureCipherList(ctx, config->CipherList);
}

/* Set outright rather than alongside loading trust anchors, because the peer is
 * also authorisable by a pinned fingerprint with no anchors at all. Tying the
 * two together is how a fingerprint-only configuration would come to verify
 * nothing - the one place in this design that could fail open rather than
 * closed. */
static inline bool OpenSslStream_RequirePeerVerification(SSL_CTX* ctx)
{
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, OpenSslStream_VerifyPeer);
    return true;
}

/* Called for each certificate in the chain; only the leaf, at depth 0, is
 * pinned. Returning zero above the leaf would stop verification before the
 * leaf was reached, so a pinned peer with no anchors waives the chain-trust
 * errors there as well. */
static int OpenSslStream_VerifyPeer(int preverifyOk, X509_STORE_CTX* storeCtx)
{
    struct SolidSyslogOpenSslStream* self = OpenSslStream_SelfFromStoreCtx(storeCtx);
    int verdict = preverifyOk;

    if (X509_STORE_CTX_get_error_depth(storeCtx) == 0)
    {
        if (self->Installed.FingerprintCount > 0U)
        {
            verdict = OpenSslStream_VerifyPinnedLeaf(self, preverifyOk, storeCtx);
        }
    }
    else if (OpenSslStream_IsChainTrustWaived(self, storeCtx))
    {
        verdict = 1;
    }
    else
    {
        /* OpenSSL's own verdict stands. */
    }

    return verdict;
}

/* OpenSSL files the SSL running the handshake under a well-known ex_data index
 * on the store context; the stream is that SSL's app data. */
static inline struct SolidSyslogOpenSslStream* OpenSslStream_SelfFromStoreCtx(X509_STORE_CTX* storeCtx)
{
    SSL* ssl = (SSL*) X509_STORE_CTX_get_ex_data(storeCtx, SSL_get_ex_data_X509_STORE_CTX_idx());
    return (struct SolidSyslogOpenSslStream*) SSL_get_app_data(ssl);
}

static inline int OpenSslStream_VerifyPinnedLeaf(
    struct SolidSyslogOpenSslStream* self,
    int preverifyOk,
    X509_STORE_CTX* storeCtx
)
{
    int verdict = preverifyOk;
    if (!OpenSslStream_LeafMatchesAPin(self, storeCtx))
    {
        X509_STORE_CTX_set_error(storeCtx, X509_V_ERR_APPLICATION_VERIFICATION);
        verdict = 0;
    }
    else if (OpenSslStream_IsChainTrustWaived(self, storeCtx))
    {
        verdict = 1;
    }
    else
    {
        /* OpenSSL's own verdict stands. */
    }
    return verdict;
}

static inline bool OpenSslStream_LeafMatchesAPin(struct SolidSyslogOpenSslStream* self, X509_STORE_CTX* storeCtx)
{
    X509* leaf = X509_STORE_CTX_get_current_cert(storeCtx);
    return SolidSyslogTlsFingerprint_Authorise(
               self->Installed.Fingerprints,
               self->Installed.FingerprintCount,
               OpenSslStream_DigestCertificate,
               leaf
           ) == SOLIDSYSLOG_TLS_AUTHORISATION_MATCHED;
}

static bool OpenSslStream_DigestCertificate(
    void* context,
    enum SolidSyslogTlsHashAlgorithm algorithm,
    uint8_t* digest,
    size_t* length
)
{
    const X509* leaf = (const X509*) context;
    const EVP_MD* md = OpenSslStream_DigestFor(algorithm);
    unsigned int written = 0U;
    bool ok = (md != NULL) && (X509_digest(leaf, md, digest, &written) == 1);
    *length = (size_t) written;
    return ok;
}

/* An algorithm this pack does not name has no digest, so a hash added to Core
 * and not handled here refuses the peer rather than being digested as
 * something else. */
static inline const EVP_MD* OpenSslStream_DigestFor(enum SolidSyslogTlsHashAlgorithm algorithm)
{
    const EVP_MD* md = NULL;
    if (algorithm == SOLIDSYSLOG_TLS_HASH_SHA1)
    {
        md = EVP_sha1();
    }
    else if (algorithm == SOLIDSYSLOG_TLS_HASH_SHA256)
    {
        md = EVP_sha256();
    }
    else
    {
        /* Left as NULL. */
    }
    return md;
}

static inline bool OpenSslStream_IsChainTrustWaived(
    const struct SolidSyslogOpenSslStream* self,
    const X509_STORE_CTX* storeCtx
)
{
    return (self->Installed.FingerprintCount > 0U) && !self->Installed.TrustAnchorsInstalled &&
           OpenSslStream_IsChainTrustError(X509_STORE_CTX_get_error(storeCtx));
}

/* The errors a missing trust anchor alone produces. Every other code describes
 * the certificate itself, which a pin does not vouch for. */
static inline bool OpenSslStream_IsChainTrustError(int error)
{
    return (error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) || (error == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) ||
           (error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) || (error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) ||
           (error == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE) || (error == X509_V_ERR_CERT_UNTRUSTED);
}

/* A floor, and deliberately no ceiling: RFC 9662, which updates RFC 5425,
 * requires TLS 1.3 to be preferred wherever it is implemented. */
static inline bool OpenSslStream_ConfigureProtocolFloor(SSL_CTX* ctx)
{
    return SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 1;
}

static inline bool OpenSslStream_ConfigureCipherList(SSL_CTX* ctx, const char* cipherList)
{
    bool ok = true;
    if (cipherList != NULL)
    {
        ok = SSL_CTX_set_cipher_list(ctx, cipherList) == 1;
    }
    return ok;
}

static inline bool OpenSslStream_InitSslSession(struct SolidSyslogOpenSslStream* self)
{
    self->Ssl = SSL_new(self->Ctx);
    bool ok = (self->Ssl != NULL) && (SSL_set_app_data(self->Ssl, self) == 1);
    if (!ok)
    {
        OpenSslStream_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
            SOLIDSYSLOG_OPENSSL_STREAM_ERROR_SESSION_INIT_FAILED
        );
    }
    return ok;
}

static inline bool OpenSslStream_AttachTransportBio(struct SolidSyslogOpenSslStream* self)
{
    BIO* bio = OpenSslStream_CreateTransportBio(self);
    bool ok = bio != NULL;
    if (ok)
    {
        BIO_set_data(bio, self->Config.Transport);
        SSL_set_bio(self->Ssl, bio, bio);
    }
    else
    {
        OpenSslStream_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
            SOLIDSYSLOG_OPENSSL_STREAM_ERROR_SESSION_INIT_FAILED
        );
    }
    return ok;
}

static inline BIO* OpenSslStream_CreateTransportBio(struct SolidSyslogOpenSslStream* self)
{
    self->BioMethod = OpenSslStream_CreateTransportBioMethod();
    BIO* bio = NULL;
    if (self->BioMethod != NULL)
    {
        bio = BIO_new(self->BioMethod);
        if (bio == NULL)
        {
            OpenSslStream_ReleaseBioMethod(self);
        }
    }
    return bio;
}

static inline BIO_METHOD* OpenSslStream_CreateTransportBioMethod(void)
{
    BIO_METHOD* method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "SolidSyslog transport BIO");
    if (method != NULL)
    {
        BIO_meth_set_create(method, OpenSslStream_TransportBioCreate);
        BIO_meth_set_read(method, OpenSslStream_TransportBioRead);
        BIO_meth_set_write(method, OpenSslStream_TransportBioWrite);
        BIO_meth_set_ctrl(method, OpenSslStream_TransportBioCtrl);
    }
    return method;
}

/* Called when BIO_new instantiates a BIO from our method. Marking init=1 tells
 * OpenSSL the BIO is ready for I/O; without it SSL_connect bails early. */
static inline int OpenSslStream_TransportBioCreate(BIO* bio)
{
    BIO_set_init(bio, 1);
    return 1;
}

/* Translate the non-blocking transport's Read contract into the OpenSSL BIO
 * contract:
 *   transport > 0 -> bytes available, BIO returns the same positive count.
 *   transport = 0 -> would-block. BIO must signal retry via BIO_set_retry_read
 *                  and return -1; without this, OpenSSL treats the 0 as EOF
 *                  and aborts the handshake on the first poll.
 *   transport < 0 -> EOF or error. BIO returns -1 with retry flags cleared so
 *                  OpenSSL surfaces the failure rather than spinning. */
static inline int OpenSslStream_TransportBioRead(BIO* bio, char* buffer, int size)
{
    struct SolidSyslogStream* transport = (struct SolidSyslogStream*) BIO_get_data(bio);
    SolidSyslogSsize n = SolidSyslogStream_Read(transport, buffer, (size_t) size);
    int result = -1;

    if (n > 0)
    {
        result = (int) n;
    }
    else if (n == 0)
    {
        BIO_set_retry_read(bio);
    }
    else
    {
        BIO_clear_retry_flags(bio);
    }
    return result;
}

static inline int OpenSslStream_TransportBioWrite(BIO* bio, const char* buffer, int size)
{
    struct SolidSyslogStream* transport = (struct SolidSyslogStream*) BIO_get_data(bio);
    int result = -1;

    if (SolidSyslogStream_Send(transport, buffer, (size_t) size))
    {
        result = size;
    }
    else
    {
        BIO_clear_retry_flags(bio);
    }
    return result;
}

/* Minimal ctrl handler. OpenSSL calls this for a variety of control commands
 * during normal operation; returning 1 for the common lifecycle commands lets
 * SSL_connect / SSL_write / SSL_shutdown proceed. Unknown commands return 0. */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters) -- signature fixed by OpenSSL BIO_ctrl_fn contract
static inline long OpenSslStream_TransportBioCtrl(BIO* bio, int cmd, long larg, void* parg)
{
    (void) bio;
    (void) larg;
    (void) parg;
    long result = 0;
    switch (cmd)
    {
        case BIO_CTRL_FLUSH:
        case BIO_CTRL_PUSH:
        case BIO_CTRL_POP:
        case BIO_CTRL_DUP:
            result = 1;
            break;
        default:
            break;
    }
    return result;
}

static inline bool OpenSslStream_ConfigureExpectedHostname(struct SolidSyslogOpenSslStream* self)
{
    bool ok = true;
    const char* serverName = self->Config.ServerName;
    if (serverName == NULL)
    {
        /* No expected identity supplied - the handshake will accept any cert that
         * chains to a trusted CA, so the peer is unverified unless a pin names
         * it. Surface it as a WARNING (still connect, preserving the IP-pinned /
         * closed-network case) rather than swallowing the MITM-class default
         * silently. */
        if (self->Installed.FingerprintCount == 0U)
        {
            OpenSslStream_Report(
                SOLIDSYSLOG_SEVERITY_WARNING,
                SOLIDSYSLOG_CAT_BAD_CONFIG,
                SOLIDSYSLOG_OPENSSL_STREAM_ERROR_SERVER_NAME_NOT_SET
            );
        }
    }
    else if (serverName[0] != '\0')
    {
        ok = (SSL_set_tlsext_host_name(self->Ssl, serverName) == 1) && (SSL_set1_host(self->Ssl, serverName) == 1);
        if (!ok)
        {
            OpenSslStream_Report(
                SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
                SOLIDSYSLOG_CAT_BAD_CONFIG,
                SOLIDSYSLOG_OPENSSL_STREAM_ERROR_SERVER_NAME_NOT_SET
            );
        }
    }
    else
    {
        /* Empty string is the deliberate opt-out: the integrator has no name to
         * verify against (IP-pinning / private CA) and has said so explicitly, so
         * connect chain-only without a diagnostic. */
    }
    return ok;
}

static inline bool OpenSslStream_IsRetryableSslError(int err)
{
    return (err == SSL_ERROR_WANT_READ) || (err == SSL_ERROR_WANT_WRITE);
}

static inline bool OpenSslStream_IsHandshakeBudgetExhausted(uint32_t totalSleptMs, uint32_t budgetMs)
{
    return totalSleptMs >= budgetMs;
}

/* Null Object substituted at Initialise when the integrator does not install a
 * getter - returns the compile-time tunable so the bounded-handshake path is a
 * single code path regardless of whether the integrator wired runtime tuning. */
static uint32_t OpenSslStream_NullHandshakeTimeoutGetter(void* context)
{
    (void) context;
    return (uint32_t) SOLIDSYSLOG_TLS_HANDSHAKE_TIMEOUT_MS;
}

static inline bool OpenSslStream_ConfigProvidesHandshakeGetter(const struct SolidSyslogOpenSslStreamConfig* config)
{
    return (config != NULL) && (config->GetHandshakeTimeoutMs != NULL);
}

/* Null Object substituted at Initialise when the integrator installs no version
 * function - reports an unchanging configuration, so the sender never reconnects
 * on this stream's account. */
static uint32_t OpenSslStream_NullVersion(void* context)
{
    (void) context;
    return 0;
}

static inline bool OpenSslStream_ConfigProvidesVersion(const struct SolidSyslogOpenSslStreamConfig* config)
{
    return (config != NULL) && (config->Version != NULL);
}

/* Bridges the integrator-installed getter (or the Null Object substituted at
 * config-copy time) to the bounded handshake deadline. Invoked at the start
 * of each handshake attempt so runtime-tunable values take effect on the next
 * reconnect. */
static inline uint32_t OpenSslStream_ResolveHandshakeTimeoutMs(struct SolidSyslogOpenSslStream* self)
{
    return self->Config.GetHandshakeTimeoutMs(self->Config.HandshakeTimeoutContext);
}

/* Drive SSL_connect to completion under non-blocking transport. Each call may
 * return WANT_READ/WANT_WRITE while waiting for the multi-RTT handshake to
 * progress; we sleep briefly between attempts (avoiding a busy spin) until
 * either the handshake completes, hits a hard error, or the bounded budget
 * expires. */
static inline bool OpenSslStream_PerformHandshake(struct SolidSyslogOpenSslStream* self)
{
    uint32_t budgetMs = OpenSslStream_ResolveHandshakeTimeoutMs(self);
    uint32_t totalSleptMs = 0;
    bool result = false;
    bool done = false;

    while (!done)
    {
        int rc = SSL_connect(self->Ssl);
        if (rc > 0)
        {
            result = true;
            done = true;
        }
        else
        {
            int err = SSL_get_error(self->Ssl, rc);
            if (!OpenSslStream_IsRetryableSslError(err))
            {
                OpenSslStream_Report(
                    SOLIDSYSLOG_SEVERITY_ERROR,
                    SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
                    OpenSslStream_RefusalDetail(self)
                );
                done = true;
            }
            else if (OpenSslStream_IsHandshakeBudgetExhausted(totalSleptMs, budgetMs))
            {
                OpenSslStream_Report(
                    SOLIDSYSLOG_SEVERITY_WARNING,
                    SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
                    SOLIDSYSLOG_OPENSSL_STREAM_ERROR_HANDSHAKE_TIMEOUT
                );
                done = true;
            }
            else
            {
                self->Config.Sleep(HANDSHAKE_POLL_INTERVAL_MILLISECONDS);
                totalSleptMs += (uint32_t) HANDSHAKE_POLL_INTERVAL_MILLISECONDS;
            }
        }
    }
    return result;
}

/* The verdict outlives the failed handshake - OpenSSL records it on the
 * connection as path validation runs - so the refusal can name the check that
 * produced it rather than the handshake that carried it. A verification failure
 * this does not name individually reads as untrusted: the certificate did not
 * validate, which is what the integrator has to act on. */
static inline enum SolidSyslogOpenSslStreamErrors OpenSslStream_RefusalDetail(struct SolidSyslogOpenSslStream* self)
{
    enum SolidSyslogOpenSslStreamErrors detail = SOLIDSYSLOG_OPENSSL_STREAM_ERROR_HANDSHAKE_REJECTED;
    long verdict = SSL_get_verify_result(self->Ssl);
    if (verdict == X509_V_ERR_APPLICATION_VERIFICATION)
    {
        detail = SOLIDSYSLOG_OPENSSL_STREAM_ERROR_PEER_FINGERPRINT_MISMATCHED;
    }
    else if (verdict == X509_V_ERR_HOSTNAME_MISMATCH)
    {
        detail = SOLIDSYSLOG_OPENSSL_STREAM_ERROR_PEER_NAME_MISMATCHED;
    }
    else if (verdict == X509_V_ERR_CERT_HAS_EXPIRED)
    {
        detail = SOLIDSYSLOG_OPENSSL_STREAM_ERROR_PEER_CERTIFICATE_EXPIRED;
    }
    else if (verdict == X509_V_ERR_CERT_NOT_YET_VALID)
    {
        detail = SOLIDSYSLOG_OPENSSL_STREAM_ERROR_PEER_CERTIFICATE_NOT_YET_VALID;
    }
    else if (verdict != X509_V_OK)
    {
        detail = SOLIDSYSLOG_OPENSSL_STREAM_ERROR_PEER_CERTIFICATE_UNTRUSTED;
    }
    else
    {
        /* Verification passed or never ran, so the refusal is a protocol or
         * transport fault rather than one the peer's certificate explains. */
    }
    return detail;
}

static inline bool OpenSslStream_Send(struct SolidSyslogStream* base, const void* buffer, size_t size)
{
    struct SolidSyslogOpenSslStream* self = OpenSslStream_SelfFromBase(base);
    int rc = SSL_write(self->Ssl, buffer, (int) size);
    bool ok = (rc > 0) && ((size_t) rc == size);

    if (!ok)
    {
        OpenSslStream_Close(base);
    }
    return ok;
}

/* SSL_read has two distinct modes worth keeping straight:
 *   1. Steady-state application read: bytes available -> return them; nothing
 *      to read right now -> SSL_ERROR_WANT_READ -> return 0 mirrors the transport
 *      Read contract.
 *   2. Renegotiation or alerts mid-stream: SSL_read may need to write (server
 *      requested re-key), surfacing as SSL_ERROR_WANT_WRITE. Under fail-fast
 *      semantics this is a transport failure - close internally; the caller
 *      reopens, store-and-forward replays. Same rule for any other SSL error.
 * Anything below the WANT_READ branch therefore takes the Close path. */
static inline SolidSyslogSsize OpenSslStream_Read(struct SolidSyslogStream* base, void* buffer, size_t size)
{
    struct SolidSyslogOpenSslStream* self = OpenSslStream_SelfFromBase(base);
    int rc = SSL_read(self->Ssl, buffer, (int) size);
    SolidSyslogSsize result = -1;

    if (rc > 0)
    {
        result = (SolidSyslogSsize) rc;
    }
    else if (SSL_get_error(self->Ssl, rc) == SSL_ERROR_WANT_READ)
    {
        result = 0;
    }
    else
    {
        OpenSslStream_Close(base);
    }
    return result;
}
