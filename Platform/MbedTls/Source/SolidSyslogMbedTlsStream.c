/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogMbedTlsStream.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogMbedTlsCredentialsDefinition.h"
#include "SolidSyslogMbedTlsStreamErrors.h"
#include "SolidSyslogMbedTlsStreamPrivate.h"
#include "SolidSyslogNullStream.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogStreamDefinition.h"
#include "SolidSyslogTlsCredentialsInstalled.h"
#include "SolidSyslogTlsFingerprint.h"
#include "SolidSyslogTlsStreamCategories.h"
#include "SolidSyslogTunables.h"

const struct SolidSyslogErrorSource SolidSyslogMbedTlsStreamErrorSource = {"MbedTlsStream"};

enum
{
    HANDSHAKE_POLL_INTERVAL_MILLISECONDS = 1
};

struct SolidSyslogAddress;

static uint32_t MbedTlsStream_NullHandshakeTimeoutGetter(void* context);
static uint32_t MbedTlsStream_NullVersion(void* context);
static inline bool MbedTlsStream_ConfigProvidesHandshakeGetter(const struct SolidSyslogMbedTlsStreamConfig* config);
static inline bool MbedTlsStream_ConfigProvidesVersion(const struct SolidSyslogMbedTlsStreamConfig* config);
static inline uint32_t MbedTlsStream_ResolveHandshakeTimeoutMs(struct SolidSyslogMbedTlsStream* self);
static inline struct SolidSyslogMbedTlsStream* MbedTlsStream_SelfFromBase(struct SolidSyslogStream* base);
static inline bool MbedTlsStream_Open(struct SolidSyslogStream* base, const struct SolidSyslogAddress* addr);
static inline bool MbedTlsStream_ApplySslConfigDefaults(struct SolidSyslogMbedTlsStream* self);
static inline void MbedTlsStream_ApplyTlsPolicy(struct SolidSyslogMbedTlsStream* self);
static inline bool MbedTlsStream_InstallCredentials(struct SolidSyslogMbedTlsStream* self);
static inline bool MbedTlsStream_PeerIsAuthorisable(const struct SolidSyslogTlsCredentialsInstalled* installed);
static inline bool MbedTlsStream_FingerprintsAreUsable(const struct SolidSyslogTlsCredentialsInstalled* installed);
static inline void MbedTlsStream_ApplyPeerVerificationPolicy(struct SolidSyslogMbedTlsStream* self);
static int MbedTlsStream_VerifyPeer(void* context, mbedtls_x509_crt* crt, int depth, uint32_t* flags);
static inline uint32_t MbedTlsStream_ChainTrustFlags(void);
static inline bool MbedTlsStream_LeafMatchesAPin(struct SolidSyslogMbedTlsStream* self, mbedtls_x509_crt* leaf);
static inline mbedtls_md_type_t MbedTlsStream_MdTypeFor(enum SolidSyslogTlsHashAlgorithm algorithm);
static bool MbedTlsStream_DigestCertificate(
    void* context,
    enum SolidSyslogTlsHashAlgorithm algorithm,
    uint8_t* digest,
    size_t* length
);
static inline void MbedTlsStream_ReleaseCredentials(struct SolidSyslogMbedTlsStream* self);
static inline bool MbedTlsStream_BindContextToConfig(struct SolidSyslogMbedTlsStream* self);
static inline bool MbedTlsStream_ConfigureExpectedHostname(struct SolidSyslogMbedTlsStream* self);
static inline void MbedTlsStream_InstallTransportCallbacks(struct SolidSyslogMbedTlsStream* self);
static inline bool MbedTlsStream_PerformHandshake(struct SolidSyslogMbedTlsStream* self);
static inline bool MbedTlsStream_PeerPassedVerification(struct SolidSyslogMbedTlsStream* self);
static inline enum SolidSyslogMbedTlsStreamErrors MbedTlsStream_RefusalDetail(struct SolidSyslogMbedTlsStream* self);
static inline bool MbedTlsStream_IsVerifyFailure(uint32_t verdict);
static inline enum SolidSyslogMbedTlsStreamErrors MbedTlsStream_DetailForVerifyFailure(uint32_t verdict);
static inline bool MbedTlsStream_HasUnnamedVerifyFailure(uint32_t verdict);
static inline bool MbedTlsStream_IsRetryableHandshakeRc(int rc);
static inline bool MbedTlsStream_IsHandshakeBudgetExhausted(uint32_t totalSleptMs, uint32_t budgetMs);
static inline bool MbedTlsStream_Send(struct SolidSyslogStream* base, const void* buffer, size_t size);
static inline SolidSyslogSsize MbedTlsStream_Read(struct SolidSyslogStream* base, void* buffer, size_t size);
static inline void MbedTlsStream_Close(struct SolidSyslogStream* base);
static uint32_t MbedTlsStream_Version(struct SolidSyslogStream* base);
static int MbedTlsStream_BioSend(void* ctx, const unsigned char* buf, size_t len);
static int MbedTlsStream_BioRecv(void* ctx, unsigned char* buf, size_t len);

void SolidSyslogMbedTlsStream_Initialise(
    struct SolidSyslogStream* base,
    const struct SolidSyslogMbedTlsStreamConfig* config
)
{
    struct SolidSyslogMbedTlsStream* self = MbedTlsStream_SelfFromBase(base);
    self->Base.Open = MbedTlsStream_Open;
    self->Base.Send = MbedTlsStream_Send;
    self->Base.Read = MbedTlsStream_Read;
    self->Base.Close = MbedTlsStream_Close;
    self->Base.Version = MbedTlsStream_Version;
    self->Config = *config;
    self->CredentialsInstalled = false;
    if (MbedTlsStream_ConfigProvidesHandshakeGetter(config) == false)
    {
        /* Substitute the Null Object so the bounded-handshake loop has a
         * single code path regardless of whether the integrator wired
         * runtime tuning. */
        self->Config.GetHandshakeTimeoutMs = MbedTlsStream_NullHandshakeTimeoutGetter;
        self->Config.HandshakeTimeoutContext = NULL;
    }
    if (MbedTlsStream_ConfigProvidesVersion(config) == false)
    {
        self->Config.Version = MbedTlsStream_NullVersion;
        self->Config.VersionContext = NULL;
    }
    /* Eager init so mbedtls_*_free in Close is always safe - whether Open
     * was ever reached, whether it succeeded, or whether Close is being
     * called twice in a row. mbedTLS guarantees a freed struct is left in
     * the same zeroed state an init produces, so re-Open after Close also
     * works without re-init. */
    mbedtls_ssl_init(&self->SslContext);
    mbedtls_ssl_config_init(&self->SslConfig);
}

/* Null Object substituted in Initialise when the integrator does not install a
 * getter - returns the compile-time tunable so the bounded-handshake path is a
 * single code path regardless of whether the integrator wired runtime tuning. */
static uint32_t MbedTlsStream_NullHandshakeTimeoutGetter(void* context)
{
    (void) context;
    return (uint32_t) SOLIDSYSLOG_TLS_HANDSHAKE_TIMEOUT_MS;
}

static inline bool MbedTlsStream_ConfigProvidesHandshakeGetter(const struct SolidSyslogMbedTlsStreamConfig* config)
{
    return (config != NULL) && (config->GetHandshakeTimeoutMs != NULL);
}

/* Null Object substituted at Initialise when the integrator installs no version
 * function - reports an unchanging configuration, so the sender never reconnects
 * on this stream's account. */
static uint32_t MbedTlsStream_NullVersion(void* context)
{
    (void) context;
    return 0U;
}

static inline bool MbedTlsStream_ConfigProvidesVersion(const struct SolidSyslogMbedTlsStreamConfig* config)
{
    return (config != NULL) && (config->Version != NULL);
}

/* Bridges the integrator-installed getter (or the Null Object substituted at
 * config-copy time) to the bounded handshake deadline. Invoked at the start
 * of each handshake attempt so runtime-tunable values take effect on the next
 * reconnect. */
static inline uint32_t MbedTlsStream_ResolveHandshakeTimeoutMs(struct SolidSyslogMbedTlsStream* self)
{
    return self->Config.GetHandshakeTimeoutMs(self->Config.HandshakeTimeoutContext);
}

static inline struct SolidSyslogMbedTlsStream* MbedTlsStream_SelfFromBase(struct SolidSyslogStream* base)
{
    return (struct SolidSyslogMbedTlsStream*) base;
}

void SolidSyslogMbedTlsStream_Cleanup(struct SolidSyslogStream* base)
{
    /* An integrator who destroys a still-Open stream must not leak the
     * underlying TLS state. */
    MbedTlsStream_Close(base);
    /* Overwrite the abstract base with the shared NullStream vtable so
     * use-after-destroy is a safe no-op rather than a NULL-fn-pointer crash. */
    *base = *SolidSyslogNullStream_Get();
}

/* Idempotent: a previous Close left the structs in mbedTLS's freed-equivalent
 * (zeroed) state, so close_notify sees conf == NULL and returns harmlessly,
 * and the *_free calls are no-ops on already-freed structs. Transport Close
 * is itself idempotent on every Stream impl. */
static inline void MbedTlsStream_Close(struct SolidSyslogStream* base)
{
    struct SolidSyslogMbedTlsStream* self = MbedTlsStream_SelfFromBase(base);
    (void) mbedtls_ssl_close_notify(&self->SslContext);
    mbedtls_ssl_free(&self->SslContext);
    /* The ssl_config holds the caller's certificates in its key_cert nodes until
       it is freed, so the credentials are told the window has closed only after
       mbedTLS has let go of them. */
    mbedtls_ssl_config_free(&self->SslConfig);
    MbedTlsStream_ReleaseCredentials(self);
    SolidSyslogStream_Close(self->Config.Transport);
}

static uint32_t MbedTlsStream_Version(struct SolidSyslogStream* base)
{
    struct SolidSyslogMbedTlsStream* self = MbedTlsStream_SelfFromBase(base);
    return self->Config.Version(self->Config.VersionContext);
}

static inline bool MbedTlsStream_Open(struct SolidSyslogStream* base, const struct SolidSyslogAddress* addr)
{
    struct SolidSyslogMbedTlsStream* self = MbedTlsStream_SelfFromBase(base);
    bool ok = SolidSyslogStream_Open(self->Config.Transport, addr) && MbedTlsStream_ApplySslConfigDefaults(self);
    if (ok)
    {
        MbedTlsStream_ApplyTlsPolicy(self);
        ok = MbedTlsStream_InstallCredentials(self) && MbedTlsStream_BindContextToConfig(self) &&
             MbedTlsStream_ConfigureExpectedHostname(self);
    }
    if (ok)
    {
        MbedTlsStream_InstallTransportCallbacks(self);
        ok = MbedTlsStream_PerformHandshake(self) && MbedTlsStream_PeerPassedVerification(self);
    }
    if (!ok)
    {
        MbedTlsStream_Close(base);
    }
    return ok;
}

static inline bool MbedTlsStream_ApplySslConfigDefaults(struct SolidSyslogMbedTlsStream* self)
{
    bool ok = mbedtls_ssl_config_defaults(
                  &self->SslConfig,
                  MBEDTLS_SSL_IS_CLIENT,
                  MBEDTLS_SSL_TRANSPORT_STREAM,
                  MBEDTLS_SSL_PRESET_DEFAULT
              ) == 0;
    if (!ok)
    {
        MbedTlsStream_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
            SOLIDSYSLOG_MBEDTLS_STREAM_ERROR_DEFAULTS_NOT_APPLIED
        );
    }
    return ok;
}

/* TLS policy owned by the library - set per-ssl_config so it cannot leak
 * into the integrator's other ssl_configs (per coexistence contract). The
 * material the policy is enforced against is not set here: the credentials
 * source installs that, so this stream holds none of it. */
static inline void MbedTlsStream_ApplyTlsPolicy(struct SolidSyslogMbedTlsStream* self)
{
    /* Pin the floor at TLS 1.2 rather than inheriting MBEDTLS_SSL_PRESET_DEFAULT,
     * which can negotiate down to TLS 1.0/1.1 on permissive integrator builds.
     * The floor is stated here so downgrade resistance does not depend on the
     * preset the integrator happens to have compiled in. No ceiling is set:
     * RFC 9662, which updates RFC 5425, requires TLS 1.3 to be preferred
     * wherever it is implemented. */
    mbedtls_ssl_conf_min_tls_version(&self->SslConfig, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_rng(&self->SslConfig, mbedtls_ctr_drbg_random, self->Config.Rng);
}

/* Asked once per connection, after the policy is on the ssl_config and before
 * the session binds to it, so material is fetched only for a connection
 * actually being made. The flag is set before the call rather than after it:
 * the contract is one Release per Install call whatever that call returned,
 * which is what spares every backend a rollback path of its own. */
static inline bool MbedTlsStream_InstallCredentials(struct SolidSyslogMbedTlsStream* self)
{
    self->Installed.TrustAnchorsInstalled = false;
    self->Installed.Fingerprints = NULL;
    self->Installed.FingerprintCount = 0U;
    self->CredentialsInstalled = true;
    bool ok = self->Config.Credentials->Install(self->Config.Credentials, &self->SslConfig, &self->Installed);
    if (ok && !MbedTlsStream_PeerIsAuthorisable(&self->Installed))
    {
        MbedTlsStream_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_MBEDTLS_STREAM_ERROR_NO_PEER_AUTHORISATION
        );
        ok = false;
    }
    if (ok)
    {
        ok = MbedTlsStream_FingerprintsAreUsable(&self->Installed);
    }
    if (ok)
    {
        MbedTlsStream_ApplyPeerVerificationPolicy(self);
    }
    return ok;
}

/* A peer is authorised by a chain to trust anchors or by a pinned certificate
 * fingerprint, and RFC 5425 4.2.1 makes the second sufficient on its own. With
 * neither, there is nothing to check the peer against, so the connection stops
 * rather than reaching a peer this stream cannot identify. */
static inline bool MbedTlsStream_PeerIsAuthorisable(const struct SolidSyslogTlsCredentialsInstalled* installed)
{
    return installed->TrustAnchorsInstalled || (installed->FingerprintCount > 0U);
} /* Inspected before the handshake, so a pin that cannot match is reported as
 * bad configuration rather than as a refused peer. */

static inline bool MbedTlsStream_FingerprintsAreUsable(const struct SolidSyslogTlsCredentialsInstalled* installed)
{
    bool ok = true;
    enum SolidSyslogTlsFingerprintListState state =
        SolidSyslogTlsFingerprint_InspectList(installed->Fingerprints, installed->FingerprintCount);
    if (state == SOLIDSYSLOG_TLS_FINGERPRINT_LIST_MALFORMED)
    {
        MbedTlsStream_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_MBEDTLS_STREAM_ERROR_FINGERPRINT_MALFORMED
        );
        ok = false;
    }
    else if (state == SOLIDSYSLOG_TLS_FINGERPRINT_LIST_USES_SHA1)
    {
        MbedTlsStream_Report(
            SOLIDSYSLOG_SEVERITY_WARNING,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_MBEDTLS_STREAM_ERROR_FINGERPRINT_SHA1
        );
    }
    else
    {
        /* Well formed, or no pins at all. */
    }
    return ok;
}

/* Mbed TLS fails VERIFY_REQUIRED outright when no CA chain was installed -
 * MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED, whatever a verify callback decides - so a
 * peer authorised by pin alone is verified optionally and judged here instead. */
static inline void MbedTlsStream_ApplyPeerVerificationPolicy(struct SolidSyslogMbedTlsStream* self)
{
    int authmode = self->Installed.TrustAnchorsInstalled ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_OPTIONAL;
    mbedtls_ssl_conf_authmode(&self->SslConfig, authmode);
    mbedtls_ssl_conf_verify(&self->SslConfig, MbedTlsStream_VerifyPeer, self);
}

/* Called for each certificate in the chain, and Mbed TLS merges what each one
 * leaves in *flags into a single verdict - so a chain-trust objection above the
 * leaf reaches the result unless it is cleared there too. Only the leaf is
 * pinned; the certificate's own validity is never cleared. */
static int MbedTlsStream_VerifyPeer(void* context, mbedtls_x509_crt* crt, int depth, uint32_t* flags)
{
    struct SolidSyslogMbedTlsStream* self = (struct SolidSyslogMbedTlsStream*) context;

    if (self->Installed.FingerprintCount > 0U)
    {
        if (!self->Installed.TrustAnchorsInstalled)
        {
            *flags &= ~MbedTlsStream_ChainTrustFlags();
        }
        if ((depth == 0) && !MbedTlsStream_LeafMatchesAPin(self, crt))
        {
            *flags |= (uint32_t) MBEDTLS_X509_BADCERT_OTHER;
        }
    }

    return 0;
}

/* The objections a missing trust anchor alone produces. Every other flag
 * describes the certificate itself, which a pin does not vouch for. */
static inline uint32_t MbedTlsStream_ChainTrustFlags(void)
{
    return (uint32_t) MBEDTLS_X509_BADCERT_NOT_TRUSTED | (uint32_t) MBEDTLS_X509_BADCERT_MISSING;
}

static inline bool MbedTlsStream_LeafMatchesAPin(struct SolidSyslogMbedTlsStream* self, mbedtls_x509_crt* leaf)
{
    return SolidSyslogTlsFingerprint_Authorise(
               self->Installed.Fingerprints,
               self->Installed.FingerprintCount,
               MbedTlsStream_DigestCertificate,
               leaf
           ) == SOLIDSYSLOG_TLS_AUTHORISATION_MATCHED;
}

/* A hash compiled out of Mbed TLS has no md_info, which is the Core callback's
 * "algorithm cannot be computed" and refuses the peer. */
static bool MbedTlsStream_DigestCertificate(
    void* context,
    enum SolidSyslogTlsHashAlgorithm algorithm,
    uint8_t* digest,
    size_t* length
)
{
    const mbedtls_x509_crt* leaf = (const mbedtls_x509_crt*) context;
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MbedTlsStream_MdTypeFor(algorithm));
    bool ok = info != NULL;

    if (ok)
    {
        ok = mbedtls_md(info, leaf->raw.p, leaf->raw.len, digest) == 0;
        *length = mbedtls_md_get_size(info);
    }

    return ok;
}

/* An algorithm this pack does not name resolves to MBEDTLS_MD_NONE, which has
 * no md_info - so a hash added to Core and not handled here refuses the peer
 * rather than being digested as something else. */
static inline mbedtls_md_type_t MbedTlsStream_MdTypeFor(enum SolidSyslogTlsHashAlgorithm algorithm)
{
    mbedtls_md_type_t type = MBEDTLS_MD_NONE;
    if (algorithm == SOLIDSYSLOG_TLS_HASH_SHA1)
    {
        type = MBEDTLS_MD_SHA1;
    }
    else if (algorithm == SOLIDSYSLOG_TLS_HASH_SHA256)
    {
        type = MBEDTLS_MD_SHA256;
    }
    else
    {
        /* Left as MBEDTLS_MD_NONE. */
    }
    return type;
}

/* Answers every Install, so the integrator is always told when the credential
 * window has closed - including on the paths where Open failed part way. */
static inline void MbedTlsStream_ReleaseCredentials(struct SolidSyslogMbedTlsStream* self)
{
    if (self->CredentialsInstalled)
    {
        self->CredentialsInstalled = false;
        self->Config.Credentials->Release(self->Config.Credentials);
    }
}

static inline bool MbedTlsStream_BindContextToConfig(struct SolidSyslogMbedTlsStream* self)
{
    bool ok = mbedtls_ssl_setup(&self->SslContext, &self->SslConfig) == 0;
    if (!ok)
    {
        MbedTlsStream_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_TLS_STREAM_INIT_FAILED,
            SOLIDSYSLOG_MBEDTLS_STREAM_ERROR_SESSION_INIT_FAILED
        );
    }
    return ok;
}

static inline bool MbedTlsStream_ConfigureExpectedHostname(struct SolidSyslogMbedTlsStream* self)
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
            MbedTlsStream_Report(
                SOLIDSYSLOG_SEVERITY_WARNING,
                SOLIDSYSLOG_CAT_BAD_CONFIG,
                SOLIDSYSLOG_MBEDTLS_STREAM_ERROR_SERVER_NAME_NOT_SET
            );
        }
    }
    else if (serverName[0] != '\0')
    {
        ok = mbedtls_ssl_set_hostname(&self->SslContext, serverName) == 0;
        if (!ok)
        {
            MbedTlsStream_Report(
                SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
                SOLIDSYSLOG_CAT_BAD_CONFIG,
                SOLIDSYSLOG_MBEDTLS_STREAM_ERROR_SERVER_NAME_NOT_SET
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

static inline void MbedTlsStream_InstallTransportCallbacks(struct SolidSyslogMbedTlsStream* self)
{
    mbedtls_ssl_set_bio(&self->SslContext, self, MbedTlsStream_BioSend, MbedTlsStream_BioRecv, NULL);
}

/* Drive mbedtls_ssl_handshake to completion under non-blocking transport.
 * Each call may return WANT_READ/WANT_WRITE while waiting for the multi-RTT
 * handshake to progress; we sleep briefly between attempts (avoiding a busy
 * spin) until either the handshake completes, hits a hard error, or the
 * bounded budget expires. Each non-success exit emits a distinct
 * protocol-level error code so the integrator can tell rejection from
 * timeout. */
static inline bool MbedTlsStream_PerformHandshake(struct SolidSyslogMbedTlsStream* self)
{
    uint32_t budgetMs = MbedTlsStream_ResolveHandshakeTimeoutMs(self);
    uint32_t totalSleptMs = 0;
    bool result = false;
    bool done = false;

    while (!done)
    {
        int rc = mbedtls_ssl_handshake(&self->SslContext);
        if (rc == 0)
        {
            result = true;
            done = true;
        }
        else if (!MbedTlsStream_IsRetryableHandshakeRc(rc))
        {
            MbedTlsStream_Report(
                SOLIDSYSLOG_SEVERITY_ERROR,
                SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
                MbedTlsStream_RefusalDetail(self)
            );
            done = true;
        }
        else if (MbedTlsStream_IsHandshakeBudgetExhausted(totalSleptMs, budgetMs))
        {
            MbedTlsStream_Report(
                SOLIDSYSLOG_SEVERITY_WARNING,
                SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
                SOLIDSYSLOG_MBEDTLS_STREAM_ERROR_HANDSHAKE_TIMEOUT
            );
            done = true;
        }
        else
        {
            self->Config.Sleep(HANDSHAKE_POLL_INTERVAL_MILLISECONDS);
            totalSleptMs += (uint32_t) HANDSHAKE_POLL_INTERVAL_MILLISECONDS;
        }
    }
    return result;
}

/* Verifying optionally completes the handshake and leaves the verdict to be
 * read, so a peer authorised by pin alone is refused here rather than by Mbed
 * TLS. Where anchors are installed the handshake has already failed on a bad
 * certificate and the verdict is clean, so this costs nothing. */
static inline bool MbedTlsStream_PeerPassedVerification(struct SolidSyslogMbedTlsStream* self)
{
    bool ok = !MbedTlsStream_IsVerifyFailure(mbedtls_ssl_get_verify_result(&self->SslContext));
    if (!ok)
    {
        MbedTlsStream_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_TLS_STREAM_HANDSHAKE_FAILED,
            MbedTlsStream_RefusalDetail(self)
        );
    }
    return ok;
}

/* The verdict outlives the failed handshake - mbedTLS records every fault it
 * found on the session being negotiated - so the refusal can name the check that
 * produced it rather than the handshake that carried it. */
static inline enum SolidSyslogMbedTlsStreamErrors MbedTlsStream_RefusalDetail(struct SolidSyslogMbedTlsStream* self)
{
    enum SolidSyslogMbedTlsStreamErrors detail = SOLIDSYSLOG_MBEDTLS_STREAM_ERROR_HANDSHAKE_REJECTED;
    uint32_t verdict = mbedtls_ssl_get_verify_result(&self->SslContext);
    if (MbedTlsStream_IsVerifyFailure(verdict))
    {
        detail = MbedTlsStream_DetailForVerifyFailure(verdict);
    }
    return detail;
}

/* Zero is mbedTLS for "nothing wrong" and 0xFFFFFFFF for "no result to give".
 * Neither is a check the peer's certificate failed, so neither may be read as a
 * set of flags - every flag reads as set in the second of them. */
static inline bool MbedTlsStream_IsVerifyFailure(uint32_t verdict)
{
    const uint32_t verifyResultUnavailable = 0xFFFFFFFFU;
    return (verdict != 0U) && (verdict != verifyResultUnavailable);
}

/* The flags accumulate, so a compound verdict resolves by precedence: an
 * untrusted chain is reported ahead of anything the certificate says about
 * itself, because a certificate no anchor vouches for is not made acceptable by
 * the dates it carries. */
static inline enum SolidSyslogMbedTlsStreamErrors MbedTlsStream_DetailForVerifyFailure(uint32_t verdict)
{
    enum SolidSyslogMbedTlsStreamErrors detail = SOLIDSYSLOG_MBEDTLS_STREAM_ERROR_PEER_CERTIFICATE_UNTRUSTED;
    if ((verdict & (uint32_t) MBEDTLS_X509_BADCERT_OTHER) != 0U)
    {
        detail = SOLIDSYSLOG_MBEDTLS_STREAM_ERROR_PEER_FINGERPRINT_MISMATCHED;
    }
    else if (MbedTlsStream_HasUnnamedVerifyFailure(verdict))
    {
        /* Untrusted, which the detail already holds. */
    }
    else if ((verdict & (uint32_t) MBEDTLS_X509_BADCERT_CN_MISMATCH) != 0U)
    {
        detail = SOLIDSYSLOG_MBEDTLS_STREAM_ERROR_PEER_NAME_MISMATCHED;
    }
    else if ((verdict & (uint32_t) MBEDTLS_X509_BADCERT_EXPIRED) != 0U)
    {
        detail = SOLIDSYSLOG_MBEDTLS_STREAM_ERROR_PEER_CERTIFICATE_EXPIRED;
    }
    else
    {
        /* A named flag is set and the others are not, so this is it. */
        detail = SOLIDSYSLOG_MBEDTLS_STREAM_ERROR_PEER_CERTIFICATE_NOT_YET_VALID;
    }
    return detail;
}

/* Every flag the cascade above does not name individually. A certificate that
 * fails path validation for one of them is untrusted whichever it is, and the
 * integrator's next step - replace the certificate, not the network - is the
 * same. */
static inline bool MbedTlsStream_HasUnnamedVerifyFailure(uint32_t verdict)
{
    const uint32_t named = (uint32_t) MBEDTLS_X509_BADCERT_CN_MISMATCH | (uint32_t) MBEDTLS_X509_BADCERT_EXPIRED |
                           (uint32_t) MBEDTLS_X509_BADCERT_FUTURE | (uint32_t) MBEDTLS_X509_BADCERT_OTHER;
    return (verdict & ~named) != 0U;
}

static inline bool MbedTlsStream_IsRetryableHandshakeRc(int rc)
{
    return (rc == MBEDTLS_ERR_SSL_WANT_READ) || (rc == MBEDTLS_ERR_SSL_WANT_WRITE);
}

static inline bool MbedTlsStream_IsHandshakeBudgetExhausted(uint32_t totalSleptMs, uint32_t budgetMs)
{
    return totalSleptMs >= budgetMs;
}

static int MbedTlsStream_BioSend(void* ctx, const unsigned char* buf, size_t len)
{
    struct SolidSyslogMbedTlsStream* self = (struct SolidSyslogMbedTlsStream*) ctx;
    return SolidSyslogStream_Send(self->Config.Transport, buf, len) ? (int) len : -1;
}

/* Translate the non-blocking transport's Read contract into mbedTLS's BIO
 * recv contract:
 *   transport > 0 -> bytes available, return the same positive count.
 *   transport = 0 -> would-block. Must return MBEDTLS_ERR_SSL_WANT_READ so
 *                  the handshake retry loop polls; returning 0 or -1 would
 *                  abort the handshake on the first non-blocking read. */
static int MbedTlsStream_BioRecv(void* ctx, unsigned char* buf, size_t len)
{
    struct SolidSyslogMbedTlsStream* self = (struct SolidSyslogMbedTlsStream*) ctx;
    SolidSyslogSsize n = SolidSyslogStream_Read(self->Config.Transport, buf, len);
    int result = -1;
    if (n > 0)
    {
        result = (int) n;
    }
    else if (n == 0)
    {
        result = MBEDTLS_ERR_SSL_WANT_READ;
    }
    else
    {
        /* n < 0 - transport-level error; keep result = -1 to signal a
           hard failure to mbedTLS so the handshake / read aborts. */
    }
    return result;
}

/* TLS-level write failure means the session state is unrecoverable - close
 * so the StreamSender reconnect path runs on the next tick. Fail-fast is the
 * contract every TLS stream adapter honours. */
static inline bool MbedTlsStream_Send(struct SolidSyslogStream* base, const void* buffer, size_t size)
{
    struct SolidSyslogMbedTlsStream* self = MbedTlsStream_SelfFromBase(base);
    int rc = mbedtls_ssl_write(&self->SslContext, (const unsigned char*) buffer, size);
    bool ok = (rc > 0) && ((size_t) rc == size);
    if (!ok)
    {
        MbedTlsStream_Close(base);
    }
    return ok;
}

/* mbedtls_ssl_read has two distinct outcomes worth keeping straight:
 *   1. Steady-state read: bytes available -> positive count; nothing to read
 *      right now -> WANT_READ -> return 0, mirroring the transport contract.
 *   2. Any other negative return (alerts, renegotiation surfacing as
 *      WANT_WRITE, hard transport error) is fatal under fail-fast semantics
 *      - close internally; the caller reopens and store-and-forward replays. */
static inline SolidSyslogSsize MbedTlsStream_Read(struct SolidSyslogStream* base, void* buffer, size_t size)
{
    struct SolidSyslogMbedTlsStream* self = MbedTlsStream_SelfFromBase(base);
    int rc = mbedtls_ssl_read(&self->SslContext, (unsigned char*) buffer, size);
    SolidSyslogSsize result = -1;
    if (rc > 0)
    {
        result = (SolidSyslogSsize) rc;
    }
    else if (rc == MBEDTLS_ERR_SSL_WANT_READ)
    {
        result = 0;
    }
    else
    {
        MbedTlsStream_Close(base);
    }
    return result;
}
