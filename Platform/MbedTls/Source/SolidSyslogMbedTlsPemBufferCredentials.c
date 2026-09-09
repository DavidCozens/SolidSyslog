/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogMbedTlsPemBufferCredentials.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <stdbool.h>
#include <stddef.h>

#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogMbedTlsCredentialsDefinition.h"
#include "SolidSyslogMbedTlsPemBufferCredentialsPrivate.h"
#include "SolidSyslogTlsCredentialsInstalled.h"

const struct SolidSyslogErrorSource SolidSyslogMbedTlsPemBufferCredentialsErrorSource = {"MbedTlsPemBufferCredentials"};

static bool MbedTlsPemBufferCredentials_Install(
    struct SolidSyslogMbedTlsCredentials* base,
    struct mbedtls_ssl_config* conf,
    struct SolidSyslogTlsCredentialsInstalled* installed
);
static inline bool MbedTlsPemBufferCredentials_ParseTrustAnchors(
    struct SolidSyslogMbedTlsPemBufferCredentials* self,
    struct mbedtls_ssl_config* conf
);
static inline void MbedTlsPemBufferCredentials_ConfigureClientIdentity(
    struct SolidSyslogMbedTlsPemBufferCredentials* self,
    struct mbedtls_ssl_config* conf
);
static inline bool MbedTlsPemBufferCredentials_HasClientCredential(
    const struct SolidSyslogMbedTlsPemBufferCredentialsConfig* config
);
static inline bool MbedTlsPemBufferCredentials_HasHalfOfClientCredential(
    const struct SolidSyslogMbedTlsPemBufferCredentialsConfig* config
);
static inline bool MbedTlsPemBufferCredentials_ClientPemIsTerminated(
    const struct SolidSyslogMbedTlsPemBufferCredentialsConfig* config
);
static inline bool MbedTlsPemBufferCredentials_ParseClientCredential(struct SolidSyslogMbedTlsPemBufferCredentials* self
);
static inline bool MbedTlsPemBufferCredentials_ClientKeyMatchesCertificate(
    struct SolidSyslogMbedTlsPemBufferCredentials* self
);
static inline bool MbedTlsPemBufferCredentials_IsSupplied(const struct SolidSyslogMbedTlsPemBuffer* pem);
static inline bool MbedTlsPemBufferCredentials_IsTerminated(const struct SolidSyslogMbedTlsPemBuffer* pem);
static void MbedTlsPemBufferCredentials_Release(struct SolidSyslogMbedTlsCredentials* base);
static inline struct SolidSyslogMbedTlsPemBufferCredentials* MbedTlsPemBufferCredentials_SelfFromBase(
    struct SolidSyslogMbedTlsCredentials* base
);

void SolidSyslogMbedTlsPemBufferCredentials_Initialise(
    struct SolidSyslogMbedTlsCredentials* base,
    const struct SolidSyslogMbedTlsPemBufferCredentialsConfig* config
)
{
    struct SolidSyslogMbedTlsPemBufferCredentials* self = MbedTlsPemBufferCredentials_SelfFromBase(base);
    self->Base.Install = MbedTlsPemBufferCredentials_Install;
    self->Base.Release = MbedTlsPemBufferCredentials_Release;
    self->Config = *config;
    mbedtls_x509_crt_init(&self->CaChain);
    mbedtls_x509_crt_init(&self->ClientCertChain);
    mbedtls_pk_init(&self->ClientKey);
}

static inline struct SolidSyslogMbedTlsPemBufferCredentials* MbedTlsPemBufferCredentials_SelfFromBase(
    struct SolidSyslogMbedTlsCredentials* base
)
{
    return (struct SolidSyslogMbedTlsPemBufferCredentials*) base;
}

void SolidSyslogMbedTlsPemBufferCredentials_Cleanup(struct SolidSyslogMbedTlsCredentials* base)
{
    MbedTlsPemBufferCredentials_Release(base);
}

/* Parsed here rather than at Create, so the material exists only for a
 * connection actually being made. Every Install is answered by a Release, which
 * is where it goes again. */
static bool MbedTlsPemBufferCredentials_Install(
    struct SolidSyslogMbedTlsCredentials* base,
    struct mbedtls_ssl_config* conf,
    struct SolidSyslogTlsCredentialsInstalled* installed
)
{
    struct SolidSyslogMbedTlsPemBufferCredentials* self = MbedTlsPemBufferCredentials_SelfFromBase(base);
    installed->TrustAnchorsInstalled = false;
    installed->Fingerprints = self->Config.PeerFingerprints;
    installed->FingerprintCount = self->Config.PeerFingerprintCount;
    bool ok = true;
    if (MbedTlsPemBufferCredentials_IsSupplied(&self->Config.CaPem))
    {
        installed->TrustAnchorsInstalled = MbedTlsPemBufferCredentials_ParseTrustAnchors(self, conf);
        ok = installed->TrustAnchorsInstalled;
    }
    if (ok)
    {
        MbedTlsPemBufferCredentials_ConfigureClientIdentity(self, conf);
    }
    return ok;
}

/* No fault in our own credential stops delivery: the collector is the
 * enforcement point for it, and one that requires a client certificate refuses
 * the handshake anyway. Every failure here leaves nothing installed, so the
 * connection continues server-authenticated rather than half-presenting a
 * credential. Whatever was parsed before the fault is released with the rest at
 * Close. */
static inline void MbedTlsPemBufferCredentials_ConfigureClientIdentity(
    struct SolidSyslogMbedTlsPemBufferCredentials* self,
    struct mbedtls_ssl_config* conf
)
{
    if (MbedTlsPemBufferCredentials_HasClientCredential(&self->Config))
    {
        if (MbedTlsPemBufferCredentials_ClientPemIsTerminated(&self->Config) == false)
        {
            MbedTlsPemBufferCredentials_Report(
                SOLIDSYSLOG_SEVERITY_WARNING,
                SOLIDSYSLOG_CAT_BAD_CONFIG,
                SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_PEM_NOT_TERMINATED
            );
        }
        else if (MbedTlsPemBufferCredentials_ParseClientCredential(self) == false)
        {
            MbedTlsPemBufferCredentials_Report(
                SOLIDSYSLOG_SEVERITY_WARNING,
                SOLIDSYSLOG_CAT_BAD_CONFIG,
                SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_NOT_PARSED
            );
        }
        else if (MbedTlsPemBufferCredentials_ClientKeyMatchesCertificate(self) == false)
        {
            MbedTlsPemBufferCredentials_Report(
                SOLIDSYSLOG_SEVERITY_WARNING,
                SOLIDSYSLOG_CAT_BAD_CONFIG,
                SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_MISMATCHED
            );
        }
        /* Only MBEDTLS_ERR_SSL_ALLOC_FAILED, which returns before the key_cert
         * node is appended, so nothing is left half-configured. */
        else if (mbedtls_ssl_conf_own_cert(conf, &self->ClientCertChain, &self->ClientKey) != 0)
        {
            MbedTlsPemBufferCredentials_Report(
                SOLIDSYSLOG_SEVERITY_WARNING,
                SOLIDSYSLOG_CAT_BAD_CONFIG,
                SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_NOT_INSTALLED
            );
        }
        else
        {
            /* Parsed, paired and installed - the credential will be presented. */
        }
    }
    else if (MbedTlsPemBufferCredentials_HasHalfOfClientCredential(&self->Config))
    {
        MbedTlsPemBufferCredentials_Report(
            SOLIDSYSLOG_SEVERITY_WARNING,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_INCOMPLETE
        );
    }
    else
    {
        /* Neither supplied - server-authenticated TLS is the deliberate case. */
    }
}

static inline bool MbedTlsPemBufferCredentials_HasClientCredential(
    const struct SolidSyslogMbedTlsPemBufferCredentialsConfig* config
)
{
    return MbedTlsPemBufferCredentials_IsSupplied(&config->ClientCertPem) &&
           MbedTlsPemBufferCredentials_IsSupplied(&config->ClientKeyPem);
}

/* One half without the other. The integrator asked for mutual TLS and will not
 * get it, so it is reported rather than read as a decision to go without. */
static inline bool MbedTlsPemBufferCredentials_HasHalfOfClientCredential(
    const struct SolidSyslogMbedTlsPemBufferCredentialsConfig* config
)
{
    return MbedTlsPemBufferCredentials_IsSupplied(&config->ClientCertPem) !=
           MbedTlsPemBufferCredentials_IsSupplied(&config->ClientKeyPem);
}

/* Both halves, because a certificate whose key is unusable is no more use than
 * neither. */
static inline bool MbedTlsPemBufferCredentials_ClientPemIsTerminated(
    const struct SolidSyslogMbedTlsPemBufferCredentialsConfig* config
)
{
    return MbedTlsPemBufferCredentials_IsTerminated(&config->ClientCertPem) &&
           MbedTlsPemBufferCredentials_IsTerminated(&config->ClientKeyPem);
}

static inline bool MbedTlsPemBufferCredentials_ParseClientCredential(struct SolidSyslogMbedTlsPemBufferCredentials* self
)
{
    return (mbedtls_x509_crt_parse(
                &self->ClientCertChain,
                self->Config.ClientCertPem.Bytes,
                self->Config.ClientCertPem.Length
            ) == 0) &&
           (mbedtls_pk_parse_key(
                &self->ClientKey,
                self->Config.ClientKeyPem.Bytes,
                self->Config.ClientKeyPem.Length,
                NULL,
                0U,
                mbedtls_ctr_drbg_random,
                self->Config.Rng
            ) == 0);
}

/* mbedtls_ssl_conf_own_cert does not check the pair it is handed, and names this
 * function in its own documentation as the way to check it. */
static inline bool MbedTlsPemBufferCredentials_ClientKeyMatchesCertificate(
    struct SolidSyslogMbedTlsPemBufferCredentials* self
)
{
    return mbedtls_pk_check_pair(
               &self->ClientCertChain.pk,
               &self->ClientKey,
               mbedtls_ctr_drbg_random,
               self->Config.Rng
           ) == 0;
}

/* Mbed TLS reads a certificate buffer whose last byte is not NUL as DER, so a
 * length given as strlen rather than strlen + 1 fails as "not a certificate"
 * and says nothing about the length. The check is one byte inside the declared
 * extent, and it names the fault the integrator actually made. */
static inline bool MbedTlsPemBufferCredentials_ParseTrustAnchors(
    struct SolidSyslogMbedTlsPemBufferCredentials* self,
    struct mbedtls_ssl_config* conf
)
{
    bool parsed = false;
    if (MbedTlsPemBufferCredentials_IsTerminated(&self->Config.CaPem) == false)
    {
        MbedTlsPemBufferCredentials_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_PEM_NOT_TERMINATED
        );
    }
    else if (mbedtls_x509_crt_parse(&self->CaChain, self->Config.CaPem.Bytes, self->Config.CaPem.Length) != 0)
    {
        MbedTlsPemBufferCredentials_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_TRUST_ANCHORS_NOT_PARSED
        );
    }
    else
    {
        mbedtls_ssl_conf_ca_chain(conf, &self->CaChain, NULL);
        parsed = true;
    }
    return parsed;
}

/* A NULL buffer is the documented way to say "not supplied". A pointer with an
 * unusable extent is a mistake instead, and is reported rather than read as a
 * decision to go without - the integrator who made it believes the material is
 * in force. */
static inline bool MbedTlsPemBufferCredentials_IsSupplied(const struct SolidSyslogMbedTlsPemBuffer* pem)
{
    return pem->Bytes != NULL;
}

/* Guards its own read: a zero length has no last byte to test, and would index
 * at SIZE_MAX. */
static inline bool MbedTlsPemBufferCredentials_IsTerminated(const struct SolidSyslogMbedTlsPemBuffer* pem)
{
    return (pem->Length > 0U) && (pem->Bytes[pem->Length - 1U] == (unsigned char) '\0');
}

/* Freeing is what wipes: mbedtls_pk_free zeroises the key context and every
 * limb of the private key, and mbedtls_x509_crt_free zeroises the DER it
 * decoded. Both leave the structs in the state an init produces, so the next
 * Install parses into them again, and a second Release is harmless. */
static void MbedTlsPemBufferCredentials_Release(struct SolidSyslogMbedTlsCredentials* base)
{
    struct SolidSyslogMbedTlsPemBufferCredentials* self = MbedTlsPemBufferCredentials_SelfFromBase(base);
    mbedtls_x509_crt_free(&self->CaChain);
    mbedtls_x509_crt_free(&self->ClientCertChain);
    mbedtls_pk_free(&self->ClientKey);
}
