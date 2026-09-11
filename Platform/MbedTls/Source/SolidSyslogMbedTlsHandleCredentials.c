/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogMbedTlsHandleCredentials.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <stdbool.h>
#include <stddef.h>

#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogMbedTlsCredentialsDefinition.h"
#include "SolidSyslogMbedTlsHandleCredentialsPrivate.h"
#include "SolidSyslogTlsCredentialsInstalled.h"

const struct SolidSyslogErrorSource SolidSyslogMbedTlsHandleCredentialsErrorSource = {"MbedTlsHandleCredentials"};

static bool MbedTlsHandleCredentials_Install(
    struct SolidSyslogMbedTlsCredentials* base,
    struct mbedtls_ssl_config* conf,
    struct SolidSyslogTlsCredentialsInstalled* installed
);
static inline void MbedTlsHandleCredentials_ConfigureClientIdentity(
    struct mbedtls_ssl_config* conf,
    const struct SolidSyslogMbedTlsHandleCredentialsConfig* config
);
static inline bool MbedTlsHandleCredentials_HasClientCredential(
    const struct SolidSyslogMbedTlsHandleCredentialsConfig* config
);
static inline bool MbedTlsHandleCredentials_ClientKeyMatchesCertificate(
    const struct SolidSyslogMbedTlsHandleCredentialsConfig* config
);
static inline bool MbedTlsHandleCredentials_HasHalfOfClientCredential(
    const struct SolidSyslogMbedTlsHandleCredentialsConfig* config
);
static void MbedTlsHandleCredentials_Release(struct SolidSyslogMbedTlsCredentials* base);
static inline struct SolidSyslogMbedTlsHandleCredentials* MbedTlsHandleCredentials_SelfFromBase(
    struct SolidSyslogMbedTlsCredentials* base
);

void SolidSyslogMbedTlsHandleCredentials_Initialise(
    struct SolidSyslogMbedTlsCredentials* base,
    const struct SolidSyslogMbedTlsHandleCredentialsConfig* config
)
{
    struct SolidSyslogMbedTlsHandleCredentials* self = MbedTlsHandleCredentials_SelfFromBase(base);
    self->Base.Install = MbedTlsHandleCredentials_Install;
    self->Base.Release = MbedTlsHandleCredentials_Release;
    self->Config = *config;
}

static inline struct SolidSyslogMbedTlsHandleCredentials* MbedTlsHandleCredentials_SelfFromBase(
    struct SolidSyslogMbedTlsCredentials* base
)
{
    return (struct SolidSyslogMbedTlsHandleCredentials*) base;
}

/* The handles are installed on every connection rather than held on the
 * ssl_config across them, because mbedtls_ssl_config_free at Close takes the
 * key_cert nodes with it - each Open builds the configuration again from what
 * the integrator still owns. */
static bool MbedTlsHandleCredentials_Install(
    struct SolidSyslogMbedTlsCredentials* base,
    struct mbedtls_ssl_config* conf,
    struct SolidSyslogTlsCredentialsInstalled* installed
)
{
    struct SolidSyslogMbedTlsHandleCredentials* self = MbedTlsHandleCredentials_SelfFromBase(base);
    installed->TrustAnchorsInstalled = self->Config.CaChain != NULL;
    installed->Fingerprints = self->Config.PeerFingerprints;
    installed->FingerprintCount = self->Config.PeerFingerprintCount;
    if (installed->TrustAnchorsInstalled)
    {
        mbedtls_ssl_conf_ca_chain(conf, self->Config.CaChain, NULL);
    }
    MbedTlsHandleCredentials_ConfigureClientIdentity(conf, &self->Config);
    return true;
}

/* No fault in our own credential stops delivery: the collector is the
 * enforcement point for it, and one that requires a client certificate refuses
 * the handshake anyway. Every failure here leaves nothing installed, so the
 * connection continues server-authenticated rather than half-presenting a
 * credential. */
static inline void MbedTlsHandleCredentials_ConfigureClientIdentity(
    struct mbedtls_ssl_config* conf,
    const struct SolidSyslogMbedTlsHandleCredentialsConfig* config
)
{
    if (MbedTlsHandleCredentials_HasClientCredential(config))
    {
        if (MbedTlsHandleCredentials_ClientKeyMatchesCertificate(config) == false)
        {
            MbedTlsHandleCredentials_Report(
                SOLIDSYSLOG_SEVERITY_WARNING,
                SOLIDSYSLOG_CAT_BAD_CONFIG,
                SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_MISMATCHED
            );
        }
        /* Only MBEDTLS_ERR_SSL_ALLOC_FAILED, which returns before the key_cert
         * node is appended, so nothing is left half-configured. */
        else if (mbedtls_ssl_conf_own_cert(conf, config->ClientCertChain, config->ClientKey) != 0)
        {
            MbedTlsHandleCredentials_Report(
                SOLIDSYSLOG_SEVERITY_WARNING,
                SOLIDSYSLOG_CAT_BAD_CONFIG,
                SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_NOT_INSTALLED
            );
        }
        else
        {
            /* Paired and installed - the credential will be presented. */
        }
    }
    else if (MbedTlsHandleCredentials_HasHalfOfClientCredential(config))
    {
        MbedTlsHandleCredentials_Report(
            SOLIDSYSLOG_SEVERITY_WARNING,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_INCOMPLETE
        );
    }
    else
    {
        /* Neither supplied - server-authenticated TLS is the deliberate case. */
    }
}

static inline bool MbedTlsHandleCredentials_HasClientCredential(
    const struct SolidSyslogMbedTlsHandleCredentialsConfig* config
)
{
    return (config->ClientCertChain != NULL) && (config->ClientKey != NULL);
}

/* mbedtls_ssl_conf_own_cert does not check the pair it is handed, and names this
 * function in its own documentation as the way to check it. */
static inline bool MbedTlsHandleCredentials_ClientKeyMatchesCertificate(
    const struct SolidSyslogMbedTlsHandleCredentialsConfig* config
)
{
    return mbedtls_pk_check_pair(
               &config->ClientCertChain->pk,
               config->ClientKey,
               mbedtls_ctr_drbg_random,
               config->Rng
           ) == 0;
}

/* One half without the other. The integrator asked for mutual TLS and will not
 * get it, so it is reported rather than read as a decision to go without. */
static inline bool MbedTlsHandleCredentials_HasHalfOfClientCredential(
    const struct SolidSyslogMbedTlsHandleCredentialsConfig* config
)
{
    return (config->ClientCertChain != NULL) != (config->ClientKey != NULL);
}

/* Nothing to release. This backend carries handles the integrator built and
 * still owns, and the ssl_config the stream frees at Close lets go of them. A
 * backend that acquires material itself - one parsing a PEM buffer, or
 * unwrapping a key - is where Release does real work. */
static void MbedTlsHandleCredentials_Release(struct SolidSyslogMbedTlsCredentials* base)
{
    (void) base;
}
