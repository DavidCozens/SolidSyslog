/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogOpenSslPemFileCredentials.h"

#include <stdbool.h>
#include <stddef.h>

#include <openssl/ssl.h>

#include "SolidSyslogOpenSslCredentialsDefinition.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogOpenSslPemFileCredentialsPrivate.h"
#include "SolidSyslogTlsCredentialsInstalled.h"

const struct SolidSyslogErrorSource SolidSyslogOpenSslPemFileCredentialsErrorSource = {"OpenSslPemFileCredentials"};

static bool OpenSslPemFileCredentials_Install(
    struct SolidSyslogOpenSslCredentials* base,
    SSL_CTX* ctx,
    struct SolidSyslogTlsCredentialsInstalled* installed
);
static inline void OpenSslPemFileCredentials_ConfigureClientIdentity(
    SSL_CTX* ctx,
    const struct SolidSyslogOpenSslPemFileCredentialsConfig* config
);
static inline bool OpenSslPemFileCredentials_HasClientCredential(
    const struct SolidSyslogOpenSslPemFileCredentialsConfig* config
);
static inline bool OpenSslPemFileCredentials_HasHalfOfClientCredential(
    const struct SolidSyslogOpenSslPemFileCredentialsConfig* config
);
static inline void OpenSslPemFileCredentials_LoadClientCredential(
    SSL_CTX* ctx,
    const struct SolidSyslogOpenSslPemFileCredentialsConfig* config
);
static void OpenSslPemFileCredentials_Release(struct SolidSyslogOpenSslCredentials* base);
static inline struct SolidSyslogOpenSslPemFileCredentials* OpenSslPemFileCredentials_SelfFromBase(
    struct SolidSyslogOpenSslCredentials* base
);

void SolidSyslogOpenSslPemFileCredentials_Initialise(
    struct SolidSyslogOpenSslCredentials* base,
    const struct SolidSyslogOpenSslPemFileCredentialsConfig* config
)
{
    struct SolidSyslogOpenSslPemFileCredentials* self = OpenSslPemFileCredentials_SelfFromBase(base);
    self->Base.Install = OpenSslPemFileCredentials_Install;
    self->Base.Release = OpenSslPemFileCredentials_Release;
    self->Config = *config;
}

static inline struct SolidSyslogOpenSslPemFileCredentials* OpenSslPemFileCredentials_SelfFromBase(
    struct SolidSyslogOpenSslCredentials* base
)
{
    return (struct SolidSyslogOpenSslPemFileCredentials*) base;
}

/* Trust anchors are named by path and opened by OpenSSL - this library performs
 * no file handling of its own, so the PEM bytes never pass through it. The
 * paths are re-read here rather than at Create, so a credential replaced while
 * the device runs is picked up on the next connection. */
static bool OpenSslPemFileCredentials_Install(
    struct SolidSyslogOpenSslCredentials* base,
    SSL_CTX* ctx,
    struct SolidSyslogTlsCredentialsInstalled* installed
)
{
    struct SolidSyslogOpenSslPemFileCredentials* self = OpenSslPemFileCredentials_SelfFromBase(base);
    bool ok = true;
    installed->TrustAnchorsInstalled = false;
    installed->Fingerprints = self->Config.PeerFingerprints;
    installed->FingerprintCount = self->Config.PeerFingerprintCount;
    if (self->Config.CaBundlePath != NULL)
    {
        installed->TrustAnchorsInstalled = SSL_CTX_load_verify_locations(ctx, self->Config.CaBundlePath, NULL) == 1;
        ok = installed->TrustAnchorsInstalled;
        if (!ok)
        {
            OpenSslPemFileCredentials_Report(
                SOLIDSYSLOG_SEVERITY_ERROR,
                SOLIDSYSLOG_CAT_BAD_CONFIG,
                SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_TRUST_ANCHORS_NOT_LOADED
            );
        }
    }
    OpenSslPemFileCredentials_ConfigureClientIdentity(ctx, &self->Config);
    return ok;
}

/* No fault in our own credential stops delivery: the collector is the
 * enforcement point for it, and one that requires a client certificate refuses
 * the handshake anyway. OpenSSL presents a certificate only where both halves
 * are installed and paired, so a credential it will not take degrades to
 * server-authenticated TLS rather than being half-presented. */
static inline void OpenSslPemFileCredentials_ConfigureClientIdentity(
    SSL_CTX* ctx,
    const struct SolidSyslogOpenSslPemFileCredentialsConfig* config
)
{
    if (OpenSslPemFileCredentials_HasClientCredential(config))
    {
        OpenSslPemFileCredentials_LoadClientCredential(ctx, config);
    }
    else if (OpenSslPemFileCredentials_HasHalfOfClientCredential(config))
    {
        OpenSslPemFileCredentials_Report(
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

static inline bool OpenSslPemFileCredentials_HasClientCredential(
    const struct SolidSyslogOpenSslPemFileCredentialsConfig* config
)
{
    return (config->ClientCertChainPath != NULL) && (config->ClientKeyPath != NULL);
}

/* One half without the other. The integrator asked for mutual TLS and will not
 * get it, so it is reported rather than read as a decision to go without. */
static inline bool OpenSslPemFileCredentials_HasHalfOfClientCredential(
    const struct SolidSyslogOpenSslPemFileCredentialsConfig* config
)
{
    return (config->ClientCertChainPath != NULL) != (config->ClientKeyPath != NULL);
}

/* A key that does not match its certificate is refused by SSL_CTX_use_PrivateKey_file
 * itself where both are of the same type, so it reaches the explicit pairing check
 * only as a cross-type pair. The two are reported apart where OpenSSL tells them
 * apart, and a mismatch it hides inside the load is reported as one that would
 * not install. */
static inline void OpenSslPemFileCredentials_LoadClientCredential(
    SSL_CTX* ctx,
    const struct SolidSyslogOpenSslPemFileCredentialsConfig* config
)
{
    bool installed = (SSL_CTX_use_certificate_chain_file(ctx, config->ClientCertChainPath) == 1) &&
                     (SSL_CTX_use_PrivateKey_file(ctx, config->ClientKeyPath, SSL_FILETYPE_PEM) == 1);
    if (installed == false)
    {
        OpenSslPemFileCredentials_Report(
            SOLIDSYSLOG_SEVERITY_WARNING,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_NOT_INSTALLED
        );
    }
    else if (SSL_CTX_check_private_key(ctx) != 1)
    {
        OpenSslPemFileCredentials_Report(
            SOLIDSYSLOG_SEVERITY_WARNING,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_MISMATCHED
        );
    }
    else
    {
        /* Installed and paired - the credential will be presented. */
    }
}

/* Nothing to release. This backend holds paths, and OpenSSL owns what it parsed
 * from them: the SSL_CTX the stream frees at Close takes the certificate and the
 * key with it. A backend that parses material itself - one reading a PEM buffer,
 * or unwrapping a key - is where Release does real work. */
static void OpenSslPemFileCredentials_Release(struct SolidSyslogOpenSslCredentials* base)
{
    (void) base;
}
