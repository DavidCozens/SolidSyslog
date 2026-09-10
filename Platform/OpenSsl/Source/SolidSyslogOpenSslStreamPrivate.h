/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#ifndef SOLIDSYSLOGOPENSSLSTREAMPRIVATE_H
#define SOLIDSYSLOGOPENSSLSTREAMPRIVATE_H

#include <stdbool.h>
#include <stdint.h>

#include <openssl/bio.h>
#include <openssl/types.h>

#include "SolidSyslogError.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogStreamDefinition.h"
#include "SolidSyslogOpenSslStream.h"
#include "SolidSyslogOpenSslStreamErrors.h"
#include "SolidSyslogTlsCredentialsInstalled.h"

struct SolidSyslogOpenSslStream
{
    struct SolidSyslogStream Base;
    struct SolidSyslogOpenSslStreamConfig Config;
    SSL_CTX* Ctx;
    SSL* Ssl;
    BIO_METHOD* BioMethod;
    /* Set immediately before Install is called, cleared by the Release that
     * answers it. The contract is one Release per Install call whatever that
     * call returned, and Close is idempotent, so the flag is what keeps both
     * true at once. */
    bool CredentialsInstalled;
    /* What the last Install reported. Read after Install returns, by the verify
     * callback and by the hostname step; valid only while CredentialsInstalled. */
    struct SolidSyslogTlsCredentialsInstalled Installed;
    /* Pulled at the start of each Open and read for the rest of it. */
    struct SolidSyslogOpenSslProfile Profile;
};

void SolidSyslogOpenSslStream_Initialise(
    struct SolidSyslogStream* base,
    const struct SolidSyslogOpenSslStreamConfig* config
);
void SolidSyslogOpenSslStream_Cleanup(struct SolidSyslogStream* base);

static inline void OpenSslStream_Report(
    enum SolidSyslogSeverity severity,
    uint16_t category,
    enum SolidSyslogTlsStreamErrors code
)
{
    SolidSyslog_Error(severity, &SolidSyslogOpenSslStreamErrorSource, category, (int32_t) code);
}

#endif /* SOLIDSYSLOGOPENSSLSTREAMPRIVATE_H */
