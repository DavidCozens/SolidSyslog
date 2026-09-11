/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#ifndef SOLIDSYSLOGMBEDTLSPEMBUFFERCREDENTIALSPRIVATE_H
#define SOLIDSYSLOGMBEDTLSPEMBUFFERCREDENTIALSPRIVATE_H

#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogMbedTlsCredentialsDefinition.h"
#include "SolidSyslogMbedTlsPemBufferCredentials.h"
#include "SolidSyslogMbedTlsPemBufferCredentialsErrors.h"
#include "SolidSyslogPrival.h"

struct SolidSyslogMbedTlsPemBufferCredentials
{
    struct SolidSyslogMbedTlsCredentials Base;
    struct SolidSyslogMbedTlsPemBufferCredentialsConfig Config;
    /* Holds the parsed material for the length of one connection only. Init'd
     * at Create so the frees in Release are safe whether or not Install ever
     * ran, and left in Mbed TLS's freed-equivalent state afterwards so the next
     * Install parses into them again. */
    mbedtls_x509_crt CaChain;
    mbedtls_x509_crt ClientCertChain;
    mbedtls_pk_context ClientKey;
};

void SolidSyslogMbedTlsPemBufferCredentials_Initialise(
    struct SolidSyslogMbedTlsCredentials* base,
    const struct SolidSyslogMbedTlsPemBufferCredentialsConfig* config
);
void SolidSyslogMbedTlsPemBufferCredentials_Cleanup(struct SolidSyslogMbedTlsCredentials* base);

static inline void MbedTlsPemBufferCredentials_Report(
    enum SolidSyslogSeverity severity,
    uint16_t category,
    enum SolidSyslogTlsCredentialsErrors code
)
{
    SolidSyslog_Error(severity, &SolidSyslogMbedTlsPemBufferCredentialsErrorSource, category, (int32_t) code);
}

#endif /* SOLIDSYSLOGMBEDTLSPEMBUFFERCREDENTIALSPRIVATE_H */
