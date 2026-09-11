/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#ifndef SOLIDSYSLOGMBEDTLSHMACSHA256POLICYPRIVATE_H
#define SOLIDSYSLOGMBEDTLSHMACSHA256POLICYPRIVATE_H

#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogMbedTlsHmacSha256Policy.h"
#include "SolidSyslogMbedTlsHmacSha256PolicyErrors.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogSecurityPolicyDefinition.h"

struct SolidSyslogMbedTlsHmacSha256Policy
{
    struct SolidSyslogSecurityPolicy Base;
    struct SolidSyslogMbedTlsHmacSha256PolicyConfig Config;
};

void SolidSyslogMbedTlsHmacSha256Policy_Initialise(
    struct SolidSyslogSecurityPolicy* base,
    const struct SolidSyslogMbedTlsHmacSha256PolicyConfig* config
);
void SolidSyslogMbedTlsHmacSha256Policy_Cleanup(struct SolidSyslogSecurityPolicy* base);

static inline void MbedTlsHmacSha256Policy_Report(
    enum SolidSyslogSeverity severity,
    uint16_t category,
    enum SolidSyslogHmacSha256PolicyErrors code
)
{
    SolidSyslog_Error(severity, &SolidSyslogMbedTlsHmacSha256PolicyErrorSource, category, (int32_t) code);
}

#endif /* SOLIDSYSLOGMBEDTLSHMACSHA256POLICYPRIVATE_H */
