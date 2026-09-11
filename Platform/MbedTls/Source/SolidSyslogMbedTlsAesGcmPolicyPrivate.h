/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#ifndef SOLIDSYSLOGMBEDTLSAESGCMPOLICYPRIVATE_H
#define SOLIDSYSLOGMBEDTLSAESGCMPOLICYPRIVATE_H

#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogMbedTlsAesGcmPolicy.h"
#include "SolidSyslogMbedTlsAesGcmPolicyErrors.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogSecurityPolicyDefinition.h"

struct SolidSyslogMbedTlsAesGcmPolicy
{
    struct SolidSyslogSecurityPolicy Base;
    struct SolidSyslogMbedTlsAesGcmPolicyConfig Config;
};

void SolidSyslogMbedTlsAesGcmPolicy_Initialise(
    struct SolidSyslogSecurityPolicy* base,
    const struct SolidSyslogMbedTlsAesGcmPolicyConfig* config
);
void SolidSyslogMbedTlsAesGcmPolicy_Cleanup(struct SolidSyslogSecurityPolicy* base);

static inline void MbedTlsAesGcmPolicy_Report(
    enum SolidSyslogSeverity severity,
    uint16_t category,
    enum SolidSyslogAesGcmPolicyErrors code
)
{
    SolidSyslog_Error(severity, &SolidSyslogMbedTlsAesGcmPolicyErrorSource, category, (int32_t) code);
}

#endif /* SOLIDSYSLOGMBEDTLSAESGCMPOLICYPRIVATE_H */
