/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#ifndef SOLIDSYSLOGOPENSSLAESGCMPOLICYPRIVATE_H
#define SOLIDSYSLOGOPENSSLAESGCMPOLICYPRIVATE_H

#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogOpenSslAesGcmPolicy.h"
#include "SolidSyslogOpenSslAesGcmPolicyErrors.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogSecurityPolicyDefinition.h"

struct SolidSyslogOpenSslAesGcmPolicy
{
    struct SolidSyslogSecurityPolicy Base;
    struct SolidSyslogOpenSslAesGcmPolicyConfig Config;
};

void SolidSyslogOpenSslAesGcmPolicy_Initialise(
    struct SolidSyslogSecurityPolicy* base,
    const struct SolidSyslogOpenSslAesGcmPolicyConfig* config
);
void SolidSyslogOpenSslAesGcmPolicy_Cleanup(struct SolidSyslogSecurityPolicy* base);

static inline void OpenSslAesGcmPolicy_Report(
    enum SolidSyslogSeverity severity,
    uint16_t category,
    enum SolidSyslogAesGcmPolicyErrors code
)
{
    SolidSyslog_Error(severity, &SolidSyslogOpenSslAesGcmPolicyErrorSource, category, (int32_t) code);
}

#endif /* SOLIDSYSLOGOPENSSLAESGCMPOLICYPRIVATE_H */
