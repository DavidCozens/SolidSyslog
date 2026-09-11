/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#ifndef SOLIDSYSLOGOPENSSLHMACSHA256POLICYPRIVATE_H
#define SOLIDSYSLOGOPENSSLHMACSHA256POLICYPRIVATE_H

#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogOpenSslHmacSha256Policy.h"
#include "SolidSyslogOpenSslHmacSha256PolicyErrors.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogSecurityPolicyDefinition.h"

struct SolidSyslogOpenSslHmacSha256Policy
{
    struct SolidSyslogSecurityPolicy Base;
    struct SolidSyslogOpenSslHmacSha256PolicyConfig Config;
};

void SolidSyslogOpenSslHmacSha256Policy_Initialise(
    struct SolidSyslogSecurityPolicy* base,
    const struct SolidSyslogOpenSslHmacSha256PolicyConfig* config
);
void SolidSyslogOpenSslHmacSha256Policy_Cleanup(struct SolidSyslogSecurityPolicy* base);

static inline void OpenSslHmacSha256Policy_Report(
    enum SolidSyslogSeverity severity,
    uint16_t category,
    enum SolidSyslogHmacSha256PolicyErrors code
)
{
    SolidSyslog_Error(severity, &SolidSyslogOpenSslHmacSha256PolicyErrorSource, category, (int32_t) code);
}

#endif /* SOLIDSYSLOGOPENSSLHMACSHA256POLICYPRIVATE_H */
