/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#ifndef SOLIDSYSLOGMBEDTLSHANDLECREDENTIALSPRIVATE_H
#define SOLIDSYSLOGMBEDTLSHANDLECREDENTIALSPRIVATE_H

#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogMbedTlsCredentialsDefinition.h"
#include "SolidSyslogMbedTlsHandleCredentials.h"
#include "SolidSyslogMbedTlsHandleCredentialsErrors.h"
#include "SolidSyslogPrival.h"

struct SolidSyslogMbedTlsHandleCredentials
{
    struct SolidSyslogMbedTlsCredentials Base;
    struct SolidSyslogMbedTlsHandleCredentialsConfig Config;
};

void SolidSyslogMbedTlsHandleCredentials_Initialise(
    struct SolidSyslogMbedTlsCredentials* base,
    const struct SolidSyslogMbedTlsHandleCredentialsConfig* config
);

static inline void MbedTlsHandleCredentials_Report(
    enum SolidSyslogSeverity severity,
    uint16_t category,
    enum SolidSyslogTlsCredentialsErrors code
)
{
    SolidSyslog_Error(severity, &SolidSyslogMbedTlsHandleCredentialsErrorSource, category, (int32_t) code);
}

#endif /* SOLIDSYSLOGMBEDTLSHANDLECREDENTIALSPRIVATE_H */
