/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  Source identity for the MbedTlsPemBufferCredentials adapter; the detail codes it reports are
 *  the portable ones in SolidSyslogTlsCredentialsErrors.h. */
#ifndef SOLIDSYSLOGMBEDTLSPEMBUFFERCREDENTIALSERRORS_H
#define SOLIDSYSLOGMBEDTLSPEMBUFFERCREDENTIALSERRORS_H

#include "SolidSyslogExternC.h"
#include "SolidSyslogTlsCredentialsErrors.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct SolidSyslogErrorSource;

    /** Identity for events raised by a MbedTlsPemBufferCredentials. A handler matches by
     *  address (event->Source == &SolidSyslogMbedTlsPemBufferCredentialsErrorSource), then reads
     *  event->Detail as an enum SolidSyslogTlsCredentialsErrors. */
    extern const struct SolidSyslogErrorSource SolidSyslogMbedTlsPemBufferCredentialsErrorSource;

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGMBEDTLSPEMBUFFERCREDENTIALSERRORS_H */
