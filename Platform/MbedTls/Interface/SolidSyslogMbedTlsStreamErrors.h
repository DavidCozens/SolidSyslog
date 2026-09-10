/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  Source identity for the MbedTlsStream adapter; the detail codes it reports are
 *  the portable ones in SolidSyslogTlsStreamErrors.h. */
#ifndef SOLIDSYSLOGMBEDTLSSTREAMERRORS_H
#define SOLIDSYSLOGMBEDTLSSTREAMERRORS_H

#include "SolidSyslogExternC.h"
#include "SolidSyslogTlsStreamErrors.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct SolidSyslogErrorSource;

    /** Identity for events raised by an MbedTlsStream. A handler matches by address
     *  (event->Source == &SolidSyslogMbedTlsStreamErrorSource), then reads event->Detail as an
     *  enum SolidSyslogTlsStreamErrors. */
    extern const struct SolidSyslogErrorSource SolidSyslogMbedTlsStreamErrorSource;

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGMBEDTLSSTREAMERRORS_H */
