/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  Source identity for the OpenSslPemFileCredentials adapter; the detail codes it reports are
 *  the portable ones in SolidSyslogTlsCredentialsErrors.h. */
#ifndef SOLIDSYSLOGOPENSSLPEMFILECREDENTIALSERRORS_H
#define SOLIDSYSLOGOPENSSLPEMFILECREDENTIALSERRORS_H

#include "SolidSyslogExternC.h"
#include "SolidSyslogTlsCredentialsErrors.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct SolidSyslogErrorSource;

    /** Identity for events raised by a OpenSslPemFileCredentials. A handler matches by
     *  address (event->Source == &SolidSyslogOpenSslPemFileCredentialsErrorSource), then reads
     *  event->Detail as an enum SolidSyslogTlsCredentialsErrors. */
    extern const struct SolidSyslogErrorSource SolidSyslogOpenSslPemFileCredentialsErrorSource;

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGOPENSSLPEMFILECREDENTIALSERRORS_H */
