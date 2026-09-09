/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  Error codes and Source identity for the OpenSslPemFileCredentials backend. */
#ifndef SOLIDSYSLOGOPENSSLPEMFILECREDENTIALSERRORS_H
#define SOLIDSYSLOGOPENSSLPEMFILECREDENTIALSERRORS_H

#include "SolidSyslogExternC.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct SolidSyslogErrorSource;

    /** Detail codes for events whose Source is SolidSyslogOpenSslPemFileCredentialsErrorSource.
     *  A handler reads these off event->Detail after matching event->Source; the
     *  members name their own fault. */
    enum SolidSyslogOpenSslPemFileCredentialsErrors
    {
        SOLIDSYSLOG_OPENSSL_PEM_FILE_CREDENTIALS_ERROR_POOL_EXHAUSTED,
        SOLIDSYSLOG_OPENSSL_PEM_FILE_CREDENTIALS_ERROR_UNKNOWN_DESTROY,
        SOLIDSYSLOG_OPENSSL_PEM_FILE_CREDENTIALS_ERROR_NULL_CONFIG,
        SOLIDSYSLOG_OPENSSL_PEM_FILE_CREDENTIALS_ERROR_NULL_PEER_FINGERPRINT,
        SOLIDSYSLOG_OPENSSL_PEM_FILE_CREDENTIALS_ERROR_TRUST_ANCHORS_NOT_LOADED,
        SOLIDSYSLOG_OPENSSL_PEM_FILE_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_INCOMPLETE,
        SOLIDSYSLOG_OPENSSL_PEM_FILE_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_MISMATCHED,
        SOLIDSYSLOG_OPENSSL_PEM_FILE_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_NOT_INSTALLED,
        SOLIDSYSLOG_OPENSSL_PEM_FILE_CREDENTIALS_ERROR_MAX /**< One past the last code; never emitted. Bounds the range for iteration. */
    };

    /** Identity for events raised by an OpenSslPemFileCredentials. A handler
     *  matches by address (event->Source == &SolidSyslogOpenSslPemFileCredentialsErrorSource),
     *  then reads event->Detail as an enum
     *  SolidSyslogOpenSslPemFileCredentialsErrors. */
    extern const struct SolidSyslogErrorSource SolidSyslogOpenSslPemFileCredentialsErrorSource;

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGOPENSSLPEMFILECREDENTIALSERRORS_H */
