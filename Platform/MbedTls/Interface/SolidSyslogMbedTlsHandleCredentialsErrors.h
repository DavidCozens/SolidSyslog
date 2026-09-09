/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  Error codes and Source identity for the MbedTlsHandleCredentials backend. */
#ifndef SOLIDSYSLOGMBEDTLSHANDLECREDENTIALSERRORS_H
#define SOLIDSYSLOGMBEDTLSHANDLECREDENTIALSERRORS_H

#include "SolidSyslogExternC.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct SolidSyslogErrorSource;

    /** Detail codes for events whose Source is SolidSyslogMbedTlsHandleCredentialsErrorSource.
     *  A handler reads these off event->Detail after matching event->Source; the
     *  members name their own fault. */
    enum SolidSyslogMbedTlsHandleCredentialsErrors
    {
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_POOL_EXHAUSTED,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_UNKNOWN_DESTROY,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_NULL_CONFIG,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_NULL_RNG,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_NULL_PEER_FINGERPRINT,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_INCOMPLETE,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_MISMATCHED,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_NOT_INSTALLED,
        SOLIDSYSLOG_MBEDTLS_HANDLE_CREDENTIALS_ERROR_MAX /**< One past the last code; never emitted. Bounds the range for iteration. */
    };

    /** Identity for events raised by an MbedTlsHandleCredentials. A handler
     *  matches by address (event->Source == &SolidSyslogMbedTlsHandleCredentialsErrorSource),
     *  then reads event->Detail as an enum
     *  SolidSyslogMbedTlsHandleCredentialsErrors. */
    extern const struct SolidSyslogErrorSource SolidSyslogMbedTlsHandleCredentialsErrorSource;

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGMBEDTLSHANDLECREDENTIALSERRORS_H */
