/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  Error codes and Source identity for the MbedTlsPemBufferCredentials backend. */
#ifndef SOLIDSYSLOGMBEDTLSPEMBUFFERCREDENTIALSERRORS_H
#define SOLIDSYSLOGMBEDTLSPEMBUFFERCREDENTIALSERRORS_H

#include "SolidSyslogExternC.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct SolidSyslogErrorSource;

    /** Detail codes for events whose Source is SolidSyslogMbedTlsPemBufferCredentialsErrorSource.
     *  A handler reads these off event->Detail after matching event->Source; the
     *  members name their own fault. */
    enum SolidSyslogMbedTlsPemBufferCredentialsErrors
    {
        SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_POOL_EXHAUSTED,
        SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_UNKNOWN_DESTROY,
        SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_NULL_CONFIG,
        SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_NULL_RNG,
        SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_NULL_PEER_FINGERPRINT,
        /** A buffer's Length does not include a terminating NUL. */
        SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_PEM_NOT_TERMINATED,
        SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_TRUST_ANCHORS_NOT_PARSED,
        SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_INCOMPLETE,
        SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_NOT_PARSED,
        SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_MISMATCHED,
        SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_NOT_INSTALLED,
        SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_MAX /**< One past the last code; never emitted. Bounds the range for iteration. */
    };

    /** Identity for events raised by an MbedTlsPemBufferCredentials. A handler
     *  matches by address (event->Source == &SolidSyslogMbedTlsPemBufferCredentialsErrorSource),
     *  then reads event->Detail as an enum
     *  SolidSyslogMbedTlsPemBufferCredentialsErrors. */
    extern const struct SolidSyslogErrorSource SolidSyslogMbedTlsPemBufferCredentialsErrorSource;

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGMBEDTLSPEMBUFFERCREDENTIALSERRORS_H */
