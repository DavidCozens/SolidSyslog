/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  Error codes and Source identity for the OpenSslStream adapter. */
#ifndef SOLIDSYSLOGOPENSSLSTREAMERRORS_H
#define SOLIDSYSLOGOPENSSLSTREAMERRORS_H

#include "SolidSyslogExternC.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct SolidSyslogErrorSource;

    /** Detail codes for events whose Source is SolidSyslogOpenSslStreamErrorSource. A handler
     *  reads these off event->Detail after matching event->Source; the members
     *  name their own fault. */
    enum SolidSyslogOpenSslStreamErrors
    {
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_POOL_EXHAUSTED,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_UNKNOWN_DESTROY,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_CONTEXT_INIT_FAILED,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_SESSION_INIT_FAILED,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_SERVER_NAME_NOT_SET,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_HANDSHAKE_REJECTED,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_HANDSHAKE_TIMEOUT,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_NULL_CONFIG,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_NULL_TRANSPORT,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_NULL_SLEEP,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_NULL_CREDENTIALS,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_NO_PEER_AUTHORISATION,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_PEER_CERTIFICATE_UNTRUSTED,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_PEER_NAME_MISMATCHED,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_PEER_CERTIFICATE_EXPIRED,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_PEER_CERTIFICATE_NOT_YET_VALID,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_FINGERPRINT_MALFORMED,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_FINGERPRINT_SHA1,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_PEER_FINGERPRINT_MISMATCHED,
        SOLIDSYSLOG_OPENSSL_STREAM_ERROR_MAX /**< One past the last code; never emitted. Bounds the range for iteration. */
    };

    /** Identity for events raised by a OpenSslStream. A handler matches by address
     *  (event->Source == &SolidSyslogOpenSslStreamErrorSource), then reads event->Detail as an
     *  enum SolidSyslogOpenSslStreamErrors. */
    extern const struct SolidSyslogErrorSource SolidSyslogOpenSslStreamErrorSource;

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGOPENSSLSTREAMERRORS_H */
