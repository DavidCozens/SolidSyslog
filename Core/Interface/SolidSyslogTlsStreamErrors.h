/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  Portable detail codes for the TLS-stream role, shared by every TLS backend. */
#ifndef SOLIDSYSLOGTLSSTREAMERRORS_H
#define SOLIDSYSLOGTLSSTREAMERRORS_H

#include "SolidSyslogExternC.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    /** Detail codes a TLS stream reports through event->Detail, shared by every
     *  TLS backend (OpenSSL, Mbed TLS, or an integrator's own). A handler that
     *  matches on these reacts to a fault identically whichever library produced
     *  it, and keeps working when the backend is swapped.
     *
     *  event->Source still names the backend that spoke, for diagnosis. Which of
     *  these codes a given backend can raise is a property of that backend and is
     *  stated on its own page; a code it never raises is simply one a handler
     *  never sees. */
    enum SolidSyslogTlsStreamErrors
    {
        SOLIDSYSLOG_TLS_STREAM_ERROR_POOL_EXHAUSTED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_UNKNOWN_DESTROY,
        /* Wiring the stream cannot work without. */
        SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_CONFIG,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_TRANSPORT,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_SLEEP,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_CREDENTIALS,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_RNG,
        /* Bringing the library up, before any peer is contacted. */
        SOLIDSYSLOG_TLS_STREAM_ERROR_CONTEXT_INIT_FAILED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_DEFAULTS_NOT_APPLIED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_SESSION_INIT_FAILED,
        /* What the connection was asked to check, and could not be. */
        SOLIDSYSLOG_TLS_STREAM_ERROR_SERVER_NAME_NOT_SET,
        SOLIDSYSLOG_TLS_STREAM_ERROR_NO_PEER_AUTHORISATION,
        SOLIDSYSLOG_TLS_STREAM_ERROR_FINGERPRINT_MALFORMED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_FINGERPRINT_SHA1,
        /* How the handshake ended. */
        SOLIDSYSLOG_TLS_STREAM_ERROR_HANDSHAKE_REJECTED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_HANDSHAKE_TIMEOUT,
        /* Why the peer was refused, where the library said which. */
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_UNTRUSTED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_NAME_MISMATCHED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_EXPIRED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_CERTIFICATE_NOT_YET_VALID,
        SOLIDSYSLOG_TLS_STREAM_ERROR_PEER_FINGERPRINT_MISMATCHED,
        SOLIDSYSLOG_TLS_STREAM_ERROR_MAX /**< One past the last code; never emitted. Bounds the range for iteration. */
    };

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGTLSSTREAMERRORS_H */
