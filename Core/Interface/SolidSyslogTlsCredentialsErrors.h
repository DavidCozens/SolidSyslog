/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  Portable detail codes for the TLS-credentials role, shared by every credentials
 *  backend. */
#ifndef SOLIDSYSLOGTLSCREDENTIALSERRORS_H
#define SOLIDSYSLOGTLSCREDENTIALSERRORS_H

#include "SolidSyslogExternC.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    /** Detail codes a credentials backend reports through event->Detail, shared by
     *  every backend whatever it fetches material from - a PEM file, a caller-built
     *  handle, a PEM buffer, or a secure element of an integrator's own. A handler
     *  that matches on these reacts to a fault identically whichever backend
     *  produced it, and keeps working when the backend is swapped.
     *
     *  event->Source still names the backend that spoke, for diagnosis. Which of
     *  these codes a given backend can raise is a property of that backend and is
     *  stated on its own page; a code it never raises is simply one a handler
     *  never sees. */
    enum SolidSyslogTlsCredentialsErrors
    {
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_POOL_EXHAUSTED,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_UNKNOWN_DESTROY,
        /* Wiring the backend cannot work without. */
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_NULL_CONFIG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_NULL_RNG,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_NULL_PEER_FINGERPRINT,
        /* Material that would not read. */
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_PEM_NOT_TERMINATED,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_TRUST_ANCHORS_NOT_LOADED,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_TRUST_ANCHORS_NOT_PARSED,
        /* A client credential that will not be presented, so mutual TLS is not in
           force even though the integrator configured it. Delivery continues. */
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_INCOMPLETE,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_NOT_PARSED,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_MISMATCHED,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_CLIENT_CREDENTIAL_NOT_INSTALLED,
        SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_MAX /**< One past the last code; never emitted. Bounds the range for iteration. */
    };

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGTLSCREDENTIALSERRORS_H */
