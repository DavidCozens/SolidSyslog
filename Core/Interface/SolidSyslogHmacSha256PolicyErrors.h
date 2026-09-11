/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  Portable detail codes for the HMAC-SHA-256 security-policy role, shared by every
 *  crypto backend that fills it. */
#ifndef SOLIDSYSLOGHMACSHA256POLICYERRORS_H
#define SOLIDSYSLOGHMACSHA256POLICYERRORS_H

#include "SolidSyslogExternC.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    /** Detail codes an HMAC-SHA-256 policy reports through event->Detail, shared by
     *  every crypto backend. Sealing a record at rest fails for the same reasons
     *  whichever library performs it, so a handler matching on these keeps working
     *  when the backend is swapped.
     *
     *  event->Source still names the backend that spoke, for diagnosis. */
    enum SolidSyslogHmacSha256PolicyErrors
    {
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_POOL_EXHAUSTED,
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_UNKNOWN_DESTROY,
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_BAD_CONFIG,
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_KEY_UNAVAILABLE,
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_KEY_TOO_SHORT,
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_HMAC_FAILED,
        SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_MAX /**< One past the last code; never emitted. Bounds the range for iteration. */
    };

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGHMACSHA256POLICYERRORS_H */
