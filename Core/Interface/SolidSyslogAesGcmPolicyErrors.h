/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  Portable detail codes for the AES-GCM security-policy role, shared by every
 *  crypto backend that fills it. */
#ifndef SOLIDSYSLOGAESGCMPOLICYERRORS_H
#define SOLIDSYSLOGAESGCMPOLICYERRORS_H

#include "SolidSyslogExternC.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    /** Detail codes an AES-GCM policy reports through event->Detail, shared by every
     *  crypto backend. Sealing a record at rest fails for the same reasons whichever
     *  library performs it, so a handler matching on these keeps working when the
     *  backend is swapped.
     *
     *  event->Source still names the backend that spoke, for diagnosis. */
    enum SolidSyslogAesGcmPolicyErrors
    {
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_POOL_EXHAUSTED,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_UNKNOWN_DESTROY,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_BAD_CONFIG,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_KEY_UNAVAILABLE,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_NONCE_FAILED,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_ENCRYPT_FAILED,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_DECRYPT_FAILED,
        SOLIDSYSLOG_AES_GCM_POLICY_ERROR_MAX /**< One past the last code; never emitted. Bounds the range for iteration. */
    };

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGAESGCMPOLICYERRORS_H */
