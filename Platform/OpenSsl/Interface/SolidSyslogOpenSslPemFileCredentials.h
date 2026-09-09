/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  An OpenSSL credentials backend that names its material by file path, and
 *  hands those paths to OpenSSL to open and parse. This library performs no
 *  file handling of its own: it neither opens, reads, parses nor buffers the
 *  PEM, so key bytes never pass through it.
 *
 *  Paths are re-read on every connection, so a device issued new credentials
 *  while it is running uses them on its next connect without a restart. */
#ifndef SOLIDSYSLOGOPENSSLPEMFILECREDENTIALS_H
#define SOLIDSYSLOGOPENSSLPEMFILECREDENTIALS_H

#include <stddef.h>

#include "SolidSyslogExternC.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct SolidSyslogOpenSslCredentials;

    /** Where this backend's material lives. Every member is the caller's and
     *  must stay valid for the lifetime of the credentials. */
    struct SolidSyslogOpenSslPemFileCredentialsConfig
    {
        /** PEM file of trust anchors the peer certificate must chain to; NULL
         *  installs none, which leaves the peer authorised only if the stream
         *  has another means to do it. */
        const char* CaBundlePath;
        /** PEM leaf certificate (plus intermediates) for mutual TLS; NULL means
         *  no client credential. Certificate and key are all-or-nothing -
         *  supplying one without the other is reported. */
        const char* ClientCertChainPath;
        /** PEM private key matching ClientCertChainPath; NULL means no client
         *  credential. */
        const char* ClientKeyPath;
        /** Fingerprints of certificates the peer may present, any one of which
         *  authorises it. Each is the RFC 5425 §4.2.2 form: the IANA hash
         *  name, a colon, then the digest of the DER certificate as
         *  colon-separated uppercase hexadecimal bytes, e.g.
         *  `sha-256:E1:2D:...`. `sha-256` and `sha-1` are accepted; a `sha-1`
         *  pin is reported on every connection. A pin in any other form is
         *  reported when the stream opens and that attempt fails. NULL with a
         *  count of zero pins no peer; a count with no list behind it, or a
         *  NULL pin in one, is reported at Create, which returns the Null
         *  credentials. The array and the strings must outlive the
         *  credentials. */
        const char* const * PeerFingerprints;
        size_t PeerFingerprintCount;
    };

    /** Draw a credentials instance from the pool. A NULL config is reported and
     *  falls back to the shared Null credentials, as does an exhausted pool. */
    struct SolidSyslogOpenSslCredentials* SolidSyslogOpenSslPemFileCredentials_Create(
        const struct SolidSyslogOpenSslPemFileCredentialsConfig* config
    );
    /** Release the pool slot. */
    void SolidSyslogOpenSslPemFileCredentials_Destroy(struct SolidSyslogOpenSslCredentials * base);

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGOPENSSLPEMFILECREDENTIALS_H */
