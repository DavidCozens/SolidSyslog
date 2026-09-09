/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  An Mbed TLS credentials backend that parses PEM held in memory, for the
 *  duration of one connection.
 *
 *  Where the handle backend asks the integrator to keep parsed material alive,
 *  this one parses on Install and releases on Close, so between connections
 *  nothing but the integrator's own PEM is in memory. The PEM may live in
 *  read-only flash, or be fetched into a buffer the integrator wipes itself;
 *  this library copies none of it.
 *
 *  What Release frees, Mbed TLS wipes: mbedtls_pk_free zeroises the key context
 *  and every limb of the private key, and mbedtls_x509_crt_free zeroises the
 *  DER it decoded. */
#ifndef SOLIDSYSLOGMBEDTLSPEMBUFFERCREDENTIALS_H
#define SOLIDSYSLOGMBEDTLSPEMBUFFERCREDENTIALS_H

#include <stddef.h>

#include "SolidSyslogExternC.h"

/* Forward declarations keep the header free of any mbedTLS include, as the
 * stream header does. Integrators include the relevant mbedTLS headers
 * themselves before this one to bring the types into scope. */
struct mbedtls_ctr_drbg_context;

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct SolidSyslogMbedTlsCredentials;

    /** PEM text and its extent. Borrowed - the caller owns the bytes and must
     *  keep them valid for the lifetime of the credentials. */
    struct SolidSyslogMbedTlsPemBuffer
    {
        /** PEM text; NULL means this piece of material is not supplied. */
        const unsigned char* Bytes;
        /** Length of Bytes **including** the terminating NUL, which is the
         *  length Mbed TLS's own parsers require of PEM - so
         *  `strlen(pem) + 1`. Getting this wrong is reported rather than left
         *  to surface as a parse failure: Mbed TLS reads a certificate buffer
         *  whose last byte is not NUL as DER instead, which fails as "not a
         *  certificate" and says nothing about the length. */
        size_t Length;
    };

    /** Where this backend's material lives. */
    struct SolidSyslogMbedTlsPemBufferCredentialsConfig
    {
        /** Trust anchors the peer certificate must chain to; an unsupplied
         *  buffer installs none, which leaves the peer authorised only if the
         *  stream has another means to do it. */
        struct SolidSyslogMbedTlsPemBuffer CaPem;
        /** Leaf certificate (plus intermediates) for mutual TLS. Certificate
         *  and key are all-or-nothing - supplying one without the other is
         *  reported. */
        struct SolidSyslogMbedTlsPemBuffer ClientCertPem;
        /** Private key matching ClientCertPem. Must not be encrypted: no
         *  password can be supplied. */
        struct SolidSyslogMbedTlsPemBuffer ClientKeyPem;
        /** Seeded CTR-DRBG. Mbed TLS requires one to parse a private key, and
         *  it also checks the key against its certificate; required - a NULL is
         *  reported at SolidSyslogMbedTlsPemBufferCredentials_Create. The
         *  stream takes its own handshake RNG separately, and the same one
         *  serves both. */
        struct mbedtls_ctr_drbg_context* Rng;
        /** Fingerprints of certificates the peer may present, any one of which
         *  authorises it. Each is the RFC 5425 §4.2.2 form: the IANA hash
         *  name, a colon, then the digest of the DER certificate as
         *  colon-separated hexadecimal bytes in either case, e.g.
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

    /** Draw a credentials instance from the pool. A NULL config or a NULL Rng is
     *  reported and falls back to the shared Null credentials, as does an
     *  exhausted pool. */
    struct SolidSyslogMbedTlsCredentials* SolidSyslogMbedTlsPemBufferCredentials_Create(
        const struct SolidSyslogMbedTlsPemBufferCredentialsConfig* config
    );
    /** Release the pool slot, freeing any material still parsed into it. */
    void SolidSyslogMbedTlsPemBufferCredentials_Destroy(struct SolidSyslogMbedTlsCredentials * base);

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGMBEDTLSPEMBUFFERCREDENTIALS_H */
