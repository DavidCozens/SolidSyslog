/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  Certificate fingerprints in the RFC 5425 §4.2.2 form, and the peer
 *  authorisation a TLS stream performs with them. No TLS library type appears
 *  here: a stream supplies the digest of the peer's certificate through a
 *  callback, and Core owns the parse and the comparison, so every TLS pack
 *  authorises a pinned peer by the same rule. */
#ifndef SOLIDSYSLOGTLSFINGERPRINT_H
#define SOLIDSYSLOGTLSFINGERPRINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogExternC.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    /** The hash algorithms a fingerprint label may name. RFC 5425 §4.2.2 makes
     *  SHA-1 mandatory; SHA-256 is the one to configure. */
    enum SolidSyslogTlsHashAlgorithm
    {
        SOLIDSYSLOG_TLS_HASH_SHA1,
        SOLIDSYSLOG_TLS_HASH_SHA256
    };

    /** The longest digest a supported algorithm produces, in bytes. */
    enum
    {
        SOLIDSYSLOG_TLS_FINGERPRINT_DIGEST_MAX = 32
    };

    /** A parsed fingerprint: which hash, and its bytes. */
    struct SolidSyslogTlsFingerprint
    {
        enum SolidSyslogTlsHashAlgorithm Algorithm;
        uint8_t Digest[SOLIDSYSLOG_TLS_FINGERPRINT_DIGEST_MAX];
        size_t Length;
    };

    /** Parses @p text in the RFC 5425 §4.2.2 form - an IANA hash label, a
     *  colon, then the digest as colon-separated hex pairs, in either case -
     *  into @p out. Returns false, leaving @p out unspecified, where the label
     *  is not a supported algorithm or the digest is not that algorithm's
     *  length in exactly that form. */
    bool SolidSyslogTlsFingerprint_Parse(const char* text, struct SolidSyslogTlsFingerprint* out);

    /** The worst state found in a pin list: a pin that will not parse
     *  outweighs one that names SHA-1. */
    enum SolidSyslogTlsFingerprintListState
    {
        SOLIDSYSLOG_TLS_FINGERPRINT_LIST_WELL_FORMED,
        SOLIDSYSLOG_TLS_FINGERPRINT_LIST_USES_SHA1,
        SOLIDSYSLOG_TLS_FINGERPRINT_LIST_MALFORMED
    };

    /** Inspects @p count pins before a handshake, so a stream can refuse a
     *  malformed list and warn of a SHA-1 pin once per connection. An empty
     *  list is well formed, as is a NULL one with a count of zero; a count
     *  with no list behind it, or a NULL pin in one, is malformed. */
    enum SolidSyslogTlsFingerprintListState SolidSyslogTlsFingerprint_InspectList(
        const char* const * fingerprints,
        size_t count
    );

    /** How a TLS stream obtains the digest of the peer's certificate: writes
     *  the hash of its DER encoding under @p algorithm into @p digest, which
     *  holds SOLIDSYSLOG_TLS_FINGERPRINT_DIGEST_MAX bytes, and its length into
     *  @p length. Returns false where the algorithm cannot be computed, for
     *  instance a hash compiled out of the TLS library; the peer is then
     *  refused. */
    typedef bool (*SolidSyslogTlsDigestFunction)(
        void* context,
        enum SolidSyslogTlsHashAlgorithm algorithm,
        uint8_t* digest,
        size_t* length
    );

    /** The verdict on a peer certificate against a list of pins. Only
     *  MATCHED authorises. */
    enum SolidSyslogTlsAuthorisation
    {
        SOLIDSYSLOG_TLS_AUTHORISATION_MATCHED,
        SOLIDSYSLOG_TLS_AUTHORISATION_NO_MATCH,
        SOLIDSYSLOG_TLS_AUTHORISATION_MALFORMED,
        SOLIDSYSLOG_TLS_AUTHORISATION_DIGEST_UNAVAILABLE
    };

    /** Authorises a peer against @p count pins, any one of which suffices.
     *  Pins are parsed here, at the point of comparison, so a list has no
     *  fixed capacity. The walk stops at the first pin that matches, is
     *  malformed, or names a digest @p digest cannot supply, and reports
     *  which; a walk that finishes is NO_MATCH, as is an empty list. */
    enum SolidSyslogTlsAuthorisation SolidSyslogTlsFingerprint_Authorise(
        const char* const * fingerprints,
        size_t count,
        SolidSyslogTlsDigestFunction digest,
        void* context
    );

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGTLSFINGERPRINT_H */
