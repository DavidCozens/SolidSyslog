/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  TLS over an injected byte-transport Stream (OpenSSL reference integration),
 *  for a StreamSender that needs an encrypted channel. The transport (a plain
 *  TcpStream, typically) carries the ciphertext; this stream owns the TLS.
 *
 *  What the stream does through its vtable is the substance:
 *
 *  - Open opens the transport, then builds a fresh SSL_CTX every call (the
 *    cert-rotation contract - a reconnect re-reads the cert/key files), pins the
 *    TLS 1.2 floor, loads CaBundlePath as the trust anchors with SSL_VERIFY_PEER,
 *    wires the transport as a custom BIO, sets SNI + the expected peer identity
 *    from ServerName, and drives the handshake. Any step failing closes the whole
 *    stream so the sender reconnects on its next pass.
 *  - The handshake is a bounded, non-blocking retry: SSL_connect is polled, and
 *    each WANT_READ / WANT_WRITE sleeps briefly via the injected Sleep until the
 *    handshake completes, hits a hard error (rejected), or the deadline from
 *    GetHandshakeTimeoutMs expires (re-read each attempt, so a runtime-tunable
 *    value applies on the next reconnect).
 *  - Send is all-or-nothing over SSL_write: a short write or any error is taken
 *    as a dead connection, so the stream closes itself and the sender reconnects.
 *  - Read returns the bytes read, 0 for would-block (WANT_READ, connection kept),
 *    or closes on anything else - including a mid-stream WANT_WRITE (renegotiation)
 *    which fail-fast semantics treat as a transport failure; store-and-forward
 *    replays after the reopen. */
#ifndef SOLIDSYSLOGOPENSSLSTREAM_H
#define SOLIDSYSLOGOPENSSLSTREAM_H

#include "SolidSyslogExternC.h"
#include "SolidSyslogSleep.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogTlsHandshakeTimeoutFunction.h"

struct SolidSyslogStream;
struct SolidSyslogOpenSslCredentials;

SOLIDSYSLOG_EXTERN_C_BEGIN

    /** What one connection is made with, supplied by the integrator at each Open.
     *  The stream zeroes this before asking, so a field left alone is one the
     *  integrator has no policy on and the library's own default stands. Anything
     *  supplied must stay valid until the connection closes. */
    struct SolidSyslogOpenSslProfile
    {
        /** SNI plus the expected peer identity. A non-empty name is verified against
         *  the cert (SAN/CN); one that parses as an address literal is verified as an
         *  address, so the cert must carry it as an iPAddress SAN and a DNS entry
         *  spelling the same digits does not match. NULL asks for neither, and what
         *  that means depends on the Credentials: a usable pinned fingerprint names the
         *  peer instead, so nothing is reported; without one the peer is only
         *  chain-authenticated and a WARNING says so (MITM-class). "" is the
         *  no-name-check opt-out (closed network / private CA): still verified against
         *  whatever the credentials installed, endpoint identity unchecked; no
         *  diagnostic. */
        const char* ServerName;
        const char* CipherList; /**< TLS 1.2 and below; NULL uses the OpenSSL default. */
        /** TLS 1.3 ciphersuites, which OpenSSL keeps in a list of their own - a
         *  CipherList alone does not bind a TLS 1.3 connection. NULL uses the OpenSSL
         *  default, which is RFC 8446's mandatory suite plus both it recommends. */
        const char* CipherSuites;
    };

    /** Called at each Open to fill @p profile. Runs on the servicing thread, so a
     *  value the integrator changes elsewhere is read here rather than stored, and
     *  moving the stream's Version is what makes the change take effect.
     *  @p context is ProfileContext, passed through unchanged. */
    typedef void (*SolidSyslogOpenSslProfileFunction)(struct SolidSyslogOpenSslProfile* profile, void* context);

    /** Wires SolidSyslogOpenSslStream to its transport, trust anchors, and identity.
     *  Wiring only: every value a connection is made with arrives through the
     *  Credentials or the Profile, so nothing here goes stale when a deployment
     *  changes. */
    struct SolidSyslogOpenSslStreamConfig
    {
        /** Underlying byte stream carrying the ciphertext; required - a NULL is
         *  reported at SolidSyslogOpenSslStream_Create. Borrowed - this stream
         *  may Close it but never
         *  destroys it; the caller owns it and must keep it valid until
         *  SolidSyslogOpenSslStream_Destroy. */
        struct SolidSyslogStream* Transport;
        /** Where the trust anchors, any pinned peer fingerprints and the mutual-TLS
         *  client credential come from; required - a NULL is reported at
         *  SolidSyslogOpenSslStream_Create. Asked once per connection, so material
         *  is fetched only for a connection actually being made, and told when the
         *  connection ends. Borrowed - the caller owns it and must keep it valid
         *  until SolidSyslogOpenSslStream_Destroy. */
        struct SolidSyslogOpenSslCredentials* Credentials;
        SolidSyslogSleepFunction Sleep; /**< Drives the bounded handshake retry between WANT_READ/WANT_WRITE
                                         *  polls; required - a NULL is reported at
                                         *  SolidSyslogOpenSslStream_Create. */
        SolidSyslogTlsHandshakeTimeoutFunction GetHandshakeTimeoutMs; /**< Per-attempt handshake deadline in ms;
                                                                       *  NULL uses the
                                                                       *  SOLIDSYSLOG_TLS_HANDSHAKE_TIMEOUT_MS
                                                                       *  tunable. */
        void* HandshakeTimeoutContext; /**< Passed back to GetHandshakeTimeoutMs unchanged; NULL is fine. */
        /** Supplies the per-connection profile. NULL leaves every profile field at
         *  the library default, which for ServerName means an unverified peer. */
        SolidSyslogOpenSslProfileFunction Profile;
        void* ProfileContext; /**< Passed to Profile unchanged; NULL is fine. */
        /** Bumped by the integrator when anything the stream uses changes at runtime -
         *  the Credentials, or anything the Profile supplies. The sender polls it every Send and
         *  reconnects on the next pass when it moves, so a rotation applies without
         *  calling SolidSyslogSender_Disconnect. Polled from the servicing thread,
         *  so it must be cheap and pure. NULL means this configuration never
         *  changes. */
        SolidSyslogStreamVersionFunction Version;
        void* VersionContext; /**< Passed to Version unchanged; NULL is fine. */
    };

    /** Draw a TLS stream from the pool over the injected transport (see the file
     *  overview for the handshake and I/O behaviour). A NULL config, a NULL
     *  Transport, a NULL Sleep or a NULL Credentials is reported and falls back to
     *  the shared NullStream, as does an exhausted pool (default size 1). */
    struct SolidSyslogStream* SolidSyslogOpenSslStream_Create(const struct SolidSyslogOpenSslStreamConfig* config);
    /** Release the pool slot; closes the TLS session and the underlying transport
     *  first if the stream is still Open. */
    void SolidSyslogOpenSslStream_Destroy(struct SolidSyslogStream * base);

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGOPENSSLSTREAM_H */
