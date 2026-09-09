/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  TLS over an injected byte-transport Stream via Mbed TLS, itself a Stream - so
 *  a StreamSender speaks TLS to a remote collector without knowing the transport
 *  underneath, whether a TCP stream from a platform pack or one the caller
 *  supplies.
 *
 *  What the stream does through its vtable is the substance:
 *
 *  - Open first opens the underlying transport, applies the library-owned TLS
 *    policy (client mode, TLS 1.2 floor, VERIFY_REQUIRED), asks the credentials
 *    source to install the material for this connection, installs the peer
 *    identity, then drives the handshake to completion. The
 *    non-blocking transport means each mbedtls_ssl_handshake may want more I/O;
 *    the injected Sleep bridges those polls until the handshake completes, hits
 *    a hard error (HANDSHAKE_REJECTED), or the bounded budget expires
 *    (HANDSHAKE_TIMEOUT - re-read from GetHandshakeTimeoutMs each attempt, so a
 *    runtime-tunable value applies on the next reconnect). A failed Open closes
 *    the stream so the sender reconnects on its next pass.
 *  - Send is all-or-nothing: a short write or any TLS error is taken as an
 *    unrecoverable session and closes the stream, so the sender reconnects.
 *  - Read returns the bytes read, 0 for would-block, or closes the stream on any
 *    other TLS return (alert, transport error) - fail-fast, and store-and-forward
 *    replays after the reconnect.
 *
 *  Peer identity is set by ServerName (see the config member). No key material
 *  reaches this stream: it asks its credentials source to install onto the
 *  ssl_config at Open and tells it at Close, so a deployment can keep material
 *  out of memory between connections. Coexistence contract: this adapter touches
 *  only per-instance ssl_config / ssl_context state and never calls
 *  process-global mbedTLS APIs
 *  (platform setup/teardown, psa_crypto_init, threading-alt, debug hooks), so it
 *  drops into an integrator process that already uses Mbed TLS elsewhere. See
 *  docs/platforms/mbedtls/setup.md. */
#ifndef SOLIDSYSLOGMBEDTLSSTREAM_H
#define SOLIDSYSLOGMBEDTLSSTREAM_H

#include "SolidSyslogExternC.h"
#include "SolidSyslogSleep.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogTlsHandshakeTimeoutFunction.h"

struct SolidSyslogStream;
struct SolidSyslogMbedTlsCredentials;

/* Forward declarations keep the public header free of any mbedTLS include.
 * Integrators include the relevant mbedTLS headers themselves before this
 * one to bring the types into scope. */
struct mbedtls_ctr_drbg_context;

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct SolidSyslogMbedTlsStreamConfig
    {
        /** Underlying byte stream the TLS records ride on; required - a NULL is
         *  reported at SolidSyslogMbedTlsStream_Create. Borrowed - this stream
         *  may Close it but never
         *  destroys it; the caller owns it and must keep it valid until
         *  SolidSyslogMbedTlsStream_Destroy. */
        struct SolidSyslogStream* Transport;
        /** Where the trust anchors, any pinned peer fingerprints and the mutual-TLS
         *  client credential come from; required - a NULL is reported at
         *  SolidSyslogMbedTlsStream_Create. Asked once per connection, so material
         *  is fetched only for a connection actually being made, and told when the
         *  connection ends. Borrowed - the caller owns it and must keep it valid
         *  until SolidSyslogMbedTlsStream_Destroy. */
        struct SolidSyslogMbedTlsCredentials* Credentials;
        SolidSyslogSleepFunction Sleep; /**< Bridges the WANT_READ/WANT_WRITE polls of the bounded handshake
                                             retry; required - a NULL is reported at
                                             SolidSyslogMbedTlsStream_Create. */
        SolidSyslogTlsHandshakeTimeoutFunction GetHandshakeTimeoutMs; /**< Per-attempt handshake deadline in ms;
                                             NULL uses the SOLIDSYSLOG_TLS_HANDSHAKE_TIMEOUT_MS tunable. */
        void* HandshakeTimeoutContext; /**< Passed back to GetHandshakeTimeoutMs unchanged; NULL is fine. */
        struct mbedtls_ctr_drbg_context* Rng; /**< Seeded CTR-DRBG for the handshake; caller-built and caller-owned.
                                             Required - a NULL is reported at
                                             SolidSyslogMbedTlsStream_Create. */
        /** SNI + peer-identity check. A non-empty name is verified against the peer
         *  cert (SAN/CN). NULL connects chain-only but emits a WARNING - the peer is
         *  unverified (MITM-class). "" is the no-name-check opt-out (closed network /
         *  private CA): the peer must still satisfy whatever the credentials
         *  installed, but the endpoint identity is not checked; no diagnostic. */
        const char* ServerName;
        /** Bumped by the integrator when anything above changes at runtime - the
         *  Credentials or ServerName. The sender polls it every Send and reconnects
         *  on the next pass when it moves, so a rotation applies without calling
         *  SolidSyslogSender_Disconnect. Polled from the servicing thread, so it
         *  must be cheap and pure. NULL means this configuration never changes. */
        SolidSyslogStreamVersionFunction Version;
        void* VersionContext; /**< Passed to Version unchanged; NULL is fine. */
    };

    /** Draw a TLS stream from the pool over the config's Transport (see the file
     *  overview for the handshake and I/O behaviour). A NULL config, a NULL
     *  Transport, a NULL Sleep, a NULL Rng or a NULL Credentials is reported and
     *  falls back to the shared NullStream, as does an exhausted pool. */
    struct SolidSyslogStream* SolidSyslogMbedTlsStream_Create(const struct SolidSyslogMbedTlsStreamConfig* config);
    /** Release the pool slot; closes the TLS session and the underlying transport
     *  if the stream is still open. */
    void SolidSyslogMbedTlsStream_Destroy(struct SolidSyslogStream * base);

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGMBEDTLSSTREAM_H */
