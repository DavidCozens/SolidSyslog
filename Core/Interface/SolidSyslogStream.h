/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  The stream role: connection-oriented byte transport (Open / Send / Read /
 *  Close) for octet-framed delivery. These calls dispatch to the injected
 *  stream's vtable, so behaviour - connect bound, blocking discipline, any TLS
 *  layering - is that stream's. */
#ifndef SOLIDSYSLOGSTREAM_H
#define SOLIDSYSLOGSTREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogExternC.h"

struct SolidSyslogAddress;

SOLIDSYSLOG_EXTERN_C_BEGIN

    /** Signed byte count, the return type of Read. Models POSIX ssize_t using a
     *  standard-C type for portability to targets that lack <sys/types.h>'s
     *  ssize_t (notably MSVC). */
    typedef intptr_t SolidSyslogSsize;

    struct SolidSyslogStream;

    /** Connect to @p addr, bounded (a stream implementation caps the connect,
     *  and any TLS handshake, so the servicing thread cannot hang on an
     *  unresponsive peer). On failure the underlying socket is already closed
     *  internally, so a bare Open retries cleanly.
     *
     *  @retval true  connected and ready for Send / Read.
     *  @retval false not connected; call Open again to retry. */
    bool SolidSyslogStream_Open(struct SolidSyslogStream * stream, const struct SolidSyslogAddress* addr);

    /** Non-blocking, all-or-nothing send of @p buffer[0..size). A short write or
     *  any error (would-block, reset, broken pipe) is treated as a lost
     *  connection: the socket is closed internally and false returned, so the
     *  caller must Open before the next Send or Read. Bounded this way, the
     *  servicing thread's drain rate stays insensitive to a wedged peer or a full
     *  kernel send buffer. @p buffer is read during the call and need not outlive
     *  it. */
    bool SolidSyslogStream_Send(struct SolidSyslogStream * stream, const void* buffer, size_t size);

    /** Non-blocking read of up to @p size bytes into @p buffer. The zero return is
     *  distinct from the negative one: 0 keeps the connection, negative tears it
     *  down.
     *
     *  @retval >0  bytes transferred into @p buffer.
     *  @retval 0   nothing available right now (would-block); connection intact.
     *  @retval <0  EOF or error; the socket is closed internally, so the caller
     *              must Open before the next Send or Read. */
    SolidSyslogSsize SolidSyslogStream_Read(struct SolidSyslogStream * stream, void* buffer, size_t size);

    /** Close the underlying socket. Idempotent, and the stream is reusable:
     *  a later Open reconnects. */
    void SolidSyslogStream_Close(struct SolidSyslogStream * stream);

    /** Returns a monotonic version the integrator bumps when the stream's
     *  configuration changes - the material it presents, the peer it will accept.
     *  A stream implementation polls this to answer SolidSyslogStream_Version, so
     *  it must be cheap and pure. @p context is the paired context field on that
     *  stream's config, passed through unchanged. */
    typedef uint32_t (*SolidSyslogStreamVersionFunction)(void* context);

    /** The stream's current configuration version. The sender polls this every
     *  Send and reconnects when it has moved, so a stream whose configuration
     *  cannot change at runtime reports 0 throughout. */
    uint32_t SolidSyslogStream_Version(struct SolidSyslogStream * stream);

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGSTREAM_H */
