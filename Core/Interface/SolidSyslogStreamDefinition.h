/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

/** @file
 *  The Stream vtable (Open / Send / Read / Close) - the byte-stream (TCP, TLS
 *  over TCP) transport contract an implementor fills in (the Stream extension
 *  point). */
#ifndef SOLIDSYSLOGSTREAMDEFINITION_H
#define SOLIDSYSLOGSTREAMDEFINITION_H

#include <stdbool.h>
#include <stddef.h>

#include "SolidSyslogStream.h"
#include "SolidSyslogExternC.h"

struct SolidSyslogAddress;

SOLIDSYSLOG_EXTERN_C_BEGIN

    /** The contract a byte-stream transport (TCP, TLS over TCP) fills in; the
     *  library drives it from the servicing pass, so it need not be reentrant.
     *  What a caller may expect of each call is documented on the corresponding
     *  SolidSyslogStream_* function in SolidSyslogStream.h; what follows is the
     *  same contract as obligations on the implementer. */
    struct SolidSyslogStream
    {
        /** Bound the connect, and any handshake above it. One servicing pass
         *  drives every sender, so a connect that blocks stalls the whole drain,
         *  not just this stream. Leave nothing open on a failed path: the caller
         *  retries with a bare Open and never calls Close first. */
        bool (*Open)(struct SolidSyslogStream* base, const struct SolidSyslogAddress* addr);
        /** All-or-nothing. Never report a partial write as success - the record
         *  is gone from the caller's hands once you return true. If the whole
         *  buffer cannot go, close internally and return false; the caller
         *  reopens and store-and-forward replays. */
        bool (*Send)(struct SolidSyslogStream* base, const void* buffer, size_t size);
        /** Return 0 when nothing is available, never a negative - the two are
         *  acted on differently, and a would-block reported as an error costs a
         *  reconnect on an idle link. Reserve the negative return for a real
         *  teardown, and close internally before making it. */
        SolidSyslogSsize (*Read)(struct SolidSyslogStream* base, void* buffer, size_t size);
        /** Idempotent, and leaves the instance reusable - a later Open
         *  reconnects it. Called on a stream that is already closed, on one that
         *  never opened, and again from Destroy. */
        void (*Close)(struct SolidSyslogStream* base);
        /** Report a monotonic version of this stream's own configuration - what it
         *  will present or accept on the next Open. Bump it when that changes and
         *  the sender reconnects on its next pass. Polled every Send, so it must be
         *  cheap and pure. A stream with nothing to change reports 0 for its
         *  lifetime. */
        uint32_t (*Version)(struct SolidSyslogStream* base);
    };

SOLIDSYSLOG_EXTERN_C_END

#endif /* SOLIDSYSLOGSTREAMDEFINITION_H */
