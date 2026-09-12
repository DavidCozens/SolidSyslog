/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "lwip/opt.h"

/* This component requires lwIP built with TCP. */
#if LWIP_TCP

#include "SolidSyslogLwipRawTcpStream.h"
#include "SolidSyslogLwipRawTcpStreamPrivate.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogLwipRawAddressPrivate.h"
#include "SolidSyslogLwipRawMarshalPrivate.h"
#include "SolidSyslogLwipRawTcpStreamErrors.h"
#include "SolidSyslogNullStream.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogTunables.h"
#include "lwip/arch.h"
#include "lwip/err.h"
#include "lwip/ip.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/tcpbase.h"

const struct SolidSyslogErrorSource SolidSyslogLwipRawTcpStreamErrorSource = {"LwipRawTcpStream"};

struct SolidSyslogAddress;
struct SolidSyslogStream;

/* Per-operation parameters carried across one marshal hop. Each public op
 * fills only the fields it needs (Close/Abort set just Self); read-back
 * results (ConnectErr / SendResult / ReadResult) are returned in the same
 * struct. One struct per class so the void*-context recovery has a single
 * cast site (LwipRawTcpStreamCallFromContext) - see D.002 in
 * docs/misra-deviations.md. Send/Read fields never overlap in one call. */
struct LwipRawTcpStreamCall
{
    struct SolidSyslogLwipRawTcpStream* Self;
    const struct SolidSyslogLwipRawAddress* Dst;
    const void* SendBuffer;
    void* ReadBuffer;
    size_t Length;
    err_t ConnectErr;
    bool SendResult;
    SolidSyslogSsize ReadResult;
};

static uint32_t LwipRawTcpStream_NullConnectTimeoutGetter(void* context);

static bool LwipRawTcpStream_Open(struct SolidSyslogStream* base, const struct SolidSyslogAddress* addr);
static bool LwipRawTcpStream_Send(struct SolidSyslogStream* base, const void* buffer, size_t size);
static SolidSyslogSsize LwipRawTcpStream_Read(struct SolidSyslogStream* base, void* buffer, size_t size);
static void LwipRawTcpStream_Close(struct SolidSyslogStream* base);
static uint32_t LwipRawTcpStream_Version(struct SolidSyslogStream* base);

static inline struct SolidSyslogLwipRawTcpStream* LwipRawTcpStream_SelfFromBase(struct SolidSyslogStream* base);
static inline struct SolidSyslogLwipRawTcpStream* LwipRawTcpStream_SelfFromArg(void* arg);
static inline struct LwipRawTcpStreamCall* LwipRawTcpStreamCallFromContext(void* context);
static inline bool LwipRawTcpStream_ConfigProvidesGetter(const struct SolidSyslogLwipRawTcpStreamConfig* config);
static inline bool LwipRawTcpStream_IsOpen(const struct SolidSyslogLwipRawTcpStream* self);
static inline bool LwipRawTcpStream_IsWritable(const struct SolidSyslogLwipRawTcpStream* self);
static inline bool LwipRawTcpStream_HasQueuedRx(const struct SolidSyslogLwipRawTcpStream* self);
static inline bool LwipRawTcpStream_RxQueueIsFull(const struct SolidSyslogLwipRawTcpStream* self);
static inline bool LwipRawTcpStream_HasCloseWork(const struct SolidSyslogLwipRawTcpStream* self);
static inline bool LwipRawTcpStream_HasReadWork(const struct SolidSyslogLwipRawTcpStream* self);
static void LwipRawTcpStream_DoOpenAndConnect(void* context);
static void LwipRawTcpStream_DoAbort(void* context);
static void LwipRawTcpStream_DoSend(void* context);
static void LwipRawTcpStream_DoRead(void* context);
static void LwipRawTcpStream_DoClose(void* context);
static struct tcp_pcb* LwipRawTcpStream_OpenAndConfigurePcb(struct SolidSyslogLwipRawTcpStream* self);
static bool LwipRawTcpStream_WaitForConnectedCallback(struct SolidSyslogLwipRawTcpStream* self);
static uint32_t LwipRawTcpStream_ResolveConnectTimeoutMs(struct SolidSyslogLwipRawTcpStream* self);
static bool LwipRawTcpStream_SendOrCloseOnFailure(
    struct SolidSyslogLwipRawTcpStream* self,
    const void* buffer,
    size_t size
);
static bool LwipRawTcpStream_OutputResultIsAcceptable(err_t outputErr);
static size_t LwipRawTcpStream_DrainHeadBytes(struct SolidSyslogLwipRawTcpStream* self, void* buffer, size_t size);
static void LwipRawTcpStream_EnqueueRxPbuf(struct SolidSyslogLwipRawTcpStream* self, struct pbuf* p);
static void LwipRawTcpStream_DrainAllQueuedPbufs(struct SolidSyslogLwipRawTcpStream* self);
static void LwipRawTcpStream_ClosePcb(struct SolidSyslogLwipRawTcpStream* self);
static void LwipRawTcpStream_DetachPcb(struct tcp_pcb* pcb);

static err_t LwipRawTcpStream_ConnectedCallback(void* arg, struct tcp_pcb* pcb, err_t err);
static err_t LwipRawTcpStream_RecvCallback(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err);
static err_t LwipRawTcpStream_SentCallback(void* arg, struct tcp_pcb* tpcb, u16_t len);
static void LwipRawTcpStream_ErrCallback(void* arg, err_t err);

void SolidSyslogLwipRawTcpStream_Initialise(
    struct SolidSyslogStream* base,
    const struct SolidSyslogLwipRawTcpStreamConfig* config
)
{
    static const struct SolidSyslogLwipRawTcpStream DefaultLwipRawTcpStream = {
        .Base =
            {.Open = LwipRawTcpStream_Open,
             .Send = LwipRawTcpStream_Send,
             .Read = LwipRawTcpStream_Read,
             .Close = LwipRawTcpStream_Close,
             .Version = LwipRawTcpStream_Version},
        .Config =
            {.GetConnectTimeoutMs = LwipRawTcpStream_NullConnectTimeoutGetter,
             .ConnectTimeoutContext = NULL,
             .Sleep = NULL},
        .Pcb = NULL,
        .Connected = false,
        .Errored = false,
        .RxQueue = {0},
        .RxQueueHead = 0,
        .RxQueueCount = 0,
        .RxHeadOffset = 0,
    };

    struct SolidSyslogLwipRawTcpStream* self = LwipRawTcpStream_SelfFromBase(base);
    *self = DefaultLwipRawTcpStream;
    self->Config.Sleep = config->Sleep;
    self->Config.ConnectTimeoutContext = config->ConnectTimeoutContext;
    if (LwipRawTcpStream_ConfigProvidesGetter(config))
    {
        self->Config.GetConnectTimeoutMs = config->GetConnectTimeoutMs;
    }
}

static inline bool LwipRawTcpStream_ConfigProvidesGetter(const struct SolidSyslogLwipRawTcpStreamConfig* config)
{
    return config->GetConnectTimeoutMs != NULL;
}

/* Null Object substituted when the integrator does not install a getter -
 * returns the compile-time tunable so the bounded-wait path has a single
 * code path regardless of whether the integrator wired runtime tuning. */
static uint32_t LwipRawTcpStream_NullConnectTimeoutGetter(void* context)
{
    (void) context;
    return (uint32_t) SOLIDSYSLOG_TCP_CONNECT_TIMEOUT_MS;
}

static inline struct SolidSyslogLwipRawTcpStream* LwipRawTcpStream_SelfFromBase(struct SolidSyslogStream* base)
{
    return (struct SolidSyslogLwipRawTcpStream*) base;
}

/* Recovers our self pointer from the void* argument lwIP passes back into
 * every callback we registered via tcp_arg(pcb, self). Single named helper
 * so the void->struct cast lives in one place - and MISRA 11.5 has one
 * suppression site, not one per callback. */
static inline struct SolidSyslogLwipRawTcpStream* LwipRawTcpStream_SelfFromArg(void* arg)
{
    return (struct SolidSyslogLwipRawTcpStream*) arg;
}

/* Recovers the per-op call struct from the void* context the marshal passes
 * back into each Do* callback - the marshal-seam analogue of SelfFromArg,
 * one cast site for all marshalled ops (see D.002). */
static inline struct LwipRawTcpStreamCall* LwipRawTcpStreamCallFromContext(void* context)
{
    return (struct LwipRawTcpStreamCall*) context;
}

void SolidSyslogLwipRawTcpStream_Cleanup(struct SolidSyslogStream* base)
{
    LwipRawTcpStream_Close(base);
    /* Overwrite the abstract base with the shared NullStream vtable so
     * use-after-destroy is a safe no-op rather than a NULL-fn-pointer crash. */
    *base = *SolidSyslogNullStream_Get();
}

static bool LwipRawTcpStream_Open(struct SolidSyslogStream* base, const struct SolidSyslogAddress* addr)
{
    struct SolidSyslogLwipRawTcpStream* self = LwipRawTcpStream_SelfFromBase(base);
    if (!LwipRawTcpStream_IsOpen(self))
    {
        struct LwipRawTcpStreamCall call = {.Self = self, .Dst = SolidSyslogLwipRawAddress_AsConst(addr)};
        SolidSyslogLwipRaw_Marshal(LwipRawTcpStream_DoOpenAndConnect, &call);
        if (LwipRawTcpStream_IsOpen(self))
        {
            bool connected = false;
            if (call.ConnectErr == ERR_OK)
            {
                connected = LwipRawTcpStream_WaitForConnectedCallback(self);
            }
            if (!connected)
            {
                SolidSyslogLwipRaw_Marshal(LwipRawTcpStream_DoAbort, &call);
            }
        }
    }
    return LwipRawTcpStream_IsOpen(self);
}

/* The setup-and-connect hop: tcp_new + pcb configuration + tcp_connect all
 * run on the lwIP-owning thread in one marshalled batch. The connected_cb
 * may fire here (synchronously, on the same thread) - it only flips volatile
 * flags. The bounded spin that waits for those flags stays on the caller's
 * thread (sleeping the lwIP thread mid-connect would starve RX/timers). */
static void LwipRawTcpStream_DoOpenAndConnect(void* context)
{
    struct LwipRawTcpStreamCall* call = LwipRawTcpStreamCallFromContext(context);
    struct SolidSyslogLwipRawTcpStream* self = call->Self;
    self->Pcb = LwipRawTcpStream_OpenAndConfigurePcb(self);
    if (LwipRawTcpStream_IsOpen(self))
    {
        self->Connected = false;
        self->Errored = false;
        call->ConnectErr = tcp_connect(self->Pcb, &call->Dst->Ip, call->Dst->Port, LwipRawTcpStream_ConnectedCallback);
    }
}

static inline bool LwipRawTcpStream_IsOpen(const struct SolidSyslogLwipRawTcpStream* self)
{
    return self->Pcb != NULL;
}

static inline bool LwipRawTcpStream_HasQueuedRx(const struct SolidSyslogLwipRawTcpStream* self)
{
    return self->RxQueueCount > 0U;
}

static inline bool LwipRawTcpStream_RxQueueIsFull(const struct SolidSyslogLwipRawTcpStream* self)
{
    return self->RxQueueCount >= SOLIDSYSLOG_LWIP_RAW_TCP_RX_QUEUE_SIZE;
}

static struct tcp_pcb* LwipRawTcpStream_OpenAndConfigurePcb(struct SolidSyslogLwipRawTcpStream* self)
{
    struct tcp_pcb* pcb = tcp_new();
    if (pcb != NULL)
    {
        ip_set_option(pcb, SOF_KEEPALIVE);
        /* Disable Nagle. The syslog client writes small, latency-sensitive
         * records (octet-framed messages, and - when an upper TLS layer is
         * stacked on this stream - multi-segment handshake flights) and never
         * pipelines a second write behind an unacked one. With Nagle on, lwIP
         * holds a sub-MSS segment until the previous one is ACKed; a TLS
         * handshake flight (e.g. a client certificate) then stalls mid-exchange
         * waiting for an ACK that the peer only sends after it has the whole
         * flight - a deadlock observed against syslog-ng over mutual TLS.
         * TCP_NODELAY is the right default for this request/response workload. */
        tcp_nagle_disable(pcb);
        tcp_arg(pcb, self);
        tcp_recv(pcb, LwipRawTcpStream_RecvCallback);
        tcp_sent(pcb, LwipRawTcpStream_SentCallback);
        tcp_err(pcb, LwipRawTcpStream_ErrCallback);
    }
    return pcb;
}

/* Bounded synchronous-Open spin: each iteration sleeps via the
 * integrator-injected Sleep so lwIP's timer / RX paths get cycles to
 * advance the SYN/SYN-ACK exchange. Runs on the caller's thread - never the
 * lwIP thread. Exits on Connected (success), Errored (set by connected_cb
 * on non-ERR_OK or by tcp_err), or elapsed >= deadline (timeout). */
static bool LwipRawTcpStream_WaitForConnectedCallback(struct SolidSyslogLwipRawTcpStream* self)
{
    const uint32_t pollMs = (uint32_t) SOLIDSYSLOG_LWIP_RAW_TCP_CONNECT_POLL_MS;
    const uint32_t deadlineMs = LwipRawTcpStream_ResolveConnectTimeoutMs(self);
    uint32_t elapsedMs = 0;
    while (!self->Connected && !self->Errored && (elapsedMs < deadlineMs))
    {
        self->Config.Sleep((int) pollMs);
        elapsedMs += pollMs;
    }
    return self->Connected;
}

/* Bridges the integrator-installed getter (or the Null Object substituted
 * in Initialise) to the bounded spin deadline. Invoked on every connect
 * attempt so a runtime-tunable value takes effect on the next reconnect. */
static uint32_t LwipRawTcpStream_ResolveConnectTimeoutMs(struct SolidSyslogLwipRawTcpStream* self)
{
    return self->Config.GetConnectTimeoutMs(self->Config.ConnectTimeoutContext);
}

/* Connect failed or timed out - release the pcb cleanly on the lwIP thread.
 * tcp_abort (not tcp_close) because a half-open pcb has no graceful close. */
static void LwipRawTcpStream_DoAbort(void* context)
{
    struct SolidSyslogLwipRawTcpStream* self = LwipRawTcpStreamCallFromContext(context)->Self;
    tcp_abort(self->Pcb);
    self->Pcb = NULL;
}

static bool LwipRawTcpStream_Send(struct SolidSyslogStream* base, const void* buffer, size_t size)
{
    struct SolidSyslogLwipRawTcpStream* self = LwipRawTcpStream_SelfFromBase(base);
    bool sent = false;
    if (LwipRawTcpStream_IsWritable(self))
    {
        struct LwipRawTcpStreamCall call = {.Self = self, .SendBuffer = buffer, .Length = size};
        SolidSyslogLwipRaw_Marshal(LwipRawTcpStream_DoSend, &call);
        sent = call.SendResult;
    }
    return sent;
}

/* Sendable means the pcb is live AND no peer close / error has been observed.
 * A peer FIN (RecvCallback with NULL p) sets Errored but leaves the pcb non-NULL,
 * so IsOpen alone would keep writing into a doomed connection; failing the send
 * lets StreamSender close and reconnect. Read deliberately still runs while
 * Errored - it must drain queued bytes and then close on EOF. */
static inline bool LwipRawTcpStream_IsWritable(const struct SolidSyslogLwipRawTcpStream* self)
{
    return LwipRawTcpStream_IsOpen(self) && !self->Errored;
}

static void LwipRawTcpStream_DoSend(void* context)
{
    struct LwipRawTcpStreamCall* call = LwipRawTcpStreamCallFromContext(context);
    call->SendResult = LwipRawTcpStream_SendOrCloseOnFailure(call->Self, call->SendBuffer, call->Length);
}

static bool LwipRawTcpStream_SendOrCloseOnFailure(
    struct SolidSyslogLwipRawTcpStream* self,
    const void* buffer,
    size_t size
)
{
    /* TCP_WRITE_FLAG_COPY hands the caller's buffer to lwIP-owned pbufs
     * before tcp_write returns - caller buffer lifetime ends here.
     * tcp_output nudges transmission; ERR_MEM there is "queued, lwIP
     * retries" so we still report success (lwIP owns the bytes). */
    err_t writeErr = tcp_write(self->Pcb, buffer, (u16_t) size, TCP_WRITE_FLAG_COPY);
    bool ok = (writeErr == ERR_OK);
    if (ok)
    {
        err_t outputErr = tcp_output(self->Pcb);
        ok = LwipRawTcpStream_OutputResultIsAcceptable(outputErr);
    }
    if (!ok)
    {
        LwipRawTcpStream_ClosePcb(self);
    }
    return ok;
}

static bool LwipRawTcpStream_OutputResultIsAcceptable(err_t outputErr)
{
    return (outputErr == ERR_OK) || (outputErr == ERR_MEM);
}

static SolidSyslogSsize LwipRawTcpStream_Read(struct SolidSyslogStream* base, void* buffer, size_t size)
{
    /* SolidSyslogStream_Read returns < 0 to signal EOF/error (socket closed
     * internally); -1 is the in-tree convention across the Stream adapters. */
    static const SolidSyslogSsize READ_FAILED = -1;

    struct SolidSyslogLwipRawTcpStream* self = LwipRawTcpStream_SelfFromBase(base);
    SolidSyslogSsize result = READ_FAILED;
    if (LwipRawTcpStream_IsOpen(self))
    {
        if (LwipRawTcpStream_HasReadWork(self))
        {
            struct LwipRawTcpStreamCall call = {
                .Self = self,
                .ReadBuffer = buffer,
                .Length = size,
                .ReadResult = READ_FAILED,
            };
            SolidSyslogLwipRaw_Marshal(LwipRawTcpStream_DoRead, &call);
            result = call.ReadResult;
        }
        else
        {
            result = 0; /* would-block */
        }
    }
    return result;
}

/* Read touches lwIP only when there is queued data to drain/ack or a drained
 * peer-FIN to close on. The pure would-block case (open, empty queue, not
 * errored) does no lwIP work, so it takes no marshal hop. */
static inline bool LwipRawTcpStream_HasReadWork(const struct SolidSyslogLwipRawTcpStream* self)
{
    return LwipRawTcpStream_HasQueuedRx(self) || self->Errored;
}

static void LwipRawTcpStream_DoRead(void* context)
{
    struct LwipRawTcpStreamCall* call = LwipRawTcpStreamCallFromContext(context);
    struct SolidSyslogLwipRawTcpStream* self = call->Self;
    if (LwipRawTcpStream_HasQueuedRx(self))
    {
        size_t copied = LwipRawTcpStream_DrainHeadBytes(self, call->ReadBuffer, call->Length);
        tcp_recved(self->Pcb, (u16_t) copied);
        call->ReadResult = (SolidSyslogSsize) copied;
    }
    else
    {
        /* Peer FIN drained -> close internally per the Stream contract
         * ("< 0 means EOF AND socket closed internally"); ReadResult stays
         * READ_FAILED. */
        LwipRawTcpStream_ClosePcb(self);
    }
}

/* Copies up to `size` bytes out of the head pbuf chain, advancing the read
 * cursor. The cursor (RxHeadOffset) and the fully-drained test are keyed off
 * tot_len, not the first link's len - lwIP hands us a pbuf chain whenever a
 * segment spans more than one pool pbuf, and pbuf_copy_partial walks head->next
 * for us so the tail links are not lost. The cursor advances by the count
 * pbuf_copy_partial actually copied, not the requested amount: under lwIP's
 * tot_len == sum of link->len invariant the two are equal, but keying off the real
 * copy keeps a malformed/overstated tot_len from advancing past un-copied
 * bytes and reporting stale buffer content as received. When the whole chain
 * is drained, pbuf_free's it (frees every link) and advances the queue head -
 * tail entries shift up through the bounded ring via modular arithmetic, no
 * compaction. */
static size_t LwipRawTcpStream_DrainHeadBytes(struct SolidSyslogLwipRawTcpStream* self, void* buffer, size_t size)
{
    struct pbuf* head = self->RxQueue[self->RxQueueHead];
    size_t available = (size_t) head->tot_len - self->RxHeadOffset;
    size_t toCopy = (size < available) ? size : available;
    size_t copied = (size_t) pbuf_copy_partial(head, buffer, (u16_t) toCopy, (u16_t) self->RxHeadOffset);
    self->RxHeadOffset += copied;
    if (self->RxHeadOffset >= (size_t) head->tot_len)
    {
        (void) pbuf_free(head);
        self->RxQueueHead = (self->RxQueueHead + 1U) % SOLIDSYSLOG_LWIP_RAW_TCP_RX_QUEUE_SIZE;
        self->RxQueueCount--;
        self->RxHeadOffset = 0;
    }
    return copied;
}

static void LwipRawTcpStream_EnqueueRxPbuf(struct SolidSyslogLwipRawTcpStream* self, struct pbuf* p)
{
    size_t tail = (self->RxQueueHead + self->RxQueueCount) % SOLIDSYSLOG_LWIP_RAW_TCP_RX_QUEUE_SIZE;
    self->RxQueue[tail] = p;
    self->RxQueueCount++;
}

/* Drains every queued pbuf via pbuf_free. Used by ClosePcb so an explicit
 * Close, Send-failure-induced Close, or Destroy never leaks the pbufs lwIP
 * handed us via tcp_recv. After tcp_err nulls Pcb the queue may still hold
 * pbufs we accepted before the error - those need freeing too. */
static void LwipRawTcpStream_DrainAllQueuedPbufs(struct SolidSyslogLwipRawTcpStream* self)
{
    while (LwipRawTcpStream_HasQueuedRx(self))
    {
        (void) pbuf_free(self->RxQueue[self->RxQueueHead]);
        self->RxQueueHead = (self->RxQueueHead + 1U) % SOLIDSYSLOG_LWIP_RAW_TCP_RX_QUEUE_SIZE;
        self->RxQueueCount--;
    }
    self->RxHeadOffset = 0;
}

static void LwipRawTcpStream_Close(struct SolidSyslogStream* base)
{
    struct SolidSyslogLwipRawTcpStream* self = LwipRawTcpStream_SelfFromBase(base);
    if (LwipRawTcpStream_HasCloseWork(self))
    {
        struct LwipRawTcpStreamCall call = {.Self = self};
        SolidSyslogLwipRaw_Marshal(LwipRawTcpStream_DoClose, &call);
    }
}

static uint32_t LwipRawTcpStream_Version(struct SolidSyslogStream* base)
{
    (void) base;
    return 0U;
}

/* Close touches lwIP only if there is a pcb to close or queued pbufs to
 * free. Close-before-open and close-after-tcp_err (Pcb already nulled, queue
 * empty) do no lwIP work and take no marshal hop. */
static inline bool LwipRawTcpStream_HasCloseWork(const struct SolidSyslogLwipRawTcpStream* self)
{
    return LwipRawTcpStream_IsOpen(self) || LwipRawTcpStream_HasQueuedRx(self);
}

static void LwipRawTcpStream_DoClose(void* context)
{
    LwipRawTcpStream_ClosePcb(LwipRawTcpStreamCallFromContext(context)->Self);
}

/* tcp_close must NOT be called on a pcb that has already been released by
 * tcp_err - that's a use-after-free in lwIP. The Pcb != NULL guard works
 * because LwipRawTcpStream_ErrCallback nulls Pcb when lwIP releases the
 * pcb on its side. The queue drain runs unconditionally - pbufs we
 * accepted via tcp_recv are ours to free regardless of pcb state. Always
 * called from inside a marshalled hop (DoSend / DoRead / DoClose). */
static void LwipRawTcpStream_ClosePcb(struct SolidSyslogLwipRawTcpStream* self)
{
    LwipRawTcpStream_DrainAllQueuedPbufs(self);
    if (LwipRawTcpStream_IsOpen(self))
    {
        struct tcp_pcb* pcb = self->Pcb;
        self->Pcb = NULL;
        LwipRawTcpStream_DetachPcb(pcb);
        if (tcp_close(pcb) != ERR_OK)
        {
            /* Close could not be queued (ERR_MEM). Abort frees the pcb now -
               leaving it would strand it, since nothing holds it any more. */
            tcp_abort(pcb);
        }
    }
}

/* lwIP keeps a closed pcb until its close completes, and while it lives it
   calls whatever tcp_arg holds - which, on a stream that has since reconnected,
   is the state of a different connection. Detaching before the close is what
   makes that impossible: the pcb we are finished with holds no way back to us. */
static void LwipRawTcpStream_DetachPcb(struct tcp_pcb* pcb)
{
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_err(pcb, NULL);
}

static err_t LwipRawTcpStream_ConnectedCallback(void* arg, struct tcp_pcb* pcb, err_t err)
{
    (void) pcb;
    struct SolidSyslogLwipRawTcpStream* self = LwipRawTcpStream_SelfFromArg(arg);
    if (err == ERR_OK)
    {
        self->Connected = true;
    }
    else
    {
        self->Errored = true;
    }
    return ERR_OK;
}

/* tcp_recv fires when lwIP has bytes for us - non-NULL p means a pbuf
 * arrived; NULL p means peer half-closed (FIN). Backpressure on a full
 * queue by returning non-ERR_OK; lwIP holds the pbuf and replays the
 * callback when the queue drains. Runs on the lwIP thread (lwIP invokes it
 * directly), touches no lwIP API, so it needs no marshalling. */
static err_t LwipRawTcpStream_RecvCallback(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err)
{
    (void) tpcb;
    (void) err;
    struct SolidSyslogLwipRawTcpStream* self = LwipRawTcpStream_SelfFromArg(arg);
    err_t result = ERR_OK;
    if (p == NULL)
    {
        self->Errored = true;
    }
    else if (LwipRawTcpStream_RxQueueIsFull(self))
    {
        result = ERR_MEM;
    }
    else
    {
        LwipRawTcpStream_EnqueueRxPbuf(self, p);
    }
    return result;
}

/* Real tcp_sent handling is unused under TCP_WRITE_FLAG_COPY - caller
 * buffers are released at Send return, not at peer-ACK time. The slot
 * exists because lwIP requires the callback set when the pcb is wired. */
static err_t LwipRawTcpStream_SentCallback(void* arg, struct tcp_pcb* tpcb, u16_t len)
{
    (void) arg;
    (void) tpcb;
    (void) len;
    return ERR_OK;
}

/* lwIP fires tcp_err for fatal events (RST, OOM, ABRT) AFTER releasing the
 * pcb upstream - we must null our Pcb pointer and NOT call tcp_close.
 * Subsequent Stream_Close sees Pcb == NULL and is a safe no-op. Runs on the
 * lwIP thread, touches no lwIP API. */
static void LwipRawTcpStream_ErrCallback(void* arg, err_t err)
{
    (void) err;
    struct SolidSyslogLwipRawTcpStream* self = LwipRawTcpStream_SelfFromArg(arg);
    self->Pcb = NULL;
    self->Errored = true;
}

#else

/* ISO C forbids an empty translation unit. */
typedef int LwipRawTcpStream_EmptyTranslationUnit;

#endif /* LWIP_TCP */
