/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "FreeRTOS_IP.h"

/* This component requires FreeRTOS-Plus-TCP built with TCP. */
#if (ipconfigUSE_TCP == 1)

// NOLINTBEGIN(performance-no-int-to-ptr) -- FREERTOS_INVALID_SOCKET is ((Socket_t)~0U) from FreeRTOS-Plus-TCP; the int-to-ptr cast is intrinsic to the upstream
// sentinel and unavoidable.

#include "SolidSyslogPlusTcpTcpStream.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "FreeRTOS.h"
#include "FreeRTOS_ARP.h"
#include "FreeRTOS_Sockets.h"
#include "SolidSyslogError.h"
#include "SolidSyslogNullStream.h"
#include "SolidSyslogPlusTcpAddressPrivate.h"
#include "SolidSyslogPlusTcpTcpStreamErrors.h"
#include "SolidSyslogPlusTcpTcpStreamPrivate.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogTunables.h"
#include "task.h"

const struct SolidSyslogErrorSource SolidSyslogPlusTcpTcpStreamErrorSource = {"PlusTcpTcpStream"};

struct SolidSyslogAddress;

/* SolidSyslogStream_Read returns < 0 to signal EOF/error (socket closed
 * internally); -1 is the in-tree convention across the Stream adapters. */
static const SolidSyslogSsize READ_FAILED = -1;

enum
{
    /* FreeRTOS-Plus-TCP's setsockopt ignores the level argument (no
     * SOL_SOCKET vs IPPROTO_TCP split; option codes are flat); pass 0 by
     * convention. */
    SETSOCKOPT_LEVEL_DEFAULT = 0,
    /* No MSG_PEEK / MSG_DONTWAIT / zero-copy - the timeouts cleared after
     * connect already give us the non-blocking single-call behaviour
     * SolidSyslogStream requires. */
    SEND_RECV_FLAGS_DEFAULT = 0
};

static uint32_t PlusTcpTcpStream_NullConnectTimeoutGetter(void* context);

static bool PlusTcpTcpStream_Open(struct SolidSyslogStream* base, const struct SolidSyslogAddress* addr);
static bool PlusTcpTcpStream_Send(struct SolidSyslogStream* base, const void* buffer, size_t size);
static SolidSyslogSsize PlusTcpTcpStream_Read(struct SolidSyslogStream* base, void* buffer, size_t size);
static void PlusTcpTcpStream_Close(struct SolidSyslogStream* base);
static uint32_t PlusTcpTcpStream_Version(struct SolidSyslogStream* base);

static inline struct SolidSyslogPlusTcpTcpStream* PlusTcpTcpStream_SelfFromBase(struct SolidSyslogStream* base);
static inline bool PlusTcpTcpStream_ConfigProvidesGetter(const struct SolidSyslogPlusTcpTcpStreamConfig* config);
static inline bool PlusTcpTcpStream_IsOpen(const struct SolidSyslogPlusTcpTcpStream* self);
static inline bool PlusTcpTcpStream_IsClosed(const struct SolidSyslogPlusTcpTcpStream* self);
static void PlusTcpTcpStream_OpenSocket(struct SolidSyslogPlusTcpTcpStream* self);
static void PlusTcpTcpStream_ConnectOrCloseOnFailure(
    struct SolidSyslogPlusTcpTcpStream* self,
    const struct SolidSyslogAddress* addr
);
static bool PlusTcpTcpStream_TryConnect(
    struct SolidSyslogPlusTcpTcpStream* self,
    const struct SolidSyslogAddress* addr
);
static inline void PlusTcpTcpStream_PrimeArpIfMissing(uint32_t ip);
static void PlusTcpTcpStream_ClearTimeouts(Socket_t socket);
static void PlusTcpTcpStream_SetSendTimeout(Socket_t socket, TickType_t ticks);
static void PlusTcpTcpStream_SetRecvTimeout(Socket_t socket, TickType_t ticks);
static uint32_t PlusTcpTcpStream_ResolveConnectTimeoutMs(struct SolidSyslogPlusTcpTcpStream* self);
static bool PlusTcpTcpStream_SendOrCloseOnFailure(
    struct SolidSyslogPlusTcpTcpStream* self,
    const void* buffer,
    size_t size
);
static bool PlusTcpTcpStream_TrySend(struct SolidSyslogPlusTcpTcpStream* self, const void* buffer, size_t size);
static bool PlusTcpTcpStream_AllBytesSent(BaseType_t sentCount, size_t expected);
static SolidSyslogSsize PlusTcpTcpStream_ReceiveOrCloseOnFailure(
    struct SolidSyslogPlusTcpTcpStream* self,
    void* buffer,
    size_t size
);
static void PlusTcpTcpStream_CloseSocket(struct SolidSyslogPlusTcpTcpStream* self);

void SolidSyslogPlusTcpTcpStream_Initialise(
    struct SolidSyslogStream* base,
    const struct SolidSyslogPlusTcpTcpStreamConfig* config
)
{
    static const struct SolidSyslogPlusTcpTcpStream DefaultPlusTcpTcpStream = {
        .Base =
            {.Open = PlusTcpTcpStream_Open,
             .Send = PlusTcpTcpStream_Send,
             .Read = PlusTcpTcpStream_Read,
             .Close = PlusTcpTcpStream_Close,
             .Version = PlusTcpTcpStream_Version},
        .Config = {.GetConnectTimeoutMs = PlusTcpTcpStream_NullConnectTimeoutGetter, .ConnectTimeoutContext = NULL},
        .Socket = FREERTOS_INVALID_SOCKET,
    };

    struct SolidSyslogPlusTcpTcpStream* self = PlusTcpTcpStream_SelfFromBase(base);
    *self = DefaultPlusTcpTcpStream;
    if (PlusTcpTcpStream_ConfigProvidesGetter(config) == true)
    {
        self->Config = *config;
    }
}

static inline bool PlusTcpTcpStream_ConfigProvidesGetter(const struct SolidSyslogPlusTcpTcpStreamConfig* config)
{
    return (config != NULL) && (config->GetConnectTimeoutMs != NULL);
}

/* Null Object substituted when the integrator does not install a getter -
 * returns the compile-time tunable so the bounded-wait path has a single
 * code path regardless of whether the integrator wired runtime tuning. */
static uint32_t PlusTcpTcpStream_NullConnectTimeoutGetter(void* context)
{
    (void) context;
    return (uint32_t) SOLIDSYSLOG_TCP_CONNECT_TIMEOUT_MS;
}

static inline struct SolidSyslogPlusTcpTcpStream* PlusTcpTcpStream_SelfFromBase(struct SolidSyslogStream* base)
{
    return (struct SolidSyslogPlusTcpTcpStream*) base;
}

void SolidSyslogPlusTcpTcpStream_Cleanup(struct SolidSyslogStream* base)
{
    struct SolidSyslogPlusTcpTcpStream* self = PlusTcpTcpStream_SelfFromBase(base);
    PlusTcpTcpStream_CloseSocket(self);
    /* Overwrite the abstract base with the shared NullStream vtable so
     * use-after-destroy is a safe no-op rather than a NULL-fn-pointer crash. */
    *base = *SolidSyslogNullStream_Get();
}

static void PlusTcpTcpStream_CloseSocket(struct SolidSyslogPlusTcpTcpStream* self)
{
    if (PlusTcpTcpStream_IsOpen(self))
    {
        (void) FreeRTOS_closesocket(self->Socket);
        self->Socket = FREERTOS_INVALID_SOCKET;
    }
}

static bool PlusTcpTcpStream_Open(struct SolidSyslogStream* base, const struct SolidSyslogAddress* addr)
{
    struct SolidSyslogPlusTcpTcpStream* self = PlusTcpTcpStream_SelfFromBase(base);
    if (PlusTcpTcpStream_IsClosed(self))
    {
        PlusTcpTcpStream_OpenSocket(self);
        if (PlusTcpTcpStream_IsOpen(self))
        {
            PlusTcpTcpStream_ConnectOrCloseOnFailure(self, addr);
        }
    }
    return PlusTcpTcpStream_IsOpen(self);
}

static inline bool PlusTcpTcpStream_IsOpen(const struct SolidSyslogPlusTcpTcpStream* self)
{
    return self->Socket != FREERTOS_INVALID_SOCKET;
}

static inline bool PlusTcpTcpStream_IsClosed(const struct SolidSyslogPlusTcpTcpStream* self)
{
    return !PlusTcpTcpStream_IsOpen(self);
}

static void PlusTcpTcpStream_OpenSocket(struct SolidSyslogPlusTcpTcpStream* self)
{
    self->Socket = FreeRTOS_socket(FREERTOS_AF_INET, FREERTOS_SOCK_STREAM, FREERTOS_IPPROTO_TCP);
}

static void PlusTcpTcpStream_ConnectOrCloseOnFailure(
    struct SolidSyslogPlusTcpTcpStream* self,
    const struct SolidSyslogAddress* addr
)
{
    if (PlusTcpTcpStream_TryConnect(self, addr))
    {
        PlusTcpTcpStream_ClearTimeouts(self->Socket);
    }
    else
    {
        PlusTcpTcpStream_CloseSocket(self);
    }
}

static bool PlusTcpTcpStream_TryConnect(struct SolidSyslogPlusTcpTcpStream* self, const struct SolidSyslogAddress* addr)
{
    /* Both SO_SNDTIMEO and SO_RCVTIMEO are set before FreeRTOS_connect -
     * upstream gates connect on SO_RCVTIMEO, but we set both as belt-and-
     * braces against an upstream change. After connect both timeouts go
     * back to 0 so subsequent Send/Read follow the non-blocking single-
     * call contract from SolidSyslogStream. The default
     * SOLIDSYSLOG_TCP_CONNECT_TIMEOUT_MS = 200 is short enough that the
     * Service task keeps draining predictably during an outage, long
     * enough for a healthy peer to ACK over slirp/LAN. */
    const TickType_t connectTimeoutTicks = pdMS_TO_TICKS(PlusTcpTcpStream_ResolveConnectTimeoutMs(self));

    const struct freertos_sockaddr* dest = SolidSyslogPlusTcpAddress_AsConstFreertosSockaddr(addr);
    PlusTcpTcpStream_PrimeArpIfMissing(dest->sin_address.ulIP_IPv4);
    PlusTcpTcpStream_SetSendTimeout(self->Socket, connectTimeoutTicks);
    PlusTcpTcpStream_SetRecvTimeout(self->Socket, connectTimeoutTicks);
    return FreeRTOS_connect(self->Socket, dest, sizeof(*dest)) == 0;
}

/* Bridges the integrator-installed getter (or the Null Object substituted in
 * Initialise) to the bounded SO_*TIMEO deadline. Invoked on every connect
 * attempt so a runtime-tunable value takes effect on the next reconnect. */
static uint32_t PlusTcpTcpStream_ResolveConnectTimeoutMs(struct SolidSyslogPlusTcpTcpStream* self)
{
    return self->Config.GetConnectTimeoutMs(self->Config.ConnectTimeoutContext);
}

/* On ARP cache miss issue a probe and yield once for the reply to land
 * before FreeRTOS_connect runs. Without this, the cold-start SYN is dropped
 * at the IP layer (FreeRTOS-Plus-TCP does not queue while ARP resolves) and
 * the bounded 200 ms connect timeout expires before the SYN-and-resend
 * cycle completes. Symmetric with PlusTcpDatagram_SendTo. */
static inline void PlusTcpTcpStream_PrimeArpIfMissing(uint32_t ip)
{
    /* Yield window for the IP task to receive an ARP reply and populate
     * the cache before we attempt FreeRTOS_connect. Mirrors the
     * established SolidSyslogPlusTcpDatagram pattern (see
     * [[freertos-arp-first-packet]]) - without this, a cold-start TCP
     * connect fires SYN before ARP resolves, the SYN is dropped at the
     * IP layer, and the bounded 200 ms RCV-timeout connect expires
     * before the retransmit ARP-and-resend cycle completes. */
    static const TickType_t ARP_RESOLUTION_WAIT_TICKS = pdMS_TO_TICKS(50);

    if (xIsIPInARPCache(ip) == pdFALSE)
    {
        FreeRTOS_OutputARPRequest(ip);
        vTaskDelay(ARP_RESOLUTION_WAIT_TICKS);
    }
}

static void PlusTcpTcpStream_ClearTimeouts(Socket_t socket)
{
    static const TickType_t NO_TIMEOUT_TICKS = 0;

    PlusTcpTcpStream_SetSendTimeout(socket, NO_TIMEOUT_TICKS);
    PlusTcpTcpStream_SetRecvTimeout(socket, NO_TIMEOUT_TICKS);
}

static void PlusTcpTcpStream_SetSendTimeout(Socket_t socket, TickType_t ticks)
{
    (void) FreeRTOS_setsockopt(socket, SETSOCKOPT_LEVEL_DEFAULT, FREERTOS_SO_SNDTIMEO, &ticks, sizeof(ticks));
}

static void PlusTcpTcpStream_SetRecvTimeout(Socket_t socket, TickType_t ticks)
{
    (void) FreeRTOS_setsockopt(socket, SETSOCKOPT_LEVEL_DEFAULT, FREERTOS_SO_RCVTIMEO, &ticks, sizeof(ticks));
}

static bool PlusTcpTcpStream_Send(struct SolidSyslogStream* base, const void* buffer, size_t size)
{
    struct SolidSyslogPlusTcpTcpStream* self = PlusTcpTcpStream_SelfFromBase(base);
    bool sent = false;
    if (PlusTcpTcpStream_IsOpen(self))
    {
        sent = PlusTcpTcpStream_SendOrCloseOnFailure(self, buffer, size);
    }
    return sent;
}

static bool PlusTcpTcpStream_SendOrCloseOnFailure(
    struct SolidSyslogPlusTcpTcpStream* self,
    const void* buffer,
    size_t size
)
{
    bool sent = PlusTcpTcpStream_TrySend(self, buffer, size);
    if (!sent)
    {
        PlusTcpTcpStream_CloseSocket(self);
    }
    return sent;
}

static bool PlusTcpTcpStream_TrySend(struct SolidSyslogPlusTcpTcpStream* self, const void* buffer, size_t size)
{
    BaseType_t sentCount = FreeRTOS_send(self->Socket, buffer, size, SEND_RECV_FLAGS_DEFAULT);
    return PlusTcpTcpStream_AllBytesSent(sentCount, size);
}

static bool PlusTcpTcpStream_AllBytesSent(BaseType_t sentCount, size_t expected)
{
    return (sentCount >= 0) && ((size_t) sentCount == expected);
}

/* FreeRTOS_recv with RCVTIMEO=0 returns 0 when no data is available (would
 * block); the Service thread treats that as "nothing to read right now".
 * Negative returns are real errors - close the socket and surface failure. */
static SolidSyslogSsize PlusTcpTcpStream_Read(struct SolidSyslogStream* base, void* buffer, size_t size)
{
    struct SolidSyslogPlusTcpTcpStream* self = PlusTcpTcpStream_SelfFromBase(base);
    SolidSyslogSsize result = READ_FAILED;
    if (PlusTcpTcpStream_IsOpen(self))
    {
        result = PlusTcpTcpStream_ReceiveOrCloseOnFailure(self, buffer, size);
    }
    return result;
}

static SolidSyslogSsize PlusTcpTcpStream_ReceiveOrCloseOnFailure(
    struct SolidSyslogPlusTcpTcpStream* self,
    void* buffer,
    size_t size
)
{
    BaseType_t receivedCount = FreeRTOS_recv(self->Socket, buffer, size, SEND_RECV_FLAGS_DEFAULT);
    SolidSyslogSsize result = READ_FAILED;
    if (receivedCount >= 0)
    {
        result = (SolidSyslogSsize) receivedCount;
    }
    else
    {
        PlusTcpTcpStream_CloseSocket(self);
    }
    return result;
}

static void PlusTcpTcpStream_Close(struct SolidSyslogStream* base)
{
    PlusTcpTcpStream_CloseSocket(PlusTcpTcpStream_SelfFromBase(base));
}

static uint32_t PlusTcpTcpStream_Version(struct SolidSyslogStream* base)
{
    (void) base;
    return 0U;
}

// NOLINTEND(performance-no-int-to-ptr)

#else

/* ISO C forbids an empty translation unit. */
typedef int PlusTcpTcpStream_EmptyTranslationUnit;

#endif /* ipconfigUSE_TCP */
