/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogPosixTcpStream.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "SolidSyslogError.h"
#include "SolidSyslogNullStream.h"
#include "SolidSyslogPosixAddressPrivate.h"
#include "SolidSyslogPosixTcpStreamErrors.h"
#include "SolidSyslogPosixTcpStreamPrivate.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogTunables.h"

const struct SolidSyslogErrorSource SolidSyslogPosixTcpStreamErrorSource = {"PosixTcpStream"};

struct SolidSyslogAddress;

enum
{
    INVALID_FD = -1,
    /* Keepalive parameters - bound the dead-peer detection window when the
       socket is idle. Worst case: 45 + 4 * 10 = 85 s before ETIMEDOUT.
       TCP_USER_TIMEOUT covers the pending-write case (where keepalive does
       not fire) by capping how long unacked data can sit in the send queue. */
    KEEPALIVE_IDLE_SECONDS = 45,
    KEEPALIVE_INTERVAL_SECONDS = 10,
    KEEPALIVE_PROBE_COUNT = 4,
    USER_TIMEOUT_MILLISECONDS = 30000
};

static uint32_t PosixTcpStream_NullConnectTimeoutGetter(void* context);

static bool PosixTcpStream_Open(struct SolidSyslogStream* base, const struct SolidSyslogAddress* addr);
static bool PosixTcpStream_Send(struct SolidSyslogStream* base, const void* buffer, size_t size);
static SolidSyslogSsize PosixTcpStream_Read(struct SolidSyslogStream* base, void* buffer, size_t size);
static void PosixTcpStream_Close(struct SolidSyslogStream* base);
static uint32_t PosixTcpStream_Version(struct SolidSyslogStream* base);

static inline struct SolidSyslogPosixTcpStream* PosixTcpStream_SelfFromBase(struct SolidSyslogStream* base);
static inline bool PosixTcpStream_ConfigProvidesGetter(const struct SolidSyslogPosixTcpStreamConfig* config);

static int PosixTcpStream_OpenAndConfigureSocket(void);
static bool PosixTcpStream_ConfigureSocket(int fd);
static void PosixTcpStream_EnableTcpNoDelay(int fd);
static void PosixTcpStream_EnableKeepalive(int fd);
static bool PosixTcpStream_SetNonBlocking(int fd);
static inline bool PosixTcpStream_IsFileDescriptorValid(int fd);
static bool PosixTcpStream_ConnectOrCloseOnFailure(
    struct SolidSyslogPosixTcpStream* self,
    const struct sockaddr_in* sin
);
static bool PosixTcpStream_Connect(int fd, const struct sockaddr_in* sin, long timeoutMicros);
static bool PosixTcpStream_WaitForConnectCompletion(int fd, long timeoutMicros);
static bool PosixTcpStream_ReadDeferredConnectError(int fd);
static long PosixTcpStream_ResolveConnectTimeoutMicros(struct SolidSyslogPosixTcpStream* self);
static bool PosixTcpStream_WroteAllBytes(ssize_t sent, size_t expected);
static inline bool PosixTcpStream_WouldBlock(int err);

void SolidSyslogPosixTcpStream_Initialise(
    struct SolidSyslogStream* base,
    const struct SolidSyslogPosixTcpStreamConfig* config
)
{
    static const struct SolidSyslogPosixTcpStream DefaultPosixTcpStream = {
        .Base =
            {.Open = PosixTcpStream_Open,
             .Send = PosixTcpStream_Send,
             .Read = PosixTcpStream_Read,
             .Close = PosixTcpStream_Close,
             .Version = PosixTcpStream_Version},
        .Config = {.GetConnectTimeoutMs = PosixTcpStream_NullConnectTimeoutGetter, .ConnectTimeoutContext = NULL},
        .Fd = INVALID_FD,
    };

    struct SolidSyslogPosixTcpStream* self = PosixTcpStream_SelfFromBase(base);
    *self = DefaultPosixTcpStream;
    if (PosixTcpStream_ConfigProvidesGetter(config) == true)
    {
        self->Config = *config;
    }
}

static inline bool PosixTcpStream_ConfigProvidesGetter(const struct SolidSyslogPosixTcpStreamConfig* config)
{
    return (config != NULL) && (config->GetConnectTimeoutMs != NULL);
}

/* Null Object substituted when the integrator does not install a getter -
 * returns the compile-time tunable so the bounded-wait path has a single
 * code path regardless of whether the integrator wired runtime tuning. */
static uint32_t PosixTcpStream_NullConnectTimeoutGetter(void* context)
{
    (void) context;
    return (uint32_t) SOLIDSYSLOG_TCP_CONNECT_TIMEOUT_MS;
}

static inline struct SolidSyslogPosixTcpStream* PosixTcpStream_SelfFromBase(struct SolidSyslogStream* base)
{
    return (struct SolidSyslogPosixTcpStream*) base;
}

void SolidSyslogPosixTcpStream_Cleanup(struct SolidSyslogStream* base)
{
    struct SolidSyslogPosixTcpStream* self = PosixTcpStream_SelfFromBase(base);
    if (PosixTcpStream_IsFileDescriptorValid(self->Fd))
    {
        close(self->Fd);
        self->Fd = INVALID_FD;
    }
    /* Overwrite the abstract base with the shared NullStream vtable so
     * use-after-destroy is a safe no-op rather than a NULL-fn-pointer crash. */
    *base = *SolidSyslogNullStream_Get();
}

static inline bool PosixTcpStream_IsFileDescriptorValid(int fd)
{
    return (fd >= 0);
}

static bool PosixTcpStream_Open(struct SolidSyslogStream* base, const struct SolidSyslogAddress* addr)
{
    struct SolidSyslogPosixTcpStream* self = PosixTcpStream_SelfFromBase(base);
    const struct sockaddr_in* sin = SolidSyslogPosixAddress_AsConstSockaddrIn(addr);
    bool connected = false;

    self->Fd = PosixTcpStream_OpenAndConfigureSocket();
    if (PosixTcpStream_IsFileDescriptorValid(self->Fd))
    {
        connected = PosixTcpStream_ConnectOrCloseOnFailure(self, sin);
    }
    return connected;
}

/* Non-blocking from the start: connect() reports EINPROGRESS, the wait is
 * bounded by select(), and PosixTcpStream_Send/PosixTcpStream_Read never block the service thread on a
 * wedged peer or a full kernel send buffer. */
static int PosixTcpStream_OpenAndConfigureSocket(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (PosixTcpStream_IsFileDescriptorValid(fd) && !PosixTcpStream_ConfigureSocket(fd))
    {
        close(fd);
        fd = INVALID_FD;
    }
    return fd;
}

static bool PosixTcpStream_ConfigureSocket(int fd)
{
    PosixTcpStream_EnableTcpNoDelay(fd);
    PosixTcpStream_EnableKeepalive(fd);
    return PosixTcpStream_SetNonBlocking(fd);
}

static void PosixTcpStream_EnableTcpNoDelay(int fd)
{
    int enable = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
}

/* Enable kernel TCP keepalive so a dead peer is surfaced as ETIMEDOUT during
 * idle periods, not on the next PosixTcpStream_Send. TCP_USER_TIMEOUT covers the orthogonal
 * pending-write case (keepalive only fires on a fully idle socket). Linux is
 * the POSIX target - TCP_KEEP* and TCP_USER_TIMEOUT are all available there;
 * other POSIX targets are out of scope until we actually port to one. */
static void PosixTcpStream_EnableKeepalive(int fd)
{
    int enable = 1;
    int idle = KEEPALIVE_IDLE_SECONDS;
    int interval = KEEPALIVE_INTERVAL_SECONDS;
    int count = KEEPALIVE_PROBE_COUNT;
    int userTimeout = USER_TIMEOUT_MILLISECONDS;

    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
    setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &userTimeout, sizeof(userTimeout));
}

static bool PosixTcpStream_SetNonBlocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return (flags >= 0) && (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1);
}

static bool PosixTcpStream_ConnectOrCloseOnFailure(
    struct SolidSyslogPosixTcpStream* self,
    const struct sockaddr_in* sin
)
{
    long timeoutMicros = PosixTcpStream_ResolveConnectTimeoutMicros(self);
    bool connected = PosixTcpStream_Connect(self->Fd, sin, timeoutMicros);
    if (!connected)
    {
        close(self->Fd);
        self->Fd = INVALID_FD;
    }
    return connected;
}

/* Bridges the integrator-installed getter (or the Null Object substituted in
 * Initialise) to the bounded select() deadline. Invoked on every connect
 * attempt so a runtime-tunable value takes effect on the next reconnect. */
static long PosixTcpStream_ResolveConnectTimeoutMicros(struct SolidSyslogPosixTcpStream* self)
{
    uint32_t ms = self->Config.GetConnectTimeoutMs(self->Config.ConnectTimeoutContext);
    return (long) ms * 1000L;
}

/* Non-blocking connect with bounded wait. connect() returns immediately:
 *   0           - connected (loopback success path).
 *   -1 EINPROGRESS - connect started; wait via select() up to
 *                    CONNECT_TIMEOUT_MICROSECONDS, then read SO_ERROR to
 *                    distinguish completed-success from deferred-failure.
 *   -1 other    - immediate fail-fast (refused, unreachable, etc.). */
static bool PosixTcpStream_Connect(int fd, const struct sockaddr_in* sin, long timeoutMicros)
{
    bool connected = false;
    int rc = connect(fd, (const struct sockaddr*) sin, sizeof(*sin));
    /* Capture errno immediately after connect so the EINPROGRESS test
     * below satisfies MISRA 22.10 - no intervening C-library calls
     * between the errno-setting function and the read. */
    int connectErrno = (rc < 0) ? errno : 0;

    if (rc == 0)
    {
        connected = true;
    }
    else if (connectErrno == EINPROGRESS)
    {
        connected =
            PosixTcpStream_WaitForConnectCompletion(fd, timeoutMicros) && PosixTcpStream_ReadDeferredConnectError(fd);
    }
    else
    {
        /* immediate fail-fast (refused, unreachable, etc.) - connected stays false */
    }
    return connected;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters) -- fd is a kernel file descriptor; timeoutMicros is a duration; distinct semantics
static bool PosixTcpStream_WaitForConnectCompletion(int fd, long timeoutMicros)
{
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(fd, &writeSet);

    fd_set errorSet;
    FD_ZERO(&errorSet);
    FD_SET(fd, &errorSet);

    struct timeval timeout = {.tv_sec = timeoutMicros / 1000000L, .tv_usec = timeoutMicros % 1000000L};

    int rc = select(fd + 1, NULL, &writeSet, &errorSet, &timeout);
    return (rc > 0) && FD_ISSET(fd, &writeSet) && !FD_ISSET(fd, &errorSet);
}

static bool PosixTcpStream_ReadDeferredConnectError(int fd)
{
    int err = 0;
    socklen_t errlen = (socklen_t) sizeof(err);
    int rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
    return (rc == 0) && (err == 0);
}

static bool PosixTcpStream_Send(struct SolidSyslogStream* base, const void* buffer, size_t size)
{
    struct SolidSyslogPosixTcpStream* self = PosixTcpStream_SelfFromBase(base);
    ssize_t sent = send(self->Fd, buffer, size, MSG_NOSIGNAL);
    bool ok = PosixTcpStream_WroteAllBytes(sent, size);

    if (!ok)
    {
        PosixTcpStream_Close(base);
    }
    return ok;
}

/* Non-blocking single-call contract: short write or any error means the
 * connection is gone; the caller closes and reconnects on the next attempt. */
static bool PosixTcpStream_WroteAllBytes(ssize_t sent, size_t expected)
{
    return (sent >= 0) && ((size_t) sent == expected);
}

static SolidSyslogSsize PosixTcpStream_Read(struct SolidSyslogStream* base, void* buffer, size_t size)
{
    struct SolidSyslogPosixTcpStream* self = PosixTcpStream_SelfFromBase(base);
    ssize_t n = recv(self->Fd, buffer, size, 0);
    /* Capture errno immediately after recv so the WouldBlock test below
     * satisfies MISRA 22.10 - passing the captured value into the helper
     * keeps the predicate pure and decouples it from errno's lifetime. */
    int recvErrno = (n < 0) ? errno : 0;
    SolidSyslogSsize result = -1;

    if (n > 0)
    {
        result = (SolidSyslogSsize) n;
    }
    else if ((n < 0) && PosixTcpStream_WouldBlock(recvErrno))
    {
        result = 0;
    }
    else
    {
        PosixTcpStream_Close(base);
    }
    return result;
}

static inline bool PosixTcpStream_WouldBlock(int err)
{
    return (err == EAGAIN) || (err == EWOULDBLOCK);
}

static void PosixTcpStream_Close(struct SolidSyslogStream* base)
{
    struct SolidSyslogPosixTcpStream* self = PosixTcpStream_SelfFromBase(base);
    if (PosixTcpStream_IsFileDescriptorValid(self->Fd))
    {
        close(self->Fd);
        self->Fd = INVALID_FD;
    }
}

static uint32_t PosixTcpStream_Version(struct SolidSyslogStream* base)
{
    (void) base;
    return 0U;
}
