/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogEndpoint.h"
#include "SolidSyslogEndpointHostPrivate.h"
#include "SolidSyslogError.h"
#include "SolidSyslogFormatter.h"
#include "SolidSyslogNullSender.h"
#include "SolidSyslogResolver.h"
#include "SolidSyslogSenderDefinition.h"
#include "SolidSyslogSenderHealth.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogStreamSender.h"
#include "SolidSyslogStreamSenderErrors.h"
#include "SolidSyslogStreamSenderPrivate.h"
#include "SolidSyslogTransport.h"

const struct SolidSyslogErrorSource SolidSyslogStreamSenderErrorSource = {"StreamSender"};

struct SolidSyslogAddress;
struct SolidSyslogFormatter;

enum
{
    UINT32_MAX_DECIMAL_DIGITS = 10,
    OCTET_COUNTING_SEPARATOR = 1,
    OCTET_COUNTING_NULL_TERMINATOR = 1,
    OCTET_COUNTING_PREFIX_CAPACITY =
        UINT32_MAX_DECIMAL_DIGITS + OCTET_COUNTING_SEPARATOR + OCTET_COUNTING_NULL_TERMINATOR
};

static bool StreamSender_Send(struct SolidSyslogSender* base, const void* buffer, size_t size);
static void StreamSender_Disconnect(struct SolidSyslogSender* base);

static inline void StreamSender_UpdateDeliveryHealth(struct SolidSyslogStreamSender* self, bool delivered);
static inline struct SolidSyslogStreamSender* StreamSender_SelfFromBase(struct SolidSyslogSender* base);

static inline bool StreamSender_Reconcile(struct SolidSyslogStreamSender* self);
static inline void StreamSender_DisconnectIfStale(struct SolidSyslogStreamSender* self);
static inline bool StreamSender_ConfigurationMoved(
    const struct SolidSyslogStreamSender* self,
    uint32_t endpointVersion,
    uint32_t streamVersion
);
static inline bool StreamSender_EnsureConnected(struct SolidSyslogStreamSender* self);
static inline bool StreamSender_Connected(struct SolidSyslogStreamSender* self);
static bool StreamSender_Connect(struct SolidSyslogStreamSender* self);
static bool StreamSender_ResolveDestination(struct SolidSyslogStreamSender* self, struct SolidSyslogAddress* addr);
static inline void StreamSender_CloseStream(struct SolidSyslogStreamSender* self);
static bool StreamSender_TransmitFramed(struct SolidSyslogStreamSender* self, const void* buffer, size_t size);
static struct SolidSyslogFormatter* StreamSender_FormatOctetCountingPrefix(
    SolidSyslogFormatterStorage* storage,
    size_t messageSize
);
static bool StreamSender_SendBytes(struct SolidSyslogStreamSender* self, const void* data, size_t len);
static void StreamSender_NilEndpoint(struct SolidSyslogEndpoint* endpoint, void* context);
static uint32_t StreamSender_NilEndpointVersion(void* context);

void SolidSyslogStreamSender_Initialise(
    struct SolidSyslogSender* base,
    const struct SolidSyslogStreamSenderConfig* config
)
{
    struct SolidSyslogStreamSender* self = StreamSender_SelfFromBase(base);
    self->Base.Send = StreamSender_Send;
    self->Base.Disconnect = StreamSender_Disconnect;
    self->Config.Resolver = config->Resolver;
    self->Config.Stream = config->Stream;
    self->Config.Address = config->Address;
    self->Config.Endpoint = (config->Endpoint != NULL) ? config->Endpoint : StreamSender_NilEndpoint;
    self->Config.EndpointVersion =
        (config->EndpointVersion != NULL) ? config->EndpointVersion : StreamSender_NilEndpointVersion;
    self->Config.EndpointContext = config->EndpointContext;
    self->Connected = false;
    self->DeliveryHealthy = true;
    self->LastEndpointVersion = 0;
    self->LastStreamVersion = 0;
}

void SolidSyslogStreamSender_Cleanup(struct SolidSyslogSender* base)
{
    /* Disconnect first so the live Config.Stream is still reachable; then overwrite the
     * abstract base with the shared NullSender vtable so use-after-destroy is a safe
     * no-op rather than a NULL-fn-pointer crash. Derived fields are private to this TU
     * so the next SolidSyslogStreamSender_Initialise overwrites them; no need to wipe here. */
    StreamSender_Disconnect(base);
    *base = *SolidSyslogNullSender_Get();
}

static bool StreamSender_Send(struct SolidSyslogSender* base, const void* buffer, size_t size)
{
    struct SolidSyslogStreamSender* self = StreamSender_SelfFromBase(base);
    bool delivered = StreamSender_Reconcile(self) && StreamSender_TransmitFramed(self, buffer, size);
    StreamSender_UpdateDeliveryHealth(self, delivered);
    return delivered;
}

static inline void StreamSender_UpdateDeliveryHealth(struct SolidSyslogStreamSender* self, bool delivered)
{
    static const struct SolidSyslogSenderHealthReporter reporter = {
        .Source = &SolidSyslogStreamSenderErrorSource,
        .FailedDetail = (int32_t) SOLIDSYSLOG_STREAM_SENDER_ERROR_DELIVERY_FAILED,
        .RestoredDetail = (int32_t) SOLIDSYSLOG_STREAM_SENDER_ERROR_DELIVERY_RESTORED
    };
    SolidSyslogSenderHealth_Update(&self->DeliveryHealthy, delivered, &reporter);
}

static inline bool StreamSender_Reconcile(struct SolidSyslogStreamSender* self)
{
    StreamSender_DisconnectIfStale(self);
    return StreamSender_EnsureConnected(self);
}

static inline void StreamSender_DisconnectIfStale(struct SolidSyslogStreamSender* self)
{
    uint32_t endpointVersion = self->Config.EndpointVersion(self->Config.EndpointContext);
    uint32_t streamVersion = SolidSyslogStream_Version(self->Config.Stream);

    if (StreamSender_ConfigurationMoved(self, endpointVersion, streamVersion))
    {
        StreamSender_Disconnect(&self->Base);
        self->LastEndpointVersion = endpointVersion;
        self->LastStreamVersion = streamVersion;
    }
}

static inline bool StreamSender_ConfigurationMoved(
    const struct SolidSyslogStreamSender* self,
    uint32_t endpointVersion,
    uint32_t streamVersion
)
{
    return (endpointVersion != self->LastEndpointVersion) || (streamVersion != self->LastStreamVersion);
}

static inline bool StreamSender_EnsureConnected(struct SolidSyslogStreamSender* self)
{
    return StreamSender_Connected(self) || StreamSender_Connect(self);
}

static inline bool StreamSender_Connected(struct SolidSyslogStreamSender* self)
{
    return self->Connected;
}

static bool StreamSender_Connect(struct SolidSyslogStreamSender* self)
{
    struct SolidSyslogAddress* addr = self->Config.Address;

    if (StreamSender_ResolveDestination(self, addr))
    {
        self->Connected = SolidSyslogStream_Open(self->Config.Stream, addr);
    }

    return StreamSender_Connected(self);
}

static bool StreamSender_ResolveDestination(struct SolidSyslogStreamSender* self, struct SolidSyslogAddress* addr)
{
    SolidSyslogFormatterStorage hostStorage[SOLIDSYSLOG_FORMATTER_STORAGE_SIZE(SOLIDSYSLOG_MAX_HOST_SIZE)];
    struct SolidSyslogFormatter* hostFormatter = SolidSyslogFormatter_Create(hostStorage, SOLIDSYSLOG_MAX_HOST_SIZE);
    struct SolidSyslogEndpointHost hostSink;
    SolidSyslogEndpointHost_FromFormatter(&hostSink, hostFormatter);
    struct SolidSyslogEndpoint endpoint = {.Host = &hostSink, .Port = 0};

    self->Config.Endpoint(&endpoint, self->Config.EndpointContext);

    return SolidSyslogResolver_Resolve(
        self->Config.Resolver,
        SOLIDSYSLOG_TRANSPORT_TCP,
        SolidSyslogFormatter_AsFormattedBuffer(hostFormatter),
        endpoint.Port,
        addr
    );
}

static void StreamSender_Disconnect(struct SolidSyslogSender* base)
{
    struct SolidSyslogStreamSender* self = StreamSender_SelfFromBase(base);

    if (StreamSender_Connected(self))
    {
        StreamSender_CloseStream(self);
    }
}

static inline struct SolidSyslogStreamSender* StreamSender_SelfFromBase(struct SolidSyslogSender* base)
{
    return (struct SolidSyslogStreamSender*) base;
}

static inline void StreamSender_CloseStream(struct SolidSyslogStreamSender* self)
{
    SolidSyslogStream_Close(self->Config.Stream);
    self->Connected = false;
}

static bool StreamSender_TransmitFramed(struct SolidSyslogStreamSender* self, const void* buffer, size_t size)
{
    SolidSyslogFormatterStorage prefixStorage[SOLIDSYSLOG_FORMATTER_STORAGE_SIZE(OCTET_COUNTING_PREFIX_CAPACITY)];
    struct SolidSyslogFormatter* prefix = StreamSender_FormatOctetCountingPrefix(prefixStorage, size);

    return StreamSender_SendBytes(
               self,
               SolidSyslogFormatter_AsFormattedBuffer(prefix),
               SolidSyslogFormatter_Length(prefix)
           ) &&
           StreamSender_SendBytes(self, buffer, size);
}

static struct SolidSyslogFormatter* StreamSender_FormatOctetCountingPrefix(
    SolidSyslogFormatterStorage* storage,
    size_t messageSize
)
{
    struct SolidSyslogFormatter* f = SolidSyslogFormatter_Create(storage, OCTET_COUNTING_PREFIX_CAPACITY);
    SolidSyslogFormatter_Uint32(f, (uint32_t) messageSize);
    SolidSyslogFormatter_AsciiCharacter(f, ' ');
    return f;
}

static bool StreamSender_SendBytes(struct SolidSyslogStreamSender* self, const void* data, size_t len)
{
    bool sent = SolidSyslogStream_Send(self->Config.Stream, data, len);

    if (!sent)
    {
        StreamSender_CloseStream(self);
    }

    return sent;
}

static void StreamSender_NilEndpoint(struct SolidSyslogEndpoint* endpoint, void* context)
{
    (void) context;
    SolidSyslogEndpointHost_String(endpoint->Host, "", 0);
    endpoint->Port = 0;
}

static uint32_t StreamSender_NilEndpointVersion(void* context)
{
    (void) context;
    return 0;
}
