#include "BddTargetTlsSender.h"
#include "SolidSyslogSenderDefinition.h"

#include <stddef.h>
#include <stdio.h>

static bool warned;

static bool NilSend(struct SolidSyslogSender* self, const void* buffer, size_t size)
{
    (void) self;
    (void) buffer;
    (void) size;
    if (!warned)
    {
        (void) fprintf(
            stderr,
            "BddTargetTlsSender: TLS support not compiled in — messages routed to the TLS slot will be dropped\n"
        );
        warned = true;
    }
    return false;
}

static void NilDisconnect(struct SolidSyslogSender* self)
{
    (void) self;
}

static struct SolidSyslogSender nilSender = {NilSend, NilDisconnect};

struct SolidSyslogSender* BddTargetTlsSender_Create(struct SolidSyslogResolver* resolver, bool mtls)
{
    (void) resolver;
    (void) mtls;
    warned = false;
    return &nilSender;
}

void BddTargetTlsSender_Destroy(void)
{
}

const struct SolidSyslogErrorSource* BddTargetTlsSender_ErrorSource(void)
{
    return NULL;
}
