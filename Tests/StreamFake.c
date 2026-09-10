#include "StreamFake.h"
#include "SolidSyslogStreamDefinition.h"

#include <stdlib.h>

struct StreamFake
{
    struct SolidSyslogStream Base;
    int OpenCallCount;
    const struct SolidSyslogAddress* LastOpenAddr;
    bool OpenFails;
    int SendCallCount;
    const void* LastSendBuf;
    size_t LastSendSize;
    bool SendFails;
    int ReadCallCount;
    void* LastReadBuf;
    size_t LastReadSize;
    SolidSyslogSsize ReadReturn;
    int CloseCallCount;
    uint32_t Version;
};

static bool Open(struct SolidSyslogStream* self, const struct SolidSyslogAddress* addr)
{
    struct StreamFake* fake = (struct StreamFake*) self;
    fake->OpenCallCount++;
    fake->LastOpenAddr = addr;
    return !fake->OpenFails;
}

static bool Send(struct SolidSyslogStream* self, const void* buffer, size_t size)
{
    struct StreamFake* fake = (struct StreamFake*) self;
    fake->SendCallCount++;
    fake->LastSendBuf = buffer;
    fake->LastSendSize = size;
    return !fake->SendFails;
}

static SolidSyslogSsize Read(struct SolidSyslogStream* self, void* buffer, size_t size)
{
    struct StreamFake* fake = (struct StreamFake*) self;
    fake->ReadCallCount++;
    fake->LastReadBuf = buffer;
    fake->LastReadSize = size;
    return fake->ReadReturn;
}

static uint32_t Version(struct SolidSyslogStream* self)
{
    struct StreamFake* fake = (struct StreamFake*) self;
    return fake->Version;
}

static void Close(struct SolidSyslogStream* self)
{
    struct StreamFake* fake = (struct StreamFake*) self;
    fake->CloseCallCount++;
}

struct SolidSyslogStream* StreamFake_Create(void)
{
    struct StreamFake* fake = (struct StreamFake*) calloc(1, sizeof(struct StreamFake));
    fake->Base.Open = Open;
    fake->Base.Send = Send;
    fake->Base.Read = Read;
    fake->Base.Close = Close;
    fake->Base.Version = Version;
    return &fake->Base;
}

void StreamFake_Destroy(struct SolidSyslogStream* stream)
{
    free(stream);
}

int StreamFake_OpenCallCount(struct SolidSyslogStream* stream)
{
    return ((struct StreamFake*) stream)->OpenCallCount;
}

const struct SolidSyslogAddress* StreamFake_LastOpenAddr(struct SolidSyslogStream* stream)
{
    return ((struct StreamFake*) stream)->LastOpenAddr;
}

int StreamFake_SendCallCount(struct SolidSyslogStream* stream)
{
    return ((struct StreamFake*) stream)->SendCallCount;
}

const void* StreamFake_LastSendBuf(struct SolidSyslogStream* stream)
{
    return ((struct StreamFake*) stream)->LastSendBuf;
}

size_t StreamFake_LastSendSize(struct SolidSyslogStream* stream)
{
    return ((struct StreamFake*) stream)->LastSendSize;
}

int StreamFake_ReadCallCount(struct SolidSyslogStream* stream)
{
    return ((struct StreamFake*) stream)->ReadCallCount;
}

void* StreamFake_LastReadBuf(struct SolidSyslogStream* stream)
{
    return ((struct StreamFake*) stream)->LastReadBuf;
}

size_t StreamFake_LastReadSize(struct SolidSyslogStream* stream)
{
    return ((struct StreamFake*) stream)->LastReadSize;
}

void StreamFake_SetReadReturn(struct SolidSyslogStream* stream, SolidSyslogSsize value)
{
    ((struct StreamFake*) stream)->ReadReturn = value;
}

void StreamFake_SetOpenFails(struct SolidSyslogStream* stream, bool fails)
{
    ((struct StreamFake*) stream)->OpenFails = fails;
}

void StreamFake_SetSendFails(struct SolidSyslogStream* stream, bool fails)
{
    ((struct StreamFake*) stream)->SendFails = fails;
}

int StreamFake_CloseCallCount(struct SolidSyslogStream* stream)
{
    return ((struct StreamFake*) stream)->CloseCallCount;
}

void StreamFake_SetVersion(struct SolidSyslogStream* stream, uint32_t value)
{
    ((struct StreamFake*) stream)->Version = value;
}
