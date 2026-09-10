/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogStreamDefinition.h"
#include "SolidSyslogStream.h"

struct SolidSyslogAddress;

bool SolidSyslogStream_Open(struct SolidSyslogStream* stream, const struct SolidSyslogAddress* addr)
{
    return stream->Open(stream, addr);
}

bool SolidSyslogStream_Send(struct SolidSyslogStream* stream, const void* buffer, size_t size)
{
    return stream->Send(stream, buffer, size);
}

SolidSyslogSsize SolidSyslogStream_Read(struct SolidSyslogStream* stream, void* buffer, size_t size)
{
    return stream->Read(stream, buffer, size);
}

void SolidSyslogStream_Close(struct SolidSyslogStream* stream)
{
    stream->Close(stream);
}

uint32_t SolidSyslogStream_Version(struct SolidSyslogStream* stream)
{
    return stream->Version(stream);
}
