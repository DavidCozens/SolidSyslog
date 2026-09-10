/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogOpenSslStream.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogNullStream.h"
#include "SolidSyslogPoolAllocator.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogOpenSslStreamErrors.h"
#include "SolidSyslogOpenSslStreamPrivate.h"
#include "SolidSyslogTunables.h"

struct SolidSyslogStream;

static inline bool OpenSslStream_IsValidConfig(const struct SolidSyslogOpenSslStreamConfig* config);
static inline size_t OpenSslStream_IndexFromHandle(const struct SolidSyslogStream* base);
static inline void OpenSslStream_CleanupAtIndex(size_t index, void* context);

static bool OpenSslStream_InUse[SOLIDSYSLOG_TLS_STREAM_POOL_SIZE];
static struct SolidSyslogOpenSslStream OpenSslStream_Pool[SOLIDSYSLOG_TLS_STREAM_POOL_SIZE];
static struct SolidSyslogPoolAllocator OpenSslStream_Allocator = {
    OpenSslStream_InUse,
    SOLIDSYSLOG_TLS_STREAM_POOL_SIZE
};

struct SolidSyslogStream* SolidSyslogOpenSslStream_Create(const struct SolidSyslogOpenSslStreamConfig* config)
{
    struct SolidSyslogStream* handle = SolidSyslogNullStream_Get();
    if (OpenSslStream_IsValidConfig(config))
    {
        size_t index = SolidSyslogPoolAllocator_AcquireFirstFree(&OpenSslStream_Allocator);
        if (SolidSyslogPoolAllocator_IndexIsValid(&OpenSslStream_Allocator, index) == true)
        {
            SolidSyslogOpenSslStream_Initialise(&OpenSslStream_Pool[index].Base, config);
            handle = &OpenSslStream_Pool[index].Base;
        }
        else
        {
            OpenSslStream_Report(
                SOLIDSYSLOG_POOL_EXHAUSTED_SEVERITY,
                SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
                SOLIDSYSLOG_TLS_STREAM_ERROR_POOL_EXHAUSTED
            );
        }
    }
    return handle;
}

static inline bool OpenSslStream_IsValidConfig(const struct SolidSyslogOpenSslStreamConfig* config)
{
    bool valid = false;
    if (config == NULL)
    {
        OpenSslStream_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_CONFIG
        );
    }
    else if (config->Transport == NULL)
    {
        OpenSslStream_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_TRANSPORT
        );
    }
    else if (config->Sleep == NULL)
    {
        OpenSslStream_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_SLEEP
        );
    }
    else if (config->Credentials == NULL)
    {
        OpenSslStream_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_CREDENTIALS
        );
    }
    else
    {
        valid = true;
    }
    return valid;
}

void SolidSyslogOpenSslStream_Destroy(struct SolidSyslogStream* base)
{
    size_t index = OpenSslStream_IndexFromHandle(base);
    bool released =
        SolidSyslogPoolAllocator_IndexIsValid(&OpenSslStream_Allocator, index) &&
        SolidSyslogPoolAllocator_FreeIfInUse(&OpenSslStream_Allocator, index, OpenSslStream_CleanupAtIndex, NULL);
    if (!released)
    {
        OpenSslStream_Report(
            SOLIDSYSLOG_UNKNOWN_DESTROY_SEVERITY,
            SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
            SOLIDSYSLOG_TLS_STREAM_ERROR_UNKNOWN_DESTROY
        );
    }
}

static inline size_t OpenSslStream_IndexFromHandle(const struct SolidSyslogStream* base)
{
    size_t result = SOLIDSYSLOG_TLS_STREAM_POOL_SIZE;
    for (size_t poolIndex = 0; poolIndex < SOLIDSYSLOG_TLS_STREAM_POOL_SIZE; poolIndex++)
    {
        if (base == &OpenSslStream_Pool[poolIndex].Base)
        {
            result = poolIndex;
            break;
        }
    }
    return result;
}

static inline void OpenSslStream_CleanupAtIndex(size_t index, void* context)
{
    (void) context;
    SolidSyslogOpenSslStream_Cleanup(&OpenSslStream_Pool[index].Base);
}
