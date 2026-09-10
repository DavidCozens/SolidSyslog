/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogMbedTlsStream.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogMbedTlsStreamErrors.h"
#include "SolidSyslogMbedTlsStreamPrivate.h"
#include "SolidSyslogNullStream.h"
#include "SolidSyslogPoolAllocator.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogTunables.h"

struct SolidSyslogStream;

static inline bool MbedTlsStream_IsValidConfig(const struct SolidSyslogMbedTlsStreamConfig* config);
static inline size_t MbedTlsStream_IndexFromHandle(const struct SolidSyslogStream* base);
static inline void MbedTlsStream_CleanupAtIndex(size_t index, void* context);

static bool MbedTlsStream_InUse[SOLIDSYSLOG_TLS_STREAM_POOL_SIZE];
static struct SolidSyslogMbedTlsStream MbedTlsStream_Pool[SOLIDSYSLOG_TLS_STREAM_POOL_SIZE];
static struct SolidSyslogPoolAllocator MbedTlsStream_Allocator = {
    MbedTlsStream_InUse,
    SOLIDSYSLOG_TLS_STREAM_POOL_SIZE
};

struct SolidSyslogStream* SolidSyslogMbedTlsStream_Create(const struct SolidSyslogMbedTlsStreamConfig* config)
{
    struct SolidSyslogStream* handle = SolidSyslogNullStream_Get();
    if (MbedTlsStream_IsValidConfig(config))
    {
        size_t index = SolidSyslogPoolAllocator_AcquireFirstFree(&MbedTlsStream_Allocator);
        if (SolidSyslogPoolAllocator_IndexIsValid(&MbedTlsStream_Allocator, index) == true)
        {
            SolidSyslogMbedTlsStream_Initialise(&MbedTlsStream_Pool[index].Base, config);
            handle = &MbedTlsStream_Pool[index].Base;
        }
        else
        {
            MbedTlsStream_Report(
                SOLIDSYSLOG_POOL_EXHAUSTED_SEVERITY,
                SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
                SOLIDSYSLOG_TLS_STREAM_ERROR_POOL_EXHAUSTED
            );
        }
    }
    return handle;
}

static inline bool MbedTlsStream_IsValidConfig(const struct SolidSyslogMbedTlsStreamConfig* config)
{
    bool valid = false;
    if (config == NULL)
    {
        MbedTlsStream_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_CONFIG
        );
    }
    else if (config->Transport == NULL)
    {
        MbedTlsStream_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_TRANSPORT
        );
    }
    else if (config->Sleep == NULL)
    {
        MbedTlsStream_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_SLEEP
        );
    }
    else if (config->Rng == NULL)
    {
        MbedTlsStream_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_TLS_STREAM_ERROR_NULL_RNG
        );
    }
    else if (config->Credentials == NULL)
    {
        MbedTlsStream_Report(
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

void SolidSyslogMbedTlsStream_Destroy(struct SolidSyslogStream* base)
{
    size_t index = MbedTlsStream_IndexFromHandle(base);
    bool released =
        SolidSyslogPoolAllocator_IndexIsValid(&MbedTlsStream_Allocator, index) &&
        SolidSyslogPoolAllocator_FreeIfInUse(&MbedTlsStream_Allocator, index, MbedTlsStream_CleanupAtIndex, NULL);
    if (!released)
    {
        MbedTlsStream_Report(
            SOLIDSYSLOG_UNKNOWN_DESTROY_SEVERITY,
            SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
            SOLIDSYSLOG_TLS_STREAM_ERROR_UNKNOWN_DESTROY
        );
    }
}

static inline size_t MbedTlsStream_IndexFromHandle(const struct SolidSyslogStream* base)
{
    size_t result = SOLIDSYSLOG_TLS_STREAM_POOL_SIZE;
    for (size_t poolIndex = 0; poolIndex < SOLIDSYSLOG_TLS_STREAM_POOL_SIZE; poolIndex++)
    {
        if (base == &MbedTlsStream_Pool[poolIndex].Base)
        {
            result = poolIndex;
            break;
        }
    }
    return result;
}

static inline void MbedTlsStream_CleanupAtIndex(size_t index, void* context)
{
    (void) context;
    SolidSyslogMbedTlsStream_Cleanup(&MbedTlsStream_Pool[index].Base);
}
