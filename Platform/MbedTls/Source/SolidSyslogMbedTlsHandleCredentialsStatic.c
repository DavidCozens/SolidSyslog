/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogMbedTlsHandleCredentials.h"

#include <stdbool.h>
#include <stddef.h>

#include "SolidSyslogError.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogMbedTlsCredentialsDefinition.h"
#include "SolidSyslogMbedTlsHandleCredentialsPrivate.h"
#include "SolidSyslogMbedTlsNullCredentials.h"
#include "SolidSyslogPoolAllocator.h"
#include "SolidSyslogTlsFingerprint.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogTunables.h"

static inline bool MbedTlsHandleCredentials_IsValidConfig(const struct SolidSyslogMbedTlsHandleCredentialsConfig* config
);
static inline size_t MbedTlsHandleCredentials_IndexFromHandle(const struct SolidSyslogMbedTlsCredentials* base);
static inline void MbedTlsHandleCredentials_CleanupAtIndex(size_t index, void* context);

static bool MbedTlsHandleCredentials_InUse[SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE];
static struct SolidSyslogMbedTlsHandleCredentials MbedTlsHandleCredentials_Pool[SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE];
static struct SolidSyslogPoolAllocator MbedTlsHandleCredentials_Allocator = {
    MbedTlsHandleCredentials_InUse,
    SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE
};

struct SolidSyslogMbedTlsCredentials* SolidSyslogMbedTlsHandleCredentials_Create(
    const struct SolidSyslogMbedTlsHandleCredentialsConfig* config
)
{
    struct SolidSyslogMbedTlsCredentials* handle = SolidSyslogMbedTlsNullCredentials_Get();
    if (MbedTlsHandleCredentials_IsValidConfig(config))
    {
        size_t index = SolidSyslogPoolAllocator_AcquireFirstFree(&MbedTlsHandleCredentials_Allocator);
        if (SolidSyslogPoolAllocator_IndexIsValid(&MbedTlsHandleCredentials_Allocator, index) == true)
        {
            SolidSyslogMbedTlsHandleCredentials_Initialise(&MbedTlsHandleCredentials_Pool[index].Base, config);
            handle = &MbedTlsHandleCredentials_Pool[index].Base;
        }
        else
        {
            MbedTlsHandleCredentials_Report(
                SOLIDSYSLOG_POOL_EXHAUSTED_SEVERITY,
                SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
                SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_POOL_EXHAUSTED
            );
        }
    }
    return handle;
}

/* The RNG is checked here rather than where it is used, so a wiring fault is
 * one Create-time report instead of a surprise on the connection that first
 * presents a client credential. */
static inline bool MbedTlsHandleCredentials_IsValidConfig(const struct SolidSyslogMbedTlsHandleCredentialsConfig* config
)
{
    bool valid = false;
    if (config == NULL)
    {
        MbedTlsHandleCredentials_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_NULL_CONFIG
        );
    }
    else if (config->Rng == NULL)
    {
        MbedTlsHandleCredentials_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_NULL_RNG
        );
    }
    else if (!SolidSyslogTlsFingerprint_ListIsPresent(config->PeerFingerprints, config->PeerFingerprintCount))
    {
        MbedTlsHandleCredentials_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_NULL_PEER_FINGERPRINT
        );
    }
    else
    {
        valid = true;
    }
    return valid;
}

void SolidSyslogMbedTlsHandleCredentials_Destroy(struct SolidSyslogMbedTlsCredentials* base)
{
    size_t index = MbedTlsHandleCredentials_IndexFromHandle(base);
    bool released = SolidSyslogPoolAllocator_IndexIsValid(&MbedTlsHandleCredentials_Allocator, index) &&
                    SolidSyslogPoolAllocator_FreeIfInUse(
                        &MbedTlsHandleCredentials_Allocator,
                        index,
                        MbedTlsHandleCredentials_CleanupAtIndex,
                        NULL
                    );
    if (!released)
    {
        MbedTlsHandleCredentials_Report(
            SOLIDSYSLOG_UNKNOWN_DESTROY_SEVERITY,
            SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
            SOLIDSYSLOG_TLS_CREDENTIALS_ERROR_UNKNOWN_DESTROY
        );
    }
}

static inline size_t MbedTlsHandleCredentials_IndexFromHandle(const struct SolidSyslogMbedTlsCredentials* base)
{
    size_t result = SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE;
    for (size_t poolIndex = 0; poolIndex < SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE; poolIndex++)
    {
        if (base == &MbedTlsHandleCredentials_Pool[poolIndex].Base)
        {
            result = poolIndex;
            break;
        }
    }
    return result;
}

static inline void MbedTlsHandleCredentials_CleanupAtIndex(size_t index, void* context)
{
    (void) context;
    (void) index;
}
