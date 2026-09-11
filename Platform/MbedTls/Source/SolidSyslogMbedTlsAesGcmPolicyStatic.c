/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogMbedTlsAesGcmPolicy.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogMbedTlsAesGcmPolicyErrors.h"
#include "SolidSyslogMbedTlsAesGcmPolicyPrivate.h"
#include "SolidSyslogNullSecurityPolicy.h"
#include "SolidSyslogPoolAllocator.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogSecurityPolicyDefinition.h"
#include "SolidSyslogTunables.h"

static inline bool MbedTlsAesGcmPolicy_ConfigIsValid(const struct SolidSyslogMbedTlsAesGcmPolicyConfig* config);
static inline size_t MbedTlsAesGcmPolicy_IndexFromHandle(const struct SolidSyslogSecurityPolicy* base);
static inline void MbedTlsAesGcmPolicy_CleanupAtIndex(size_t index, void* context);

static bool MbedTlsAesGcmPolicy_InUse[SOLIDSYSLOG_AES_GCM_POLICY_POOL_SIZE];
static struct SolidSyslogMbedTlsAesGcmPolicy MbedTlsAesGcmPolicy_Pool[SOLIDSYSLOG_AES_GCM_POLICY_POOL_SIZE];
static struct SolidSyslogPoolAllocator MbedTlsAesGcmPolicy_Allocator = {
    MbedTlsAesGcmPolicy_InUse,
    SOLIDSYSLOG_AES_GCM_POLICY_POOL_SIZE
};

struct SolidSyslogSecurityPolicy* SolidSyslogMbedTlsAesGcmPolicy_Create(
    const struct SolidSyslogMbedTlsAesGcmPolicyConfig* config
)
{
    struct SolidSyslogSecurityPolicy* handle = SolidSyslogNullSecurityPolicy_Get();
    if (MbedTlsAesGcmPolicy_ConfigIsValid(config))
    {
        size_t index = SolidSyslogPoolAllocator_AcquireFirstFree(&MbedTlsAesGcmPolicy_Allocator);
        if (SolidSyslogPoolAllocator_IndexIsValid(&MbedTlsAesGcmPolicy_Allocator, index) == true)
        {
            SolidSyslogMbedTlsAesGcmPolicy_Initialise(&MbedTlsAesGcmPolicy_Pool[index].Base, config);
            handle = &MbedTlsAesGcmPolicy_Pool[index].Base;
        }
        else
        {
            MbedTlsAesGcmPolicy_Report(
                SOLIDSYSLOG_POOL_EXHAUSTED_SEVERITY,
                SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
                SOLIDSYSLOG_AES_GCM_POLICY_ERROR_POOL_EXHAUSTED
            );
        }
    }
    else
    {
        MbedTlsAesGcmPolicy_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_AES_GCM_POLICY_ERROR_BAD_CONFIG
        );
    }
    return handle;
}

void SolidSyslogMbedTlsAesGcmPolicy_Destroy(struct SolidSyslogSecurityPolicy* base)
{
    size_t index = MbedTlsAesGcmPolicy_IndexFromHandle(base);
    bool released = SolidSyslogPoolAllocator_IndexIsValid(&MbedTlsAesGcmPolicy_Allocator, index) &&
                    SolidSyslogPoolAllocator_FreeIfInUse(
                        &MbedTlsAesGcmPolicy_Allocator,
                        index,
                        MbedTlsAesGcmPolicy_CleanupAtIndex,
                        NULL
                    );
    if (!released)
    {
        MbedTlsAesGcmPolicy_Report(
            SOLIDSYSLOG_UNKNOWN_DESTROY_SEVERITY,
            SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
            SOLIDSYSLOG_AES_GCM_POLICY_ERROR_UNKNOWN_DESTROY
        );
    }
}

static inline bool MbedTlsAesGcmPolicy_ConfigIsValid(const struct SolidSyslogMbedTlsAesGcmPolicyConfig* config)
{
    return (config != NULL) && (config->GetKey != NULL) && (config->Rng != NULL);
}

static inline size_t MbedTlsAesGcmPolicy_IndexFromHandle(const struct SolidSyslogSecurityPolicy* base)
{
    size_t result = SOLIDSYSLOG_AES_GCM_POLICY_POOL_SIZE;
    for (size_t poolIndex = 0; poolIndex < SOLIDSYSLOG_AES_GCM_POLICY_POOL_SIZE; poolIndex++)
    {
        if (base == &MbedTlsAesGcmPolicy_Pool[poolIndex].Base)
        {
            result = poolIndex;
            break;
        }
    }
    return result;
}

static inline void MbedTlsAesGcmPolicy_CleanupAtIndex(size_t index, void* context)
{
    (void) context;
    SolidSyslogMbedTlsAesGcmPolicy_Cleanup(&MbedTlsAesGcmPolicy_Pool[index].Base);
}
