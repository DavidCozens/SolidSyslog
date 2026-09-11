/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogMbedTlsHmacSha256Policy.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogMbedTlsHmacSha256PolicyErrors.h"
#include "SolidSyslogMbedTlsHmacSha256PolicyPrivate.h"
#include "SolidSyslogNullSecurityPolicy.h"
#include "SolidSyslogPoolAllocator.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogSecurityPolicyDefinition.h"
#include "SolidSyslogTunables.h"

static inline bool MbedTlsHmacSha256Policy_ConfigIsValid(const struct SolidSyslogMbedTlsHmacSha256PolicyConfig* config);
static inline size_t MbedTlsHmacSha256Policy_IndexFromHandle(const struct SolidSyslogSecurityPolicy* base);
static inline void MbedTlsHmacSha256Policy_CleanupAtIndex(size_t index, void* context);

static bool MbedTlsHmacSha256Policy_InUse[SOLIDSYSLOG_HMAC_SHA256_POLICY_POOL_SIZE];
static struct SolidSyslogMbedTlsHmacSha256Policy MbedTlsHmacSha256Policy_Pool[SOLIDSYSLOG_HMAC_SHA256_POLICY_POOL_SIZE];
static struct SolidSyslogPoolAllocator MbedTlsHmacSha256Policy_Allocator = {
    MbedTlsHmacSha256Policy_InUse,
    SOLIDSYSLOG_HMAC_SHA256_POLICY_POOL_SIZE
};

struct SolidSyslogSecurityPolicy* SolidSyslogMbedTlsHmacSha256Policy_Create(
    const struct SolidSyslogMbedTlsHmacSha256PolicyConfig* config
)
{
    struct SolidSyslogSecurityPolicy* handle = SolidSyslogNullSecurityPolicy_Get();
    if (MbedTlsHmacSha256Policy_ConfigIsValid(config))
    {
        size_t index = SolidSyslogPoolAllocator_AcquireFirstFree(&MbedTlsHmacSha256Policy_Allocator);
        if (SolidSyslogPoolAllocator_IndexIsValid(&MbedTlsHmacSha256Policy_Allocator, index) == true)
        {
            SolidSyslogMbedTlsHmacSha256Policy_Initialise(&MbedTlsHmacSha256Policy_Pool[index].Base, config);
            handle = &MbedTlsHmacSha256Policy_Pool[index].Base;
        }
        else
        {
            MbedTlsHmacSha256Policy_Report(
                SOLIDSYSLOG_POOL_EXHAUSTED_SEVERITY,
                SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
                SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_POOL_EXHAUSTED
            );
        }
    }
    else
    {
        MbedTlsHmacSha256Policy_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_BAD_CONFIG
        );
    }
    return handle;
}

void SolidSyslogMbedTlsHmacSha256Policy_Destroy(struct SolidSyslogSecurityPolicy* base)
{
    size_t index = MbedTlsHmacSha256Policy_IndexFromHandle(base);
    bool released = SolidSyslogPoolAllocator_IndexIsValid(&MbedTlsHmacSha256Policy_Allocator, index) &&
                    SolidSyslogPoolAllocator_FreeIfInUse(
                        &MbedTlsHmacSha256Policy_Allocator,
                        index,
                        MbedTlsHmacSha256Policy_CleanupAtIndex,
                        NULL
                    );
    if (!released)
    {
        MbedTlsHmacSha256Policy_Report(
            SOLIDSYSLOG_UNKNOWN_DESTROY_SEVERITY,
            SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
            SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_UNKNOWN_DESTROY
        );
    }
}

static inline bool MbedTlsHmacSha256Policy_ConfigIsValid(const struct SolidSyslogMbedTlsHmacSha256PolicyConfig* config)
{
    return (config != NULL) && (config->GetKey != NULL);
}

static inline size_t MbedTlsHmacSha256Policy_IndexFromHandle(const struct SolidSyslogSecurityPolicy* base)
{
    size_t result = SOLIDSYSLOG_HMAC_SHA256_POLICY_POOL_SIZE;
    for (size_t poolIndex = 0; poolIndex < SOLIDSYSLOG_HMAC_SHA256_POLICY_POOL_SIZE; poolIndex++)
    {
        if (base == &MbedTlsHmacSha256Policy_Pool[poolIndex].Base)
        {
            result = poolIndex;
            break;
        }
    }
    return result;
}

static inline void MbedTlsHmacSha256Policy_CleanupAtIndex(size_t index, void* context)
{
    (void) context;
    SolidSyslogMbedTlsHmacSha256Policy_Cleanup(&MbedTlsHmacSha256Policy_Pool[index].Base);
}
