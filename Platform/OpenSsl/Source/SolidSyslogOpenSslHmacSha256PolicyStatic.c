/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogOpenSslHmacSha256Policy.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogNullSecurityPolicy.h"
#include "SolidSyslogOpenSslHmacSha256PolicyErrors.h"
#include "SolidSyslogOpenSslHmacSha256PolicyPrivate.h"
#include "SolidSyslogPoolAllocator.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogSecurityPolicyDefinition.h"
#include "SolidSyslogTunables.h"

static inline bool OpenSslHmacSha256Policy_ConfigIsValid(const struct SolidSyslogOpenSslHmacSha256PolicyConfig* config);
static inline size_t OpenSslHmacSha256Policy_IndexFromHandle(const struct SolidSyslogSecurityPolicy* base);
static inline void OpenSslHmacSha256Policy_CleanupAtIndex(size_t index, void* context);

static bool OpenSslHmacSha256Policy_InUse[SOLIDSYSLOG_HMAC_SHA256_POLICY_POOL_SIZE];
static struct SolidSyslogOpenSslHmacSha256Policy OpenSslHmacSha256Policy_Pool[SOLIDSYSLOG_HMAC_SHA256_POLICY_POOL_SIZE];
static struct SolidSyslogPoolAllocator OpenSslHmacSha256Policy_Allocator = {
    OpenSslHmacSha256Policy_InUse,
    SOLIDSYSLOG_HMAC_SHA256_POLICY_POOL_SIZE
};

struct SolidSyslogSecurityPolicy* SolidSyslogOpenSslHmacSha256Policy_Create(
    const struct SolidSyslogOpenSslHmacSha256PolicyConfig* config
)
{
    struct SolidSyslogSecurityPolicy* handle = SolidSyslogNullSecurityPolicy_Get();
    if (OpenSslHmacSha256Policy_ConfigIsValid(config))
    {
        size_t index = SolidSyslogPoolAllocator_AcquireFirstFree(&OpenSslHmacSha256Policy_Allocator);
        if (SolidSyslogPoolAllocator_IndexIsValid(&OpenSslHmacSha256Policy_Allocator, index) == true)
        {
            SolidSyslogOpenSslHmacSha256Policy_Initialise(&OpenSslHmacSha256Policy_Pool[index].Base, config);
            handle = &OpenSslHmacSha256Policy_Pool[index].Base;
        }
        else
        {
            OpenSslHmacSha256Policy_Report(
                SOLIDSYSLOG_POOL_EXHAUSTED_SEVERITY,
                SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
                SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_POOL_EXHAUSTED
            );
        }
    }
    else
    {
        OpenSslHmacSha256Policy_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_BAD_CONFIG
        );
    }
    return handle;
}

void SolidSyslogOpenSslHmacSha256Policy_Destroy(struct SolidSyslogSecurityPolicy* base)
{
    size_t index = OpenSslHmacSha256Policy_IndexFromHandle(base);
    bool released = SolidSyslogPoolAllocator_IndexIsValid(&OpenSslHmacSha256Policy_Allocator, index) &&
                    SolidSyslogPoolAllocator_FreeIfInUse(
                        &OpenSslHmacSha256Policy_Allocator,
                        index,
                        OpenSslHmacSha256Policy_CleanupAtIndex,
                        NULL
                    );
    if (!released)
    {
        OpenSslHmacSha256Policy_Report(
            SOLIDSYSLOG_UNKNOWN_DESTROY_SEVERITY,
            SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
            SOLIDSYSLOG_HMAC_SHA256_POLICY_ERROR_UNKNOWN_DESTROY
        );
    }
}

static inline bool OpenSslHmacSha256Policy_ConfigIsValid(const struct SolidSyslogOpenSslHmacSha256PolicyConfig* config)
{
    return (config != NULL) && (config->GetKey != NULL);
}

static inline size_t OpenSslHmacSha256Policy_IndexFromHandle(const struct SolidSyslogSecurityPolicy* base)
{
    size_t result = SOLIDSYSLOG_HMAC_SHA256_POLICY_POOL_SIZE;
    for (size_t poolIndex = 0; poolIndex < SOLIDSYSLOG_HMAC_SHA256_POLICY_POOL_SIZE; poolIndex++)
    {
        if (base == &OpenSslHmacSha256Policy_Pool[poolIndex].Base)
        {
            result = poolIndex;
            break;
        }
    }
    return result;
}

static inline void OpenSslHmacSha256Policy_CleanupAtIndex(size_t index, void* context)
{
    (void) context;
    SolidSyslogOpenSslHmacSha256Policy_Cleanup(&OpenSslHmacSha256Policy_Pool[index].Base);
}
