/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogMbedTlsPemBufferCredentials.h"

#include <stdbool.h>
#include <stddef.h>

#include "SolidSyslogError.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogMbedTlsCredentialsDefinition.h"
#include "SolidSyslogMbedTlsPemBufferCredentialsPrivate.h"
#include "SolidSyslogMbedTlsNullCredentials.h"
#include "SolidSyslogPoolAllocator.h"
#include "SolidSyslogTlsFingerprint.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogTunables.h"

static inline bool MbedTlsPemBufferCredentials_IsValidConfig(
    const struct SolidSyslogMbedTlsPemBufferCredentialsConfig* config
);
static inline size_t MbedTlsPemBufferCredentials_IndexFromHandle(const struct SolidSyslogMbedTlsCredentials* base);
static inline void MbedTlsPemBufferCredentials_CleanupAtIndex(size_t index, void* context);

static bool MbedTlsPemBufferCredentials_InUse[SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE];
static struct SolidSyslogMbedTlsPemBufferCredentials
    MbedTlsPemBufferCredentials_Pool[SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE];
static struct SolidSyslogPoolAllocator MbedTlsPemBufferCredentials_Allocator = {
    MbedTlsPemBufferCredentials_InUse,
    SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE
};

struct SolidSyslogMbedTlsCredentials* SolidSyslogMbedTlsPemBufferCredentials_Create(
    const struct SolidSyslogMbedTlsPemBufferCredentialsConfig* config
)
{
    struct SolidSyslogMbedTlsCredentials* handle = SolidSyslogMbedTlsNullCredentials_Get();
    if (MbedTlsPemBufferCredentials_IsValidConfig(config))
    {
        size_t index = SolidSyslogPoolAllocator_AcquireFirstFree(&MbedTlsPemBufferCredentials_Allocator);
        if (SolidSyslogPoolAllocator_IndexIsValid(&MbedTlsPemBufferCredentials_Allocator, index) == true)
        {
            SolidSyslogMbedTlsPemBufferCredentials_Initialise(&MbedTlsPemBufferCredentials_Pool[index].Base, config);
            handle = &MbedTlsPemBufferCredentials_Pool[index].Base;
        }
        else
        {
            MbedTlsPemBufferCredentials_Report(
                SOLIDSYSLOG_POOL_EXHAUSTED_SEVERITY,
                SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
                SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_POOL_EXHAUSTED
            );
        }
    }
    return handle;
}

/* The RNG is checked here rather than where it is used, so a wiring fault is
 * one Create-time report instead of a surprise on the first connection - Mbed
 * TLS needs one to parse a private key at all. */
static inline bool MbedTlsPemBufferCredentials_IsValidConfig(
    const struct SolidSyslogMbedTlsPemBufferCredentialsConfig* config
)
{
    bool valid = false;
    if (config == NULL)
    {
        MbedTlsPemBufferCredentials_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_NULL_CONFIG
        );
    }
    else if (config->Rng == NULL)
    {
        MbedTlsPemBufferCredentials_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_NULL_RNG
        );
    }
    else if (!SolidSyslogTlsFingerprint_ListIsPresent(config->PeerFingerprints, config->PeerFingerprintCount))
    {
        MbedTlsPemBufferCredentials_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_NULL_PEER_FINGERPRINT
        );
    }
    else
    {
        valid = true;
    }
    return valid;
}

void SolidSyslogMbedTlsPemBufferCredentials_Destroy(struct SolidSyslogMbedTlsCredentials* base)
{
    size_t index = MbedTlsPemBufferCredentials_IndexFromHandle(base);
    bool released = SolidSyslogPoolAllocator_IndexIsValid(&MbedTlsPemBufferCredentials_Allocator, index) &&
                    SolidSyslogPoolAllocator_FreeIfInUse(
                        &MbedTlsPemBufferCredentials_Allocator,
                        index,
                        MbedTlsPemBufferCredentials_CleanupAtIndex,
                        NULL
                    );
    if (!released)
    {
        MbedTlsPemBufferCredentials_Report(
            SOLIDSYSLOG_UNKNOWN_DESTROY_SEVERITY,
            SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
            SOLIDSYSLOG_MBEDTLS_PEM_BUFFER_CREDENTIALS_ERROR_UNKNOWN_DESTROY
        );
    }
}

static inline size_t MbedTlsPemBufferCredentials_IndexFromHandle(const struct SolidSyslogMbedTlsCredentials* base)
{
    size_t result = SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE;
    for (size_t poolIndex = 0; poolIndex < SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE; poolIndex++)
    {
        if (base == &MbedTlsPemBufferCredentials_Pool[poolIndex].Base)
        {
            result = poolIndex;
            break;
        }
    }
    return result;
}

/* Destroying a source part way through a connection must not leave a parsed
 * private key in a slot the pool is about to hand out again. */
static inline void MbedTlsPemBufferCredentials_CleanupAtIndex(size_t index, void* context)
{
    (void) context;
    SolidSyslogMbedTlsPemBufferCredentials_Cleanup(&MbedTlsPemBufferCredentials_Pool[index].Base);
}
