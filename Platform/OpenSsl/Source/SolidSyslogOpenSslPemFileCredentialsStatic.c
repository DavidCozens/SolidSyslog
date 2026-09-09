/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogOpenSslPemFileCredentials.h"

#include <stdbool.h>
#include <stddef.h>

#include "SolidSyslogError.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogOpenSslCredentialsDefinition.h"
#include "SolidSyslogOpenSslNullCredentials.h"
#include "SolidSyslogOpenSslPemFileCredentialsPrivate.h"
#include "SolidSyslogPoolAllocator.h"
#include "SolidSyslogTlsFingerprint.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogTunables.h"

static inline size_t OpenSslPemFileCredentials_IndexFromHandle(const struct SolidSyslogOpenSslCredentials* base);
static inline void OpenSslPemFileCredentials_CleanupAtIndex(size_t index, void* context);

static bool OpenSslPemFileCredentials_InUse[SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE];
static struct SolidSyslogOpenSslPemFileCredentials
    OpenSslPemFileCredentials_Pool[SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE];
static struct SolidSyslogPoolAllocator OpenSslPemFileCredentials_Allocator = {
    OpenSslPemFileCredentials_InUse,
    SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE
};

struct SolidSyslogOpenSslCredentials* SolidSyslogOpenSslPemFileCredentials_Create(
    const struct SolidSyslogOpenSslPemFileCredentialsConfig* config
)
{
    struct SolidSyslogOpenSslCredentials* handle = SolidSyslogOpenSslNullCredentials_Get();
    if (config == NULL)
    {
        OpenSslPemFileCredentials_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_OPENSSL_PEM_FILE_CREDENTIALS_ERROR_NULL_CONFIG
        );
    }
    else if (!SolidSyslogTlsFingerprint_ListIsPresent(config->PeerFingerprints, config->PeerFingerprintCount))
    {
        OpenSslPemFileCredentials_Report(
            SOLIDSYSLOG_BAD_CONFIG_FATAL_SEVERITY,
            SOLIDSYSLOG_CAT_BAD_CONFIG,
            SOLIDSYSLOG_OPENSSL_PEM_FILE_CREDENTIALS_ERROR_NULL_PEER_FINGERPRINT
        );
    }
    else
    {
        size_t index = SolidSyslogPoolAllocator_AcquireFirstFree(&OpenSslPemFileCredentials_Allocator);
        if (SolidSyslogPoolAllocator_IndexIsValid(&OpenSslPemFileCredentials_Allocator, index) == true)
        {
            SolidSyslogOpenSslPemFileCredentials_Initialise(&OpenSslPemFileCredentials_Pool[index].Base, config);
            handle = &OpenSslPemFileCredentials_Pool[index].Base;
        }
        else
        {
            OpenSslPemFileCredentials_Report(
                SOLIDSYSLOG_POOL_EXHAUSTED_SEVERITY,
                SOLIDSYSLOG_CAT_POOL_EXHAUSTED,
                SOLIDSYSLOG_OPENSSL_PEM_FILE_CREDENTIALS_ERROR_POOL_EXHAUSTED
            );
        }
    }
    return handle;
}

void SolidSyslogOpenSslPemFileCredentials_Destroy(struct SolidSyslogOpenSslCredentials* base)
{
    size_t index = OpenSslPemFileCredentials_IndexFromHandle(base);
    bool released = SolidSyslogPoolAllocator_IndexIsValid(&OpenSslPemFileCredentials_Allocator, index) &&
                    SolidSyslogPoolAllocator_FreeIfInUse(
                        &OpenSslPemFileCredentials_Allocator,
                        index,
                        OpenSslPemFileCredentials_CleanupAtIndex,
                        NULL
                    );
    if (!released)
    {
        OpenSslPemFileCredentials_Report(
            SOLIDSYSLOG_UNKNOWN_DESTROY_SEVERITY,
            SOLIDSYSLOG_CAT_UNKNOWN_DESTROY,
            SOLIDSYSLOG_OPENSSL_PEM_FILE_CREDENTIALS_ERROR_UNKNOWN_DESTROY
        );
    }
}

static inline size_t OpenSslPemFileCredentials_IndexFromHandle(const struct SolidSyslogOpenSslCredentials* base)
{
    size_t result = SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE;
    for (size_t poolIndex = 0; poolIndex < SOLIDSYSLOG_TLS_CREDENTIALS_POOL_SIZE; poolIndex++)
    {
        if (base == &OpenSslPemFileCredentials_Pool[poolIndex].Base)
        {
            result = poolIndex;
            break;
        }
    }
    return result;
}

static inline void OpenSslPemFileCredentials_CleanupAtIndex(size_t index, void* context)
{
    (void) context;
    (void) index;
}
