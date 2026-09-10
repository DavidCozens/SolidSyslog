#include "BddTargetTlsConfig.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "SolidSyslogEndpoint.h"
#include "SolidSyslogEndpointHost.h"
#include "SolidSyslogTransport.h"

/* Test CA for BDD. Paths are relative to the working directory the example is
 * launched from (/workspaces/SolidSyslog in the BDD container). */
static const char* const BDD_TARGET_TLS_CA_BUNDLE_PATH = "Bdd/syslog-ng/tls/ca.pem";

/* The value that means something other than itself, wherever a knob has to be
 * able to say "nothing" over a protocol that only carries strings. */
static const char* const BDD_TARGET_TLS_NONE = "none";

enum
{
    BDD_TARGET_TLS_MAX_PATH = 128,
    /* A sha-256 pin in the RFC 5425 4.2.2 form is 103 characters. */
    BDD_TARGET_TLS_MAX_FINGERPRINT = 160,
    BDD_TARGET_TLS_MAX_NAME = 64
};

static const char* tlsHost;
static const char* tlsServerName;
static bool serverNameSuppressed;
static uint16_t tlsPort;
static const char* caBundlePath;
static char caBundleStorage[BDD_TARGET_TLS_MAX_PATH];
static char hostStorage[BDD_TARGET_TLS_MAX_NAME];
static char serverNameStorage[BDD_TARGET_TLS_MAX_NAME];
static char fingerprintStorage[BDD_TARGET_TLS_MAX_FINGERPRINTS][BDD_TARGET_TLS_MAX_FINGERPRINT];
static const char* fingerprints[BDD_TARGET_TLS_MAX_FINGERPRINTS];
static size_t fingerprintCount;
static uint32_t version;
static bool defaultsApplied;

static void TlsConfig_EnsureDefaults(void);
static bool TlsConfig_Store(char* destination, size_t size, const char* value);
static bool TlsConfig_SetPort(const char* value);
static bool TlsConfig_SetCaBundlePath(const char* value);
static bool TlsConfig_SetName(const char* value);
static bool TlsConfig_AddFingerprint(const char* value);

void BddTargetTlsConfig_Reset(void)
{
    defaultsApplied = true;
    tlsHost = "syslog-ng";
    tlsServerName = NULL;
    serverNameSuppressed = false;
    tlsPort = (uint16_t) SOLIDSYSLOG_TLS_DEFAULT_PORT;
    caBundlePath = BDD_TARGET_TLS_CA_BUNDLE_PATH;
    fingerprintCount = 0;
    version = 0;
}

void BddTargetTlsConfig_SetHost(const char* host)
{
    TlsConfig_EnsureDefaults();
    if (host != NULL)
    {
        tlsHost = host;
        version++;
    }
}

void BddTargetTlsConfig_SetServerName(const char* serverName)
{
    TlsConfig_EnsureDefaults();
    if (serverName != NULL)
    {
        tlsServerName = serverName;
        serverNameSuppressed = false;
        version++;
    }
}

const char* BddTargetTlsConfig_GetHost(void)
{
    TlsConfig_EnsureDefaults();
    return tlsHost;
}

/* Every entry point starts here, so a target that never calls Reset still sees
   the defaults whichever function it reaches first. A setter needs it as much
   as a getter: main.c calls SetHost before anything reads a port. */
static void TlsConfig_EnsureDefaults(void)
{
    if (!defaultsApplied)
    {
        BddTargetTlsConfig_Reset();
    }
}

uint16_t BddTargetTlsConfig_GetPort(void)
{
    TlsConfig_EnsureDefaults();
    return tlsPort;
}

const char* BddTargetTlsConfig_GetCaBundlePath(void)
{
    TlsConfig_EnsureDefaults();
    return caBundlePath;
}

const char* BddTargetTlsConfig_GetServerName(void)
{
    TlsConfig_EnsureDefaults();
    const char* result = NULL;
    if (!serverNameSuppressed)
    {
        result = (tlsServerName != NULL) ? tlsServerName : BddTargetTlsConfig_GetHost();
    }
    return result;
}

const char* const * BddTargetTlsConfig_GetPeerFingerprints(void)
{
    TlsConfig_EnsureDefaults();
    return fingerprints;
}

size_t BddTargetTlsConfig_GetPeerFingerprintCount(void)
{
    TlsConfig_EnsureDefaults();
    return fingerprintCount;
}

void BddTargetTlsConfig_GetEndpoint(struct SolidSyslogEndpoint* endpoint, void* context)
{
    (void) context;
    SolidSyslogEndpointHost_String(endpoint->Host, BddTargetTlsConfig_GetHost(), SOLIDSYSLOG_MAX_HOST_SIZE);
    endpoint->Port = BddTargetTlsConfig_GetPort();
}

uint32_t BddTargetTlsConfig_GetEndpointVersion(void* context)
{
    (void) context;
    TlsConfig_EnsureDefaults();
    return version;
}

uint32_t BddTargetTlsConfig_GetStreamVersion(void* context)
{
    return BddTargetTlsConfig_GetEndpointVersion(context);
}

bool BddTargetTlsConfig_SetByName(const char* name, const char* value)
{
    TlsConfig_EnsureDefaults();

    bool applied = false;
    if (strcmp(name, "tls-host") == 0)
    {
        applied = TlsConfig_Store(hostStorage, sizeof(hostStorage), value);
        if (applied)
        {
            tlsHost = hostStorage;
        }
    }
    else if (strcmp(name, "tls-port") == 0)
    {
        applied = TlsConfig_SetPort(value);
    }
    else if (strcmp(name, "tls-ca") == 0)
    {
        applied = TlsConfig_SetCaBundlePath(value);
    }
    else if (strcmp(name, "tls-name") == 0)
    {
        applied = TlsConfig_SetName(value);
    }
    else if (strcmp(name, "tls-pin") == 0)
    {
        applied = TlsConfig_AddFingerprint(value);
    }
    else
    {
        /* Not a name this module owns, so the caller tries another handler. */
    }

    if (applied)
    {
        version++;
    }
    return applied;
}

static bool TlsConfig_Store(char* destination, size_t size, const char* value)
{
    size_t length = strlen(value);
    bool fits = length < size;
    if (fits)
    {
        memcpy(destination, value, length);
        destination[length] = '\0';
    }
    return fits;
}

static bool TlsConfig_SetPort(const char* value)
{
    char* end = NULL;
    long parsed = strtol(value, &end, 10);
    bool ok = (end != value) && (*end == '\0') && (parsed > 0) && (parsed <= UINT16_MAX);
    if (ok)
    {
        tlsPort = (uint16_t) parsed;
    }
    return ok;
}

static bool TlsConfig_SetCaBundlePath(const char* value)
{
    bool ok = true;
    if (strcmp(value, BDD_TARGET_TLS_NONE) == 0)
    {
        caBundlePath = NULL;
    }
    else
    {
        ok = TlsConfig_Store(caBundleStorage, sizeof(caBundleStorage), value);
        if (ok)
        {
            caBundlePath = caBundleStorage;
        }
    }
    return ok;
}

static bool TlsConfig_SetName(const char* value)
{
    bool ok = true;
    if (strcmp(value, BDD_TARGET_TLS_NONE) == 0)
    {
        serverNameSuppressed = true;
    }
    else
    {
        ok = TlsConfig_Store(serverNameStorage, sizeof(serverNameStorage), value);
        if (ok)
        {
            serverNameSuppressed = false;
            tlsServerName = serverNameStorage;
        }
    }
    return ok;
}

static bool TlsConfig_AddFingerprint(const char* value)
{
    bool ok = true;
    if (strcmp(value, BDD_TARGET_TLS_NONE) == 0)
    {
        fingerprintCount = 0;
    }
    else if (fingerprintCount >= (size_t) BDD_TARGET_TLS_MAX_FINGERPRINTS)
    {
        ok = false;
    }
    else
    {
        char* slot = fingerprintStorage[fingerprintCount];
        ok = TlsConfig_Store(slot, (size_t) BDD_TARGET_TLS_MAX_FINGERPRINT, value);
        if (ok)
        {
            fingerprints[fingerprintCount] = slot;
            fingerprintCount++;
        }
    }
    return ok;
}
