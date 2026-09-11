/* Shared FreeRTOS BDD-target pipeline - see BddTargetFreeRtosPipeline.h.
 *
 * Extracted from the two near-identical FreeRTOS target main.c files
 * (Bdd/Targets/FreeRtos = FreeRTOS-Plus-TCP, Bdd/Targets/FreeRtosLwip = lwIP)
 * in SolidSyslog S29.03. Everything here is platform-independent; the network
 * backend each target wires stays in its main.c behind the
 * BddTargetFreeRtosPipelineConfig seam. */

#include "BddTargetFreeRtosPipeline.h"

#include "BddTargetEnterpriseId.h"
#include "BddTargetErrorText.h"
#include "BddTargetInteractive.h"
#include "BddTargetIps.h"
#include "BddTargetLanguage.h"
#include "BddTargetSwitchConfig.h"
#include "BddTargetTlsConfig.h"
#include "BddTargetTlsSender.h"
#include "CmsdkUart.h"

#include "SolidSyslog.h"
#include "SolidSyslogAtomicCounter.h"
#include "SolidSyslogBlockStore.h"
#include "SolidSyslogCircularBuffer.h"
#include "SolidSyslogConfig.h"
#include "SolidSyslogCrc16Policy.h"
#include "SolidSyslogEndpoint.h"
#include "SolidSyslogEndpointHost.h"
#include "SolidSyslogError.h"
#include "SolidSyslogFileBlockDevice.h"
#include "SolidSyslogHeaderField.h"
#include "SolidSyslogFreeRtosMutex.h"
#include "SolidSyslogFreeRtosSysUpTime.h"
#include "SolidSyslogMbedTlsAesGcmPolicy.h"
#include "SolidSyslogMbedTlsHmacSha256Policy.h"
#include "SolidSyslogMetaSd.h"
#include "SolidSyslogMutex.h"
#include "SolidSyslogNullSecurityPolicy.h"
#include "SolidSyslogNullStore.h"
#include "SolidSyslogOriginSd.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogStdAtomicCounter.h"
#include "SolidSyslogTimeQuality.h"
#include "SolidSyslogTimeQualitySd.h"
#include "SolidSyslogTunables.h"

#include <FreeRTOS.h>
#include <task.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Unprivileged mirror of SOLIDSYSLOG_UDP_DEFAULT_PORT (514) for BDD listeners. */
#define BDD_TARGET_UDP_PORT 5514U

/* The injected platform seam - set once via BddTargetFreeRtosPipeline_SetConfig
 * before the tasks run. */
static const struct BddTargetFreeRtosPipelineConfig* g_config = NULL;

/* Mutable walking-skeleton state. Defaults populated at boot; the interactive
 * `set <name> <value>` command rewrites these in-place via OnSet. Storage sizes
 * match RFC 5424 maxima where applicable (APP-NAME 48, MSGID 32) plus null
 * terminator; MSG matches SOLIDSYSLOG_MAX_MESSAGE_SIZE; host fits an IPv4
 * dotted-quad or the short DNS alias. */
static char appName[49] = "SolidSyslogBddTarget";
static char messageId[33] = "example";
static char msg[SOLIDSYSLOG_MAX_MESSAGE_SIZE] = "Hello from FreeRTOS";
static char host[16] = "";
static uint16_t port = (uint16_t) BDD_TARGET_UDP_PORT;
static uint32_t endpointVersion = 0U;

static struct SolidSyslogMessage testMessage = {
    .Facility = SOLIDSYSLOG_FACILITY_LOCAL0,
    .Severity = SOLIDSYSLOG_SEVERITY_INFORMATIONAL,
    .MessageId = messageId,
    .Msg = msg,
};

/* CircularBuffer + FreeRtosMutex for cross-task emission. 8 max-sized messages
 * is comfortably above the 3-message BDD scenarios. */
enum
{
    BDD_TARGET_BUFFER_MESSAGES = 8
};

static uint8_t bufferRing[SOLIDSYSLOG_CIRCULAR_BUFFER_RING_BYTES(BDD_TARGET_BUFFER_MESSAGES)];

/* Lifecycle mutex serialises SolidSyslog_Service against the rebuild path
 * (`set store file` swaps NullStore for the file-backed BlockStore) and against
 * teardown. solidSyslogTeardown is set inside the critical section so Service
 * observes it atomically with the destroy and self-deletes before the mutex
 * goes. */
static struct SolidSyslogMutex* lifecycleMutex = NULL;
static struct SolidSyslog* solidSyslog = NULL;
static volatile bool solidSyslogReady = false;
static volatile bool solidSyslogTeardown = false;

/* File-backed store storage. Lives in .bss so it persists across the `set store
 * file` rebuild; only populated when that command fires. STORE_PATH_PREFIX is
 * "/STORE" - sequence-numbered filenames land at the volume root as
 * /STORE00.log, /STORE01.log, ... which fit 8.3 short-filename mode. The leading
 * slash makes the path absolute: ChaN-FatFs treats it as the default-drive root
 * (unchanged behaviour), and FreeRTOS-Plus-FAT's ff_stdio requires an absolute
 * path when ffconfigHAS_CWD is 0 (its prvABSPath is a pass-through). */
static const char STORE_PATH_PREFIX[] = "/STORE";

static struct SolidSyslogFile* storeFile = NULL;
static struct SolidSyslogBlockDevice* storeBlockDevice = NULL;
static struct SolidSyslogStore* currentStore = NULL;
static bool currentStoreIsFile = false;

/* Pending values populated by the `set max-blocks` / `max-block-size` /
 * `discard-policy` / `halt-exit` / `capacity-threshold` / `security-policy` /
 * `no-sd` commands and consumed by `set store file`. */
enum
{
    DEFAULT_PENDING_MAX_BLOCKS = 10,
    DEFAULT_PENDING_MAX_BLOCK_SIZE = 65536,
};

static size_t pendingMaxBlocks = DEFAULT_PENDING_MAX_BLOCKS;
static size_t pendingMaxBlockSize = DEFAULT_PENDING_MAX_BLOCK_SIZE;
static const char* pendingDiscardPolicy = "oldest";
static volatile bool pendingHaltExit = false;
static size_t pendingCapacityThreshold = 0;
/* At-rest integrity policy for the file store: "crc16" (default), "hmac-sha256"
 * (mbedTLS), "aes-256-gcm" (mbedTLS AEAD), or "null". Set before `store file`;
 * consumed by RebuildWithFileStore. currentPolicy holds the created handle so
 * DestroyCurrentStore can release it. */
static const char* pendingSecurityPolicy = "crc16";
static struct SolidSyslogSecurityPolicy* currentPolicy = NULL;
/* The policy kind captured when currentPolicy was built - DestroySecurityPolicy
 * must dispatch on this, NOT pendingSecurityPolicy, which a later `set
 * security-policy` can change out from under the installed policy. */
static const char* installedSecurityPolicy = "crc16";
/* When true, SolidSyslog gets only the meta SD - timeQuality and origin are
 * dropped. Mirrors Linux's --no-sd. */
static volatile bool pendingNoSd = false;

/* Holds the final SolidSyslog config so the rebuild path can rewrite .Store and
 * pass the same struct back into SolidSyslog_Create. */
static struct SolidSyslogConfig solidSyslogConfig;
static struct SolidSyslogStructuredData* sdList[3];
static struct SolidSyslogAtomicCounter* atomicCounter = NULL;
static struct SolidSyslogStructuredData* metaSd = NULL;
static struct SolidSyslogStructuredData* timeQualitySd = NULL;
static struct SolidSyslogStructuredData* originSd = NULL;

static struct SolidSyslogBuffer* buffer = NULL;
static struct SolidSyslogMutex* bufferMutex = NULL;

/* Service task handle is self-registered by ServiceTask so the interactive task
 * can report its peak stack alongside its own on `quit` and bound the teardown
 * wait on a real "service stopped" signal. */
static TaskHandle_t serviceTaskHandle = NULL;
/* The task awaiting ServiceTask's exit during teardown; ServiceTask notifies it
 * the instant before it self-deletes. */
static TaskHandle_t serviceStopWaiter = NULL;

/* Upper bound on the teardown wait for ServiceTask to self-delete. */
enum
{
    SERVICE_STOP_TIMEOUT_MS = 1000,
};

static bool TryUpdateString(char* storage, size_t storageSize, const char* value);
static bool TryParseUInt(const char* value, unsigned long* out);
static bool OnSet(const char* name, const char* value);
static struct SolidSyslogSecurityPolicy* CreateSecurityPolicy(void);
static void DestroySecurityPolicy(void);
static bool RebuildWithFileStore(void);
static void DestroyCurrentStore(void);
static enum SolidSyslogDiscardPolicy MapDiscardPolicy(const char* policy);
static void OnStoreFull(void* context);
static size_t GetCapacityThreshold(void* context);
static void OnThresholdCrossed(void* context);
static void TeardownAll(void);
static void GetAppName(struct SolidSyslogHeaderField* field, void* context);
static void GetTimeQuality(struct SolidSyslogTimeQuality* timeQuality);
static void ErrorHandlerEx(void* context, const struct SolidSyslogErrorEvent* event);

static uint32_t MmioRead32(uintptr_t address)
{
    // NOLINTNEXTLINE(performance-no-int-to-ptr) -- mapping the CMSDK UART MMIO address into a 32-bit volatile pointer.
    return *(volatile uint32_t*) address;
}

static void MmioWrite32(uintptr_t address, uint32_t value)
{
    // NOLINTNEXTLINE(performance-no-int-to-ptr) -- mapping the CMSDK UART MMIO address into a 32-bit volatile pointer.
    *(volatile uint32_t*) address = value;
}

void BddTargetFreeRtosPipeline_Sleep(int milliseconds)
{
    /* Round any non-zero millisecond request up to at least one tick so a
     * sub-tick sleep (e.g. CmsdkUart's 1 ms yield against a 100 Hz tick) still
     * blocks the task instead of busy-spinning. */
    TickType_t ticks = pdMS_TO_TICKS((TickType_t) milliseconds);
    if ((milliseconds > 0) && (ticks == 0U))
    {
        ticks = 1U;
    }
    vTaskDelay(ticks);
}

static const CmsdkUartMemoryAccess MMIO_ACCESS = {MmioRead32, MmioWrite32, BddTargetFreeRtosPipeline_Sleep};

void BddTargetFreeRtosPipeline_InitConsole(uint32_t uartBaseAddress)
{
    CmsdkUart_Init(&MMIO_ACCESS, uartBaseAddress);
}

void BddTargetFreeRtosPipeline_SetConfig(const struct BddTargetFreeRtosPipelineConfig* config)
{
    g_config = config;
}

static void GetAppName(struct SolidSyslogHeaderField* field, void* context)
{
    (void) context;
    SolidSyslogHeaderField_PrintUsAscii(field, appName, strlen(appName));
}

/* No RTC and no time-sync on these reference targets - RFC 5424 §6.2.3.1
 * mandates NILVALUE TIMESTAMP, and the timeQuality SD reports tzKnown=0,
 * isSynced=0. SolidSyslogConfig.Clock=NULL drops through to the library's
 * NilClock. */
static void GetTimeQuality(struct SolidSyslogTimeQuality* timeQuality)
{
    timeQuality->TzKnown = false;
    timeQuality->IsSynced = false;
    timeQuality->SyncAccuracyMicroseconds = SOLIDSYSLOG_SYNC_ACCURACY_OMIT;
}

void BddTargetFreeRtosPipeline_GetEndpoint(struct SolidSyslogEndpoint* endpoint, void* context)
{
    (void) context;
    SolidSyslogEndpointHost_String(endpoint->Host, host, strlen(host));
    endpoint->Port = port;
}

uint32_t BddTargetFreeRtosPipeline_GetEndpointVersion(void* context)
{
    (void) context;
    return endpointVersion;
}

static void ErrorHandlerEx(void* context, const struct SolidSyslogErrorEvent* event)
{
    (void) context;
    const char* sourceName = "<unknown>";
    const struct SolidSyslogErrorSource* source = event->Source;
    if (source != NULL)
    {
        sourceName = source->Name;
    }
    const char* message = BddTargetErrorText_Category(event->Category);
    /* Same marking as the hosted handler: detail codes are per-class, so a step
       needs to know the report came from the TLS-stream role before it can read
       one as a portable code. */
    const struct SolidSyslogErrorSource* tlsSource = BddTargetTlsSender_ErrorSource();
    const char* role = ((tlsSource != NULL) && (source == tlsSource)) ? "role=tls " : "";
    (void) printf(
        "[solidsyslog] severity=%d [%s %scat=%u detail=%ld] %s\n",
        (int) event->Severity,
        sourceName,
        role,
        (unsigned) event->Category,
        (long) event->Detail,
        message
    );
}

static bool OnSet(const char* name, const char* value)
{
    if (strcmp(name, "appname") == 0)
    {
        return TryUpdateString(appName, sizeof(appName), value);
    }
    if (strcmp(name, "msgid") == 0)
    {
        return TryUpdateString(messageId, sizeof(messageId), value);
    }
    if (strcmp(name, "msg") == 0)
    {
        return TryUpdateString(msg, sizeof(msg), value);
    }
    if (strcmp(name, "host") == 0)
    {
        return TryUpdateString(host, sizeof(host), value);
    }
    if (strcmp(name, "port") == 0)
    {
        unsigned long parsed = 0U;
        if (!TryParseUInt(value, &parsed) || parsed == 0U || parsed > UINT16_MAX)
        {
            return false;
        }
        port = (uint16_t) parsed;
        endpointVersion++;
        return true;
    }
    if (strcmp(name, "facility") == 0)
    {
        /* Forward the parsed value unchanged so the library is the single
         * authority on what's valid (out-of-range encodes as PRIVAL 43). */
        unsigned long parsed = 0U;
        if (!TryParseUInt(value, &parsed))
        {
            return false;
        }
        testMessage.Facility = (enum SolidSyslogFacility) parsed;
        return true;
    }
    if (strcmp(name, "severity") == 0)
    {
        unsigned long parsed = 0U;
        if (!TryParseUInt(value, &parsed))
        {
            return false;
        }
        testMessage.Severity = (enum SolidSyslogSeverity) parsed;
        return true;
    }
    if (strcmp(name, "transport") == 0)
    {
        BddTargetSwitchConfig_SetByName(value);
        return true;
    }
    if (strcmp(name, "max-blocks") == 0)
    {
        unsigned long parsed = 0U;
        if (!TryParseUInt(value, &parsed))
        {
            return false;
        }
        pendingMaxBlocks = (size_t) parsed;
        return true;
    }
    if (strcmp(name, "max-block-size") == 0)
    {
        unsigned long parsed = 0U;
        if (!TryParseUInt(value, &parsed))
        {
            return false;
        }
        pendingMaxBlockSize = (size_t) parsed;
        return true;
    }
    if (strcmp(name, "discard-policy") == 0)
    {
        if ((strcmp(value, "oldest") != 0) && (strcmp(value, "newest") != 0) && (strcmp(value, "halt") != 0))
        {
            return false;
        }
        /* String literal storage - target_driver.py emits one of the three
         * literals so the pointer stays valid (no copy needed). */
        pendingDiscardPolicy =
            (strcmp(value, "newest") == 0) ? "newest" : ((strcmp(value, "halt") == 0) ? "halt" : "oldest");
        return true;
    }
    if (strcmp(name, "security-policy") == 0)
    {
        if ((strcmp(value, "crc16") != 0) && (strcmp(value, "hmac-sha256") != 0) &&
            (strcmp(value, "aes-256-gcm") != 0) && (strcmp(value, "null") != 0))
        {
            return false;
        }
        /* String literal storage - see discard-policy above. */
        if (strcmp(value, "hmac-sha256") == 0)
        {
            pendingSecurityPolicy = "hmac-sha256";
        }
        else if (strcmp(value, "aes-256-gcm") == 0)
        {
            pendingSecurityPolicy = "aes-256-gcm";
        }
        else if (strcmp(value, "null") == 0)
        {
            pendingSecurityPolicy = "null";
        }
        else
        {
            pendingSecurityPolicy = "crc16";
        }
        return true;
    }
    if (strcmp(name, "capacity-threshold") == 0)
    {
        unsigned long parsed = 0U;
        if (!TryParseUInt(value, &parsed))
        {
            return false;
        }
        pendingCapacityThreshold = (size_t) parsed;
        return true;
    }
    if (strcmp(name, "halt-exit") == 0)
    {
        /* Harness emits `set halt-exit 1` (or `0`); anything non-zero trips the
         * halt path. Mirrors Linux's bare --halt-exit flag. */
        unsigned long parsed = 0U;
        if (!TryParseUInt(value, &parsed))
        {
            return false;
        }
        pendingHaltExit = (parsed != 0U);
        return true;
    }
    if (strcmp(name, "no-sd") == 0)
    {
        /* `set no-sd 1` drops the SD list to only metaSd - mirrors Linux's
         * --no-sd. Takes effect via SolidSyslog re-Create. */
        unsigned long parsed = 0U;
        if (!TryParseUInt(value, &parsed))
        {
            return false;
        }
        pendingNoSd = (parsed != 0U);
        return true;
    }
    if (strcmp(name, "store") == 0)
    {
        /* "null" is the default state - accept it as a no-op so the harness can
         * pass --store null without special-casing. "file" triggers the rebuild
         * (one-way for the lifetime of this QEMU instance). */
        if (strcmp(value, "null") == 0)
        {
            return true;
        }
        if (strcmp(value, "file") == 0)
        {
            return RebuildWithFileStore();
        }
        return false;
    }
    if (strcmp(name, "shutdown") == 0)
    {
        /* Any non-zero value triggers a full teardown then exits QEMU. The BDD
         * `the client is killed` step on freertos sends `set shutdown 1`. */
        unsigned long parsed = 0U;
        if (!TryParseUInt(value, &parsed))
        {
            return false;
        }
        if (parsed != 0U)
        {
            TeardownAll();
            BddTargetFreeRtosPipeline_Exit(0);
        }
        return true;
    }
    /* Anything left is either a TLS knob or nothing we own; the TLS module says
       which, so its table lives in one place rather than being mirrored here. */
    return BddTargetTlsConfig_SetByName(name, value);
}

static bool TryUpdateString(char* storage, size_t storageSize, const char* value)
{
    size_t length = strlen(value);
    if ((length == 0U) || (length >= storageSize))
    {
        return false;
    }
    memcpy(storage, value, length);
    storage[length] = '\0';
    return true;
}

static bool TryParseUInt(const char* value, unsigned long* out)
{
    if (*value == '\0')
    {
        return false;
    }
    char* end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    /* strtoul accepts a leading '-' and wraps to a huge unsigned. The port call
     * site bounds-checks; facility/severity intentionally don't, mirroring the
     * Linux example's atoi-and-cast so wrapped values encode as PRIVAL 43. */
    if (*end != '\0')
    {
        return false;
    }
    *out = parsed;
    return true;
}

/* DEMO KEY ONLY. A real integrator supplies key material from a secure element,
 * a KDF, or encrypted NVM via their own SolidSyslogKeyFunction - never a
 * hard-coded constant. This exists so the BDD scenario can exercise the mbedTLS
 * HMAC-SHA256 / AES-256-GCM at-rest policies end-to-end with real crypto. */
static bool BddDemoGetKey(void* context, uint8_t* keyOut, size_t capacity, size_t* keyLengthOut)
{
    enum
    {
        DEMO_KEY_SIZE = 32
    };

    (void) context;
    size_t written = (capacity < DEMO_KEY_SIZE) ? capacity : (size_t) DEMO_KEY_SIZE;
    (void) memset(keyOut, 0x5A, written);
    *keyLengthOut = written;
    return true;
}

static struct SolidSyslogSecurityPolicy* CreateSecurityPolicy(void)
{
    /* Latch the kind now so teardown destroys against what we actually built,
     * not whatever `set security-policy` may set afterwards. pendingSecurityPolicy
     * is always one of the four validated string literals. */
    installedSecurityPolicy = pendingSecurityPolicy;
    struct SolidSyslogSecurityPolicy* policy = NULL;
    if (strcmp(pendingSecurityPolicy, "hmac-sha256") == 0)
    {
        static const struct SolidSyslogMbedTlsHmacSha256PolicyConfig hmacConfig = {BddDemoGetKey, NULL};
        policy = SolidSyslogMbedTlsHmacSha256Policy_Create(&hmacConfig);
    }
    else if (strcmp(pendingSecurityPolicy, "aes-256-gcm") == 0)
    {
        /* Reuse the TLS module's already-seeded CTR-DRBG as the AEAD nonce
         * source - see BddTargetTlsSender_GetRng. Not static const: Rng is a
         * runtime handle. */
        const struct SolidSyslogMbedTlsAesGcmPolicyConfig aesConfig =
            {BddDemoGetKey, NULL, BddTargetTlsSender_GetRng()};
        policy = SolidSyslogMbedTlsAesGcmPolicy_Create(&aesConfig);
    }
    else if (strcmp(pendingSecurityPolicy, "null") == 0)
    {
        policy = SolidSyslogNullSecurityPolicy_Get();
    }
    else
    {
        policy = SolidSyslogCrc16Policy_Create();
    }
    return policy;
}

/* `set store file` trigger: swap the default NullStore for a file-backed
 * BlockStore over the platform FS-mount seam. One-way for the lifetime of this
 * QEMU instance. The lifecycle mutex blocks the Service task across the
 * Destroy -> re-Create transition. */
static bool RebuildWithFileStore(void)
{
    SolidSyslogMutex_Lock(lifecycleMutex);

    /* The FS layer does NOT auto-mount on first open - mount (and
     * format-on-first-use) via the platform FS-mount seam before tearing down
     * the existing store so a mount failure leaves the target running on the
     * original NullStore (zero-disruption); return false so OnSet reports the
     * failure to the harness. */
    if (!g_config->MountStore())
    {
        SolidSyslogMutex_Unlock(lifecycleMutex);
        return false;
    }

    solidSyslogReady = false;
    SolidSyslog_Destroy(solidSyslog);
    solidSyslog = NULL;
    DestroyCurrentStore();

    storeFile = g_config->CreateStoreFile();
    storeBlockDevice = SolidSyslogFileBlockDevice_Create(storeFile, STORE_PATH_PREFIX, pendingMaxBlockSize);

    struct SolidSyslogSecurityPolicy* policy = CreateSecurityPolicy();
    currentPolicy = policy;
    struct SolidSyslogBlockStoreConfig storeConfig = {
        .BlockDevice = storeBlockDevice,
        .MaxBlocks = pendingMaxBlocks,
        .DiscardPolicy = MapDiscardPolicy(pendingDiscardPolicy),
        .SecurityPolicy = policy,
        .OnStoreFull = OnStoreFull,
        .StoreFullContext = NULL,
        .GetCapacityThreshold = GetCapacityThreshold,
        .OnThresholdCrossed = OnThresholdCrossed,
        .ThresholdContext = &pendingCapacityThreshold,
    };
    currentStore = SolidSyslogBlockStore_Create(&storeConfig);
    currentStoreIsFile = true;

    solidSyslogConfig.Store = currentStore;
    /* Re-honour `set no-sd 1` if it arrived before this rebuild - target_driver.py
     * sorts `set no-sd` before `set store file`, so the value is final here. */
    solidSyslogConfig.SdCount = pendingNoSd ? 1U : (sizeof(sdList) / sizeof(sdList[0]));
    solidSyslog = SolidSyslog_Create(&solidSyslogConfig);
    solidSyslogReady = true;
    SolidSyslogMutex_Unlock(lifecycleMutex);
    return true;
}

static void DestroySecurityPolicy(void)
{
    if (strcmp(installedSecurityPolicy, "hmac-sha256") == 0)
    {
        SolidSyslogMbedTlsHmacSha256Policy_Destroy(currentPolicy);
    }
    else if (strcmp(installedSecurityPolicy, "aes-256-gcm") == 0)
    {
        SolidSyslogMbedTlsAesGcmPolicy_Destroy(currentPolicy);
    }
    else if (strcmp(installedSecurityPolicy, "crc16") == 0)
    {
        SolidSyslogCrc16Policy_Destroy();
    }
    /* else "null": the shared NullSecurityPolicy is immutable - nothing to free. */
    currentPolicy = NULL;
}

/* Tears down whichever store is currently installed (file-backed or null).
 * The platform DestroyStoreFile hook's Close flushes any buffered dir entry /
 * file data through to the media. */
static void DestroyCurrentStore(void)
{
    if (currentStoreIsFile)
    {
        SolidSyslogBlockStore_Destroy(currentStore);
        SolidSyslogFileBlockDevice_Destroy(storeBlockDevice);
        DestroySecurityPolicy();
        g_config->DestroyStoreFile(storeFile);
    }
    /* else: NullStore is shared and immutable - nothing to destroy. */
}

static enum SolidSyslogDiscardPolicy MapDiscardPolicy(const char* policy)
{
    if (strcmp(policy, "newest") == 0)
    {
        return SOLIDSYSLOG_DISCARD_POLICY_NEWEST;
    }
    if (strcmp(policy, "halt") == 0)
    {
        return SOLIDSYSLOG_DISCARD_POLICY_HALT;
    }
    return SOLIDSYSLOG_DISCARD_POLICY_OLDEST;
}

static void OnStoreFull(void* context)
{
    (void) context;
    if (pendingHaltExit)
    {
        /* Semihosting SYS_EXIT - terminates QEMU with status 2 so the BDD
         * harness sees the run end deterministically. Mirrors the Linux
         * example's _exit(2). */
        BddTargetFreeRtosPipeline_Exit(2);
    }
}

static size_t GetCapacityThreshold(void* context)
{
    return *(const size_t*) context;
}

/* Stdout marker the behave harness watches for. The Linux equivalent writes a
 * host file unreachable from the QEMU guest; instead we print a line-anchored
 * token to the UART, which the captured-stdout reader in syslog_steps.py scans. */
static void OnThresholdCrossed(void* context)
{
    (void) context;
    (void) printf("[THRESHOLD-CROSSED]\r\n");
}

/* Full teardown of every shared resource. Two entry points - `quit` (falls
 * through after BddTargetInteractive_Run returns) and `set shutdown 1` - both
 * route through here. The platform UnmountStore hook fires regardless so the
 * next session's mount finds STORE*.log directory entries up-to-date
 * (power_cycle_replay relies on this). The lifecycle mutex held across the
 * SolidSyslog + store destroy keeps Service from racing the teardown. The
 * platform's network teardown runs last, after the shared resources are
 * released. */
static void TeardownAll(void)
{
    SolidSyslogMutex_Lock(lifecycleMutex);
    serviceStopWaiter = xTaskGetCurrentTaskHandle();
    solidSyslogTeardown = true;
    solidSyslogReady = false;
    SolidSyslog_Destroy(solidSyslog);
    solidSyslog = NULL;
    SolidSyslogOriginSd_Destroy(originSd);
    SolidSyslogTimeQualitySd_Destroy(timeQualitySd);
    SolidSyslogMetaSd_Destroy(metaSd);
    SolidSyslogStdAtomicCounter_Destroy(atomicCounter);
    DestroyCurrentStore();
    g_config->UnmountStore();
    SolidSyslogMutex_Unlock(lifecycleMutex);

    /* Wait for Service to observe the teardown flag and vTaskDelete itself
     * before the lifecycle mutex is destroyed under it. Bounded so a Service
     * task that never started (xTaskCreate failure -> NULL handle) cannot wedge
     * teardown. */
    if (serviceTaskHandle != NULL)
    {
        (void) ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(SERVICE_STOP_TIMEOUT_MS));
    }
    serviceTaskHandle = NULL;

    SolidSyslogCircularBuffer_Destroy(buffer);
    SolidSyslogFreeRtosMutex_Destroy(bufferMutex);
    SolidSyslogFreeRtosMutex_Destroy(lifecycleMutex);
    lifecycleMutex = NULL;

    /* Platform sender + network adapters last. */
    g_config->TeardownNetwork();
}

void BddTargetFreeRtosPipeline_Exit(int status)
{
    /* SYS_EXIT_EXTENDED (0x20) - the only ARM Semihosting exit form on AArch32
     * that propagates a non-zero status: R1 points to a { reason, subcode }
     * block. QEMU terminates the VM; the for(;;) is defensive. */
    const struct
    {
        uint32_t reason;
        uint32_t subcode;
    } args = {0x20026U, (uint32_t) status};

    register int r0 __asm("r0") = 0x20;
    register const void* r1 __asm("r1") = &args;
    __asm volatile("bkpt 0xAB" : "+r"(r0) : "r"(r1) : "memory");
    for (;;)
    {
    }
}

void BddTargetFreeRtosPipeline_InteractiveTask(void* argument)
{
    (void) argument;

    /* Seed the destination host with the platform default before any `set host`. */
    size_t hostLength = strlen(g_config->DefaultHost);
    if (hostLength < sizeof(host))
    {
        memcpy(host, g_config->DefaultHost, hostLength + 1U);
    }

    /* Platform brings up its network and hands back a ready-to-use sender with
     * the default transport already selected. */
    struct SolidSyslogSender* sender = g_config->BuildSender();

    /* CircularBuffer drained by ServiceTask, with a FreeRtosMutex gating
     * concurrent producers. */
    bufferMutex = SolidSyslogFreeRtosMutex_Create();
    buffer = SolidSyslogCircularBuffer_Create(bufferMutex, bufferRing, sizeof(bufferRing));

    /* Lifecycle mutex created up front so the Service task can take it from its
     * very first iteration without a NULL check. */
    lifecycleMutex = SolidSyslogFreeRtosMutex_Create();

    /* Default store is NullStore - flipped to the file-backed BlockStore by
     * `set store file` via RebuildWithFileStore(). */
    currentStore = SolidSyslogNullStore_Get();
    currentStoreIsFile = false;

    atomicCounter = SolidSyslogStdAtomicCounter_Create();
    struct SolidSyslogMetaSdConfig metaConfig = {
        .Counter = atomicCounter,
        .GetSysUpTime = SolidSyslogFreeRtos_GetSysUpTime,
        .GetLanguage = BddTargetLanguage_Get,
    };
    metaSd = SolidSyslogMetaSd_Create(&metaConfig);
    timeQualitySd = SolidSyslogTimeQualitySd_Create(GetTimeQuality);
    struct SolidSyslogOriginSdConfig originConfig = {
        .Software = "SolidSyslogBddTarget",
        .SwVersion = "0.7.0",
        .EnterpriseId = BDD_TARGET_ENTERPRISE_ID,
        .GetIpCount = BddTargetIps_Count,
        .GetIpAt = BddTargetIps_At,
    };
    originSd = SolidSyslogOriginSd_Create(&originConfig);
    sdList[0] = metaSd;
    sdList[1] = timeQualitySd;
    sdList[2] = originSd;

    solidSyslogConfig = (struct SolidSyslogConfig) {
        .Buffer = buffer,
        .Sender = sender,
        .Clock = NULL,
        .GetHostname = g_config->GetHostname,
        .GetAppName = GetAppName,
        /* PROCID - RFC 5424 §6.2.6 NILVALUE: no process model on these targets. */
        .GetProcessId = NULL,
        .Store = currentStore,
        .Sd = sdList,
        .SdCount = pendingNoSd ? 1U : (sizeof(sdList) / sizeof(sdList[0])),
    };
    SolidSyslog_SetErrorHandler(ErrorHandlerEx, NULL);
    solidSyslog = SolidSyslog_Create(&solidSyslogConfig);
    solidSyslogReady = true;

    BddTargetInteractive_Run(solidSyslog, &testMessage, stdin, BddTargetSwitchConfig_SetByName, OnSet);

    /* Peak stack usage report on `quit`. Words, not bytes (StackType_t units).
     * serviceTaskHandle is guarded because uxTaskGetStackHighWaterMark(NULL)
     * means "the calling task". */
    const UBaseType_t interactiveHwm = uxTaskGetStackHighWaterMark(NULL);
    const UBaseType_t serviceHwm = (serviceTaskHandle != NULL) ? uxTaskGetStackHighWaterMark(serviceTaskHandle) : 0U;
    (void) printf(
        "[stack-hwm] interactive=%lu words service=%lu words\n",
        (unsigned long) interactiveHwm,
        (unsigned long) serviceHwm
    );

    TeardownAll();
    vTaskDelete(NULL);
}

void BddTargetFreeRtosPipeline_ServiceTask(void* argument)
{
    (void) argument;
    /* Self-register so the interactive task can report our stack HWM and bound
     * its teardown wait on a real "service stopped" signal. */
    serviceTaskHandle = xTaskGetCurrentTaskHandle();

    /* Wait until the interactive task has finished initial Setup and created the
     * lifecycle mutex / SolidSyslog. After that the mutex is the source of
     * truth - Setup, RebuildWithFileStore, and Teardown all hold it across their
     * Destroy/Create transitions. */
    while ((lifecycleMutex == NULL) || !solidSyslogReady)
    {
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    for (;;)
    {
        SolidSyslogMutex_Lock(lifecycleMutex);
        if (solidSyslogTeardown)
        {
            /* Teardown set this flag inside the lifecycle critical section and is
             * now blocked waiting for us. Capture the waiter under the lock,
             * release, notify it, then self-delete before Teardown destroys the
             * mutex. */
            TaskHandle_t waiter = serviceStopWaiter;
            SolidSyslogMutex_Unlock(lifecycleMutex);
            if (waiter != NULL)
            {
                (void) xTaskNotifyGive(waiter);
            }
            vTaskDelete(NULL);
        }
        if (solidSyslogReady)
        {
            SolidSyslog_Service(solidSyslog);
        }
        SolidSyslogMutex_Unlock(lifecycleMutex);
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}
