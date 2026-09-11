#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include "BddTargetAppName.h"
#include "BddTargetCommandLine.h"
#include "BddTargetEnterpriseId.h"
#include "BddTargetInteractive.h"
#include "BddTargetIps.h"
#include "BddTargetLanguage.h"
#include "BddTargetMtlsConfig.h"
#include "BddTargetServiceThread.h"
#include "BddTargetStderrErrorHandler.h"
#include "BddTargetSwitchConfig.h"
#include "BddTargetTcpConfig.h"
#include "BddTargetTlsConfig.h"
#include "BddTargetTlsSender.h"
#include "BddTargetUdpConfig.h"
#include "SolidSyslog.h"
#include "SolidSyslogStdAtomicCounter.h"
#include "SolidSyslogTunables.h"
#include "SolidSyslogConfig.h"
#include "SolidSyslogCrc16Policy.h"
#include "SolidSyslogNullSecurityPolicy.h"
#include "SolidSyslogOpenSslHmacSha256Policy.h"
#include "SolidSyslogOpenSslAesGcmPolicy.h"
#include "SolidSyslogFileBlockDevice.h"
#include "SolidSyslogBlockStore.h"
#include "SolidSyslogMetaSd.h"
#include "SolidSyslogOriginSd.h"
#include "SolidSyslogTimeQualitySd.h"
#include "SolidSyslogNullStore.h"
#include "SolidSyslogPosixClock.h"
#include "SolidSyslogPosixFile.h"
#include "SolidSyslogPosixHostname.h"
#include "SolidSyslogPosixMessageQueueBuffer.h"
#include "SolidSyslogPosixProcessId.h"
#include "SolidSyslogPosixSleep.h"
#include "SolidSyslogPosixSysUpTime.h"
#include "SolidSyslogPosixResolver.h"
#include "SolidSyslogPosixAddress.h"
#include "SolidSyslogPosixDatagram.h"
#include "SolidSyslogPosixTcpStream.h"
#include "SolidSyslogSwitchingSender.h"
#include "SolidSyslogStreamSender.h"
#include "SolidSyslogUdpSender.h"
#include "SolidSyslogTimeQuality.h"

struct SolidSyslogStore;

static const char* const STORE_PATH_PREFIX = "/tmp/STORE";
static const char* const THRESHOLD_MARKER_PATH = "/tmp/solidsyslog_threshold_marker.log";
static struct SolidSyslogFile* storeFile;
static struct SolidSyslogBlockDevice* storeBlockDevice;
static struct SolidSyslogStream* plainTcpStream;
static struct SolidSyslogAddress* plainTcpAddress;
static struct SolidSyslogSender* plainTcpSender;
static struct SolidSyslogSender* udpSender;
static struct SolidSyslogSender* switchingSender;
static struct SolidSyslogDatagram* udpDatagram;
static struct SolidSyslogAddress* udpAddress;
static struct SolidSyslogResolver* sharedResolver;
/* Holds the created at-rest SecurityPolicy handle so DestroyStore can release
 * it. The keyed policies (hmac-sha256, aes-256-gcm) need the handle to destroy;
 * crc16 is dispatched by name to its singleton Destroy, and null needs no
 * cleanup. */
static struct SolidSyslogSecurityPolicy* securityPolicy;

static void GetTimeQuality(struct SolidSyslogTimeQuality* timeQuality)
{
    timeQuality->TzKnown = true;
    timeQuality->IsSynced = true;
    timeQuality->SyncAccuracyMicroseconds = SOLIDSYSLOG_SYNC_ACCURACY_OMIT;
}

static volatile bool shutdown_flag;
static struct SolidSyslog* solidSyslog;

static void* ServiceThreadEntry(void* arg)
{
    volatile bool* shutdown = (volatile bool*) arg;
    BddTargetServiceThread_Run(solidSyslog, shutdown, SolidSyslogPosix_Sleep);
    return NULL;
}

static struct SolidSyslogSender* CreateSender(const struct BddTargetOptions* options)
{
    bool mtlsModeActive = (strcmp(options->Transport, "mtls") == 0);

    sharedResolver = SolidSyslogPosixResolver_Create();
    struct SolidSyslogResolver* resolver = sharedResolver;

    udpDatagram = SolidSyslogPosixDatagram_Create();
    udpAddress = SolidSyslogPosixAddress_Create();
    static struct SolidSyslogUdpSenderConfig udpConfig = {0};
    udpConfig.Resolver = resolver;
    udpConfig.Datagram = udpDatagram;
    udpConfig.Address = udpAddress;
    udpConfig.Endpoint = BddTargetUdpConfig_GetEndpoint;
    udpConfig.EndpointVersion = BddTargetUdpConfig_GetEndpointVersion;
    udpSender = SolidSyslogUdpSender_Create(&udpConfig);

    plainTcpStream = SolidSyslogPosixTcpStream_Create(NULL);
    plainTcpAddress = SolidSyslogPosixAddress_Create();
    static struct SolidSyslogStreamSenderConfig tcpConfig = {0};
    tcpConfig.Resolver = resolver;
    tcpConfig.Stream = plainTcpStream;
    tcpConfig.Address = plainTcpAddress;
    tcpConfig.Endpoint = BddTargetTcpConfig_GetEndpoint;
    tcpConfig.EndpointVersion = BddTargetTcpConfig_GetEndpointVersion;
    plainTcpSender = SolidSyslogStreamSender_Create(&tcpConfig);

    struct SolidSyslogSender* tlsSender = BddTargetTlsSender_Create(resolver, mtlsModeActive);

    static struct SolidSyslogSender* inners[BDD_TARGET_SWITCH_COUNT];
    inners[BDD_TARGET_SWITCH_UDP] = udpSender;
    inners[BDD_TARGET_SWITCH_TCP] = plainTcpSender;
    inners[BDD_TARGET_SWITCH_TLS] = tlsSender;

    static struct SolidSyslogSwitchingSenderConfig switchConfig = {0};
    switchConfig.Senders = inners;
    switchConfig.SenderCount = BDD_TARGET_SWITCH_COUNT;
    switchConfig.Selector = BddTargetSwitchConfig_Selector;

    BddTargetSwitchConfig_SetByName(options->Transport);
    switchingSender = SolidSyslogSwitchingSender_Create(&switchConfig);
    return switchingSender;
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

static volatile bool haltExit;

static void OnStoreFull(void* context)
{
    (void) context;
    if (haltExit)
    {
        _exit(2);
    }
}

static size_t GetCapacityThreshold(void* context)
{
    return *(const size_t*) context;
}

static void OnThresholdCrossed(void* context)
{
    (void) context;
    FILE* fp = fopen(THRESHOLD_MARKER_PATH, "a");
    if (fp != NULL)
    {
        fputs("crossed\n", fp);
        fclose(fp);
    }
}

/* DEMO KEY ONLY. A real integrator supplies key material from a secure element,
 * a KDF, or encrypted NVM via their own SolidSyslogKeyFunction - never a
 * hard-coded constant. This exists so the BDD scenario can exercise the OpenSSL
 * HMAC-SHA256 at-rest policy end-to-end with real crypto. */
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

static struct SolidSyslogSecurityPolicy* CreateSecurityPolicy(const struct BddTargetOptions* options)
{
    struct SolidSyslogSecurityPolicy* policy = NULL;
    if (strcmp(options->SecurityPolicy, "hmac-sha256") == 0)
    {
        static const struct SolidSyslogOpenSslHmacSha256PolicyConfig hmacConfig = {BddDemoGetKey, NULL};
        policy = SolidSyslogOpenSslHmacSha256Policy_Create(&hmacConfig);
    }
    else if (strcmp(options->SecurityPolicy, "aes-256-gcm") == 0)
    {
        static const struct SolidSyslogOpenSslAesGcmPolicyConfig aesConfig = {BddDemoGetKey, NULL};
        policy = SolidSyslogOpenSslAesGcmPolicy_Create(&aesConfig);
    }
    else if (strcmp(options->SecurityPolicy, "null") == 0)
    {
        policy = SolidSyslogNullSecurityPolicy_Get();
    }
    else
    {
        policy = SolidSyslogCrc16Policy_Create();
    }
    return policy;
}

static struct SolidSyslogStore* CreateStore(const struct BddTargetOptions* options)
{
    bool useFile = (strcmp(options->Store, "file") == 0);

    if (useFile)
    {
        storeFile = SolidSyslogPosixFile_Create();

        storeBlockDevice = SolidSyslogFileBlockDevice_Create(storeFile, STORE_PATH_PREFIX, options->MaxBlockSize);

        static size_t capacityThreshold;
        capacityThreshold = options->CapacityThreshold;
        securityPolicy = CreateSecurityPolicy(options);
        static struct SolidSyslogBlockStoreConfig storeConfig = {0};
        storeConfig.BlockDevice = storeBlockDevice;
        storeConfig.MaxBlocks = options->MaxBlocks;
        storeConfig.DiscardPolicy = MapDiscardPolicy(options->DiscardPolicy);
        storeConfig.SecurityPolicy = securityPolicy;
        storeConfig.OnStoreFull = OnStoreFull;
        storeConfig.GetCapacityThreshold = GetCapacityThreshold;
        storeConfig.OnThresholdCrossed = OnThresholdCrossed;
        storeConfig.ThresholdContext = &capacityThreshold;

        return SolidSyslogBlockStore_Create(&storeConfig);
    }

    return SolidSyslogNullStore_Get();
}

static void DestroySender(void)
{
    SolidSyslogSwitchingSender_Destroy(switchingSender);
    BddTargetTlsSender_Destroy();
    SolidSyslogStreamSender_Destroy(plainTcpSender);
    SolidSyslogPosixAddress_Destroy(plainTcpAddress);
    SolidSyslogPosixTcpStream_Destroy(plainTcpStream);
    SolidSyslogUdpSender_Destroy(udpSender);
    SolidSyslogPosixAddress_Destroy(udpAddress);
    SolidSyslogPosixDatagram_Destroy(udpDatagram);
    SolidSyslogPosixResolver_Destroy(sharedResolver);
}

static void DestroySecurityPolicy(const struct BddTargetOptions* options)
{
    if (strcmp(options->SecurityPolicy, "hmac-sha256") == 0)
    {
        SolidSyslogOpenSslHmacSha256Policy_Destroy(securityPolicy);
    }
    else if (strcmp(options->SecurityPolicy, "aes-256-gcm") == 0)
    {
        SolidSyslogOpenSslAesGcmPolicy_Destroy(securityPolicy);
    }
    else if (strcmp(options->SecurityPolicy, "crc16") == 0)
    {
        SolidSyslogCrc16Policy_Destroy();
    }
    /* else "null": the shared NullSecurityPolicy is immutable - nothing to free. */
    securityPolicy = NULL;
}

static void DestroyStore(struct SolidSyslogStore* store, const struct BddTargetOptions* options)
{
    bool useFile = (strcmp(options->Store, "file") == 0);

    if (useFile)
    {
        SolidSyslogBlockStore_Destroy(store);
        SolidSyslogFileBlockDevice_Destroy(storeBlockDevice);
        DestroySecurityPolicy(options);
        SolidSyslogPosixFile_Destroy(storeFile);
    }
    /* else: NullStore is shared and immutable - nothing to destroy. */
}

/* Two owners of `set` names on this target, tried in turn: the error handler's
   own knob first, then everything BddTargetTlsConfig owns. */
static bool OnSet(const char* name, const char* value)
{
    bool applied = BddTargetStderrErrorHandler_SetByName(name, value);
    if (!applied)
    {
        applied = BddTargetTlsConfig_SetByName(name, value);
    }
    return applied;
}

int main(int argc, char* argv[])
{
    BddTargetStderrErrorHandler_Install();
    BddTargetStderrErrorHandler_SetTlsSource(BddTargetTlsSender_ErrorSource());

    /* BDD harness can override the TLS/mTLS host (defaults to "syslog-ng",
       the Linux compose service name). Same env-var contract as the Windows
       example so behave can target either oracle. */
    BddTargetTlsConfig_SetHost(getenv("SOLIDSYSLOG_BDD_TLS_HOST"));
    BddTargetMtlsConfig_SetHost(getenv("SOLIDSYSLOG_BDD_MTLS_HOST"));

    struct BddTargetOptions options;
    if (BddTargetCommandLine_Parse(argc, argv, &options) != 0)
    {
        return 1;
    }

    /* Honour --app-name when supplied (BDD scenarios pin it for record-size
       parity across runners); otherwise derive from argv[0] as before. */
    BddTargetAppName_Set((options.AppName != NULL) ? options.AppName : argv[0]);

    struct SolidSyslogSender* sender = CreateSender(&options);
    struct SolidSyslogStore* store = CreateStore(&options);

    struct SolidSyslogBuffer* buffer = SolidSyslogPosixMessageQueueBuffer_Create(SOLIDSYSLOG_MAX_MESSAGE_SIZE, 10);
    struct SolidSyslogAtomicCounter* counter = SolidSyslogStdAtomicCounter_Create();
    struct SolidSyslogMetaSdConfig metaConfig = {
        .Counter = counter,
        .GetSysUpTime = SolidSyslogPosix_GetSysUpTime,
        .GetLanguage = BddTargetLanguage_Get,
    };
    struct SolidSyslogStructuredData* metaSd = SolidSyslogMetaSd_Create(&metaConfig);

    struct SolidSyslogStructuredData* timeQuality = SolidSyslogTimeQualitySd_Create(GetTimeQuality);
    struct SolidSyslogOriginSdConfig originConfig = {
        .Software = "SolidSyslogBddTarget",
        .SwVersion = "0.7.0",
        .EnterpriseId = BDD_TARGET_ENTERPRISE_ID,
        .GetIpCount = BddTargetIps_Count,
        .GetIpAt = BddTargetIps_At,
    };
    struct SolidSyslogStructuredData* originSd = SolidSyslogOriginSd_Create(&originConfig);

    struct SolidSyslogStructuredData* sdList[3] = {metaSd, timeQuality, originSd};
    size_t sdCount = options.NoSd ? 1 : 3;

    struct SolidSyslogConfig config = {
        .Buffer = buffer,
        .Sender = sender,
        .Clock = SolidSyslogPosix_GetTimestamp,
        .GetHostname = SolidSyslogPosix_GetHostname,
        .GetAppName = BddTargetAppName_Get,
        .GetProcessId = SolidSyslogPosix_GetProcessId,
        .Store = store,
        .Sd = sdList,
        .SdCount = sdCount,
    };
    solidSyslog = SolidSyslog_Create(&config);

    shutdown_flag = false;
    haltExit = options.HaltExit;

    pthread_t serviceThread = 0;
    pthread_create(&serviceThread, NULL, ServiceThreadEntry, (void*) &shutdown_flag);

    struct SolidSyslogMessage message = {
        .Facility = options.Facility,
        .Severity = options.Severity,
        .MessageId = options.MessageId,
        .Msg = options.Msg,
    };

    BddTargetInteractive_Run(solidSyslog, &message, stdin, BddTargetSwitchConfig_SetByName, OnSet);

    shutdown_flag = true;
    pthread_join(serviceThread, NULL);

    SolidSyslog_Destroy(solidSyslog);
    SolidSyslogOriginSd_Destroy(originSd);
    SolidSyslogTimeQualitySd_Destroy(timeQuality);
    SolidSyslogMetaSd_Destroy(metaSd);
    SolidSyslogStdAtomicCounter_Destroy(counter);
    DestroyStore(store, &options);
    SolidSyslogPosixMessageQueueBuffer_Destroy(buffer);
    DestroySender();

    return 0;
}
