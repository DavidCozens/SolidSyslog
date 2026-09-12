#include <stdbool.h>
#include <string.h>
#include <stddef.h>

#include "BddTargetMtlsConfig.h"
#include "BddTargetTlsConfig.h"
#include "BddTargetTlsSender.h"
#include "SolidSyslogOpenSslStreamErrors.h"
#include "SolidSyslogPosixAddress.h"
#include "SolidSyslogPosixSleep.h"
#include "SolidSyslogPosixTcpStream.h"
#include "SolidSyslogStreamSender.h"
#include "BddTargetOpenSslCredentials.h"
#include "SolidSyslogOpenSslStream.h"

struct SolidSyslogResolver;

static struct SolidSyslogStream* underlyingStream;

static struct SolidSyslogStream* tlsStream;
static struct SolidSyslogAddress* address;
static struct SolidSyslogSender* sender;

static void BddTargetTlsSender_ApplyCipherPolicy(struct SolidSyslogOpenSslProfile* profile);

static void BddTargetTlsSender_TlsProfile(struct SolidSyslogOpenSslProfile* profile, void* context)
{
    (void) context;
    profile->ServerName = BddTargetTlsConfig_GetServerName();
    BddTargetTlsSender_ApplyCipherPolicy(profile);
}

/* One intent token, two backend-typed fields. A TLS 1.3 connection is not bound
   by a CipherList at all, so a policy that names only the TLS 1.2 half would
   leave 1.3 free to negotiate whatever both ends prefer - which is why both are
   filled here and why the token holds at either version. */
static void BddTargetTlsSender_ApplyCipherPolicy(struct SolidSyslogOpenSslProfile* profile)
{
    const char* policy = BddTargetTlsConfig_GetCipherPolicyName();
    if (strcmp(policy, "offered") == 0)
    {
        profile->CipherList = "ECDHE-RSA-AES128-GCM-SHA256";
        profile->CipherSuites = "TLS_AES_128_GCM_SHA256";
    }
    else if (strcmp(policy, "unoffered") == 0)
    {
        profile->CipherList = "DHE-RSA-AES128-CCM";
        profile->CipherSuites = "TLS_AES_128_CCM_8_SHA256";
    }
    else
    {
        /* "default" - the library's own policy, which is what an integrator who
           supplies no profile gets. */
    }
}

static void BddTargetTlsSender_MtlsProfile(struct SolidSyslogOpenSslProfile* profile, void* context)
{
    (void) context;
    profile->ServerName = BddTargetMtlsConfig_GetServerName();
}

struct SolidSyslogSender* BddTargetTlsSender_Create(struct SolidSyslogResolver* resolver, bool mtls)
{
    if (mtls)
    {
        /* The mutual-TLS transport presents a client credential by default. It
           goes through the same knob a scenario sets, so there is one place the
           credentials backend reads it from and a scenario can still override
           it - which is what the client-credential rotation cell does. */
        (void) BddTargetTlsConfig_SetByName("tls-client", "client");
    }

    underlyingStream = SolidSyslogPosixTcpStream_Create(NULL);

    static struct SolidSyslogOpenSslStreamConfig tlsStreamConfig;
    tlsStreamConfig = (struct SolidSyslogOpenSslStreamConfig) {0};
    tlsStreamConfig.Transport = underlyingStream;
    tlsStreamConfig.Sleep = SolidSyslogPosix_Sleep;
    tlsStreamConfig.Version = BddTargetTlsConfig_GetStreamVersion;
    tlsStreamConfig.Profile = mtls ? BddTargetTlsSender_MtlsProfile : BddTargetTlsSender_TlsProfile;
    tlsStreamConfig.Credentials = BddTargetOpenSslCredentials_Get();
    tlsStream = SolidSyslogOpenSslStream_Create(&tlsStreamConfig);

    address = SolidSyslogPosixAddress_Create();

    static struct SolidSyslogStreamSenderConfig senderConfig;
    senderConfig = (struct SolidSyslogStreamSenderConfig) {0};
    senderConfig.Resolver = resolver;
    senderConfig.Stream = tlsStream;
    senderConfig.Address = address;
    senderConfig.Endpoint = mtls ? BddTargetMtlsConfig_GetEndpoint : BddTargetTlsConfig_GetEndpoint;
    senderConfig.EndpointVersion =
        mtls ? BddTargetMtlsConfig_GetEndpointVersion : BddTargetTlsConfig_GetEndpointVersion;
    sender = SolidSyslogStreamSender_Create(&senderConfig);

    return sender;
}

void BddTargetTlsSender_Destroy(void)
{
    SolidSyslogStreamSender_Destroy(sender);
    SolidSyslogPosixAddress_Destroy(address);
    SolidSyslogOpenSslStream_Destroy(tlsStream);
    SolidSyslogPosixTcpStream_Destroy(underlyingStream);
}

const struct SolidSyslogErrorSource* BddTargetTlsSender_ErrorSource(void)
{
    return &SolidSyslogOpenSslStreamErrorSource;
}
