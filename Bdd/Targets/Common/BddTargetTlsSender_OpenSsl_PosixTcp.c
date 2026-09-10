#include <stdbool.h>
#include <stddef.h>

#include "BddTargetMtlsConfig.h"
#include "BddTargetTlsConfig.h"
#include "BddTargetTlsSender.h"
#include "SolidSyslogPosixAddress.h"
#include "SolidSyslogPosixSleep.h"
#include "SolidSyslogPosixTcpStream.h"
#include "SolidSyslogStreamSender.h"
#include "SolidSyslogOpenSslPemFileCredentials.h"
#include "SolidSyslogOpenSslStream.h"

struct SolidSyslogResolver;

static struct SolidSyslogStream* underlyingStream;

static struct SolidSyslogOpenSslCredentials* credentials;
static struct SolidSyslogStream* tlsStream;
static struct SolidSyslogAddress* address;
static struct SolidSyslogSender* sender;

static void BddTargetTlsSender_TlsProfile(struct SolidSyslogOpenSslProfile* profile, void* context)
{
    (void) context;
    profile->ServerName = BddTargetTlsConfig_GetServerName();
}

static void BddTargetTlsSender_MtlsProfile(struct SolidSyslogOpenSslProfile* profile, void* context)
{
    (void) context;
    profile->ServerName = BddTargetMtlsConfig_GetServerName();
}

struct SolidSyslogSender* BddTargetTlsSender_Create(struct SolidSyslogResolver* resolver, bool mtls)
{
    underlyingStream = SolidSyslogPosixTcpStream_Create(NULL);

    static struct SolidSyslogOpenSslStreamConfig tlsStreamConfig;
    tlsStreamConfig = (struct SolidSyslogOpenSslStreamConfig) {0};
    tlsStreamConfig.Transport = underlyingStream;
    tlsStreamConfig.Sleep = SolidSyslogPosix_Sleep;
    tlsStreamConfig.Version = BddTargetTlsConfig_GetStreamVersion;
    tlsStreamConfig.Profile = mtls ? BddTargetTlsSender_MtlsProfile : BddTargetTlsSender_TlsProfile;
    static struct SolidSyslogOpenSslPemFileCredentialsConfig credentialsConfig;
    credentialsConfig = (struct SolidSyslogOpenSslPemFileCredentialsConfig) {0};
    if (mtls)
    {
        credentialsConfig.CaBundlePath = BddTargetMtlsConfig_GetCaBundlePath();
        credentialsConfig.ClientCertChainPath = BddTargetMtlsConfig_GetClientCertChainPath();
        credentialsConfig.ClientKeyPath = BddTargetMtlsConfig_GetClientKeyPath();
    }
    else
    {
        credentialsConfig.CaBundlePath = BddTargetTlsConfig_GetCaBundlePath();
    }
    credentials = SolidSyslogOpenSslPemFileCredentials_Create(&credentialsConfig);
    tlsStreamConfig.Credentials = credentials;
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
    SolidSyslogOpenSslPemFileCredentials_Destroy(credentials);
    SolidSyslogPosixTcpStream_Destroy(underlyingStream);
}
