#include "BddTargetMbedTlsCredentials.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include "BddTargetSwitchConfig.h"
#include "BddTargetTlsConfig.h"
#include "SolidSyslogMbedTlsCredentialsDefinition.h"
#include "SolidSyslogTlsCredentialsInstalled.h"

static mbedtls_x509_crt* trustedAuthorityChain;
static mbedtls_x509_crt* otherAuthorityChain;
static mbedtls_x509_crt* clientCertificate;
static mbedtls_pk_context* clientPrivateKey;

static bool BddTargetMbedTlsCredentials_Install(
    struct SolidSyslogMbedTlsCredentials* self,
    struct mbedtls_ssl_config* conf,
    struct SolidSyslogTlsCredentialsInstalled* installed
);
static void BddTargetMbedTlsCredentials_Release(struct SolidSyslogMbedTlsCredentials* self);
static mbedtls_x509_crt* BddTargetMbedTlsCredentials_SelectedAuthority(void);

static struct SolidSyslogMbedTlsCredentials credentials = {
    BddTargetMbedTlsCredentials_Install,
    BddTargetMbedTlsCredentials_Release
};

void BddTargetMbedTlsCredentials_Wire(
    mbedtls_x509_crt* trustedAuthority,
    mbedtls_x509_crt* otherAuthority,
    mbedtls_x509_crt* clientCertChain,
    mbedtls_pk_context* clientKey
)
{
    trustedAuthorityChain = trustedAuthority;
    otherAuthorityChain = otherAuthority;
    clientCertificate = clientCertChain;
    clientPrivateKey = clientKey;
}

struct SolidSyslogMbedTlsCredentials* BddTargetMbedTlsCredentials_Get(void)
{
    return &credentials;
}

/* Asked once per connection, so everything a scenario set at the prompt is read
   here rather than remembered from startup. Returns true throughout: whether an
   absent anchor is acceptable is the stream's decision, not this backend's. */
static bool BddTargetMbedTlsCredentials_Install(
    struct SolidSyslogMbedTlsCredentials* self,
    struct mbedtls_ssl_config* conf,
    struct SolidSyslogTlsCredentialsInstalled* installed
)
{
    (void) self;
    installed->Fingerprints = BddTargetTlsConfig_GetPeerFingerprints();
    installed->FingerprintCount = BddTargetTlsConfig_GetPeerFingerprintCount();

    mbedtls_x509_crt* anchors = BddTargetMbedTlsCredentials_SelectedAuthority();
    installed->TrustAnchorsInstalled = anchors != NULL;
    if (installed->TrustAnchorsInstalled)
    {
        mbedtls_ssl_conf_ca_chain(conf, anchors, NULL);
    }

    /* Decided per connection, not at Create: these targets are built with mtls
       false and switch transport at runtime, so a startup decision would never
       see mutual TLS selected. The mutual-TLS transport presents a credential by
       construction; the plain TLS transport presents whatever the knob says,
       which is what lets a cell point it at the mutual-TLS listener with no
       credential and then rotate one in.

       Mbed TLS takes a client credential as a pair or not at all, so the
       half-supplied case installs nothing - which is what the contract describes
       happening, reported with delivery continuing. */
    bool presentsClientCredential =
        BddTargetSwitchConfig_IsMtlsMode() || (strcmp(BddTargetTlsConfig_GetClientCredentialName(), "client") == 0);
    if (presentsClientCredential)
    {
        (void) mbedtls_ssl_conf_own_cert(conf, clientCertificate, clientPrivateKey);
    }
    return true;
}

/* The handles outlive every connection - the sender parses them once at
   bring-up and frees them at teardown - so there is nothing to hand back. */
static void BddTargetMbedTlsCredentials_Release(struct SolidSyslogMbedTlsCredentials* self)
{
    (void) self;
}

static mbedtls_x509_crt* BddTargetMbedTlsCredentials_SelectedAuthority(void)
{
    const char* name = BddTargetTlsConfig_GetTrustAnchorName();
    mbedtls_x509_crt* anchors = NULL;
    if (strcmp(name, "ca") == 0)
    {
        anchors = trustedAuthorityChain;
    }
    else if (strcmp(name, "ca-b") == 0)
    {
        anchors = otherAuthorityChain;
    }
    else
    {
        /* "none" - no anchors, which the stream refuses unless a pin names the
           peer instead. */
    }
    return anchors;
}
