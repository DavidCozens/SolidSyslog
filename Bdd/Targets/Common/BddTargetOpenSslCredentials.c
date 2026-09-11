#include "BddTargetOpenSslCredentials.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <openssl/ssl.h>

#include "BddTargetTlsConfig.h"
#include "SolidSyslogOpenSslCredentialsDefinition.h"
#include "SolidSyslogTlsCredentialsInstalled.h"

/* Where each logical name lives on a target with a filesystem. The names
   themselves are the harness vocabulary; only this file knows they are paths. */
static const char* const TRUST_ANCHOR_CA = "Bdd/syslog-ng/tls/ca.pem";
static const char* const TRUST_ANCHOR_CA_B = "Bdd/syslog-ng/tls/ca-b.pem";
static const char* const CLIENT_CERT_CHAIN = "Bdd/syslog-ng/tls/client.pem";
static const char* const CLIENT_KEY = "Bdd/syslog-ng/tls/client.key";

static bool BddTargetOpenSslCredentials_Install(
    struct SolidSyslogOpenSslCredentials* self,
    SSL_CTX* ctx,
    struct SolidSyslogTlsCredentialsInstalled* installed
);
static void BddTargetOpenSslCredentials_Release(struct SolidSyslogOpenSslCredentials* self);
static const char* BddTargetOpenSslCredentials_TrustAnchorPath(void);

static struct SolidSyslogOpenSslCredentials credentials = {
    BddTargetOpenSslCredentials_Install,
    BddTargetOpenSslCredentials_Release
};

struct SolidSyslogOpenSslCredentials* BddTargetOpenSslCredentials_Get(void)
{
    return &credentials;
}

/* Asked once per connection, so everything a scenario set at the prompt is read
   here rather than remembered from startup. */
static bool BddTargetOpenSslCredentials_Install(
    struct SolidSyslogOpenSslCredentials* self,
    SSL_CTX* ctx,
    struct SolidSyslogTlsCredentialsInstalled* installed
)
{
    (void) self;
    installed->Fingerprints = BddTargetTlsConfig_GetPeerFingerprints();
    installed->FingerprintCount = BddTargetTlsConfig_GetPeerFingerprintCount();
    installed->TrustAnchorsInstalled = false;

    bool ok = true;
    const char* anchors = BddTargetOpenSslCredentials_TrustAnchorPath();
    if (anchors != NULL)
    {
        installed->TrustAnchorsInstalled = SSL_CTX_load_verify_locations(ctx, anchors, NULL) == 1;
        ok = installed->TrustAnchorsInstalled;
    }

    const char* client = BddTargetTlsConfig_GetClientCredentialName();
    if (strcmp(client, "client") == 0)
    {
        (void) SSL_CTX_use_certificate_chain_file(ctx, CLIENT_CERT_CHAIN);
        (void) SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM);
    }
    else if (strcmp(client, "cert-only") == 0)
    {
        /* Half a credential on purpose: the contract reports it and keeps
           delivering, which is the cell this exists for. */
        (void) SSL_CTX_use_certificate_chain_file(ctx, CLIENT_CERT_CHAIN);
    }
    else
    {
        /* No client credential, so the connection is server-authenticated. */
    }
    return ok;
}

/* Nothing is held between connections: the anchors are named by path and OpenSSL
   reads them itself, so there is nothing of ours to hand back. */
static void BddTargetOpenSslCredentials_Release(struct SolidSyslogOpenSslCredentials* self)
{
    (void) self;
}

static const char* BddTargetOpenSslCredentials_TrustAnchorPath(void)
{
    const char* name = BddTargetTlsConfig_GetTrustAnchorName();
    const char* path = NULL;
    if (strcmp(name, "ca") == 0)
    {
        path = TRUST_ANCHOR_CA;
    }
    else if (strcmp(name, "ca-b") == 0)
    {
        path = TRUST_ANCHOR_CA_B;
    }
    else
    {
        /* "none" - the configuration names no anchors, which the stream refuses
           unless a pin names the peer instead. */
    }
    return path;
}
