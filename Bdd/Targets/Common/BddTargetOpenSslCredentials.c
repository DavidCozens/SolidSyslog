#include "BddTargetOpenSslCredentials.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
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
static void BddTargetOpenSslCredentials_InstallClientCredential(SSL_CTX* ctx);
static void BddTargetOpenSslCredentials_Complain(const char* what);

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

    BddTargetOpenSslCredentials_InstallClientCredential(ctx);
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

/* A fault in our own credential never stops delivery - that is the contract the
   matrix is here to demonstrate - so nothing below fails the connection.
   
   What it does do is complain when material the scenario asked for will not
   load. That is broken harness material rather than a condition under test, and
   silence would let the mutual-TLS scenario connect with no client certificate
   at all and pass against a listener that does not require one. A green test
   proving the opposite of its name is the worst failure this suite can have.
   
   The complaint is deliberately not a SolidSyslog error report: it carries no
   role or detail, so it cannot be mistaken for something the library said. */
static void BddTargetOpenSslCredentials_InstallClientCredential(SSL_CTX* ctx)
{
    const char* wanted = BddTargetTlsConfig_GetClientCredentialName();
    bool wantsCertificate = (strcmp(wanted, "client") == 0) || (strcmp(wanted, "cert-only") == 0);
    bool wantsKey = strcmp(wanted, "client") == 0;

    if (wantsCertificate && (SSL_CTX_use_certificate_chain_file(ctx, CLIENT_CERT_CHAIN) != 1))
    {
        BddTargetOpenSslCredentials_Complain("client certificate");
        wantsKey = false;
    }
    if (wantsKey)
    {
        if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) != 1)
        {
            BddTargetOpenSslCredentials_Complain("client key");
        }
        else if (SSL_CTX_check_private_key(ctx) != 1)
        {
            BddTargetOpenSslCredentials_Complain("client key paired with its certificate");
        }
        else
        {
            /* Both halves installed and paired, so mutual TLS is in force. */
        }
    }
    /* "cert-only" stops here on purpose: half a credential is the case the
       contract reports and keeps delivering through. */
}

static void BddTargetOpenSslCredentials_Complain(const char* what)
{
    (void) fprintf(stderr, "BDD-TARGET: harness material broken - no %s\n", what);
    (void) fflush(stderr);
}
