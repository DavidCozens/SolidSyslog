#ifndef TLSTESTSERVER_H
#define TLSTESTSERVER_H

#include <openssl/types.h>

#include "SolidSyslogExternC.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct TlsTestServer;

    struct TlsTestServerConfig
    {
        const struct TlsTestCert* ServerCert; /* includes matching private key */
        const char* CipherList; /* NULL = server default */
        const struct TlsTestCert* ClientCaCert; /* NULL = no mTLS; set to require & verify client cert */
        const struct TlsTestCert* IssuerCert; /* NULL = present the leaf alone; set to also send the issuer */
    };

    struct TlsTestServer* TlsTestServer_Create(const struct TlsTestServerConfig* config);
    void TlsTestServer_Destroy(struct TlsTestServer * self);

    /* Returns the client-facing end of the internal BIO pair. Pass to
     * BioPairStream_Create and use as the transport for SolidSyslogOpenSslStream. */
    BIO* TlsTestServer_ClientSideBio(struct TlsTestServer * self);

    /* Advances the server's state machine one step. Used as a pump callback
     * so client-side reads can make cooperative progress. Context is the
     * TlsTestServer pointer. */
    void TlsTestServer_Pump(void* context);

SOLIDSYSLOG_EXTERN_C_END

#endif /* TLSTESTSERVER_H */
