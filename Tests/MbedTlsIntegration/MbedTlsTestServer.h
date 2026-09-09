#ifndef MBEDTLSTESTSERVER_H
#define MBEDTLSTESTSERVER_H

#include <mbedtls/ctr_drbg.h>
#include <stdbool.h>

#include "SolidSyslogExternC.h"

struct MbedTlsTestCert;

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct MbedTlsTestServer;

    struct MbedTlsTestServerConfig
    {
        int ServerFd; /* one end of a socketpair; ownership transferred to the server */
        const struct MbedTlsTestCert* ServerCert; /* server's cert + matching key */
        mbedtls_ctr_drbg_context* Rng; /* shared with the test fixture */
        /* Non-NULL switches the server to require + verify a client cert
         * against this CA - drives the mTLS scenarios. NULL = server-auth only. */
        const struct MbedTlsTestCert* TrustedClientCa;
        /* NULL presents the leaf alone; set to send the issuer with it, as a
           correctly configured collector does. */
        const struct MbedTlsTestCert* IssuerCert;
    };

    /* Spawns a worker thread that drives the server-side handshake. The
     * Server owns ServerFd from this point on. */
    struct MbedTlsTestServer* MbedTlsTestServer_Create(const struct MbedTlsTestServerConfig* config);

    /* Joins the worker thread and tears down all mbedTLS state. */
    void MbedTlsTestServer_Destroy(struct MbedTlsTestServer * self);

    /* Wait for the worker thread to exit and return whether the handshake
     * completed successfully. Callable once per server. */
    bool MbedTlsTestServer_JoinAndHandshakeSucceeded(struct MbedTlsTestServer * self);

SOLIDSYSLOG_EXTERN_C_END

#endif /* MBEDTLSTESTSERVER_H */
