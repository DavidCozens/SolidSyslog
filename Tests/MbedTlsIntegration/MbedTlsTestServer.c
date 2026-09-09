#include "MbedTlsTestServer.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>

#include "MbedTlsTestCert.h"
#include "mbedtls/pk.h"

struct MbedTlsTestServer
{
    int Fd;
    mbedtls_ssl_config SslConfig;
    mbedtls_ssl_context SslContext;
    pthread_t Thread;
    bool ThreadJoined;
    bool HandshakeSucceeded;
    mbedtls_x509_crt* ChainedLeaf;
};

static void* RunServer(void* arg);
static int ServerBioSend(void* ctx, const unsigned char* buf, size_t len);
static int ServerBioRecv(void* ctx, unsigned char* buf, size_t len);

struct MbedTlsTestServer* MbedTlsTestServer_Create(const struct MbedTlsTestServerConfig* config)
{
    struct MbedTlsTestServer* self = (struct MbedTlsTestServer*) calloc(1U, sizeof(struct MbedTlsTestServer));
    self->Fd = config->ServerFd;

    mbedtls_ssl_config_init(&self->SslConfig);
    mbedtls_ssl_config_defaults(
        &self->SslConfig,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    /* Pin TLS 1.2 - mirrors the rationale in the OpenSSL TlsTestServer
     * (Tests/OpenSslIntegration/TlsTestServer.c:37). In TLS 1.3 the server
     * sends Certificate/CertVerify/Finished in one flight and then blocks
     * in recv waiting for ClientFinished. On the negative paths the client's
     * verify fails after that flight is read; even if the client sends an
     * Alert, the server's blocking recv on the socketpair lands the test in
     * a teardown-order deadlock. TLS 1.2's request/response cadence keeps
     * the rejection synchronous: the server is waiting for ClientKeyExchange
     * when the client closes its end, so server-side recv returns 0 and the
     * worker exits cleanly. */
    mbedtls_ssl_conf_max_tls_version(&self->SslConfig, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_rng(&self->SslConfig, mbedtls_ctr_drbg_random, config->Rng);
    if (config->TrustedClientCa != NULL)
    {
        /* mTLS: server requires + verifies a client cert against the supplied CA. */
        mbedtls_ssl_conf_authmode(&self->SslConfig, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&self->SslConfig, (mbedtls_x509_crt*) &config->TrustedClientCa->Cert, NULL);
    }
    else
    {
        /* Server-auth only - no client cert requested. */
        mbedtls_ssl_conf_authmode(&self->SslConfig, MBEDTLS_SSL_VERIFY_NONE);
    }
    /* mbedtls_x509_crt is a linked list and the whole list is sent, so linking
       the issuer onto the leaf is what presents a chain. Unlinked in Destroy so
       neither certificate is freed through the other. */
    self->ChainedLeaf = NULL;
    if (config->IssuerCert != NULL)
    {
        self->ChainedLeaf = (mbedtls_x509_crt*) &config->ServerCert->Cert;
        self->ChainedLeaf->next = (mbedtls_x509_crt*) &config->IssuerCert->Cert;
    }
    mbedtls_ssl_conf_own_cert(
        &self->SslConfig,
        (mbedtls_x509_crt*) &config->ServerCert->Cert,
        (mbedtls_pk_context*) &config->ServerCert->Key
    );

    mbedtls_ssl_init(&self->SslContext);
    mbedtls_ssl_setup(&self->SslContext, &self->SslConfig);
    mbedtls_ssl_set_bio(&self->SslContext, &self->Fd, ServerBioSend, ServerBioRecv, NULL);

    pthread_create(&self->Thread, NULL, RunServer, self);
    return self;
}

void MbedTlsTestServer_Destroy(struct MbedTlsTestServer* self)
{
    if (self != NULL)
    {
        if (self->ChainedLeaf != NULL)
        {
            self->ChainedLeaf->next = NULL;
            self->ChainedLeaf = NULL;
        }
        if (!self->ThreadJoined)
        {
            /* Worker might still be blocked in recv. Shutting the fd
             * unblocks it; close gets called below after the join. */
            if (self->Fd >= 0)
            {
                shutdown(self->Fd, SHUT_RDWR);
            }
            pthread_join(self->Thread, NULL);
            self->ThreadJoined = true;
        }
        mbedtls_ssl_free(&self->SslContext);
        mbedtls_ssl_config_free(&self->SslConfig);
        if (self->Fd >= 0)
        {
            close(self->Fd);
        }
        free(self);
    }
}

bool MbedTlsTestServer_JoinAndHandshakeSucceeded(struct MbedTlsTestServer* self)
{
    /* RunServer exits naturally once the client closes its end (recv returns
     * 0 -> handshake or read sees EOF). Tests should close the client side
     * before calling Join so this returns promptly. */
    if (!self->ThreadJoined)
    {
        pthread_join(self->Thread, NULL);
        self->ThreadJoined = true;
    }
    return self->HandshakeSucceeded;
}

/* The thread exits as soon as the handshake settles - the tests pin
 * handshake outcome only. Reading application bytes after handshake (and
 * the blocking that implies) is intentionally not implemented. */
static void* RunServer(void* arg)
{
    struct MbedTlsTestServer* self = (struct MbedTlsTestServer*) arg;

    int handshakeRc = 0;
    do
    {
        handshakeRc = mbedtls_ssl_handshake(&self->SslContext);
    } while ((handshakeRc == MBEDTLS_ERR_SSL_WANT_READ) || (handshakeRc == MBEDTLS_ERR_SSL_WANT_WRITE));

    self->HandshakeSucceeded = (handshakeRc == 0);
    return NULL;
}

static int ServerBioSend(void* ctx, const unsigned char* buf, size_t len)
{
    int fd = *(int*) ctx;
    ssize_t n = send(fd, buf, len, 0);
    return (n >= 0) ? (int) n : -1;
}

static int ServerBioRecv(void* ctx, unsigned char* buf, size_t len)
{
    int fd = *(int*) ctx;
    ssize_t n = recv(fd, buf, len, 0);
    return (n >= 0) ? (int) n : -1;
}
