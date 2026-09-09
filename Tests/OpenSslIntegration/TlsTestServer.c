#include "TlsTestServer.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/prov_ssl.h>

#include "TlsTestCert.h"

struct TlsTestServer
{
    SSL_CTX* Ctx;
    SSL* Ssl;
    BIO* ServerBio;
    BIO* ClientBio;
    bool HandshakeComplete;
};

struct TlsTestServer* TlsTestServer_Create(const struct TlsTestServerConfig* config)
{
    struct TlsTestServer* self = (struct TlsTestServer*) calloc(1, sizeof(struct TlsTestServer));

    self->Ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(self->Ctx, config->ServerCert->cert);
    SSL_CTX_use_PrivateKey(self->Ctx, config->ServerCert->key);
    if (config->IssuerCert != NULL)
    {
        X509_up_ref(config->IssuerCert->cert);
        SSL_CTX_add_extra_chain_cert(self->Ctx, config->IssuerCert->cert);
    }
    if (config->CipherList != NULL)
    {
        SSL_CTX_set_cipher_list(self->Ctx, config->CipherList);
    }
    if (config->ClientCaCert != NULL)
    {
        X509_STORE* store = SSL_CTX_get_cert_store(self->Ctx);
        X509_STORE_add_cert(store, config->ClientCaCert->cert);
        SSL_CTX_set_verify(self->Ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        /* Pin TLS 1.2 for mTLS tests - in TLS 1.3 the client's SSL_connect
         * can return before the server's verify completes, so a cert rejection
         * on the server shows up on the client only on the next read.
         * TLS 1.2 keeps rejection synchronous within the handshake. */
        SSL_CTX_set_max_proto_version(self->Ctx, TLS1_2_VERSION);
    }

    self->Ssl = SSL_new(self->Ctx);
    BIO_new_bio_pair(&self->ServerBio, 0, &self->ClientBio, 0);
    SSL_set_bio(self->Ssl, self->ServerBio, self->ServerBio);
    self->ServerBio = NULL; /* ownership transferred to SSL via SSL_set_bio */
    SSL_set_accept_state(self->Ssl);

    return self;
}

void TlsTestServer_Destroy(struct TlsTestServer* self)
{
    if (self == NULL)
    {
        return;
    }
    if (self->Ssl != NULL)
    {
        SSL_free(self->Ssl); /* also frees serverBio */
    }
    if (self->ClientBio != NULL)
    {
        BIO_free(self->ClientBio);
    }
    if (self->Ctx != NULL)
    {
        SSL_CTX_free(self->Ctx);
    }
    free(self);
}

BIO* TlsTestServer_ClientSideBio(struct TlsTestServer* self)
{
    return self->ClientBio;
}

void TlsTestServer_Pump(void* context)
{
    struct TlsTestServer* self = (struct TlsTestServer*) context;
    if (!self->HandshakeComplete)
    {
        int ret = SSL_accept(self->Ssl);
        if (ret == 1)
        {
            self->HandshakeComplete = true;
        }
    }
}
