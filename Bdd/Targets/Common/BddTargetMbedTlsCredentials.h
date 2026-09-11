#ifndef BDDTARGETMBEDTLSCREDENTIALS_H
#define BDDTARGETMBEDTLSCREDENTIALS_H

#include "SolidSyslogExternC.h"

struct SolidSyslogMbedTlsCredentials;
struct mbedtls_pk_context;
struct mbedtls_x509_crt;

SOLIDSYSLOG_EXTERN_C_BEGIN

    /* The BDD target fills the credentials role itself rather than wiring the
       shipped handle-based backend, for the same reason the OpenSSL side does: a
       matrix cell selects its trust anchors and pins at the prompt, after the
       sender has been built, and a shipped backend copies its configuration at
       Create.

       Parsing stays with the sender, which owns the baked PEM buffers and the
       FreeRTOS-specific bring-up around them; this takes the parsed handles and
       chooses between them per connection. */
    void BddTargetMbedTlsCredentials_Wire(
        struct mbedtls_x509_crt * trustedAuthority,
        struct mbedtls_x509_crt * otherAuthority,
        struct mbedtls_x509_crt * clientCertChain,
        struct mbedtls_pk_context * clientKey
    );

    struct SolidSyslogMbedTlsCredentials* BddTargetMbedTlsCredentials_Get(void);

SOLIDSYSLOG_EXTERN_C_END

#endif /* BDDTARGETMBEDTLSCREDENTIALS_H */
