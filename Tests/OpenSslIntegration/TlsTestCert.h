#ifndef TLSTESTCERT_H
#define TLSTESTCERT_H

#include <stddef.h>
#include <time.h>
#include <openssl/types.h>

#include "SolidSyslogExternC.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct TlsTestCert
    {
        X509* cert;
        EVP_PKEY* key;
    };

    struct TlsTestCertConfig
    {
        const char* commonName;
        const char* const * subjectAltDnsNames; /* NULL-terminated array; NULL if no SAN */
        time_t notBefore; /* 0 = now */
        time_t notAfter; /* 0 = now + 3600 */
        const struct TlsTestCert* issuer; /* NULL = self-signed */
    };

    void TlsTestCert_Create(const struct TlsTestCertConfig* config, struct TlsTestCert* out);
    void TlsTestCert_Destroy(struct TlsTestCert * cert);
    void TlsTestCert_WritePemToFile(const struct TlsTestCert* cert, const char* path);
    void TlsTestCert_WritePrivateKeyPemToFile(const struct TlsTestCert* cert, const char* path);

    /* Write the certificate's fingerprint in the RFC 5425 4.2.2 form -
       "<label>:XX:XX:...", where `label` is "sha-1" or "sha-256" and names
       both the IANA hash and the digest to take. */
    void TlsTestCert_WriteFingerprint(const struct TlsTestCert* cert, const char* label, char* out, size_t capacity);

SOLIDSYSLOG_EXTERN_C_END

#endif /* TLSTESTCERT_H */
