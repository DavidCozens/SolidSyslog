#include "TlsTestCert.h"

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/safestack.h>

enum
{
    RSA_BITS = 2048,
    DEFAULT_VALIDITY_SECONDS = 3600,
};

static void SetValidity(X509* cert, const struct TlsTestCertConfig* config);
static void SetSubject(X509* cert, const char* commonName);
static void AddSubjectAltNames(X509* cert, const char* const * dnsNames);
static void AddBasicConstraintsCa(X509* cert);

void TlsTestCert_Create(const struct TlsTestCertConfig* config, struct TlsTestCert* out)
{
    EVP_PKEY* key = EVP_RSA_gen(RSA_BITS);
    X509* cert = X509_new();

    X509_set_version(cert, 2); /* X.509 v3 */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    SetValidity(cert, config);
    SetSubject(cert, config->commonName);
    AddSubjectAltNames(cert, config->subjectAltDnsNames);
    AddBasicConstraintsCa(cert);

    X509* issuerCert = (config->issuer != NULL) ? config->issuer->cert : cert;
    EVP_PKEY* issuerKey = (config->issuer != NULL) ? config->issuer->key : key;
    X509_set_issuer_name(cert, X509_get_subject_name(issuerCert));
    X509_set_pubkey(cert, key);
    X509_sign(cert, issuerKey, EVP_sha256());

    out->cert = cert;
    out->key = key;
}

void TlsTestCert_Destroy(struct TlsTestCert* cert)
{
    if (cert->cert != NULL)
    {
        X509_free(cert->cert);
        cert->cert = NULL;
    }
    if (cert->key != NULL)
    {
        EVP_PKEY_free(cert->key);
        cert->key = NULL;
    }
}

void TlsTestCert_WritePemToFile(const struct TlsTestCert* cert, const char* path)
{
    FILE* file = fopen(path, "w");
    if (file == NULL)
    {
        return;
    }
    PEM_write_X509(file, cert->cert);
    fclose(file);
}

void TlsTestCert_WritePrivateKeyPemToFile(const struct TlsTestCert* cert, const char* path)
{
    FILE* file = fopen(path, "w");
    if (file == NULL)
    {
        return;
    }
    PEM_write_PrivateKey(file, cert->key, NULL, NULL, 0, NULL, NULL);
    fclose(file);
}

void TlsTestCert_WriteFingerprint(const struct TlsTestCert* cert, const char* label, char* out, size_t capacity)
{
    static const char HEX[] = "0123456789ABCDEF";
    const EVP_MD* md = (strcmp(label, "sha-1") == 0) ? EVP_sha1() : EVP_sha256();
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    X509_digest(cert->cert, md, digest, &length);

    size_t written = strlen(label);
    if (capacity > (written + ((size_t) length * 3U)))
    {
        memcpy(out, label, written);
        for (unsigned int i = 0; i < length; i++)
        {
            out[written] = ':';
            out[written + 1U] = HEX[digest[i] >> 4U];
            out[written + 2U] = HEX[digest[i] & 0x0FU];
            written += 3U;
        }
        out[written] = '\0';
    }
}

static void SetValidity(X509* cert, const struct TlsTestCertConfig* config)
{
    time_t now = time(NULL);
    time_t start = (config->notBefore != 0) ? config->notBefore : now;
    time_t end = (config->notAfter != 0) ? config->notAfter : now + DEFAULT_VALIDITY_SECONDS;
    X509_time_adj_ex(X509_getm_notBefore(cert), 0, 0, &start);
    X509_time_adj_ex(X509_getm_notAfter(cert), 0, 0, &end);
}

static void SetSubject(X509* cert, const char* commonName)
{
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*) commonName, -1, -1, 0);
}

static void AddSubjectAltNames(X509* cert, const char* const * dnsNames)
{
    if (dnsNames == NULL)
    {
        return;
    }
    STACK_OF(GENERAL_NAME)* sans = sk_GENERAL_NAME_new_null();
    for (int i = 0; dnsNames[i] != NULL; i++)
    {
        GENERAL_NAME* gen = GENERAL_NAME_new();
        ASN1_IA5STRING* str = ASN1_IA5STRING_new();
        ASN1_STRING_set(str, dnsNames[i], -1);
        GENERAL_NAME_set0_value(gen, GEN_DNS, str);
        sk_GENERAL_NAME_push(sans, gen);
    }
    X509_add1_ext_i2d(cert, NID_subject_alt_name, sans, 0, 0);
    sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
}

/* OpenSSL 3 chain validation requires issuer certs to carry
 * basicConstraints=CA:TRUE. All test certs get it - it's harmless on leaves
 * for our purposes and lets any generated cert act as an issuer if needed. */
static void AddBasicConstraintsCa(X509* cert)
{
    BASIC_CONSTRAINTS* bc = BASIC_CONSTRAINTS_new();
    bc->ca = 1;
    X509_add1_ext_i2d(cert, NID_basic_constraints, bc, 1 /* critical */, 0);
    BASIC_CONSTRAINTS_free(bc);
}
