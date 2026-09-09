#include "MbedTlsTestCert.h"

#include <mbedtls/md.h>
#include <string.h>

#include <assert.h>
#include <mbedtls/asn1.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <stddef.h>
#include <string.h>

#include "SafeString.h"
#include "mbedtls/md.h"

enum
{
    RSA_KEY_BITS = 2048,
    RSA_EXPONENT = 65537,
    DER_BUFFER_BYTES = 4096
};

/* Obviously-fake test validity window - well outside any realistic clock skew
 * and far enough out that the integration tests don't need wall-clock-aware
 * regeneration. Named per the TEST_* convention. */
static const char* const TEST_CERT_VALIDITY_FROM = "20240101000000";
static const char* const TEST_CERT_VALIDITY_TO = "20990101000000";

/* mbedtls_x509write_crt_der writes from the END of the buffer backwards,
 * so the DER blob occupies [Bytes + StartOffset, Bytes + StartOffset + Length).
 * Capacity is the underlying storage size. Bundling these four fields keeps
 * WriteCertToDer's signature tight and dodges adjacent-size_t-parameter
 * swappability hazards. */
struct DerBuffer
{
    unsigned char* Bytes;
    size_t Capacity;
    size_t StartOffset;
    size_t Length;
};

static void GenerateKey(mbedtls_pk_context* key, mbedtls_ctr_drbg_context* rng);
static void WriteCertToDer(
    const struct MbedTlsTestCertConfig* config,
    mbedtls_pk_context* subjectKey,
    mbedtls_ctr_drbg_context* rng,
    struct DerBuffer* out
);

void MbedTlsTestCert_Create(
    const struct MbedTlsTestCertConfig* config,
    struct MbedTlsTestCert* out,
    mbedtls_ctr_drbg_context* rng
)
{
    mbedtls_pk_init(&out->Key);
    mbedtls_x509_crt_init(&out->Cert);
    SafeString_Copy(out->SubjectName, sizeof(out->SubjectName), config->SubjectName);

    GenerateKey(&out->Key, rng);

    unsigned char derBytes[DER_BUFFER_BYTES];
    struct DerBuffer der = {derBytes, sizeof(derBytes), 0U, 0U};
    WriteCertToDer(config, &out->Key, rng, &der);

    mbedtls_x509_crt_parse_der(&out->Cert, &der.Bytes[der.StartOffset], der.Length);
}

size_t MbedTlsTestCert_WriteCertPem(const struct MbedTlsTestCert* cert, unsigned char* buffer, size_t capacity)
{
    size_t written = 0U;
    int rc = mbedtls_pem_write_buffer(
        "-----BEGIN CERTIFICATE-----\n",
        "-----END CERTIFICATE-----\n",
        cert->Cert.raw.p,
        cert->Cert.raw.len,
        buffer,
        capacity,
        &written
    );
    assert(rc == 0);
    (void) rc;
    /* mbedtls_pem_write_buffer counts the terminator in `written`. */
    return written;
}

size_t MbedTlsTestCert_WriteKeyPem(const struct MbedTlsTestCert* cert, unsigned char* buffer, size_t capacity)
{
    int rc = mbedtls_pk_write_key_pem((mbedtls_pk_context*) &cert->Key, buffer, capacity);
    assert(rc == 0);
    (void) rc;
    return strlen((const char*) buffer) + 1U;
}

void MbedTlsTestCert_WriteFingerprint(const struct MbedTlsTestCert* cert, const char* label, char* out, size_t capacity)
{
    static const char HEX[] = "0123456789ABCDEF";
    mbedtls_md_type_t type = (strcmp(label, "sha-1") == 0) ? MBEDTLS_MD_SHA1 : MBEDTLS_MD_SHA256;
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(type);
    unsigned char digest[64];
    size_t length = mbedtls_md_get_size(info);
    mbedtls_md(info, cert->Cert.raw.p, cert->Cert.raw.len, digest);

    size_t written = strlen(label);
    if (capacity > (written + (length * 3U)))
    {
        memcpy(out, label, written);
        for (size_t i = 0; i < length; i++)
        {
            out[written] = ':';
            out[written + 1U] = HEX[digest[i] >> 4U];
            out[written + 2U] = HEX[digest[i] & 0x0FU];
            written += 3U;
        }
        out[written] = '\0';
    }
}

void MbedTlsTestCert_Destroy(struct MbedTlsTestCert* cert)
{
    mbedtls_x509_crt_free(&cert->Cert);
    mbedtls_pk_free(&cert->Key);
}

static void GenerateKey(mbedtls_pk_context* key, mbedtls_ctr_drbg_context* rng)
{
    mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key), mbedtls_ctr_drbg_random, rng, RSA_KEY_BITS, RSA_EXPONENT);
}

static void WriteCertToDer(
    const struct MbedTlsTestCertConfig* config,
    mbedtls_pk_context* subjectKey,
    mbedtls_ctr_drbg_context* rng,
    struct DerBuffer* out
)
{
    mbedtls_x509write_cert crt;
    mbedtls_x509write_crt_init(&crt);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_subject_key(&crt, subjectKey);
    mbedtls_x509write_crt_set_subject_name(&crt, config->SubjectName);

    /* Self-signed when Issuer == NULL - issuer name + key match the subject. */
    const char* issuerName = (config->Issuer != NULL) ? config->Issuer->SubjectName : config->SubjectName;
    mbedtls_pk_context* issuerKey = (config->Issuer != NULL) ? (mbedtls_pk_context*) &config->Issuer->Key : subjectKey;
    mbedtls_x509write_crt_set_issuer_name(&crt, issuerName);
    mbedtls_x509write_crt_set_issuer_key(&crt, issuerKey);

    const unsigned char serial[] = {0x01};
    mbedtls_x509write_crt_set_serial_raw(&crt, (unsigned char*) serial, sizeof(serial));

    const char* validityFrom = (config->ValidityFrom != NULL) ? config->ValidityFrom : TEST_CERT_VALIDITY_FROM;
    const char* validityTo = (config->ValidityTo != NULL) ? config->ValidityTo : TEST_CERT_VALIDITY_TO;
    mbedtls_x509write_crt_set_validity(&crt, validityFrom, validityTo);

    mbedtls_x509write_crt_set_basic_constraints(&crt, config->IsCa, -1);

    mbedtls_x509_san_list san;
    if (config->SubjectAltDns != NULL)
    {
        memset(&san, 0, sizeof(san));
        san.node.type = MBEDTLS_X509_SAN_DNS_NAME;
        san.node.san.unstructured_name.tag = MBEDTLS_ASN1_IA5_STRING;
        san.node.san.unstructured_name.p = (unsigned char*) config->SubjectAltDns;
        san.node.san.unstructured_name.len = strlen(config->SubjectAltDns);
        san.next = NULL;
        mbedtls_x509write_crt_set_subject_alternative_name(&crt, &san);
    }

    /* mbedtls_x509write_crt_der writes from the END of the buffer backwards. */
    int written = mbedtls_x509write_crt_der(&crt, out->Bytes, out->Capacity, mbedtls_ctr_drbg_random, rng);
    /* Surface generation failures loudly in debug. The conditional store is
     * retained so release builds with NDEBUG don't compute a giant size_t
     * from a negative `written` and corrupt the downstream parse_der. */
    assert(written > 0);
    if (written > 0)
    {
        out->StartOffset = out->Capacity - (size_t) written;
        out->Length = (size_t) written;
    }

    mbedtls_x509write_crt_free(&crt);
}
