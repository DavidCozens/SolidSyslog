/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogMbedTlsAesGcmPolicy.h"

#include <mbedtls/cipher.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/gcm.h>
#include <mbedtls/platform_util.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogError.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogMacros.h"
#include "SolidSyslogMbedTlsAesGcmPolicyErrors.h"
#include "SolidSyslogMbedTlsAesGcmPolicyPrivate.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogSecurityPolicyCategories.h"
#include "SolidSyslogSecurityPolicyDefinition.h"
#include "SolidSyslogTunables.h"

const struct SolidSyslogErrorSource SolidSyslogMbedTlsAesGcmPolicyErrorSource = {"MbedTlsAesGcmPolicy"};

enum
{
    AES_256_KEY_SIZE = 32,
    AES_256_KEY_BITS = 256,
    GCM_NONCE_SIZE = 12,
    GCM_TAG_SIZE = 16,
    /* Trailer is nonce || tag - fits SOLIDSYSLOG_MAX_INTEGRITY_SIZE (32). */
    AES_GCM_TRAILER_SIZE = GCM_NONCE_SIZE + GCM_TAG_SIZE
};

/* Seal/open write the nonce and tag into record->Trailer, which the store sizes
 * at SOLIDSYSLOG_MAX_INTEGRITY_SIZE. Fail the build - not a record at runtime -
 * if that shared buffer is ever tuned below this policy's trailer. */
SOLIDSYSLOG_STATIC_ASSERT(
    AES_GCM_TRAILER_SIZE <= SOLIDSYSLOG_MAX_INTEGRITY_SIZE,
    "AES-GCM trailer (nonce + tag) must fit SOLIDSYSLOG_MAX_INTEGRITY_SIZE"
);

static inline struct SolidSyslogMbedTlsAesGcmPolicy* MbedTlsAesGcmPolicy_SelfFromBase(
    struct SolidSyslogSecurityPolicy* base
);
static bool MbedTlsAesGcmPolicy_SealRecord(
    struct SolidSyslogSecurityPolicy* self,
    const struct SolidSyslogSecurityRecord* record
);
static bool MbedTlsAesGcmPolicy_OpenRecord(
    struct SolidSyslogSecurityPolicy* self,
    const struct SolidSyslogSecurityRecord* record
);
static bool MbedTlsAesGcmPolicy_FetchKey(struct SolidSyslogMbedTlsAesGcmPolicy* policy, uint8_t* keyOut);
static bool MbedTlsAesGcmPolicy_GcmEncrypt(const struct SolidSyslogSecurityRecord* record, const uint8_t* key);
static bool MbedTlsAesGcmPolicy_GcmDecrypt(const struct SolidSyslogSecurityRecord* record, const uint8_t* key);

void SolidSyslogMbedTlsAesGcmPolicy_Initialise(
    struct SolidSyslogSecurityPolicy* base,
    const struct SolidSyslogMbedTlsAesGcmPolicyConfig* config
)
{
    struct SolidSyslogMbedTlsAesGcmPolicy* self = MbedTlsAesGcmPolicy_SelfFromBase(base);
    self->Base.TrailerSize = AES_GCM_TRAILER_SIZE;
    self->Base.SealRecord = MbedTlsAesGcmPolicy_SealRecord;
    self->Base.OpenRecord = MbedTlsAesGcmPolicy_OpenRecord;
    self->Config = *config;
}

void SolidSyslogMbedTlsAesGcmPolicy_Cleanup(struct SolidSyslogSecurityPolicy* base)
{
    /* No owned resources to release - the key is fetched on demand via the
     * GetKey callback and never stored on the instance, and the CTR-DRBG is
     * caller-owned. */
    (void) base;
}

static inline struct SolidSyslogMbedTlsAesGcmPolicy* MbedTlsAesGcmPolicy_SelfFromBase(
    struct SolidSyslogSecurityPolicy* base
)
{
    /* Base is the first member of the instance struct - see Private.h. */
    return (struct SolidSyslogMbedTlsAesGcmPolicy*) base;
}

/* Seals in place: draws a fresh nonce into Trailer[0..GCM_NONCE_SIZE), then
 * GcmEncrypt encrypts the body (Content past HeaderLength) and writes the tag to
 * the remaining trailer bytes, authenticating the header (Content[0..HeaderLength))
 * as associated data. Fetches the key on demand and wipes it before returning. */
static bool MbedTlsAesGcmPolicy_SealRecord(
    struct SolidSyslogSecurityPolicy* self,
    const struct SolidSyslogSecurityRecord* record
)
{
    struct SolidSyslogMbedTlsAesGcmPolicy* policy = MbedTlsAesGcmPolicy_SelfFromBase(self);

    bool sealed = false;
    uint8_t key[AES_256_KEY_SIZE];
    if (MbedTlsAesGcmPolicy_FetchKey(policy, key))
    {
        /* Draw the per-record nonce straight into the trailer; GcmEncrypt reads
         * it back from there and writes the tag immediately after it. */
        if (mbedtls_ctr_drbg_random(policy->Config.Rng, record->Trailer, GCM_NONCE_SIZE) == 0)
        {
            if (MbedTlsAesGcmPolicy_GcmEncrypt(record, key))
            {
                sealed = true;
            }
            else
            {
                MbedTlsAesGcmPolicy_Report(
                    SOLIDSYSLOG_SEVERITY_ERROR,
                    SOLIDSYSLOG_CAT_SECURITY_POLICY_SEAL_FAILED,
                    SOLIDSYSLOG_AES_GCM_POLICY_ERROR_ENCRYPT_FAILED
                );
            }
        }
        else
        {
            MbedTlsAesGcmPolicy_Report(
                SOLIDSYSLOG_SEVERITY_ERROR,
                SOLIDSYSLOG_CAT_SECURITY_POLICY_SEAL_FAILED,
                SOLIDSYSLOG_AES_GCM_POLICY_ERROR_NONCE_FAILED
            );
        }
    }
    mbedtls_platform_zeroize(key, sizeof key);
    return sealed;
}

/* Fetches the AES-256 key on demand. Fails closed (and reports) if the key is
 * unavailable or not exactly 32 bytes - AES-256 admits no other key length. */
static bool MbedTlsAesGcmPolicy_FetchKey(struct SolidSyslogMbedTlsAesGcmPolicy* policy, uint8_t* keyOut)
{
    size_t keyLength = 0;
    bool fetched = policy->Config.GetKey(policy->Config.KeyContext, keyOut, AES_256_KEY_SIZE, &keyLength) &&
                   (keyLength == (size_t) AES_256_KEY_SIZE);
    if (!fetched)
    {
        MbedTlsAesGcmPolicy_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_SECURITY_POLICY_KEY_UNAVAILABLE,
            SOLIDSYSLOG_AES_GCM_POLICY_ERROR_KEY_UNAVAILABLE
        );
    }
    return fetched;
}

/* Encrypts the record's body in place and writes nonce||tag into its trailer.
 * Takes the whole record (not the unpacked buffers) so key and nonce never sit
 * adjacent as same-typed scalar parameters; the trailer/header layout lives in
 * one place. The nonce is expected already in Trailer[0..GCM_NONCE_SIZE). One-
 * shot AEAD - mbedTLS computes the whole tag in a single call (output == input
 * is permitted for GCM encryption). */
static bool MbedTlsAesGcmPolicy_GcmEncrypt(const struct SolidSyslogSecurityRecord* record, const uint8_t* key)
{
    uint8_t* body = &record->Content[record->HeaderLength];
    uint16_t bodyLength = (uint16_t) (record->ContentLength - record->HeaderLength);

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    bool ok = false;
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, AES_256_KEY_BITS) == 0)
    {
        int rc = mbedtls_gcm_crypt_and_tag(
            &ctx,
            MBEDTLS_GCM_ENCRYPT,
            bodyLength,
            record->Trailer,
            GCM_NONCE_SIZE,
            record->Content,
            record->HeaderLength,
            body,
            body,
            GCM_TAG_SIZE,
            &record->Trailer[GCM_NONCE_SIZE]
        );
        ok = (rc == 0);
    }
    mbedtls_gcm_free(&ctx);
    return ok;
}

/* Opens in place: decrypts the body and verifies the tag over the header
 * (associated data) and ciphertext. Fetches the key on demand and wipes it. A
 * tag mismatch is the expected tamper-detected outcome and returns false
 * silently; only a genuine mbedTLS error is reported. */
static bool MbedTlsAesGcmPolicy_OpenRecord(
    struct SolidSyslogSecurityPolicy* self,
    const struct SolidSyslogSecurityRecord* record
)
{
    struct SolidSyslogMbedTlsAesGcmPolicy* policy = MbedTlsAesGcmPolicy_SelfFromBase(self);

    bool opened = false;
    uint8_t key[AES_256_KEY_SIZE];
    if (MbedTlsAesGcmPolicy_FetchKey(policy, key))
    {
        opened = MbedTlsAesGcmPolicy_GcmDecrypt(record, key);
    }
    mbedtls_platform_zeroize(key, sizeof key);
    return opened;
}

/* Decrypts the record's body in place, reading nonce||tag from its trailer and
 * authenticating the header. Takes the whole record for the same reasons as
 * GcmEncrypt. mbedtls_gcm_auth_decrypt verifies the tag itself and signals the
 * verdict through its return code: 0 = authentic, GCM_AUTH_FAILED = tamper /
 * wrong key (the expected rejection - return false silently, like the HMAC
 * verify), anything else = a genuine mbedTLS error worth reporting. */
static bool MbedTlsAesGcmPolicy_GcmDecrypt(const struct SolidSyslogSecurityRecord* record, const uint8_t* key)
{
    uint8_t* body = &record->Content[record->HeaderLength];
    uint16_t bodyLength = (uint16_t) (record->ContentLength - record->HeaderLength);

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    bool opened = false;
    bool errored = true;
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, AES_256_KEY_BITS) == 0)
    {
        int verdict = mbedtls_gcm_auth_decrypt(
            &ctx,
            bodyLength,
            record->Trailer,
            GCM_NONCE_SIZE,
            record->Content,
            record->HeaderLength,
            &record->Trailer[GCM_NONCE_SIZE],
            GCM_TAG_SIZE,
            body,
            body
        );
        if (verdict == 0)
        {
            opened = true;
            errored = false;
        }
        else if (verdict == MBEDTLS_ERR_GCM_AUTH_FAILED)
        {
            errored = false;
        }
        else
        {
            /* Genuine mbedTLS failure - errored stays true and is reported below. */
        }
    }
    mbedtls_gcm_free(&ctx);
    if (errored)
    {
        MbedTlsAesGcmPolicy_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_SECURITY_POLICY_OPEN_FAILED,
            SOLIDSYSLOG_AES_GCM_POLICY_ERROR_DECRYPT_FAILED
        );
    }
    return opened;
}
