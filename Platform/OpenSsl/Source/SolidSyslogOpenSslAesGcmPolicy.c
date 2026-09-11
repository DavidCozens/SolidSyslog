/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogOpenSslAesGcmPolicy.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "SolidSyslogError.h"
#include "SolidSyslogErrorCategory.h"
#include "SolidSyslogOpenSslAesGcmPolicyErrors.h"
#include "SolidSyslogOpenSslAesGcmPolicyPrivate.h"
#include "SolidSyslogPrival.h"
#include "SolidSyslogSecurityPolicyCategories.h"
#include "SolidSyslogSecurityPolicyDefinition.h"

const struct SolidSyslogErrorSource SolidSyslogOpenSslAesGcmPolicyErrorSource = {"OpenSslAesGcmPolicy"};

enum
{
    AES_256_KEY_SIZE = 32,
    GCM_NONCE_SIZE = 12,
    GCM_TAG_SIZE = 16,
    /* Trailer is nonce || tag - fits SOLIDSYSLOG_MAX_INTEGRITY_SIZE (32). */
    AES_GCM_TRAILER_SIZE = GCM_NONCE_SIZE + GCM_TAG_SIZE
};

static inline struct SolidSyslogOpenSslAesGcmPolicy* OpenSslAesGcmPolicy_SelfFromBase(
    struct SolidSyslogSecurityPolicy* base
);
static bool OpenSslAesGcmPolicy_SealRecord(
    struct SolidSyslogSecurityPolicy* self,
    const struct SolidSyslogSecurityRecord* record
);
static bool OpenSslAesGcmPolicy_OpenRecord(
    struct SolidSyslogSecurityPolicy* self,
    const struct SolidSyslogSecurityRecord* record
);
static bool OpenSslAesGcmPolicy_FetchKey(struct SolidSyslogOpenSslAesGcmPolicy* policy, uint8_t* keyOut);
static bool OpenSslAesGcmPolicy_GcmEncrypt(
    const uint8_t* key,
    const uint8_t* nonce,
    uint8_t* body,
    uint16_t bodyLength,
    const uint8_t* aad,
    uint16_t aadLength,
    uint8_t* tagOut
);
static bool OpenSslAesGcmPolicy_GcmDecrypt(
    const uint8_t* key,
    const uint8_t* nonce,
    uint8_t* body,
    uint16_t bodyLength,
    const uint8_t* aad,
    uint16_t aadLength,
    const uint8_t* tagIn
);

void SolidSyslogOpenSslAesGcmPolicy_Initialise(
    struct SolidSyslogSecurityPolicy* base,
    const struct SolidSyslogOpenSslAesGcmPolicyConfig* config
)
{
    struct SolidSyslogOpenSslAesGcmPolicy* self = OpenSslAesGcmPolicy_SelfFromBase(base);
    self->Base.TrailerSize = AES_GCM_TRAILER_SIZE;
    self->Base.SealRecord = OpenSslAesGcmPolicy_SealRecord;
    self->Base.OpenRecord = OpenSslAesGcmPolicy_OpenRecord;
    self->Config = *config;
}

void SolidSyslogOpenSslAesGcmPolicy_Cleanup(struct SolidSyslogSecurityPolicy* base)
{
    /* No owned resources to release - the key is fetched on demand via the
     * GetKey callback and never stored on the instance. */
    (void) base;
}

static inline struct SolidSyslogOpenSslAesGcmPolicy* OpenSslAesGcmPolicy_SelfFromBase(
    struct SolidSyslogSecurityPolicy* base
)
{
    /* Base is the first member of the instance struct - see Private.h. */
    return (struct SolidSyslogOpenSslAesGcmPolicy*) base;
}

/* Seals in place: the nonce occupies Trailer[0..GCM_NONCE_SIZE) and the tag the
 * remaining bytes. The header (Content[0..HeaderLength)) is authenticated as
 * associated data and left in clear; the body (the rest) is encrypted in place.
 * Fetches the key on demand and wipes it before returning. */
static bool OpenSslAesGcmPolicy_SealRecord(
    struct SolidSyslogSecurityPolicy* self,
    const struct SolidSyslogSecurityRecord* record
)
{
    struct SolidSyslogOpenSslAesGcmPolicy* policy = OpenSslAesGcmPolicy_SelfFromBase(self);
    uint8_t* body = &record->Content[record->HeaderLength];
    uint16_t bodyLength = (uint16_t) (record->ContentLength - record->HeaderLength);
    uint8_t* nonce = record->Trailer;
    uint8_t* tag = &record->Trailer[GCM_NONCE_SIZE];

    bool sealed = false;
    uint8_t key[AES_256_KEY_SIZE];
    if (OpenSslAesGcmPolicy_FetchKey(policy, key))
    {
        if (RAND_bytes(nonce, GCM_NONCE_SIZE) == 1)
        {
            if (OpenSslAesGcmPolicy_GcmEncrypt(
                    key,
                    nonce,
                    body,
                    bodyLength,
                    record->Content,
                    record->HeaderLength,
                    tag
                ))
            {
                sealed = true;
            }
            else
            {
                OpenSslAesGcmPolicy_Report(
                    SOLIDSYSLOG_SEVERITY_ERROR,
                    SOLIDSYSLOG_CAT_SECURITY_POLICY_SEAL_FAILED,
                    SOLIDSYSLOG_AES_GCM_POLICY_ERROR_ENCRYPT_FAILED
                );
            }
        }
        else
        {
            OpenSslAesGcmPolicy_Report(
                SOLIDSYSLOG_SEVERITY_ERROR,
                SOLIDSYSLOG_CAT_SECURITY_POLICY_SEAL_FAILED,
                SOLIDSYSLOG_AES_GCM_POLICY_ERROR_NONCE_FAILED
            );
        }
    }
    OPENSSL_cleanse(key, sizeof key);
    return sealed;
}

/* Fetches the AES-256 key on demand. Fails closed (and reports) if the key is
 * unavailable or not exactly 32 bytes - AES-256 admits no other key length. */
static bool OpenSslAesGcmPolicy_FetchKey(struct SolidSyslogOpenSslAesGcmPolicy* policy, uint8_t* keyOut)
{
    size_t keyLength = 0;
    bool fetched = policy->Config.GetKey(policy->Config.KeyContext, keyOut, AES_256_KEY_SIZE, &keyLength) &&
                   (keyLength == (size_t) AES_256_KEY_SIZE);
    if (!fetched)
    {
        OpenSslAesGcmPolicy_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_SECURITY_POLICY_KEY_UNAVAILABLE,
            SOLIDSYSLOG_AES_GCM_POLICY_ERROR_KEY_UNAVAILABLE
        );
    }
    return fetched;
}

static bool OpenSslAesGcmPolicy_GcmEncrypt(
    const uint8_t* key,
    const uint8_t* nonce,
    uint8_t* body,
    uint16_t bodyLength,
    const uint8_t* aad,
    uint16_t aadLength,
    uint8_t* tagOut
)
{
    bool ok = false;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx != NULL)
    {
        int outLength = 0;
        /* GCM emits no bytes at final, so &body[outLength] is written zero bytes. */
        ok = (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1) &&
             (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, NULL) == 1) &&
             (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1) &&
             (EVP_EncryptUpdate(ctx, NULL, &outLength, aad, (int) aadLength) == 1) &&
             (EVP_EncryptUpdate(ctx, body, &outLength, body, (int) bodyLength) == 1) &&
             (EVP_EncryptFinal_ex(ctx, &body[outLength], &outLength) == 1) &&
             (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tagOut) == 1);
        EVP_CIPHER_CTX_free(ctx);
    }
    return ok;
}

/* Opens in place: decrypts the body and verifies the tag over the header
 * (associated data) and ciphertext. Fetches the key on demand and wipes it. A
 * tag mismatch is the expected tamper-detected outcome and returns false
 * silently; only a genuine OpenSSL error is reported. */
static bool OpenSslAesGcmPolicy_OpenRecord(
    struct SolidSyslogSecurityPolicy* self,
    const struct SolidSyslogSecurityRecord* record
)
{
    struct SolidSyslogOpenSslAesGcmPolicy* policy = OpenSslAesGcmPolicy_SelfFromBase(self);
    uint8_t* body = &record->Content[record->HeaderLength];
    uint16_t bodyLength = (uint16_t) (record->ContentLength - record->HeaderLength);
    const uint8_t* nonce = record->Trailer;
    const uint8_t* tag = &record->Trailer[GCM_NONCE_SIZE];

    bool opened = false;
    uint8_t key[AES_256_KEY_SIZE];
    if (OpenSslAesGcmPolicy_FetchKey(policy, key))
    {
        opened =
            OpenSslAesGcmPolicy_GcmDecrypt(key, nonce, body, bodyLength, record->Content, record->HeaderLength, tag);
    }
    OPENSSL_cleanse(key, sizeof key);
    return opened;
}

static bool OpenSslAesGcmPolicy_GcmDecrypt(
    const uint8_t* key,
    const uint8_t* nonce,
    uint8_t* body,
    uint16_t bodyLength,
    const uint8_t* aad,
    uint16_t aadLength,
    const uint8_t* tagIn
)
{
    /* Copy the expected tag into a non-const buffer - EVP_CIPHER_CTX_ctrl's
     * SET_TAG parameter is void*, and copying avoids casting away const. */
    uint8_t tag[GCM_TAG_SIZE];
    (void) memcpy(tag, tagIn, sizeof tag);

    /* A tag mismatch is the expected tamper-detected outcome - return false
     * silently, like the HMAC verify. Only a genuine OpenSSL failure (context
     * allocation or any setup step) is reported. */
    bool opened = false;
    bool errored = true;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx != NULL)
    {
        int outLength = 0;
        bool setUp = (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1) &&
                     (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, NULL) == 1) &&
                     (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1) &&
                     (EVP_DecryptUpdate(ctx, NULL, &outLength, aad, (int) aadLength) == 1) &&
                     (EVP_DecryptUpdate(ctx, body, &outLength, body, (int) bodyLength) == 1) &&
                     (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, tag) == 1);
        if (setUp)
        {
            int finalLength = 0;
            errored = false;
            opened = (EVP_DecryptFinal_ex(ctx, &body[outLength], &finalLength) == 1);
        }
        EVP_CIPHER_CTX_free(ctx);
    }
    if (errored)
    {
        OpenSslAesGcmPolicy_Report(
            SOLIDSYSLOG_SEVERITY_ERROR,
            SOLIDSYSLOG_CAT_SECURITY_POLICY_OPEN_FAILED,
            SOLIDSYSLOG_AES_GCM_POLICY_ERROR_DECRYPT_FAILED
        );
    }
    return opened;
}
