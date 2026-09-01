/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogTlsFingerprint.h"

enum
{
    TLS_FINGERPRINT_SHA1_LENGTH = 20U,
    TLS_FINGERPRINT_SHA256_LENGTH = 32U,
    TLS_FINGERPRINT_NIBBLE_BITS = 4U
};

struct TlsFingerprintLabel
{
    const char* Label;
    enum SolidSyslogTlsHashAlgorithm Algorithm;
    size_t Length;
};

static const struct TlsFingerprintLabel TLS_FINGERPRINT_LABELS[] = {
    {"sha-1", SOLIDSYSLOG_TLS_HASH_SHA1, TLS_FINGERPRINT_SHA1_LENGTH},
    {"sha-256", SOLIDSYSLOG_TLS_HASH_SHA256, TLS_FINGERPRINT_SHA256_LENGTH},
};

static inline bool TlsFingerprint_ParseLabel(
    const char* text,
    const char** digestText,
    struct SolidSyslogTlsFingerprint* out
);
static inline bool TlsFingerprint_LabelMatches(const char* text, const char* label, const char** digestText);
static inline bool TlsFingerprint_ParseHexPairs(const char* text, uint8_t* digest, size_t length);
static inline bool TlsFingerprint_ParseHexPair(const char* text, uint8_t* value);
static inline bool TlsFingerprint_HexValue(char c, uint8_t* value);
static inline enum SolidSyslogTlsAuthorisation TlsFingerprint_AuthoriseOne(
    const char* fingerprint,
    SolidSyslogTlsDigestFunction digest,
    void* context
);
static inline bool TlsFingerprint_DigestEquals(
    const struct SolidSyslogTlsFingerprint* pin,
    const uint8_t* digest,
    size_t length
);

bool SolidSyslogTlsFingerprint_Parse(const char* text, struct SolidSyslogTlsFingerprint* out)
{
    const char* digestText = NULL;
    bool parsed = TlsFingerprint_ParseLabel(text, &digestText, out);

    if (parsed)
    {
        parsed = TlsFingerprint_ParseHexPairs(digestText, out->Digest, out->Length);
    }

    return parsed;
}

static inline bool TlsFingerprint_ParseLabel(
    const char* text,
    const char** digestText,
    struct SolidSyslogTlsFingerprint* out
)
{
    bool parsed = false;
    size_t count = sizeof(TLS_FINGERPRINT_LABELS) / sizeof(TLS_FINGERPRINT_LABELS[0]);

    for (size_t i = 0; (i < count) && !parsed; i++)
    {
        if (TlsFingerprint_LabelMatches(text, TLS_FINGERPRINT_LABELS[i].Label, digestText))
        {
            out->Algorithm = TLS_FINGERPRINT_LABELS[i].Algorithm;
            out->Length = TLS_FINGERPRINT_LABELS[i].Length;
            parsed = true;
        }
    }

    return parsed;
}

static inline bool TlsFingerprint_LabelMatches(const char* text, const char* label, const char** digestText)
{
    size_t i = 0;

    while ((label[i] != '\0') && (text[i] == label[i]))
    {
        i++;
    }

    bool matches = (label[i] == '\0') && (text[i] == ':');

    if (matches)
    {
        *digestText = &text[i + 1U];
    }

    return matches;
}

static inline bool TlsFingerprint_ParseHexPairs(const char* text, uint8_t* digest, size_t length)
{
    bool parsed = true;
    size_t position = 0;

    for (size_t i = 0; (i < length) && parsed; i++)
    {
        parsed = TlsFingerprint_ParseHexPair(&text[position], &digest[i]);
        position += 2U;

        if (parsed && (i + 1U < length))
        {
            parsed = text[position] == ':';
            position++;
        }
    }

    return parsed && (text[position] == '\0');
}

static inline bool TlsFingerprint_ParseHexPair(const char* text, uint8_t* value)
{
    uint8_t high = 0;
    uint8_t low = 0;
    bool parsed = TlsFingerprint_HexValue(text[0], &high) && TlsFingerprint_HexValue(text[1], &low);

    if (parsed)
    {
        *value = (uint8_t) ((uint8_t) (high << TLS_FINGERPRINT_NIBBLE_BITS) | low);
    }

    return parsed;
}

static inline bool TlsFingerprint_HexValue(char c, uint8_t* value)
{
    bool parsed = true;

    if ((c >= '0') && (c <= '9'))
    {
        *value = (uint8_t) (c - '0');
    }
    else if ((c >= 'A') && (c <= 'F'))
    {
        *value = (uint8_t) ((c - 'A') + 10);
    }
    else
    {
        parsed = false;
    }

    return parsed;
}

enum SolidSyslogTlsAuthorisation SolidSyslogTlsFingerprint_Authorise(
    const char* const * fingerprints,
    size_t count,
    SolidSyslogTlsDigestFunction digest,
    void* context
)
{
    enum SolidSyslogTlsAuthorisation verdict = SOLIDSYSLOG_TLS_AUTHORISATION_NO_MATCH;

    for (size_t i = 0; (i < count) && (verdict == SOLIDSYSLOG_TLS_AUTHORISATION_NO_MATCH); i++)
    {
        verdict = TlsFingerprint_AuthoriseOne(fingerprints[i], digest, context);
    }

    return verdict;
}

static inline enum SolidSyslogTlsAuthorisation TlsFingerprint_AuthoriseOne(
    const char* fingerprint,
    SolidSyslogTlsDigestFunction digest,
    void* context
)
{
    enum SolidSyslogTlsAuthorisation verdict = SOLIDSYSLOG_TLS_AUTHORISATION_MALFORMED;
    struct SolidSyslogTlsFingerprint pin;
    uint8_t peerDigest[SOLIDSYSLOG_TLS_FINGERPRINT_DIGEST_MAX];
    size_t peerLength = 0;

    if (SolidSyslogTlsFingerprint_Parse(fingerprint, &pin))
    {
        verdict = SOLIDSYSLOG_TLS_AUTHORISATION_DIGEST_UNAVAILABLE;

        if (digest(context, pin.Algorithm, peerDigest, &peerLength))
        {
            verdict = TlsFingerprint_DigestEquals(&pin, peerDigest, peerLength)
                          ? SOLIDSYSLOG_TLS_AUTHORISATION_MATCHED
                          : SOLIDSYSLOG_TLS_AUTHORISATION_NO_MATCH;
        }
    }

    return verdict;
}

/* Every byte is compared whatever the first difference, so the time taken
   says nothing about how much of the pin matched. */
static inline bool TlsFingerprint_DigestEquals(
    const struct SolidSyslogTlsFingerprint* pin,
    const uint8_t* digest,
    size_t length
)
{
    bool equal = length == pin->Length;

    if (equal)
    {
        uint8_t difference = 0;

        for (size_t i = 0; i < length; i++)
        {
            difference |= (uint8_t) (pin->Digest[i] ^ digest[i]);
        }

        equal = difference == 0U;
    }

    return equal;
}
