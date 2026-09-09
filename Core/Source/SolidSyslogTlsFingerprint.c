/* SPDX-FileCopyrightText: Copyright 2026 Cozens Software Solutions Limited
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0 OR LicenseRef-COSOSO-Commercial
 */

#include "SolidSyslogTlsFingerprint.h"

enum
{
    TLS_FINGERPRINT_SHA1_LENGTH = 20U,
    TLS_FINGERPRINT_SHA256_LENGTH = 32U,
    TLS_FINGERPRINT_HEX_BASE = 16U
};

struct SolidSyslogTlsFingerprintLabel
{
    const char* Label;
    enum SolidSyslogTlsHashAlgorithm Algorithm;
    size_t Length;
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
static inline enum SolidSyslogTlsFingerprintListState TlsFingerprint_InspectOne(const char* text);
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
    static const struct SolidSyslogTlsFingerprintLabel TLS_FINGERPRINT_LABELS[] = {
        {"sha-1", SOLIDSYSLOG_TLS_HASH_SHA1, TLS_FINGERPRINT_SHA1_LENGTH},
        {"sha-256", SOLIDSYSLOG_TLS_HASH_SHA256, TLS_FINGERPRINT_SHA256_LENGTH},
    };
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

        if (parsed && ((i + 1U) < length))
        {
            parsed = (text[position] == ':');
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
        *value = (uint8_t) ((uint8_t) (high << 4U) | low);
    }

    return parsed;
}

/* Matched against the digit table rather than computed from the character's
 * code, so nothing here depends on the execution character set being one where
 * 'A' through 'F' are contiguous. */
static inline bool TlsFingerprint_HexValue(char c, uint8_t* value)
{
    static const char TLS_FINGERPRINT_HEX_DIGITS[] = "0123456789ABCDEF";
    bool parsed = false;

    for (uint8_t i = 0U; (i < TLS_FINGERPRINT_HEX_BASE) && !parsed; i++)
    {
        if (c == TLS_FINGERPRINT_HEX_DIGITS[i])
        {
            *value = i;
            parsed = true;
        }
    }

    return parsed;
}

enum SolidSyslogTlsFingerprintListState SolidSyslogTlsFingerprint_InspectList(
    const char* const * fingerprints,
    size_t count
)
{
    enum SolidSyslogTlsFingerprintListState state = SOLIDSYSLOG_TLS_FINGERPRINT_LIST_WELL_FORMED;

    for (size_t i = 0; i < count; i++)
    {
        enum SolidSyslogTlsFingerprintListState one = TlsFingerprint_InspectOne(fingerprints[i]);
        if (one > state)
        {
            state = one;
        }
    }

    return state;
}

static inline enum SolidSyslogTlsFingerprintListState TlsFingerprint_InspectOne(const char* text)
{
    struct SolidSyslogTlsFingerprint parsed;
    enum SolidSyslogTlsFingerprintListState state = SOLIDSYSLOG_TLS_FINGERPRINT_LIST_MALFORMED;

    if (SolidSyslogTlsFingerprint_Parse(text, &parsed))
    {
        state = (parsed.Algorithm == SOLIDSYSLOG_TLS_HASH_SHA1) ? SOLIDSYSLOG_TLS_FINGERPRINT_LIST_USES_SHA1
                                                                : SOLIDSYSLOG_TLS_FINGERPRINT_LIST_WELL_FORMED;
    }

    return state;
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

    if (SolidSyslogTlsFingerprint_Parse(fingerprint, &pin))
    {
        uint8_t peerDigest[SOLIDSYSLOG_TLS_FINGERPRINT_DIGEST_MAX];
        size_t peerLength = 0;
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
