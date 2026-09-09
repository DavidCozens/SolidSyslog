# Mbed TLS setup

Wiring `SolidSyslogMbedTlsStream` so a `SolidSyslogStreamSender` delivers
RFC 5425 syslog over TLS. The [TLS obligations](../../tls.md) page covers what
any TLS stream must do. The [Mbed TLS](index.md) page covers what this adapter
needs and where it falls short of that. The config fields are documented on the
struct itself, and this page is the wiring - and the things that bite.

## The layering

TLS is a Stream wrapped around another Stream. The TLS adapter carries the
records; the transport underneath carries the bytes.

```text
SolidSyslog_Log ─▶ Buffer ─▶ SolidSyslogStreamSender
                                     │
                                     ▼
                         SolidSyslogMbedTlsStream   ◀── your DRBG handle
                                     ▲
                                     └── a credentials source ◀── your CA / cert / key
                                     │
                                     ▼
                            a byte-transport Stream  ◀── your TCP/IP stack
```

You supply three things: the byte transport, the credentials source the stream
asks for its material, and the DRBG the handshake runs on. Everything
above the TLS stream is unchanged from a plaintext wiring - `StreamSender`
applies RFC 6587 octet-counting framing on top either way.

## Wiring it

First a credentials source, which is where the material comes from. Two ship
with the pack. The first carries handles you have already built:

```c
struct SolidSyslogMbedTlsHandleCredentialsConfig credentialsConfig = {
    .Rng             = &mySeededDrbg,
    .CaChain         = &myParsedCaChain,
    .ClientCertChain = &myClientCert,         /* both, or neither */
    .ClientKey       = &myClientKey,
};
struct SolidSyslogMbedTlsCredentials* credentials =
    SolidSyslogMbedTlsHandleCredentials_Create(&credentialsConfig);
```

The `Rng` here is what checks the client key against its certificate, and the
same seeded DRBG serves both configs.

To authorise the collector by its certificate rather than by a chain, pin it.
Any one pin in the list authorises, which is how a fleet crosses a renewal; the
array and the strings are yours and must outlive the credentials. A pin alone is
enough, so `CaChain` may be left NULL - and where both are set, both must be
satisfied. Either credentials source takes the same two fields:

```c
static const char* const pins[] = {
    "sha-256:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:"
    "7A:F1:9E:9D:0C:44:1B:23:5D:87:6E:A0:31:F5:C2:98"
};
credentialsConfig.PeerFingerprints     = pins;
credentialsConfig.PeerFingerprintCount = 1;
```

The second parses PEM you hold in memory, once per connection, and lets go of
what it parsed when the connection ends - so a device that connects rarely does
not keep a parsed private key in RAM in between:

```c
struct SolidSyslogMbedTlsPemBufferCredentialsConfig credentialsConfig = {
    .CaPem         = {myCaPem, sizeof(myCaPem)},
    .ClientCertPem = {myClientCertPem, sizeof(myClientCertPem)},
    .ClientKeyPem  = {myClientKeyPem, sizeof(myClientKeyPem)},
    .Rng           = &mySeededDrbg,
};
struct SolidSyslogMbedTlsCredentials* credentials =
    SolidSyslogMbedTlsPemBufferCredentials_Create(&credentialsConfig);
```

**Each length must include the terminating NUL** - `strlen(pem) + 1` - because
that is what Mbed TLS's parsers require of PEM. A length one byte short is
reported rather than left to surface as a parse failure, which matters because
Mbed TLS reads a certificate buffer whose last byte is not NUL as DER instead
and fails as "not a certificate". Material baked in by `xxd -i` is the usual
place this bites: the array it emits carries no terminator, so give the buffer
one byte more and set it. The key must not be encrypted; no password can be
supplied.

Then the stream, which is wired to whichever source you built:

```c
struct SolidSyslogMbedTlsStreamConfig cfg = {
    .Transport   = myTcpStream,
    .Sleep       = MySleep,               /* required - no fallback */
    .Rng         = &mySeededDrbg,
    .Credentials = credentials,           /* required - no fallback */
    .ServerName  = "syslog.example.com",
};
struct SolidSyslogStream* tls = SolidSyslogMbedTlsStream_Create(&cfg);
```

Each Create copies its configuration, so every field has to be set before it is
called.

Wire `tls` into a `SolidSyslogStreamSender` as its `Stream`, exactly as you
would a plain TCP stream. Tear down in reverse: the sender, the TLS stream, then
the credentials it borrows. There is nothing process-wide to install.

If your firmware already uses Mbed TLS for something else - a cloud client, an
OTA updater, a vendor framework - that is the whole integration: the adapter
consumes handles you have already built and touches no global state.

## Bringing Mbed TLS up, if it is new to the target

Port Mbed TLS itself first, following the
[upstream porting guide](https://mbed-tls.readthedocs.io/en/latest/kb/how-to/how-do-i-port-mbed-tls-to-a-new-environment-OS/).
Four things then matter specifically for this adapter, and three of them fail in
ways that are hard to read.

**Seed the DRBG from a source registered as `MBEDTLS_ENTROPY_SOURCE_STRONG`.**
Without a strong-tagged source, `mbedtls_entropy_func` never reaches its
internal threshold and every `mbedtls_ctr_drbg_seed` returns
`MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED`. Production entropy is a hardware
question - a true random number generator, a vendor security element, or a
board-specific source.

**Call `psa_crypto_init()` after the DRBG is seeded, not before.** Mbed TLS
3.6 routes TLS 1.3 through PSA, and if PSA is uninitialised the first handshake
state transition returns `MBEDTLS_ERR_ERROR_GENERIC_ERROR` before any byte
reaches the socket.

**On a target with no platform entropy, give PSA a strong source.** With
`MBEDTLS_NO_PLATFORM_ENTROPY` defined - usual on embedded - `mbedtls_entropy_init`
registers no source of its own, and `psa_crypto_init` then fails with
`PSA_ERROR_INSUFFICIENT_ENTROPY`. Two routes out, and either is enough:

- Define `MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG` and provide
  `mbedtls_psa_external_get_random` wrapping the DRBG you just seeded. PSA
  bypasses the entropy subsystem entirely, so PSA and the classic API run off
  one chain.
- Or define `MBEDTLS_ENTROPY_HARDWARE_ALT` and provide `mbedtls_hardware_poll`.
  `mbedtls_entropy_init` then registers it as a strong source, and PSA seeds its
  own DRBG through the standard path.

The first keeps one chain and is the simpler thing to reason about; the second
suits a target whose randomness already arrives through a hardware poll.

**Parse the CA chain, and the client credential if you are using mutual TLS**,
by whatever route suits the build: a filesystem, a baked-in array, a blob pulled
from a security element. PEM input must be NUL-terminated.

## Memory

The adapter allocates nothing itself. Everything a TLS session costs is Mbed
TLS's own allocation, governed by your `mbedtls_config.h` - the record buffer
sizes dominate it, and their defaults are sized for a general-purpose host
rather than a constrained target. Budget for every TLS session you intend to
run concurrently, not one, and take the sizing guidance from the
[upstream documentation](https://mbed-tls.readthedocs.io/) rather than from
here.

Where Mbed TLS takes its memory from is also your configuration. On a target
whose libc heap is not the one you intend it to use, `mbedtls_ssl_setup` is
where that shows up.

## When it does not work

Failures report through the error handler rather than silently. Install one
before you start, and read [error severity](../../error-severity.md) for what
each level is telling you - a `CRITICAL` at create time means the stream fell
back to the Null object, and nothing will be delivered.

A pin is read when the connection is made, so one that is not in the RFC 5425
form is reported on the first connect and not before. The digest is taken over
the certificate's DER encoding, which is what any certificate tool prints as its
SHA-256 fingerprint; what the pin adds is the `sha-256:` label in front,
hyphenated as the IANA registry spells it. Hex digits may be upper or lower
case.
