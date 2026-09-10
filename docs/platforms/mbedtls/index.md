# Mbed TLS

`Platform/MbedTls/` wraps [Mbed TLS](https://mbed-tls.readthedocs.io/) for TLS
transport and keyed at-rest cryptography on embedded targets. It fills the
[Stream](../../api/structSolidSyslogStream.md) role with TLS and the
[SecurityPolicy](../../api/structSolidSyslogSecurityPolicy.md) role for at-rest
integrity and confidentiality.

What a TLS stream must do is the same whichever library provides it, and is
stated once under [TLS obligations](../../tls.md). This page covers what this
adapter needs, how credentials reach it, the coexistence guarantee it makes, and
where it does not yet meet that contract.

## What it ships

## Requirements

The adapter sources compile in your target against your own `mbedtls_config.h`,
so the features you enable are the features it gets.

A `SolidSyslogSleepFunction` is required and has no default.

## Credentials come from a credentials source

Where trust anchors, pinned peer fingerprints and the mutual-TLS client
credential come from is the integrator's choice rather than this adapter's. The
stream is wired to a `SolidSyslogMbedTlsCredentials`, asked once per connection
to install its material on the `mbedtls_ssl_config` and told once per connection
when that material is no longer needed. A source backed by a security element, a
PSA opaque key or an encrypted store is a class implementing that role, and needs
no change here.

Two sources ship with the pack, and neither opens a file - which is what allows
the adapter to run on targets built without `MBEDTLS_FS_IO`.

`SolidSyslogMbedTlsHandleCredentials` carries caller-built, caller-owned handles:
an `mbedtls_x509_crt` trust chain, and for mutual TLS an `mbedtls_x509_crt` and
`mbedtls_pk_context` pair. The integrator parses the material and keeps it
parsed.

`SolidSyslogMbedTlsPemBufferCredentials` carries PEM held in memory and parses it
per connection. Between connections nothing but the integrator's own PEM is in
memory, which may be read-only flash. What Release frees, Mbed TLS wipes:
`mbedtls_pk_free` zeroises the key context and every limb of the private key,
and `mbedtls_x509_crt_free` zeroises the DER it decoded. This library copies the
PEM nowhere, so it holds no second copy to wipe.

The credential window is explicit. Install is called after the transport
connects; Release answers every Install, once, after the `ssl_config` has been
freed and with it every pointer into the material. That window is what a source
reaching a secure element or an encrypted store needs, and the PEM-buffer source
is the worked example of using it.

With the PEM-buffer source, replacing the buffer and moving the stream's
configuration version is enough - nothing is freed, and the next connection
parses whatever the buffer then points at.

The handle source is different, because rotating it means freeing material the
open connection is still reading. Moving the version applies the change but does
not say when the old handle stops being read, so the free and the re-parse belong
after the connection has closed: either call `SolidSyslogSender_Disconnect` from
the task that services the library and re-parse once it returns, or put the free
and the re-parse in a credentials source's `Release`, which the stream calls when
it has finished with the material.

## Coexistence is an auditable contract

`Platform/MbedTls/Source/` calls no process-global Mbed TLS API. It does not call
`mbedtls_platform_setup` or `mbedtls_platform_teardown`, install threading-alt
hooks, call `psa_crypto_init`, reset the global random number generator, or
replace a debug callback. TLS policy is applied per `ssl_config`, so it cannot
affect the ones you build elsewhere. A device that already uses Mbed TLS for
firmware update or a vendor cloud SDK keeps that configuration intact, and the
claim can be checked against the directory.

## What it reports

Faults are reported with the portable TLS-stream detail codes, so a handler
written against them keeps working if the TLS backend underneath changes. What
stays specific to this pack is `event->Source`, which names it as the reporter.

One of those codes describes a fault this pack cannot have, so it never raises
it: `CONTEXT_INIT_FAILED`. There is no separate context to build here - the
configuration is brought up from a library preset, and a failure at that point is
`DEFAULTS_NOT_APPLIED`.

## What a connection is made with

The stream asks for a profile once per connection, and takes the expected peer
name and the ciphersuite policy from it. Nothing is stored between connections,
so a change is a matter of returning something different and moving the stream's
version.

The ciphersuite policy is one list covering both TLS versions, given as a
0-terminated array of IANA identifiers - the `MBEDTLS_TLS_*` and
`MBEDTLS_TLS1_3_*` macros. Mbed TLS does not copy it, so the array must stay
valid for as long as the connection. Leave it unset and every ciphersuite the
build enables is offered, which on a trimmed `mbedtls_config.h` is whatever was
compiled in rather than a curated set; naming a policy is how that becomes a
decision rather than a side effect of the build.

Setting the list cannot fail here - `mbedtls_ssl_conf_ciphersuites` returns
nothing - so a policy naming only suites the build does not carry surfaces as a
refused handshake rather than as a configuration error.

Key-exchange groups and signature algorithms are not selectable here. TLS 1.3
moved both out of the ciphersuite, so a policy naming a curve has nowhere to go
yet.
