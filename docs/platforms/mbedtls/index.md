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

Rotation with the handle source is a disconnect and a re-parse: call
`SolidSyslogSender_Disconnect`, then free and re-parse into the same handle. The
next send reconnects with the new material. Freeing before the disconnect
completes is a use-after-free, because the open connection is still reading it.
With the PEM-buffer source, replacing the buffer is enough - the next connection
parses whatever it then points at.

## Coexistence is an auditable contract

`Platform/MbedTls/Source/` calls no process-global Mbed TLS API. It does not call
`mbedtls_platform_setup` or `mbedtls_platform_teardown`, install threading-alt
hooks, call `psa_crypto_init`, reset the global random number generator, or
replace a debug callback. TLS policy is applied per `ssl_config`, so it cannot
affect the ones you build elsewhere. A device that already uses Mbed TLS for
firmware update or a vendor cloud SDK keeps that configuration intact, and the
claim can be checked against the directory.

## Where it differs from the contract

Each is tracked. Read them before relying on the corresponding obligation.

### The cipher policy cannot be expressed

The configuration carries no cipher or ciphersuite field, so the ciphersuites
your `mbedtls_config.h` enables, filtered by the preset, are what gets
negotiated. The contract asks for an integrator's policy to be passed through
where the library allows one to be selected. Tracked as
[#733](https://github.com/cososo-ltd/solid-syslog/issues/733).
