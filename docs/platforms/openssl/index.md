# OpenSSL

`Platform/OpenSsl/` wraps [OpenSSL](https://docs.openssl.org/) for TLS transport
and keyed at-rest cryptography on hosted targets. It fills the
[Stream](../../api/structSolidSyslogStream.md) role with TLS and the
[SecurityPolicy](../../api/structSolidSyslogSecurityPolicy.md) role for at-rest
integrity and confidentiality.

What a TLS stream must do is the same whichever library provides it, and is
stated once under [TLS obligations](../../tls.md). This page covers what this
adapter needs, how credentials reach it, and where it does not yet meet that
contract.

## What it ships

## Requirements

OpenSSL 3.0 or later. The CMake configure fails below that rather than the build,
so an older libssl is caught before anything compiles.

A `SolidSyslogSleepFunction` is required and has no default.

## Credentials come from a credentials source

Where trust anchors, pinned peer fingerprints and the mutual-TLS client
credential come from is the integrator's choice rather than this adapter's. The
stream is wired to a `SolidSyslogOpenSslCredentials`, asked once per connection
to install its material on the `SSL_CTX` and told once per connection when that
material is no longer needed. A source backed by a hardware key store, a
keyring or an encrypted store is a class implementing that role, and needs no
change here.

One source ships with the pack: `SolidSyslogOpenSslPemFileCredentials`, which
names its material by file path. It performs no file handling of its own -
the paths go to OpenSSL, which opens and parses them, so PEM bytes never pass
through this library.

The `SSL_CTX` is rebuilt on every open and freed on close, and the credentials
source is asked again each time. Nothing is held between connections. Rotation
is therefore a replacement and a reconnection: put the new material in place,
and it is in force on the next connection, either through ordinary reconnection
after an outage or immediately by moving the stream's configuration version.
Nothing has to be freed to rotate the shipped source, which names a path that
OpenSSL reads afresh on each connection, so the version is the whole of it.

## Where it differs from the contract

Each is tracked. Read them before relying on the corresponding obligation.

### The cipher policy does not bind a TLS 1.3 connection

The cipher list is passed to OpenSSL unchanged and pins nothing of the library's
own, as the contract asks. It governs TLS 1.2 and below only. OpenSSL has kept
TLS 1.3 ciphersuites in a separate list since 1.1.1, and this adapter sets a
protocol floor without a ceiling, so against a modern peer the negotiated
connection uses OpenSSL's own TLS 1.3 defaults and the configured list has no
effect on it. Tracked as
[#733](https://github.com/cososo-ltd/solid-syslog/issues/733).
