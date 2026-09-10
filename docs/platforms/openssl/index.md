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

## What it reports

Faults are reported with the portable TLS-stream detail codes, so a handler
written against them keeps working if the TLS backend underneath changes. What
stays specific to this pack is `event->Source`, which names it as the reporter.

Two of those codes describe faults this pack cannot have, so it never raises
them: `DEFAULTS_NOT_APPLIED`, because nothing here applies a library preset, and
`NULL_RNG`, because OpenSSL carries its own entropy source and the configuration
asks for none.

## What a connection is made with

The stream asks for a profile once per connection, and takes the expected peer
name and the cipher policy from it. Nothing is stored between connections, so a
change is a matter of returning something different and moving the stream's
version.

Both of OpenSSL's cipher lists are selectable, because it keeps two: one governs
TLS 1.2 and below, the other TLS 1.3, and since no protocol ceiling is pinned the
second is usually the one in force. Leave either unset and OpenSSL's own default
stands - for TLS 1.3 that is the suite RFC 8446 makes mandatory plus the two it
recommends. A list that selects nothing fails `Open`, before any handshake, rather
than falling back, so a policy that matches no suite is reported instead of
silently ignored.

Key-exchange groups and signature algorithms are not selectable here. TLS 1.3
moved both out of the ciphersuite, so a policy naming a curve has nowhere to go
yet.
