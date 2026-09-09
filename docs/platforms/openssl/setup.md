# OpenSSL setup

Wiring `SolidSyslogOpenSslStream` so a `SolidSyslogStreamSender` delivers RFC 5425
syslog over TLS. The [TLS obligations](../../tls.md) page covers what any TLS
stream must do. The [OpenSSL](index.md) page covers what this adapter needs and
where it falls short of that. The config fields are documented on the struct
itself, and this page is the wiring.

## What you need

OpenSSL 3.0 or later on the include and link path, and a platform supplying the
TCP stream underneath - the [capability matrix](../index.md) shows which fill
that role.

```cmake
set(SOLIDSYSLOG_PLATFORMS "OpenSsl;<Network>")
```

`<Network>` is whichever platform the [capability matrix](../index.md) says
fills that role on your target - see
[naming your platforms](../../build-integration.md#cmake) for how the list is
read.

OpenSSL is a stable system API rather than a header-configured upstream, so the
adapter compiles straight into `libSolidSyslog.a` and there is no separate
target to link. [Adding it to your build](../../build-integration.md) covers the
Make and IDE routes.

## The layering

TLS is a Stream wrapped around another Stream. The TLS adapter carries the
records; the transport underneath carries the bytes, and it can be any Stream.

```text
StreamSender → SolidSyslogOpenSslStream → your TCP stream → socket
```

The TLS stream **borrows** its transport. It may close it, but it never destroys
it: the transport is yours to create and to destroy, and it must stay valid
until `SolidSyslogOpenSslStream_Destroy`.

## Wiring it

First a credentials source, which is where the material comes from. The one
that ships with the pack names it by file path:

```c
static struct SolidSyslogOpenSslPemFileCredentialsConfig credentialsConfig;
credentialsConfig = (struct SolidSyslogOpenSslPemFileCredentialsConfig) {0};
credentialsConfig.CaBundlePath = "/etc/ssl/collector-ca.pem";

/* For mutual TLS, add the client credential here - both fields, since one
   without the other is reported and leaves the connection
   server-authenticated. */
credentialsConfig.ClientCertChainPath = "/etc/ssl/device-chain.pem";
credentialsConfig.ClientKeyPath       = "/etc/ssl/device-key.pem";

/* To authorise the collector by its certificate rather than by a chain, pin
   it. Any one pin in the list authorises, which is how a fleet crosses a
   renewal; the array and the strings are yours and must outlive the
   credentials. A pin alone is enough, so CaBundlePath may be left NULL - and
   where both are set, both must be satisfied. */
static const char* const pins[] = {
    "sha-256:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:"
    "7A:F1:9E:9D:0C:44:1B:23:5D:87:6E:A0:31:F5:C2:98"
};
credentialsConfig.PeerFingerprints     = pins;
credentialsConfig.PeerFingerprintCount = 1;

struct SolidSyslogOpenSslCredentials* credentials =
    SolidSyslogOpenSslPemFileCredentials_Create(&credentialsConfig);
```

`SolidSyslogOpenSslPemFileCredentials_Create` copies the configuration, so every
field has to be set before it is called. Assigning one afterwards changes
nothing.

Then the stream, which is wired to it:

```c
/* Your TCP stream and sleep, from the platform that supplies them. */
struct SolidSyslogStream* transport = CreateTcpStream();

static struct SolidSyslogOpenSslStreamConfig tlsConfig;
tlsConfig = (struct SolidSyslogOpenSslStreamConfig) {0};
tlsConfig.Transport = transport;
tlsConfig.Sleep = MySleep;                    /* required - no fallback */
tlsConfig.Credentials = credentials;          /* required - no fallback */
tlsConfig.ServerName = "collector.example.net";

struct SolidSyslogStream* tls = SolidSyslogOpenSslStream_Create(&tlsConfig);
```

Zero-initialise each config before filling it.

The credentials outlive the stream that borrows them: destroy the stream first,
then the credentials.

Then the sender, unchanged from the plain-TCP case - it sees a Stream and does
not know or care that it is a TLS one:

```c
static struct SolidSyslogStreamSenderConfig senderConfig;
senderConfig = (struct SolidSyslogStreamSenderConfig) {0};
senderConfig.Resolver = resolver;
senderConfig.Stream   = tls;
senderConfig.Address  = CreateAddress();      /* your platform's Address */
senderConfig.Endpoint = GetEndpoint;
struct SolidSyslogSender* sender = SolidSyslogStreamSender_Create(&senderConfig);
```

Tear down in reverse order: sender, address, TLS stream, the credentials, then
the transport you created. The stream borrows the credentials, so they outlive
it.

## When it does not work

Failures report through the error handler rather than silently. Install one
before you start, and read [error severity](../../error-severity.md) for what
each level is telling you - a `CRITICAL` at create time means the stream fell
back to the Null object, and nothing will be delivered.

A pin is read when the connection is made, so one that is not in the RFC 5425
form is reported on the first connect and not before. `openssl x509 -noout
-fingerprint -sha256 -in collector.pem` prints the digest in the byte form the
pin wants; the label it needs is `sha-256:`, hyphenated, in place of what
OpenSSL prints. Hex digits may be upper or lower case.
