# TLS obligations

What a TLS `Stream` must do, whichever library provides it. Read this if you are
choosing between the TLS platforms, assessing the library against a security
standard, or writing a TLS `Stream` of your own.

The obligations here are the contract. What each shipped TLS platform actually
does, and where it differs, is on its own page - the
[capability matrix](platforms/index.md) shows which platforms fill the role.

## Delivery is preferred to silence

Syslog is how a device reports what happened to it, and a device under attack is
when that reporting matters most. A security control that fails closed stops the
reporting at exactly that point. An attacker who can block the route to a
revocation responder, or make a credential look half-configured, must not be able
to stop the device reporting.

So the default is: **report the fault through the error handler, and keep
delivering.**

The rule has a limit: **delivery stops when the peer fails the check the
integrator asked for.** That covers a configuration naming neither trust anchors
nor pinned fingerprints, a certificate that does not validate against the trust
anchors, a certificate matching none of the configured fingerprints, and a
certificate that does not match a declared identity. Continuing through any of
them would send the records to an unverified peer, losing the confidentiality of
the log and the audit trail together, with nothing to indicate it.

The check is the integrator's to set. Declaring no peer identity is a decision
rather than a failure: it states that chain verification alone is sufficient,
which on a closed network with a private CA it may be. The contract requires only
that the decision is explicit, and that the stream reports when it was never made
at all.

Every other fault leaves the peer still passing the checks the integrator
configured. Those are reported while delivery continues.

Where a store is configured, blocked delivery is delayed delivery rather than
lost delivery: records accumulate and replay on the next successful connection.
That bounds the cost of the exception without removing the reason for the rule: a
store is finite, and records replayed later do not raise an alert at the time.

## The obligations

### Pin the protocol floor

A TLS `Stream` sets its own minimum protocol version rather than inheriting
whatever the TLS library was built to permit. Downgrade resistance is then a
property of this library rather than of the integrator's build of another one.
The floor is TLS 1.2.

No ceiling is required, and setting one would be wrong. RFC 9662, which updates
RFC 5425, asks that TLS 1.3 be supported and **preferred** where it is
implemented, so a stream that pinned a ceiling to constrain something else would
breach that. BCP 195 §3.1.1 says the same for TLS generally.

### Require a trust anchor or a pinned fingerprint

A peer is authorised in one of two ways, and a `Stream` requires at least one of
them. Configured with neither, it refuses to connect rather than reach a peer it
cannot check. That is reported when a connection is attempted rather than when
the stream is created, because trust anchors are obtained per connection and a
stream cannot know at create time what its credential source will yield; the
timing rule is set out under *Check the configuration it cannot work without*.

**Certification path validation.** The peer certificate must chain to trust
anchors the integrator supplies. There is no fallback to a system trust store: an
embedded target may not have one, and on a host that store is a far larger trust
base than a device reporting to a single collector needs. Validity dates are part
of this check, not separate from it - RFC 5280 §6.1 makes the validity period an
input to path validation, so a certificate outside its own dates does not chain
and the connection stops.

**A pinned certificate fingerprint.** Covered in its own obligation below. A
certificate matched by fingerprint needs no chain: RFC 5425 §4.2.1 states that
such a certificate "can be self-signed, and no certification path validation is
needed".

Where both are configured, the peer must satisfy both. That is this contract's
choice, not a requirement of RFC 5425: §6.1 recommends that both endpoints be
authenticated and authorised by one of §5.1 or §5.2, rather than that the two be
combined. Requiring both is the safer reading of a configuration that supplies
both.

### Accept a peer authorised by certificate fingerprint

RFC 5425 §5.1 requires that a peer can be authorised by its certificate
fingerprint, not only by a chain to a trust anchor and a name. The two are
different tools: a fingerprint pins one certificate, which suits a closed network
with no PKI, where operating a CA is more than the deployment needs.

The accepted form is the one RFC 5425 §4.2.2 defines: an ASCII hash label, a
colon, then the hash of the DER-encoded certificate as colon-separated hex
pairs. §4.2.2 publishes those pairs in uppercase, but a `Stream` accepts either
case and a mixture of the two: a pin reaches a device through an engineer
transcribing it, and case carries no meaning. Labels come from the IANA
[Hash Function Textual Names](https://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xhtml)
registry and are hyphenated, so `sha-256` and `sha-1` rather than `sha256` or
`sha1`. A `Stream` accepts both of those algorithms. §4.2.2 makes SHA-1 mandatory
to support; `sha-256` is the one to configure where the collector offers a
choice, and a `sha-1` pin is reported on every connection that uses one.

A **list** of fingerprints is accepted, and any one of them authorises the peer.
A fingerprint covers the whole DER certificate, so it changes every time the
collector's certificate is renewed. Pinning the old and the new together is what
lets a fleet cross a renewal without every device stopping at once.

Where fingerprints are configured and the peer's certificate matches none of
them, the connection stops, whatever the chain says.

**A pin does not extend the validity period.** A pinned certificate outside its
validity period is refused, in fingerprint-only mode exactly as in any other. A
pin states which certificate is expected; it does not make an expired one
acceptable. The two checks are independent: the pin establishes which peer this
is, and the validity period establishes whether the issuer still stands behind
its certificate.

**Pinning makes the collector's expiry a fleet-wide event.** Every device pinned
to a certificate stops at the same `notAfter`, and a device that missed the pin
update stays stopped. Where the deployment controls its own CA and the collector
certificate is not otherwise constrained, RFC 5280 §4.1.2.5 provides for a
certificate with no well-defined expiry, `99991231235959Z`, and gives an embedded
device as its worked example. Where it does not, pin the next certificate
alongside the current one before the renewal rather than after it. A configured
store turns a missed renewal into delayed delivery rather than lost delivery, up
to the point the store fills.

### Treat endpoint identity as declared, not assumed

The integrator declares the peer identity they expect. A `Stream` verifies it
when one is declared, accepts an explicit decision not to check a name, and
reports when nothing was declared at all - because that last case is a peer that
is chain-verified but otherwise unidentified, which an attacker holding any
certificate from a trusted CA can exploit. BCP 195 §7.1 states that without the
name check, TLS proves the certificate is valid and that the peer holds its key,
but not that the intended endpoint was reached.

A configured fingerprint is itself a declaration of identity, and a stronger one
than a name: it names the exact certificate expected rather than a subject within
a trusted CA's namespace. So a `Stream` given fingerprints and no name does not
report an unidentified peer.

The states, and what each means, are documented on each platform's configuration
field.

### Obtain credentials per connection, and announce when they are released

Trust anchors, the client credential and the expected peer identity are obtained
when a connection is made, and the `Stream` says when it has finished with them.
Where credentials come from is the integrator's choice, and each platform
documents the mechanism it offers: a file, a caller-built handle, a secure
element, an encrypted store.

Two things follow from that, and one does not.

**A device issued new credentials while it is running uses them on its next
connection** without being restarted. Moving the stream's configuration version
makes it immediate.

**The window in which the integrator must keep material intact is the
connection**, not the lifetime of the stream. That is the point of announcing the
release: replacing material a stream is still holding is a use-after-free, and an
integrator should not have to infer when it is safe.

**It does not follow that the material is out of RAM for most of the time.** How
much this saves depends on two things the contract cannot settle. The first is
how long a connection lasts, which is covered below. The second is the credential
source: one that hands over a pointer to something the integrator already holds
parsed has nothing to release, whereas one that parses on demand and wipes on
release does. Each platform page states what its own source does.

What the underlying TLS library holds during a connection is a property of that
library rather than of this contract. Each keeps the parsed certificate and key
for the duration of the session, the private key included; clearing them
mid-session would break the session just established.

The expected identity travels with the destination. Where the destination can be
changed at runtime, redirecting a device to a different collector must carry the
identity its certificate is checked against, or the redirection moves the device
to an unverified peer.

### Apply a change by moving a version, not by reaching into the connection

Every `Stream` reports a configuration version, and the sender reads it on every
record. Moving that version is how a change to the material, the expected peer or
the cipher policy is applied: the sender closes the connection on its next pass
and opens a new one, so the change is in force from the following record.

This is the only lever an integrator needs from outside the task that services
the library. A version is a value the integrator owns, read back at a point of
the library's choosing; `SolidSyslogSender_Disconnect` touches the sender's own
connection state and takes no lock, so it belongs to the servicing task.

A stream whose configuration cannot change at runtime reports one version for its
lifetime, and the sender never reconnects on its account.

Applying a change is a separate question from destroying what it replaced. A
version moved from another task says nothing about when the connection actually
closed, so material the integrator must free rather than overwrite is still
governed by the release announcement above. Each platform page states what its
own credential sources require.

### A connection is long-lived, and the integrator bounds it

A `Stream` opens on the first record that needs it and stays open. It closes when
a send fails, when the destination's version moves, when the stream's own
configuration version moves, when the integrator calls
`SolidSyslogSender_Disconnect`, or when the stream is destroyed. There is no idle
timeout and no maximum lifetime, because a syslog client that reconnects on a
timer costs a handshake each time and gains nothing for a device that logs
steadily.

That is the right default, and it has a consequence: **on a device that logs
continuously, one connection may last for the device's uptime, and the credential
material stays resident for all of it.** The private key is needed once, to sign
during the handshake; it is retained for the rest because neither TLS library
offers a client a way to hand it back.

Bounding that window is the integrator's. A deployment that wants the material
resident for minutes rather than months moves the configuration version on its
own schedule; the next record reconnects and the credential source is asked
again. The same lever serves RFC 5425 §4.4's requirement that a
sender close a connection it does not expect to carry more messages.

Where the key must not be in application memory at all, that is a property of the
credential source rather than of the window: a source backed by a secure element
or a hardware key store never hands the key over in the first place.

### Report a client credential that will not be presented

Mutual TLS is all-or-nothing: a certificate without its key, or a key without its
certificate, is a configuration error and is reported as one. It is never
silently treated as a decision to use server-authenticated TLS: an integrator who
supplied half a credential believes mutual authentication is in force when it is
not.

A key that does not match the certificate it was supplied with is the same
mistake reached differently, and is detectable without going near the network, so
it is reported at the same point. Left to the handshake, it surfaces as a
rejection from the collector, sending the integrator to the collector for a fault
that is on the device.

A credential the TLS library will not take - a file that does not load, memory it
cannot allocate - is reported on the same terms. The reports distinguish the
cause where the library distinguishes it, but the result is the same: what the
integrator configured is not in force.

Delivery continues in all three cases. The receiver is the enforcement point for
the client's credential - a collector that requires a client certificate will
refuse the handshake, and one that does not was never going to check. Blocking
here would deny the audit trail without changing what the collector decides.

The rule stops at the client's own credential. A fault in the material a `Stream`
presents never stops delivery; a failed check on the peer always does, as
*Delivery is preferred to silence* sets out.

### Permit the cryptographic level to be chosen

Where the underlying library allows the cipher policy to be selected, a `Stream`
passes the integrator's choice through unchanged and pins none of its own. The
appropriate policy depends on the build present on the target and on the profile
the deployment is held to, and neither is knowable here.

For a deployment with no policy of its own, RFC 9662 §4 asks that
`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` be offered, and BCP 195 §4.2 recommends
the same shape - ECDHE with AES-GCM - for TLS 1.2. Both prefer it over the 2009
mandatory suite, which offers no forward secrecy.

Since no ceiling is set, the version negotiated may be later than the floor, and
a policy that binds only up to the floor does not bind the connection in use.
Passing the integrator's choice through means passing it through for whichever
version is negotiated.

Where the library does not allow it, its own defaults apply. What each platform
can and cannot select is on its page.

### Do not resume a session under weaker terms

A resumed session carries the security parameters of the session it resumes, so a
`Stream` that resumes must check those parameters against what the current
configuration requires and complete a full handshake instead where they fall
short. RFC 5425 §4.2.3 recommends that check; this contract requires it.

A `Stream` that never resumes meets this by construction, and it must not be
possible to start resuming without revisiting the check.

### Do not require revocation checking

Revocation checking is outside the contract. Many industrial deployments have no
route to a certificate revocation list or an OCSP responder, and a control that
depends on reaching one fails closed exactly when the network is under attack.

An integrator who needs it configures it in their own TLS library and verifies it
themselves. The library neither performs the check nor reports on whether one is
in force.

This is a deliberate deviation. BCP 195 §7.5 requires a TLS implementation to
implement a strategy to distrust revoked certificates, and no stream here
implements one. The reasoning is above; what makes it tolerable is that the
obligation moves rather than disappears. An integrator's own TLS library
can be configured for CRL or OCSP, and this library neither performs that check
nor prevents it - so an assessment that needs the obligation met should say where
it is met, rather than assume this library meets it.

It is also why certificate validity is enforced rather than tolerated. Chain,
fingerprint and identity checks all still reject a certificate, but they reject
the same certificate today as they did yesterday. Without a revocation check, the
validity period is the only mechanism by which a certificate that was acceptable
stops being so.

### Bound the handshake

A handshake cannot stall the servicing pass indefinitely. It runs against a
deadline, over a non-blocking transport, and gives up with a report rather than
blocking when the budget expires. That requires an injected sleep, which is why
every TLS `Stream` asks for one.

### Send `close_notify` before tearing down

Closing sends the TLS close notification before the connection goes away, so the
collector can distinguish an orderly shutdown from a truncated session. RFC 5425
§4.4 requires it.

### Check the configuration it cannot work without

A `Stream` is given two kinds of thing, and each is checked at the point it can
be.

**Wiring is checked when the stream is created.** A transport, a sleep, a source
of credentials, and whatever else the platform cannot operate without: given a
configuration missing one of these, a `Stream` reports a bad configuration and
returns the Null object. It does not accept the configuration and then fail on
the first connection, and it does not dereference what is missing. What each
platform cannot work without is on its own page.

**Material is checked when a connection is made**, because that is when it is
obtained. Material that authorises the peer is what the connection depends on: a
configuration naming neither trust anchors nor fingerprints, trust anchors that
cannot be produced, and a fingerprint that is not well formed are reported then,
and that connection attempt fails. The sender retries on its next pass, so a
transient source recovers on its own.

A client credential is checked at the same point and does not fail the
connection, for the reasons under *Report a client credential that will not be
presented*.

This is the library-wide rule for anything that reaches the wire rather than
anything specific to TLS: a failure an integrator caused at setup is reported at
setup rather than at first use.

### Report every one of these, and name the check that failed

All of the above surface through the error handler rather than a return code an
integrator may not read. [Error handling](error-severity.md) covers what each
severity is telling you; the short form is that `CRITICAL` at create time means
the `Stream` fell back to the Null object and nothing will be delivered.

Where a connection is refused, the report names which check refused it - an
expired certificate, one not yet valid, a chain that does not validate, a
fingerprint that matched nothing, a name that did not match. An integrator whose
device will not connect needs to know which of those it is, because a generic
handshake failure sends them looking at the network for a fault that is on a
certificate.

### Key custody stays with the integrator

The library holds no key material of its own and uses whatever it is given. File
permissions on a private key, whether it lives in a hardware security module, and
how it is rotated are properties of the deployment, not of this contract. The
per-connection obligation above is what makes those choices reachable: the
`Stream` asks for material when it needs it and reports when it is done, so where
the material rests in between is the integrator's to decide.
