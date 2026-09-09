# RFC Compliance Matrix

SolidSyslog implements the sender (client) side of four syslog RFCs. This
document tracks which requirements are met, which are met with known
limitations, and which do not apply.

Status key:

- Supported: implemented and tested
- Partial: implemented with known limitations
- Not Met: an obligation the library does not meet - the note says what is planned
- N/A: not applicable to a sender implementation, or applicable and deliberately
  excluded - the note says which, and why

A status describes the library: Core, and the role contracts it defines, with a
conforming platform supplying the roles it needs. Almost every requirement below
depends on which platform components are selected and how they are configured,
including components you write yourself, which the library cannot speak for.
Where a shipped platform does not meet an obligation, its own page records the
exception and links the issue tracking it, and the
[capability matrix](platforms/index.md) shows which platform fills which role.

Every status below describes a correctly wired instance. A component that could
not be built - a dependency left NULL, a pool sized too small - is replaced by its
Null object and reported through the error handler, at the severity
[docs/error-severity.md](error-severity.md) sets for a `Create` that fell back.
That is a wiring fault to fix before shipping, not a limit on what the library
supports, so the rows do not restate it.

## RFC 5424 - The Syslog Protocol

Checked against [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424.html), Standards Track.

| Section | Requirement | Status | Notes |
|---|---|---|---|
| [5](https://www.rfc-editor.org/rfc/rfc5424.html#section-5) | Transport MUST NOT deliberately alter the message | Supported | The sender transmits the formatted message as the formatter produced it. The length prefix added by octet-counting framing is defined by the transport mapping (RFC 5425 §4.3.1, RFC 6587 §3.4.1) and frames the message rather than altering it |
| [5.1](https://www.rfc-editor.org/rfc/rfc5424.html#section-5.1) | Minimum transport mapping - TLS MUST, UDP SHOULD | Supported | Both ship. TLS is a Stream wrapped around a byte-transport Stream; UDP is `SolidSyslogUdpSender` over the Datagram role. Which platform supplies each is in the [capability matrix](platforms/index.md). §5.1 also RECOMMENDS deployments use TLS, which is a deployment choice rather than a library one |
| [6](https://www.rfc-editor.org/rfc/rfc5424.html#section-6) | PRINTUSASCII in header fields (codes 33-126) | Supported | Non-compliant bytes substituted with `?` at format time (HOSTNAME, APP-NAME, PROCID, MSGID) |
| [6.1](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.1) | Message length - no upper limit; receivers MUST accept 480 octets and SHOULD accept 2048 | Supported | §6.1 bounds what a receiver accepts rather than what a sender emits, and permits any length. `SOLIDSYSLOG_MAX_MESSAGE_SIZE` is the sender-side choice, and defaults to the MUST floor - the only length every conforming receiver has to take. Raise it via the standard tunable mechanism where the receivers are known |
| [6.2](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.2) | HEADER - seven-bit ASCII in an eight-bit field | Supported | Every HEADER field is written through the `SolidSyslogHeaderField` sink, which substitutes any byte outside PRINTUSASCII (33-126) with `?`. PRINTUSASCII is a subset of seven-bit ASCII, so the stricter substitution satisfies §6.2 as well as the per-field productions |
| [6.2.1](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.2.1) | PRI - facility * 8 + severity | Supported | Invalid values fall back to `syslog.err` (facility 5, severity 3) |
| [6.2.2](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.2.2) | VERSION = 1 | Supported | |
| [6.2.3](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.2.3) | TIMESTAMP - derived from RFC 3339, with an optional 1-6 digit fraction | Supported | §6.2.3 restricts RFC 3339 rather than ISO 8601 generally, and its ABNF bounds TIME-SECFRAC at `1*6DIGIT` where RFC 3339 allows any number of digits. The library always writes the full 6, so microsecond resolution, with a UTC offset or `Z` |
| [6.2.3](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.2.3) | TIMESTAMP - NILVALUE when clock unavailable | Supported | NilClock produces `-` |
| [6.2.3.1](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.2.3.1) | TIMESTAMP examples | N/A | Illustrative. States no requirement of its own |
| [6.2.4](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.2.4) | HOSTNAME - max 255 chars, PRINTUSASCII | Supported | Truncated to 255. Non-PRINTUSASCII bytes substituted with `?`. Written through the public `SolidSyslogHeaderField` sink (`SolidSyslogHeaderField_PrintUsAscii`); the underlying formatter is library-private |
| [6.2.5](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.2.5) | APP-NAME - max 48 chars, PRINTUSASCII | Supported | Truncated to 48. Non-PRINTUSASCII bytes substituted with `?` |
| [6.2.6](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.2.6) | PROCID - max 128 chars, PRINTUSASCII | Supported | Truncated to 128. Non-PRINTUSASCII bytes substituted with `?` |
| [6.2.7](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.2.7) | MSGID - max 32 chars, PRINTUSASCII | Supported | Truncated to 32. Non-PRINTUSASCII bytes substituted with `?` |
| [6.3](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.3) | STRUCTURED-DATA - SD-ELEMENTs or NILVALUE | Supported | Extensible via `SolidSyslogStructuredData` vtable |
| [6.3.1](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.3.1) | SD-ELEMENT - brackets, SD-ID, space-separated SD-PARAMs | Supported | `SolidSyslogSdElement` owns the framing: `SolidSyslogSdElement_Begin` opens the bracket and writes the SD-ID, each `SolidSyslogSdElement_Param` writes a leading space and the name, and `SolidSyslogSdElement_End` closes the bracket. An author writing structured data cannot emit the delimiters directly |
| [6.3.2](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.3.2) | SD-ID and PARAM-NAME conform to SD-NAME | Supported | `SolidSyslogSdElement` owns the brackets, the `@` and enterprise number, the separators and the quoting; it bounds each name to the 32 characters §6.3.2 allows and substitutes non-printable bytes and spaces. The three remaining SD-NAME exclusions - `=`, `]` and `"` - are the author's to observe, and are stated on `SolidSyslogSdElement_Begin`, as is §6.3.2's rule that an SD-ID appears at most once in a message. Names are written by the developer authoring the SD rather than carried from runtime data, so an invalid one fails visibly on the first run rather than on some input |
| [6.3.3](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.3.3) | SD-PARAM value escaping (`]`, `\`, `"`) | Supported | `SolidSyslogSdValue` - every SD-PARAM value is written through this sink, which applies the escaping: RFC 3629 UTF-8 validated, ill-formed input substituted per-byte with U+FFFD (Unicode §3.9). `SolidSyslogOriginSd` streams software, swVersion, enterpriseId, and each ip into it; `SolidSyslogMetaSd` streams language via the integrator's `SolidSyslogSdValueFunction` callback. Both get the same escaping. |
| [6.3.4](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.3.4) | Change control - a defined SD-ID or PARAM-NAME MUST NOT change meaning | N/A | Directed at whoever defines an SD-ID, not at an implementation emitting one. The elements this library ships are the IANA-registered ones, whose syntax §7 fixes, so there is no definition here to hold stable |
| [6.3.5](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.3.5) | STRUCTURED-DATA examples | N/A | Illustrative. States no requirement of its own |
| [6.4](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.4) | MSG - UTF-8 preferred | Supported | RFC 3629 UTF-8 validated at the formatter primitives (`SolidSyslogFormatter_BoundedString`), with ill-formed input substituted per-byte with U+FFFD (Unicode §3.9). MSG is prefixed with the §6.4 UTF-8 BOM (`%xEF.BB.BF`) unconditionally. A leading BOM in the caller's body is stripped, so the wire frame contains exactly one. Truncation preserves codepoint boundaries at both layers: the formatter clips at `SOLIDSYSLOG_MAX_MESSAGE_SIZE` without splitting a codepoint, and on UDP the sender walks back over any partial codepoint when the kernel reports `EMSGSIZE` for the path MTU. TCP/TLS streams fragment transparently at the transport layer and so do not need a path-MTU trim |
| [6.5](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.5) | Message examples | N/A | Illustrative. States no requirement of its own |
| [7](https://www.rfc-editor.org/rfc/rfc5424.html#section-7) | Structured Data IDs - the IANA-registered SD-IDs are OPTIONAL | N/A | Introduces the IANA-registered SD-IDs and marks them all OPTIONAL. Its one requirement is directed at receiving applications: be prepared to accept the defined number of characters in any valid UTF-8 code point, which may be up to 6 octets each |
| [7.1](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.1) | timeQuality SD - tzKnown, isSynced, syncAccuracy | Supported | `SolidSyslogTimeQualitySd` |
| [7.1.1](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.1.1) | tzKnown - MUST be 1 when the time zone is known, 0 when in doubt | Supported | The `TzKnown` bool in `SolidSyslogTimeQuality` is emitted as `1` or `0`, so no other value can reach the wire. Which one is true is the integrator callback's to answer |
| [7.1.2](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.1.2) | isSynced - MUST be 1 when synchronised to a reliable source, 0 when not | Supported | The `IsSynced` bool is emitted as `1` or `0` on the same basis as tzKnown |
| [7.1.3](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.1.3) | syncAccuracy - MUST NOT be specified when isSynced is 0 | Supported | The library omits the parameter whenever `IsSynced` is false |
| [7.1.4](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.1.4) | timeQuality examples | N/A | Illustrative. States no requirement of its own |
| [7.2](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.2) | origin SD - software, swVersion, enterpriseId, ip | Supported | `SolidSyslogOriginSd` emits all four §7.2 parameters, each independently optional: a NULL string, or a NULL callback pair, omits that parameter. Wiring none is legal - §7.2 marks every parameter OPTIONAL - and produces a bare `[origin]`. Each parameter's own constraints are in the rows below; `SolidSyslogOriginSdConfig` states how the caller's strings are held and for how long |
| [7.2.1](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.2.1) | ip - MUST be the textual representation of an IP address | Supported | The library opens one `ip` PARAM per index and escapes what the integrator's at-callback writes into it, applying no length bound of its own. §7.2.1 lets a multi-homed originator list one address or repeat the parameter, and the count callback chooses. The textual form of each address is the integrator's to produce |
| [7.2.2](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.2.2) | enterpriseId - MUST be an IANA-registered private enterprise number | Supported | Bounded at 64 decoded bytes. §7.2.2 states no length, so 64 is this library's ceiling, set well above the private enterprise numbers and sub-identifier OIDs that appear in practice. The library registers no enterprise number of its own and does not check the value's form: which number is yours, and that it is registered with IANA, is the integrator's |
| [7.2.3](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.2.3) | software - MUST NOT be longer than 48 characters | Supported | Enforced. `SolidSyslogOriginSd` writes the value through `SolidSyslogSdValue_BoundedString` with a 48 bound, so an over-long string is truncated rather than emitted. The bound counts decoded bytes - what a receiver's un-escaping decoder extracts - so for multi-byte UTF-8 it truncates earlier than the 48 characters §7.2.3 allows, never later |
| [7.2.4](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.2.4) | swVersion - MUST NOT be longer than 32 characters | Supported | Enforced at 32 on the same terms as `software` above |
| [7.2.5](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.2.5) | origin example | N/A | Illustrative. States no requirement of its own |
| [7.3](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.3) | meta SD - sequenceId, sysUpTime, language | Supported | `SolidSyslogMetaSd` emits all three IANA-registered §7.3 parameters. `sysUpTime` and `language` are independently optional - a NULL field in `SolidSyslogMetaSdConfig` omits that parameter. The counter is required: without one there is no sequenceId, so there is no meta element to emit. Each parameter's own constraints are in the rows below |
| [7.3.1](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.3.1) | meta SD - sequenceId wraps at 2147483647 to 1 | Supported | The [AtomicCounter](api/structSolidSyslogAtomicCounter.md) contract carries the wrap: values run [1, `SOLIDSYSLOG_SEQUENCE_ID_MAX`] and never 0. The id is taken when a message is raised, so it records the order messages originated in. Delivery order may differ - messages raised from several threads, or any transport that reorders - and sorting on sequenceId recovers the order within one originator's run. §7.3.1 scopes it to that: the count starts at 1 when the syslog function starts and returns to 1 after the maximum, so it does not order across a restart, a wrap, or two originators. |
| [7.3.2](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.3.2) | sysUpTime - MUST be a decimal integer, digits only | Supported | The callback returns `uint32_t` hundredths and the value is written through `SolidSyslogSdValue_Uint32`, which emits decimal digits only. §7.3.2 also notes the SNMP management portion may differ from the syslog one, which is the integrator's to reconcile |
| [7.3.3](https://www.rfc-editor.org/rfc/rfc5424.html#section-7.3.3) | language - MUST be a BCP 47 language identifier | Supported | Streamed through a `SolidSyslogSdValueFunction` into a `SolidSyslogSdValue`, which applies §6.3.3 escaping. The parameter is optional and the identifier is the integrator's to supply; the library does not parse BCP 47 |
| [8.1](https://www.rfc-editor.org/rfc/rfc5424.html#section-8.1) | UNICODE - shortest-form encoding REQUIRED | Supported | RFC 3629 validation at the formatter primitives rejects overlong encodings, substituting each ill-formed byte with U+FFFD per Unicode §3.9, so a non-shortest-form sequence cannot pass through |
| [8.6](https://www.rfc-editor.org/rfc/rfc5424.html#section-8.6) | Congestion control - TLS REQUIRED to implement, UDP for managed networks | Supported | The implementation obligation is the same one §5.1 states, and is met. Which transport a deployment uses, and whether its network is provisioned for UDP syslog, is the integrator's choice |

## RFC 5425 - TLS Transport Mapping for Syslog

Checked against [RFC 5425](https://www.rfc-editor.org/rfc/rfc5425.html), Standards
Track, and [RFC 9662](https://www.rfc-editor.org/rfc/rfc9662.html), Standards Track,
which updates it.

TLS is a [Stream](api/structSolidSyslogStream.md) wrapped around another Stream,
so these requirements are met by whichever TLS stream the integrator wires; the
[capability matrix](platforms/index.md) shows which platforms supply one. The
statuses below are against [the TLS contract](tls.md), which states what any TLS
stream must do. Where a shipped platform does not yet meet an obligation, its own
page records the exception and links the issue tracking it.

**RFC 5425 is read together with RFC 9662**, *Updates to the Cipher Suites in
Secure Syslog*. It replaces the 2009 cipher-suite requirement, asks that TLS 1.3
be supported and preferred where it is implemented, and normatively references
BCP 195 for how TLS should be used. Rows below cite it where it is the
requirement in force, rather than tabulating it separately.

| Section | Requirement | Status | Notes |
|---|---|---|---|
| [3](https://www.rfc-editor.org/rfc/rfc5425.html#section-3) | TLS to secure syslog | Supported | A TLS `Stream` wraps a byte-transport `Stream` - a TCP one from any platform, or a caller-supplied one. §3's own caveat holds here too: the protection is hop-by-hop, so a relay that terminates the connection is authenticated in place of the originating device |
| [4.1](https://www.rfc-editor.org/rfc/rfc5425.html#section-4.1) | Default port 6514 | Supported | `SOLIDSYSLOG_TLS_DEFAULT_PORT` in `SolidSyslogTransport.h`; the endpoint callback overrides it |
| [4.2](https://www.rfc-editor.org/rfc/rfc5425.html#section-4.2) | TLS 1.2 as the mandatory-to-implement protocol | Supported | The contract pins the floor at TLS 1.2. RFC 9662 keeps it mandatory-to-implement |
| [RFC 9662 §4](https://www.rfc-editor.org/rfc/rfc9662.html#section-4) | Cipher suites - `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` SHOULD be offered, `TLS_RSA_WITH_AES_128_CBC_SHA` MAY be | N/A | Which cipher suites exist is a property of the TLS library linked on the target, not of this library, which neither adds nor removes any. RFC 9662 downgraded the 2009 mandatory suite because it offers no forward secrecy, which is the same reason a hardened build disables it. RFC 9662 §4 is internally awkward - it calls both suites REQUIRED and then states the offer preference above - so it is cited whole rather than paraphrased into something tidier |
| [RFC 9662 §4](https://www.rfc-editor.org/rfc/rfc9662.html#section-4) | TLS 1.3 SHOULD be supported, and MUST be preferred where implemented | Supported | The contract sets a floor and deliberately no ceiling, so nothing here holds a handshake below TLS 1.3 and the later version is negotiated wherever both peers offer one. This is why no ceiling is set: pinning one to constrain cipher selection would breach the preference requirement. Whether TLS 1.3 is available at all belongs to the backend the integrator links and how it was built |
| [RFC 9662 §6](https://www.rfc-editor.org/rfc/rfc9662.html#section-6) | Early data (0-RTT) MUST NOT be used | Supported | RFC 9662 forbids it because syslog has no replay protection and early data has none between connections. Sending early data is an explicit act - no shipped TLS stream calls an early-data API, so none is sent, whatever session state the backend keeps. A caller-supplied stream is the caller's to hold to the same rule |
| [4.2.1](https://www.rfc-editor.org/rfc/rfc5425.html#section-4.2.1) | Certificate-based authentication - server | Supported | Peer verification is required, not optional: the certificate must chain to the trust anchors the caller supplies, and the peer identity the caller declares is checked against it. §4.2.1 requires support for both authorisation methods - a deployment configures whichever it uses - and its end-entity bullet states that implementations MUST support the certificate fingerprints of §4.2.2, which every shipped TLS platform does - see §5.1 below |
| [4.2.1](https://www.rfc-editor.org/rfc/rfc5425.html#section-4.2.1) | Certificate-based authentication - client | Supported | A client certificate and its key are optional configuration on the TLS stream, presented only when both are given, and a partially configured pair is reported rather than silently ignored |
| [4.2.1](https://www.rfc-editor.org/rfc/rfc5425.html#section-4.2.1) | Means to generate a key pair and self-signed certificate | N/A | Deliberately excluded. The library consumes trust material and does not mint it, so key generation belongs to the deployment's provisioning. Directed at a syslog application rather than at a component one is built from |
| [4.2.2](https://www.rfc-editor.org/rfc/rfc5425.html#section-4.2.2) | Certificate fingerprints published through a management interface | N/A | Directed at a syslog application, not a component one is built from: the library has no management interface, and the certificate is the integrator's to hold and to publish. The fingerprint form §4.2.2 defines matters where a peer is authorised by one, which is §5.1 |
| [4.2.3](https://www.rfc-editor.org/rfc/rfc5425.html#section-4.2.3) | Administrators may select the cryptographic level | Partial | The contract requires an integrator's cipher policy to be passed through where the underlying library allows one to be selected. Neither shipped TLS platform delivers that on the connection actually negotiated - see each platform's page, and [#733](https://github.com/cososo-ltd/solid-syslog/issues/733) |
| [4.2.3](https://www.rfc-editor.org/rfc/rfc5425.html#section-4.2.3) | A resumed session's security parameters SHOULD be checked against the requirements of the session being requested | Supported | No shipped TLS stream resumes a session, so a resumed session's parameters cannot fall short of the requested one's. Each platform page states what its own adapter carries across a connection. [The contract](tls.md) requires a stream that does resume to perform the check, which is stronger than the SHOULD, so a stream that started resuming without it would breach the contract before it breached the RFC |
| [4.3](https://www.rfc-editor.org/rfc/rfc5425.html#section-4.3) | All syslog messages MUST be sent as TLS application data | Supported | The TLS `Stream` carries the frames the sender writes as ordinary application data; nothing is sent outside the session, and §4.3's `APPLICATION-DATA = 1*SYSLOG-FRAME` is what the octet-counting sender produces |
| [4.3.1](https://www.rfc-editor.org/rfc/rfc5425.html#section-4.3.1) | Octet-counting framing; receivers MUST process 2048 octets and SHOULD process 8192 | Supported | Reuses `SolidSyslogStreamSender`, so the frame is `MSG-LEN SP MSG`. §4.3.1 bounds what a receiver processes; the library is a sender, and emits at most `SOLIDSYSLOG_MAX_MESSAGE_SIZE`, which defaults well inside the figure every receiver must take |
| [4.4](https://www.rfc-editor.org/rfc/rfc5425.html#section-4.4) | Close a connection not expected to carry more messages, sending `close_notify` first | Supported | Close sends `close_notify` before tearing the connection down. On the closure requirement itself: a sender holds one connection open while it has records to deliver, which is the case §4.4 does not ask it to close, and closes on destroy, on a send failure and on an endpoint change. Bounding a long-lived connection beyond that is the integrator's, through `SolidSyslogSender_Disconnect` - see [the contract](tls.md). §4.4's remaining sentences bind the receiver |
| [5](https://www.rfc-editor.org/rfc/rfc5425.html#section-5) | Security policies - the deployment chooses how peers are authorised | N/A | Scoping text for the policies below. Which one a deployment runs is the integrator's, and §6.1 names §5.1 and §5.2 together as the RECOMMENDED default |
| [5.1](https://www.rfc-editor.org/rfc/rfc5425.html#section-5.1) | Authorised peers MUST be specifiable by certificate fingerprint | Supported | A peer is authorisable by pinned certificate fingerprint in the §4.2.2 form, with a list any one of which authorises so a collector's certificate can be renewed without stopping a fleet. A pin authorises on its own, with no trust anchors configured, and where both are configured both must be satisfied. Every shipped TLS platform delivers it; each platform's page states how the material is supplied |
| [5.2](https://www.rfc-editor.org/rfc/rfc5425.html#section-5.2) | Path validation, and authorised peers specifiable by host name | Supported | Peer verification chains to the trust anchors the caller supplies, and the declared peer identity is matched against the certificate. dNSName matching and the left-most wildcard rule come from the backend the integrator links |
| [5.3](https://www.rfc-editor.org/rfc/rfc5425.html#section-5.3) | Unauthenticated transport sender | N/A | A receiver-side policy: it is the receiver that chooses not to authenticate the sender. Whether this library presents a client certificate is §4.2.1 |
| [5.4](https://www.rfc-editor.org/rfc/rfc5425.html#section-5.4) | Unauthenticated transport receiver - NOT RECOMMENDED | Supported | Not offered, which is the point: peer verification is required rather than optional, so the library will not accept any certificate presented to it. Declining to check a *name* is a separate and narrower choice, and one the contract requires be reported |
| [5.5](https://www.rfc-editor.org/rfc/rfc5425.html#section-5.5) | Neither peer authenticated - NOT RECOMMENDED | Supported | Follows from §5.4: the receiver is always verified, so this policy cannot be reached from this side |

## RFC 5426 - Transmission of Syslog Messages over UDP

Checked against [RFC 5426](https://www.rfc-editor.org/rfc/rfc5426.html), Standards Track.

| Section | Requirement | Status | Notes |
|---|---|---|---|
| [3.1](https://www.rfc-editor.org/rfc/rfc5426.html#section-3.1) | One message per UDP datagram | Supported | `SolidSyslogUdpSender` sends one datagram per `Send` call |
| [3.2](https://www.rfc-editor.org/rfc/rfc5426.html#section-3.2) | Message fits in single datagram | Supported | Bounded by `SOLIDSYSLOG_MAX_MESSAGE_SIZE` |
|  [3.2](https://www.rfc-editor.org/rfc/rfc5426.html#section-3.2) | Avoid IP fragmentation (respect MTU) | Supported | The [Datagram](api/structSolidSyslogDatagram.md) contract obliges an implementor to report the path's largest payload and never guess high; where the platform can distinguish oversize, the sender trims and retries. Where no path MTU is available the fallback is 1232 octets, above the 1180 and 480 §3.2 calls safest when the MTU is unknown - advice it gives as prose rather than as an RFC 2119 requirement. The 480-octet default sits below every shipped adapter's floor; a raised cap on a platform that cannot distinguish oversize is the case each platform page documents ([#736](https://github.com/cososo-ltd/solid-syslog/issues/736)) |
| [3.3](https://www.rfc-editor.org/rfc/rfc5426.html#section-3.3) | Default port 514 | Supported | `SOLIDSYSLOG_UDP_DEFAULT_PORT` = 514 |
| [3.4](https://www.rfc-editor.org/rfc/rfc5426.html#section-3.4) | Source IP SHOULD NOT be read as the originator identity | N/A | Directed at whoever reads the datagram. The identity of the originator travels in the message, in HOSTNAME and in the origin SD when one is wired |
| [3.5](https://www.rfc-editor.org/rfc/rfc5426.html#section-3.5) | The datagram MUST adhere to the UDP and IP structure | Supported | The library hands a payload to the platform datagram, which sends it through the stack the integrator links; forming the UDP and IP headers is that stack's |
| [3.6](https://www.rfc-editor.org/rfc/rfc5426.html#section-3.6) | UDP checksums - a sender MUST NOT disable them | Supported | Nothing in the library disables UDP checksumming: no adapter sets `SO_NO_CHECK` or a vendor equivalent, so whatever the stack does by default stands. §3.6 also records that RFC 2460 mandates checksums for UDP over IPv6 |
| [4.1](https://www.rfc-editor.org/rfc/rfc5426.html#section-4.1) | Unreliable delivery - no confirmation | N/A | Inherent in UDP: §4.1 states the transport mapping provides no mechanism to detect or correct datagram loss. §5.4 restates it as a security consequence. Caller should be aware |
| [4.3](https://www.rfc-editor.org/rfc/rfc5426.html#section-4.3) | Congestion control - TLS is REQUIRED to implement, and RECOMMENDED | Supported | The TLS transport ships and is the recommended one. §4.3 confines UDP to managed networks provisioned for it - a deployment decision, and the reason the UDP rows here describe a transport the RFC would rather you did not use in the open |
| [4.4](https://www.rfc-editor.org/rfc/rfc5426.html#section-4.4) | Arrival order SHOULD NOT be taken as the order of generation | Supported | Nothing in the library asks a receiver to trust arrival order. The meta SD carries sequenceId for exactly this, and §7.3.1 of RFC 5424 covers what it does |
| [5](https://www.rfc-editor.org/rfc/rfc5426.html#section-5) | Security considerations - running this on an unsecured network is NOT RECOMMENDED | N/A | The recommendation is a deployment decision. The clauses below are §5's specific threats, each dispositioned rather than summarised |
| [5.1](https://www.rfc-editor.org/rfc/rfc5426.html#section-5.1) | Sender authentication and message forgery | N/A | UDP offers neither, and this transport mapping provides no authentication. Use the TLS transport where sender identity matters |
| [5.2](https://www.rfc-editor.org/rfc/rfc5426.html#section-5.2) | Message observation - clear text in transit | N/A | UDP offers no confidentiality. §5.2 asks that sensitive content be kept off this transport or the network be secured; both are the deployment's |
| [5.3](https://www.rfc-editor.org/rfc/rfc5426.html#section-5.3) | Replaying | N/A | Neither this transport mapping nor syslog itself has replay protection. sequenceId lets a collector spot a gap, not a replay |
| [5.4](https://www.rfc-editor.org/rfc/rfc5426.html#section-5.4) | Unreliable delivery as a security consequence | N/A | The same property §4.1 records, read as a threat: an attacker may discard datagrams to hide activity. Store-and-forward covers a sender that cannot reach its collector, not a path that drops what was sent |
| [5.5](https://www.rfc-editor.org/rfc/rfc5426.html#section-5.5) | Message prioritisation and differentiation | N/A | The mapping mandates no prioritisation and the library implements none: records are sent in the order they were raised, whatever their severity |
| [5.6](https://www.rfc-editor.org/rfc/rfc5426.html#section-5.6) | Denial of service - implementers SHOULD minimise the threat | N/A | Directed at a receiver, whose defence §5.6 gives as restricting reception to known source addresses. A sender has no part in it |

## RFC 6587 - Transmission of Syslog Messages over TCP

Checked against [RFC 6587](https://www.rfc-editor.org/rfc/rfc6587.html), Historic.

| Section | Requirement | Status | Notes |
|---|---|---|---|
| [3.3](https://www.rfc-editor.org/rfc/rfc6587.html#section-3.3) | Sender initiates TCP connection | Supported | `SolidSyslogStreamSender` connects lazily on first send |
| [3.4.1](https://www.rfc-editor.org/rfc/rfc6587.html#section-3.4.1) | Octet counting framing | Supported | `MSG-LEN SP MSG` prefix on every send |
| [3.4.2](https://www.rfc-editor.org/rfc/rfc6587.html#section-3.4.2) | Non-transparent framing (LF trailer) | N/A | Deliberately not implemented. RFC 6587 describes both framings without recommending either, but §3.4 records that non-transparent framing has known problems and that octet counting does not; §3.4.1 is also the framing RFC 5425 mandates for TLS, so the library ships that alone rather than a mode selector |
| [3.5](https://www.rfc-editor.org/rfc/rfc6587.html#section-3.5) | Session closure handling | Supported | On send failure the stream is closed; the next Send transparently reconnects |
| [3.5](https://www.rfc-editor.org/rfc/rfc6587.html#section-3.5) | Handle receiver-initiated close | Supported | Detected via send failure path - same reconnect-on-next-Send mechanism |
| - | Default port 601 | Supported | RFC 6587 standardises no port: §3.3 records that the protocol "has no standardized port assignment", and §4 that operators must select one per deployment. `SOLIDSYSLOG_TCP_DEFAULT_PORT = 601` (defined in `Core/Interface/SolidSyslogTransport.h`) is the IANA `syslog-conn` assignment from RFC 3195, and is caller-overridable via the endpoint callback |
| - | Address rotation without app restart | Supported | A library capability rather than an RFC 6587 requirement. App bumps `endpointVersion`; the sender calls `SolidSyslogSender_Disconnect` and reconnects on the next Send |
| - | Partial write handling (send returns short) | Supported | The [Stream](api/structSolidSyslogStream.md) contract makes `Send` all-or-nothing: a short write is a failure, never a partial success, so the stream closes itself, the sender reconnects on its next pass, and store-and-forward replays the message on the fresh connection. The same contract keeps steady-state `Send` and `Read` non-blocking and bounds `Open`, so a wedged peer or a full send buffer cannot stall the servicing pass. The connect bound is `SOLIDSYSLOG_TCP_CONNECT_TIMEOUT_MS` (default 200 ms), overridable at runtime through the per-Stream `GetConnectTimeoutMs(ConnectTimeoutContext)` accessor. How a transport detects a long-term wedge, and what it does about one, is on its own page |

## Summary

A `-` in the Section column marks a requirement the RFC does not number - one that comes from IANA, from another RFC, or from this library's own contract. They are requirements and are counted as such.

| RFC | Total requirements | Supported | Partial | Not Met | N/A |
|---|---|---|---|---|---|
| RFC 5424 | 40 | 33 | 0 | 0 | 7 |
| RFC 5425 | 21 | 15 | 1 | 0 | 5 |
| RFC 5426 | 17 | 8 | 0 | 0 | 9 |
| RFC 6587 | 8 | 7 | 0 | 0 | 1 |
