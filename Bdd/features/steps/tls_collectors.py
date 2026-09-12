"""The collector identities a TLS matrix cell can point a target at.

One row per identity: the port its listener answers on, and the certificate it
presents. Both oracles use the same port for the same identity
(Bdd/syslog-ng/syslog-ng.conf, Bdd/otel/config.yaml), so a scenario names the
identity and no feature file names a port or a file.

Plain data rather than steps, because the step module that configures a target
before it starts and the one that drives a running target both need it, and
behave registers a step module's steps twice if another imports it.
"""

import hashlib
import pathlib
import ssl

TLS_MATERIAL = pathlib.Path(__file__).resolve().parents[2] / "syslog-ng" / "tls"

_COLLECTORS = {
    "anchor-signed": (6514, "server.pem"),
    # The same certificate, on the listener that demands one back.
    "mtls-required": (6515, "server.pem"),
    "untrusted": (6516, "server-untrusted.pem"),
    "wrong-name": (6517, "server-wrongname.pem"),
    "self-signed": (6518, "server-selfsigned.pem"),
    "chained": (6519, "server-chained.pem"),
    # The happy-path certificate, offered over TLS 1.2 only.
    "tls-1-2": (6520, "server.pem"),
    "collector-b": (6521, "server-b.pem"),
}


def listener(identity):
    """The port and certificate of one collector identity."""
    try:
        return _COLLECTORS[identity]
    except KeyError:
        raise KeyError(
            f"No collector identity {identity!r}. Known: {sorted(_COLLECTORS)}."
        ) from None


def fingerprint_of(identity, algorithm="sha-256"):
    """The RFC 5425 4.2.2 fingerprint of the certificate that identity presents.

    Computed rather than written down, so regenerating the test material does
    not silently invalidate a feature file. The form is the one the RFC defines:
    the hash label, a colon, then the hash of the DER encoding as
    colon-separated hex pairs.
    """
    _, certificate = listener(identity)
    pem = (TLS_MATERIAL / certificate).read_text(encoding="ascii")
    digest = hashlib.new(algorithm.replace("-", ""), ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper()
    pairs = ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
    return f"{algorithm}:{pairs}"
