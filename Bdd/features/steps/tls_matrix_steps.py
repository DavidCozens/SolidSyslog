"""Steps for the TLS equivalence matrix.

The matrix asserts what the library did, not what the library it was built
against is called: the connect-or-refuse decision and the portable detail code
from `enum SolidSyslogTlsStreamErrors`, which since #813 is the same number on
every backend. `event->Source` is deliberately never asserted - it names the
library that spoke, which is the one thing that is supposed to differ.

The target's own lifecycle and the oracle's vocabulary stay in syslog_steps.py;
one step module cannot import another without behave registering its steps
twice, so what both need lives in the plain modules beside them.
"""

import hashlib
import pathlib
import ssl
import time

from behave import given, then

from tls_error_codes import tls_error_code
from tls_reports import reported_details, target_output

_TLS_MATERIAL = pathlib.Path(__file__).resolve().parents[2] / "syslog-ng" / "tls"

# One row per collector identity: the port its listener answers on, and the
# certificate it presents. Both oracles use the same port for the same
# identity (Bdd/syslog-ng/syslog-ng.conf, Bdd/otel/config.yaml), so a scenario
# names the identity and no feature file names a port or a file.
_COLLECTORS = {
    "anchor-signed": (6514, "server.pem"),
    "untrusted": (6516, "server-untrusted.pem"),
    "wrong-name": (6517, "server-wrongname.pem"),
    "self-signed": (6518, "server-selfsigned.pem"),
    "chained": (6519, "server-chained.pem"),
    "collector-b": (6521, "server-b.pem"),
}


@then('the target reports TLS detail "{name}"')
def step_target_reports_tls_detail(context, name):
    expected = tls_error_code(name)
    deadline = time.monotonic() + 20
    reported = reported_details(context.interactive_process)
    while (expected not in reported) and (time.monotonic() < deadline):
        time.sleep(0.1)
        reported = reported_details(context.interactive_process)
    assert expected in reported, (
        f"Expected TLS detail {name} ({expected}) in the target's reports; "
        f"saw {reported}.\n--- target output ---\n{target_output(context.interactive_process)}"
    )


@then('the target reports no TLS fault')
def step_target_reports_no_tls_fault(context):
    reported = reported_details(context.interactive_process)
    assert not reported, (
        f"Expected no report, saw details {reported}.\n"
        f"--- target output ---\n{target_output(context.interactive_process)}"
    )


@given('the collector presents "{identity}"')
def step_collector_presents(context, identity):
    """Point the target at the listener holding that identity."""
    port, _ = _listener(identity)
    tls_set(context, "tls-port", str(port))


@given('the BDD target trusts no certificate authority')
def step_target_trusts_nothing(context):
    tls_set(context, "tls-ca", "none")


@given('the BDD target tolerates a refused handshake')
def step_target_tolerates_refusal(context):
    """A refusal is reported at ERROR, which ends a hosted target by default so
    that an unexpected fault fails a scenario loudly rather than as a timeout.
    A cell that expects one says so."""
    tls_set(context, "errors-fatal", "0")


@given('the BDD target opts out of the peer name check')
def step_target_opts_out_of_name_check(context):
    """An empty expected name is the deliberate opt-out, as against no name at
    all: the integrator has said there is nothing to check rather than left it
    unsaid, so the library connects chain-only and reports nothing."""
    tls_set(context, "tls-name", "")


@given('the fingerprint of "{identity}" is pinned')
def step_pin_certificate(context, identity):
    """Pin a collector by computing its fingerprint here.

    Computed rather than written down, so regenerating the test material does
    not silently invalidate a feature file. The form is the one RFC 5425 4.2.2
    defines: the hash label, a colon, then the hash of the DER encoding as
    colon-separated hex pairs.
    """
    _, certificate = _listener(identity)
    tls_set(context, "tls-pin", fingerprint_of(_TLS_MATERIAL / certificate))


def tls_set(context, name, value):
    """Queue one `set NAME VALUE`, delivered once the target is at its prompt."""
    context.tls_settings = getattr(context, "tls_settings", []) + [(name, value)]


def _listener(identity):
    try:
        return _COLLECTORS[identity]
    except KeyError:
        raise KeyError(
            f"No collector identity {identity!r}. Known: {sorted(_COLLECTORS)}."
        ) from None


def fingerprint_of(certificate, algorithm="sha-256"):
    """The RFC 5425 4.2.2 fingerprint of a committed PEM certificate."""
    der = ssl.PEM_cert_to_DER_cert(pathlib.Path(certificate).read_text(encoding="ascii"))
    digest = hashlib.new(algorithm.replace("-", ""), der).hexdigest().upper()
    pairs = ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
    return f"{algorithm}:{pairs}"
