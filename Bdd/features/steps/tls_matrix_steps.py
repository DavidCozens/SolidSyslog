"""Steps for the TLS equivalence matrix.

The matrix asserts what the library did, not what the library it was built
against is called: the connect-or-refuse decision and the portable detail code
from `enum SolidSyslogTlsStreamErrors`, which since #813 is the same number on
every backend. `event->Source` is deliberately never asserted - it names the
library that spoke, which is the one thing that is supposed to differ.

Where the report is read from differs by target and cannot be helped. On Linux
and Windows the error handler writes to stderr; on FreeRTOS `_write` ignores the
file descriptor (Syscalls.c) so it lands on the same UART as the prompt
protocol. Both captured streams are searched.
"""

import hashlib
import re

from behave import given, then

from tls_error_codes import tls_error_code

# Detail codes are per-class, so a bare `detail=` is ambiguous: a resolver fault
# reporting 16 would be indistinguishable from PEER_CERTIFICATE_UNTRUSTED. Both
# handlers mark a report from the TLS-stream role, and only those are read here.
# Filtering on the mark rather than on the source name keeps this pack-agnostic:
# the two names share no pattern that excludes PosixTcpStream or StreamSender,
# and a third TLS pack would otherwise have to be added to this regex.
_REPORT = re.compile(r"role=tls cat=\d+ detail=(-?\d+)")


def _target_output(context):
    """Everything the target has said, whichever stream it said it on."""
    process = getattr(context, "interactive_process", None)
    if process is None:
        return ""

    chunks = []
    for attribute in ("_solidsyslog_stdout_log", "_solidsyslog_stderr_log"):
        log = getattr(process, attribute, None)
        if log:
            chunks.append(bytes(log).decode("utf-8", errors="replace"))
    return "\n".join(chunks)


def _reported_details(context):
    return [int(value) for value in _REPORT.findall(_target_output(context))]


@then('the target reports TLS detail "{name}"')
def step_target_reports_tls_detail(context, name):
    expected = tls_error_code(name)
    reported = _reported_details(context)
    assert expected in reported, (
        f"Expected TLS detail {name} ({expected}) in the target's reports; "
        f"saw {reported}.\n--- target output ---\n{_target_output(context)}"
    )


@then('the target reports no TLS fault')
def step_target_reports_no_tls_fault(context):
    reported = _reported_details(context)
    assert not reported, (
        f"Expected no report, saw details {reported}.\n"
        f"--- target output ---\n{_target_output(context)}"
    )


@given('the fingerprint of "{certificate}" is pinned')
def step_pin_certificate(context, certificate):
    """Pin a committed certificate by computing its fingerprint here.

    Computed rather than written down, so regenerating the test material does
    not silently invalidate a feature file. The form is the one RFC 5425 4.2.2
    defines: the hash label, a colon, then the hash of the DER encoding as
    colon-separated hex pairs.
    """
    context.tls_pins = getattr(context, "tls_pins", [])
    context.tls_pins.append(fingerprint_of(certificate))


def fingerprint_of(certificate, algorithm="sha-256"):
    """The RFC 5425 4.2.2 fingerprint of a committed PEM certificate."""
    import ssl

    der = ssl.PEM_cert_to_DER_cert(open(certificate, encoding="ascii").read())
    digest = hashlib.new(algorithm.replace("-", ""), der).hexdigest().upper()
    pairs = ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
    return f"{algorithm}:{pairs}"
