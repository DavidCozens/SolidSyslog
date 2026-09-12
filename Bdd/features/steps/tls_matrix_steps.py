"""Steps for the TLS equivalence matrix.

The matrix asserts what the library did, not what the library it was built
against is called: the connect-or-refuse decision and the portable detail code
from `enum SolidSyslogTlsStreamErrors`, which since #813 is the same number on
every backend. `event->Source` is deliberately never asserted - it names the
library that spoke, which is the one thing that is supposed to differ.

What a cell configures before the target starts is here. What it does to a
running target is in syslog_steps.py with the rest of the client's vocabulary,
and the collector identities both need are in tls_collectors.py - one step
module cannot import another without behave registering its steps twice.
"""

import time

from behave import given, then

from syslog_severities import severity_value
from tls_collectors import fingerprint_of, listener
from tls_error_codes import tls_error_code
from tls_reports import reported_details, reported_reports, target_output

REPORT_TIMEOUT_SECONDS = 20


def await_report(context, expected, read):
    """Everything reported once `expected` has been, or the budget has run out.

    A refusal is reported when a connection is attempted rather than when the
    message is handed over, so a step asserting one has to wait for it.
    """
    process = context.interactive_process
    deadline = time.monotonic() + REPORT_TIMEOUT_SECONDS
    reported = read(process)
    while (expected not in reported) and (time.monotonic() < deadline):
        time.sleep(0.1)
        reported = read(process)
    return reported


@then('the target reports TLS detail "{name}"')
def step_target_reports_tls_detail(context, name):
    expected = tls_error_code(name)
    reported = await_report(context, expected, reported_details)
    assert expected in reported, (
        f"Expected TLS detail {name} ({expected}) in the target's reports; "
        f"saw {reported}.\n--- target output ---\n{target_output(context.interactive_process)}"
    )


@then('the target reports TLS detail "{name}" at severity {severity}')
def step_target_reports_tls_detail_at_severity(context, name, severity):
    expected = (severity_value(severity), tls_error_code(name))
    reported = await_report(context, expected, reported_reports)
    assert expected in reported, (
        f"Expected TLS detail {name} at {severity} {expected} in the target's reports; "
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
    port, _ = listener(identity)
    tls_set(context, "tls-port", str(port))


@given('the BDD target trusts no certificate authority')
def step_target_trusts_nothing(context):
    tls_set(context, "tls-ca", "none")


@given('the BDD target trusts certificate authority "{anchors}"')
def step_target_trusts(context, anchors):
    tls_set(context, "tls-ca", anchors)


@given('the BDD target tolerates a refused handshake')
def step_target_tolerates_refusal(context):
    """A refusal is reported at ERROR, which ends a hosted target by default so
    that an unexpected fault fails a scenario loudly rather than as a timeout.
    A cell that expects one says so."""
    tls_set(context, "errors-fatal", "0")


@given('the BDD target declares no expected peer name')
def step_target_declares_no_name(context):
    tls_set(context, "tls-name", "none")


@given('the BDD target asks for a suite the collector offers')
def step_target_asks_for_an_offered_suite(context):
    tls_set(context, "tls-cipher", "offered")


@given('the BDD target asks for a suite the collector does not offer')
def step_target_asks_for_an_unoffered_suite(context):
    tls_set(context, "tls-cipher", "unoffered")


@given('the BDD target holds half a client credential')
def step_target_holds_half_a_client_credential(context):
    tls_set(context, "tls-client", "cert-only")


@given('the BDD target opts out of the peer name check')
def step_target_opts_out_of_name_check(context):
    """An empty expected name is the deliberate opt-out, as against no name at
    all: the integrator has said there is nothing to check rather than left it
    unsaid, so the library connects chain-only and reports nothing."""
    tls_set(context, "tls-name", "")


@given('the sha-1 fingerprint of "{identity}" is pinned')
def step_pin_certificate_by_sha1(context, identity):
    tls_set(context, "tls-pin", fingerprint_of(identity, "sha-1"))


@given('the fingerprint of "{identity}" is pinned')
def step_pin_certificate(context, identity):
    tls_set(context, "tls-pin", fingerprint_of(identity))


def tls_set(context, name, value):
    """Queue one `set NAME VALUE`, delivered once the target is at its prompt."""
    context.tls_settings = getattr(context, "tls_settings", []) + [(name, value)]
