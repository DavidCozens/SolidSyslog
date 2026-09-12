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

from tls_collectors import fingerprint_of, listener
from tls_error_codes import tls_error_code
from tls_reports import reported_details, target_output


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


@given('the BDD target opts out of the peer name check')
def step_target_opts_out_of_name_check(context):
    """An empty expected name is the deliberate opt-out, as against no name at
    all: the integrator has said there is nothing to check rather than left it
    unsaid, so the library connects chain-only and reports nothing."""
    tls_set(context, "tls-name", "")


@given('the fingerprint of "{identity}" is pinned')
def step_pin_certificate(context, identity):
    tls_set(context, "tls-pin", fingerprint_of(identity))


def tls_set(context, name, value):
    """Queue one `set NAME VALUE`, delivered once the target is at its prompt."""
    context.tls_settings = getattr(context, "tls_settings", []) + [(name, value)]
