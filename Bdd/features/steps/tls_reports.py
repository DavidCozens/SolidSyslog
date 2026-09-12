"""Reading what the BDD target reported, for the steps that assert on it.

Where the report is read from differs by target and cannot be helped. On Linux
and Windows the error handler writes to stderr; on FreeRTOS `_write` ignores the
file descriptor (Syscalls.c) so it lands on the same UART as the prompt
protocol. Both captured streams are searched.

Detail codes are per-class, so a bare `detail=` is ambiguous: a resolver fault
reporting 16 would be indistinguishable from PEER_CERTIFICATE_UNTRUSTED. Both
handlers mark a report from the TLS-stream role, and only those are read here.
Filtering on the mark rather than on the source name keeps this pack-agnostic:
the two names share no pattern that excludes PosixTcpStream or StreamSender,
and a third TLS pack would otherwise have to be added to this regex.
"""

import re

_REPORT = re.compile(r"role=tls cat=\d+ detail=(-?\d+)")


def target_output(process):
    """Everything the target has said, whichever stream it said it on."""
    if process is None:
        return ""

    chunks = []
    for attribute in ("_solidsyslog_stdout_log", "_solidsyslog_stderr_log"):
        log = getattr(process, attribute, None)
        if log:
            chunks.append(bytes(log).decode("utf-8", errors="replace"))
    return "\n".join(chunks)


def reported_details(process):
    """Every TLS-stream detail code the target has reported so far."""
    return [int(value) for value in _REPORT.findall(target_output(process))]
