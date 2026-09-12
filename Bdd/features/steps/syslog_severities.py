"""RFC 5424 severities by name, read from the header that defines them.

A cell that asserts a report asserts its severity as well as its detail code,
because severity is what decides whether delivery continues: the same fault
reported at ERROR rather than WARNING would stop a device that the contract says
should keep sending. Feature files name a severity; this maps the name to the
number the target prints.

Parsed from Core/Interface/SolidSyslogPrival.h rather than written down, for the
reason tls_error_codes.py gives: one source of truth, and a misparse fails a
scenario rather than passing it.
"""

import pathlib
import re

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_HEADER = _REPO_ROOT / "Core" / "Interface" / "SolidSyslogPrival.h"

_PREFIX = "SOLIDSYSLOG_SEVERITY_"
_MEMBER = re.compile(rf"\b{_PREFIX}([A-Z0-9_]+)\b\s*=\s*(\d+)")

_SEVERITIES = {name: int(value) for name, value in _MEMBER.findall(_HEADER.read_text(encoding="utf-8"))}

if not _SEVERITIES:
    raise RuntimeError(f"No {_PREFIX}* members in {_HEADER}")


def severity_value(name):
    """The number a target prints for the severity a feature file names."""
    try:
        return _SEVERITIES[name]
    except KeyError:
        raise KeyError(
            f"No severity {name!r}. Known: {sorted(_SEVERITIES)}."
        ) from None
