import glob
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone

from behave import given, when, then
from environment import (
    RECEIVED_MTLS_LOG,
    RECEIVED_TCP_LOG,
    RECEIVED_TLS_B_LOG,
    RECEIVED_TLS_LOG,
    RECEIVED_UDP_LOG,
    STORE_FILE_PATH,
    STORE_PATH_PREFIX,
    THRESHOLD_MARKER_PATH,
    otel_kill_oracle,
    otel_start_oracle,
)
from target_driver import apply_extra_args, spawn_example_process, stop_example_process
from tls_collectors import fingerprint_of, listener
from tls_reports import reported_details

PER_TRANSPORT_LOG_SYSLOG_NG = {
    "udp": RECEIVED_UDP_LOG,
    "tcp": RECEIVED_TCP_LOG,
    "tls": RECEIVED_TLS_LOG,
    "tls_b": RECEIVED_TLS_B_LOG,
    "mtls": RECEIVED_MTLS_LOG,
}

# OTel runner writes a per-transport file per receiver (Bdd/otel/config.yaml
# pipeline `logs/<transport>` → exporter `file/<transport>`). Lets the
# cross-platform "the syslog oracle receives N over X" step pin the transport
# actually used end-to-end on either runner.
PER_TRANSPORT_LOG_OTEL = {
    "udp":  "Bdd/output/received_udp.jsonl",
    "tcp":  "Bdd/output/received_tcp.jsonl",
    "tls":  "Bdd/output/received_tls.jsonl",
    "tls_b": "Bdd/output/received_tls_b.jsonl",
    "mtls": "Bdd/output/received_mtls.jsonl",
}


def per_transport_log(context, transport):
    """Return the per-transport oracle file path for the active runner.

    Linux (syslog-ng): per-transport `received_<X>.log` files.
    Windows (otel-jsonl): per-transport `received_<X>.jsonl` files.
    """
    if context.oracle_format == "otel-jsonl":
        return PER_TRANSPORT_LOG_OTEL[transport]
    return PER_TRANSPORT_LOG_SYSLOG_NG[transport]

# Paths used by the BDD target scenarios. context.example_binary
# (set in environment.before_all from EXAMPLE_BINARY / per-target default) is
# the single binary path on every runner — one buffered SolidSyslogBddTarget
# per platform (S24.05).
SYSLOG_NG_CTL = "/var/lib/syslog-ng/syslog-ng.ctl"
SYSLOG_NG_CONF = "Bdd/syslog-ng/syslog-ng.conf"
SYSLOG_NG_FULL_CONF = "Bdd/syslog-ng/syslog-ng-full.conf"
SYSLOG_NG_UDP_ONLY_CONF = "Bdd/syslog-ng/syslog-ng-udp-only.conf"

# Sourced from the build's configured tunables via the CMake-generated
# solidsyslog_tunables module (configure_file in top-level CMakeLists.txt
# parses Core/Interface/SolidSyslogTunablesDefaults.h, or the user override
# if SOLIDSYSLOG_USER_TUNABLES_FILE is set). The store_capacity scenarios
# depend on this value because production clamps max-block-size up to
# MAX + RECORD_OVERHEAD + integritySize at runtime, so the block size used
# by the block store is MAX-coupled even when the feature file specifies a
# smaller value.
from solidsyslog_tunables import SOLIDSYSLOG_MAX_MESSAGE_SIZE

# RFC 5424 §6.2.4 IP fallback for the FreeRTOS reference example. With no
# FQDN (no DNS resolver), no integrator-supplied hostname, and no DHCP, the
# highest-preference value the device can supply is its static IP. Mirrors
# TEST_IP_ADDRESS in Example/FreeRtos/SingleTask/main.c — keep them in sync.
EXAMPLE_FREERTOS_STATIC_IP = "10.0.2.15"


def clean_store_files():
    """Remove all rotating store files matching the path prefix."""
    for path in glob.glob(STORE_PATH_PREFIX + "*.log"):
        os.remove(path)


def line_count(path):
    """Return the number of lines in a file, or 0 if it doesn't exist."""
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as f:
        return sum(1 for _ in f)


def read_new_lines(path, skip):
    """Return all lines after the first 'skip' lines."""
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    return [line.strip() for line in lines[skip:] if line.strip()]


def _split_otel_line_into_records(line):
    """OTel's file exporter emits one JSON object per write but each object
    can carry multiple log records when messages arrive close together.
    Yield one single-record envelope (still parse_otel_jsonl_line-compatible)
    per logical record."""
    parent = json.loads(line)
    for resource_log in parent.get("resourceLogs", []):
        for scope_log in resource_log.get("scopeLogs", []):
            for log_record in scope_log.get("logRecords", []):
                yield json.dumps({
                    "resourceLogs": [{
                        "resource": resource_log.get("resource", {}),
                        "scopeLogs": [{
                            "scope": scope_log.get("scope", {}),
                            "logRecords": [log_record],
                        }],
                    }]
                })


def oracle_record_count(path, oracle_format):
    """Total number of logical oracle records in the file. For syslog-ng each
    line is one record; for OTel JSONL each line may carry several."""
    if not os.path.exists(path):
        return 0
    if oracle_format != "otel-jsonl":
        return line_count(path)
    count = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            count += sum(1 for _ in _split_otel_line_into_records(line))
    return count


def read_new_oracle_records(path, oracle_format, skip):
    """Return all logical oracle records after the first 'skip', each as a
    string ready for parse_oracle_line."""
    if not os.path.exists(path):
        return []
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if oracle_format != "otel-jsonl":
                records.append(line)
            else:
                records.extend(_split_otel_line_into_records(line))
    return records[skip:]


def read_last_line(path):
    """Return the last non-empty line from a file."""
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    for line in reversed(lines):
        if line.strip():
            return line.strip()
    return ""


UTF8_BOM_CHAR = "\ufeff"


def _strip_msg_bom(msg):
    """The library emits the RFC 5424 §6.4 UTF-8 BOM at the start of every MSG.
    It's a transport-layer prefix, not part of the body the
    test author cares about, so strip it on the receive side so that
    MSG-content assertions can compare the body bytes directly."""
    if msg.startswith(UTF8_BOM_CHAR):
        return msg[len(UTF8_BOM_CHAR):]
    return msg


def parse_syslog_ng_line(line):
    """Parse a syslog-ng key=value template line into a dict."""
    fields = {}
    for match in re.finditer(r"(\w+)=(\S+)", line):
        fields[match.group(1)] = match.group(2)

    # PROCID may be empty (= sign with no value) when the wire was the RFC 5424
    # §6.2.6 NILVALUE: syslog-ng's ${PID} macro substitutes an empty string,
    # which the general (\w+)=(\S+) regex above silently drops. Re-capture
    # explicitly with \S* so "field absent" and "field empty" stay distinct
    # downstream — NILVALUE assertions need the empty-string in fields.
    procid_match = re.search(r"PROCID=(\S*)", line)
    if procid_match:
        fields["PROCID"] = procid_match.group(1)

    # STRUCTURED_DATA may contain spaces and special chars — capture between
    # "STRUCTURED_DATA=" and " MSG="
    sd_match = re.search(r"STRUCTURED_DATA=(.*?) MSG=", line)
    if sd_match:
        fields["STRUCTURED_DATA"] = sd_match.group(1)

    # MSG may contain spaces — capture everything after "MSG="
    msg_match = re.search(r"MSG=(.*)", line)
    if msg_match:
        fields["MSG"] = _strip_msg_bom(msg_match.group(1))

    return fields


def _otel_attribute(attrs, key):
    """Pull a single attribute value (str/int) out of the OTel attribute list."""
    for attr in attrs:
        if attr.get("key") == key:
            value = attr.get("value", {})
            if "stringValue" in value:
                return value["stringValue"]
            if "intValue" in value:
                return str(value["intValue"])
            return value
    return None


def _render_otel_structured_data(sd_value):
    """Render OTel's nested kvlist structured-data attribute back into the
    syslog-ng `[sd-id k1="v1" k2="v2"]...` text form, so the existing
    regex-based Then steps don't need per-oracle branching.

    OTel shape (from the syslog receiver in rfc5424 mode):
      {"kvlistValue":{"values":[
        {"key":"meta", "value":{"kvlistValue":{"values":[
          {"key":"sequenceId", "value":{"stringValue":"1"}}]}}},
        ...
      ]}}
    """
    elements = sd_value.get("kvlistValue", {}).get("values", [])
    out = []
    for sd_element in elements:
        sd_id = sd_element.get("key", "")
        params = sd_element.get("value", {}).get("kvlistValue", {}).get("values", [])
        rendered_params = []
        for param in params:
            param_name = param.get("key", "")
            param_val = param.get("value", {})
            param_str = param_val.get("stringValue") or str(param_val.get("intValue", ""))
            rendered_params.append(f'{param_name}="{param_str}"')
        if rendered_params:
            out.append(f"[{sd_id} {' '.join(rendered_params)}]")
        else:
            out.append(f"[{sd_id}]")
    return "".join(out)


def parse_otel_jsonl_line(line):
    """Parse one JSON line from the OTel Collector file exporter into the
    same flat dict shape as parse_syslog_ng_line.

    Maps OTel's parsed RFC 5424 attributes (independent oracle, same role
    syslog-ng plays on Linux) into the flat field dict.
    """
    record = json.loads(line)
    log = record["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    attrs = log.get("attributes", [])

    fields = {}
    priority = _otel_attribute(attrs, "priority")
    if priority is not None:
        fields["PRIORITY"] = priority
    hostname = _otel_attribute(attrs, "hostname")
    if hostname is not None:
        fields["HOSTNAME"] = hostname
    appname = _otel_attribute(attrs, "appname")
    if appname is not None:
        fields["APP_NAME"] = appname
    proc_id = _otel_attribute(attrs, "proc_id")
    if proc_id is not None:
        fields["PROCID"] = proc_id
    msg_id = _otel_attribute(attrs, "msg_id")
    if msg_id is not None:
        fields["MSGID"] = msg_id
    msg = _otel_attribute(attrs, "message")
    if msg is not None:
        fields["MSG"] = _strip_msg_bom(msg)

    sd = _otel_attribute(attrs, "structured_data")
    if isinstance(sd, dict):
        fields["STRUCTURED_DATA"] = _render_otel_structured_data(sd)

    # timeUnixNano → ISO 8601 string compatible with datetime.fromisoformat
    time_ns = log.get("timeUnixNano")
    if time_ns is not None:
        seconds = int(time_ns) / 1e9
        fields["TIMESTAMP"] = datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()

    return fields


def parse_oracle_line(line, oracle_format):
    """Dispatch to the right parser based on the active oracle."""
    if oracle_format == "otel-jsonl":
        return parse_otel_jsonl_line(line)
    return parse_syslog_ng_line(line)


def _start_stdout_reader(process):
    """Start a daemon thread that reads process.stdout byte-by-byte into a queue.

    The select.select-based read pattern this replaces only worked on POSIX
    pipe fds. The thread + queue pattern is portable across POSIX and Windows
    so the prompt protocol can drive the BDD target on either host.
    Idempotent — only starts the thread once per process.
    """
    if hasattr(process, "_solidsyslog_byte_queue"):
        return

    process._solidsyslog_byte_queue = queue.Queue()
    # Sliding-window record of everything the FreeRTOS guest has printed,
    # used by after_step diagnostics when a scenario fails. Stays in-process
    # (no disk I/O) and capped so a long run doesn't grow unbounded.
    process._solidsyslog_stdout_log = bytearray()
    fd = process.stdout.fileno()

    def _reader():
        try:
            while True:
                data = os.read(fd, 1)
                if not data:
                    break
                process._solidsyslog_byte_queue.put(data)
                log = process._solidsyslog_stdout_log
                log += data
                # Cap at 16 KB — recent context only.
                if len(log) > 16384:
                    del log[: len(log) - 16384]
        finally:
            process._solidsyslog_byte_queue.put(None)

    threading.Thread(target=_reader, daemon=True).start()
    _start_stderr_reader(process)


def _start_stderr_reader(process):
    """Drain process.stderr into a capped buffer for after_step diagnostics.

    The BDD target's error handler (BddTargetStderrErrorHandler.c) writes
    every SolidSyslog error event to stderr. The prompt protocol only reads
    stdout, so without this drain the stderr PIPE is never emptied: under a
    retrying failure (e.g. a transient TLS/mTLS handshake error spun by the
    ~1ms service loop) it fills, and on Windows the next write blocks the
    target mid-Service — stalling it for the rest of the scenario and
    producing the "oracle received 0 of N" flake. Draining both prevents the
    stall and captures the client-side error so failures are diagnosable
    instead of silent. Started by _start_stdout_reader, so it shares the same
    idempotency guard.

    Reads in chunks (no byte-queue) because nothing parses stderr — it is
    diagnostics only.
    """
    if process.stderr is None:
        return

    process._solidsyslog_stderr_log = bytearray()
    fd = process.stderr.fileno()

    def _reader():
        while True:
            data = os.read(fd, 4096)
            if not data:
                break
            log = process._solidsyslog_stderr_log
            log += data
            # Cap at 16 KB — recent context only.
            if len(log) > 16384:
                del log[: len(log) - 16384]

    threading.Thread(target=_reader, daemon=True).start()


def wait_for_prompt(process, timeout=120):
    """Read stdout until we see 'SolidSyslog> ', confirming the command completed.

    Portable across POSIX and Windows: a daemon thread (started lazily by
    _start_stdout_reader) reads stdout byte-by-byte into a queue; this function
    pulls bytes off the queue with a per-iteration timeout so the deadline is
    honoured even on platforms where select.select can't monitor pipe fds.

    The default is generous (120s) for the FreeRTOS QEMU target — first-boot
    has to bring up Plus-TCP's IP task, parse the baked mbedTLS CA + client
    cert + RSA client key (multi-second under QEMU's emulated Cortex-M3),
    and then drop the interactive task. Linux/Windows native still complete
    in well under a second, so the bump is a no-op for them; see
    [[feedback-qemu-bdd-timeouts-generous]].
    """
    _start_stdout_reader(process)

    output = b""
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"Timed out waiting for prompt after {timeout}s. "
                f"Output so far: {output.decode(errors='replace')}"
            )
        try:
            data = process._solidsyslog_byte_queue.get(timeout=min(remaining, 0.5))
        except queue.Empty:
            continue
        if data is None:
            break
        output += data
        if output.endswith(b"SolidSyslog> "):
            return output.decode()
    return output.decode()


def send_command(process, command):
    """Send a command to the interactive process and wait for the prompt."""
    process.stdin.write(command + "\n")
    process.stdin.flush()
    return wait_for_prompt(process)


def wait_for_messages(context, expected_messages):
    """Wait for the oracle to flush the expected number of new records.
    Counts logical records (not raw file lines) so OTel's batch-per-line
    write behaviour doesn't undercount."""
    received_log = context.received_log
    oracle_format = context.oracle_format
    expected_total = context.lines_before + expected_messages
    deadline = time.monotonic() + 10
    while oracle_record_count(received_log, oracle_format) < expected_total:
        if time.monotonic() > deadline:
            actual = oracle_record_count(received_log, oracle_format) - context.lines_before
            raise AssertionError(
                f"oracle received {actual} of {expected_messages} "
                f"messages within 10 seconds"
            )
        time.sleep(0.1)

    context.all_lines = read_new_oracle_records(received_log, oracle_format, context.lines_before)
    context.fields = parse_oracle_line(context.all_lines[-1], oracle_format)
    context.message_count = len(context.all_lines)


def settle_prompts(process, count):
    """Consume the replies to commands someone else wrote."""
    for _ in range(count):
        wait_for_prompt(process)


def apply_tls_settings(context, process):
    """Deliver the TLS knobs a scenario configured, over the prompt protocol.

    Unlike apply_extra_args this is the same on every target: Linux and Windows
    read the lines from stdin, FreeRTOS from the UART, and all four route them
    to BddTargetTlsConfig_SetByName. A value the target will not take echoes
    `set: invalid`, which fails the scenario here rather than surfacing later as
    a connection nobody configured.
    """
    for name, value in getattr(context, "tls_settings", []):
        apply_tls_setting(process, name, value)


def apply_tls_setting(process, name, value):
    """One `set NAME VALUE`, refusing to continue if the target will not take it."""
    reply = send_command(process, f"set {name} {value}")
    assert "set: invalid" not in reply, (
        f"BDD target rejected `set {name} {value}`"
    )


def run_example(context, extra_args=None, expected_messages=1, command="send"):
    """Run the BDD target via the prompt protocol.

    Every supported runner ships a single buffered binary now — Linux
    (pthread + PosixMessageQueueBuffer), Windows (Win32 + CircularBuffer),
    FreeRTOS-on-QEMU (Service task + CircularBuffer) — and every runner's
    binary is named SolidSyslogBddTarget so the RFC 5424 APP-NAME field
    matches the platform-agnostic feature assertions without a pin
    (S24.05).

    The pre-S13.18 implementation wrote `send N\\nquit\\n` upfront via
    process.communicate() and relied on PassthroughBuffer's synchronous Send to
    guarantee delivery before exit. That assumption broke once the
    target became buffered — `quit` could land before the service
    thread had drained, losing the UDP packet. The prompt protocol
    coordinates around it: wait for the oracle to confirm receipt before
    sending `quit`.
    """
    binary = context.example_binary
    assert os.path.exists(binary), (
        f"BDD target binary not found at {binary} — build with cmake first"
    )

    process = spawn_example_process(context, extra_args=extra_args, binary=binary)
    # On the context as well as in hand, so a step that runs after this one can
    # read what the target reported, and after_step can dump it on a failure.
    context.interactive_process = process
    context.example_pid = process.pid

    try:
        wait_for_prompt(process)
        settle_prompts(process, apply_extra_args(context, process, extra_args))
        apply_tls_settings(context, process)
        send_command(process, f"{command} {expected_messages}")
        wait_for_messages(context, expected_messages)

        returncode = stop_example_process(process, context.target)
        # FreeRTOS keeps the QEMU VM alive after `quit` (the scheduler
        # idles so a GDB attach works), so stop_example_process kills
        # QEMU and returns None — no exit code to assert. Linux/Windows
        # binaries exit cleanly on `quit` and their return code is
        # meaningful.
        assert returncode in (0, None), (
            f"Example failed with exit code {returncode}"
        )
    finally:
        # Don't let an intermediate exception leak the helper into later
        # scenarios — kill if it's still running after the assertions above.
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def syslog_ng_reload():
    """Send RELOAD to syslog-ng via its Unix control socket."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(SYSLOG_NG_CTL)
        sock.sendall(b"RELOAD\n")
        response = sock.recv(1024)
    assert b"OK" in response, f"syslog-ng reload failed: {response}"
    # Allow time for syslog-ng to complete the reload
    time.sleep(0.5)


def syslog_ng_swap_config(config_path):
    """Replace the active syslog-ng config and reload.

    Uses copyfile (data only, no chmod) rather than copy. The destination
    is bind-mounted from the host on developer machines; chmod fails with
    'Operation not permitted' when the host owner is not the container's
    `developer` user. The file already exists with the correct mode
    so copying just the contents is sufficient.
    """
    shutil.copyfile(config_path, SYSLOG_NG_CONF)
    syslog_ng_reload()


@given("the syslog oracle is running")
def step_syslog_ng_is_running(context):
    # Only assert the syslog-ng control socket when syslog-ng is actually the
    # active oracle. Other runners (e.g. the OTel Collector on Windows) reuse
    # this step text but expose no such socket.
    if context.oracle_format == "syslog-ng":
        assert os.path.exists(SYSLOG_NG_CTL), (
            f"syslog-ng control socket not found at {SYSLOG_NG_CTL}"
        )

    # Record current logical-record count so we can detect the new message.
    # Field name kept (`lines_before`) for legacy callers, but for OTel one
    # JSONL file line may carry several records.
    context.lines_before = oracle_record_count(context.received_log, context.oracle_format)

    # Per-transport baselines for SwitchingSender / TLS / mTLS scenarios.
    # Linux: all four transports. Windows OTel: tls + mtls only (udp/tcp
    # share received.jsonl on Windows so the per-transport step would be
    # ambiguous; SwitchingSender stays Linux-only via @buffered for now).
    # Count logical records (not file lines) so the OTel file exporter's
    # batched-into-one-line behaviour is handled correctly when several
    # messages arrive close together.
    context.lines_before_per_transport = {}
    table = (PER_TRANSPORT_LOG_OTEL if context.oracle_format == "otel-jsonl"
             else PER_TRANSPORT_LOG_SYSLOG_NG)
    for transport, path in table.items():
        context.lines_before_per_transport[transport] = oracle_record_count(
            path, context.oracle_format
        )


def build_buffered_extra_args(context, transport, no_sd=False):
    """Build the extra-args list for the buffered BDD target.

    Returned list excludes the binary itself — start_bdd_target_process
    routes the spawn through target_driver.spawn_example_process, which
    appends the args to argv on Linux/Windows and translates them to
    interactive `set NAME VALUE` lines after the prompt on FreeRTOS.

    Linux runner (syslog-ng oracle) and Windows runner (OTel oracle) both
    ship SolidSyslogBddTarget — same basename, same flags, same wire-record
    sizes byte-for-byte (S24.05 unified the basename so capacity-feature
    block packing is identical across runners).
    """
    args = ["--transport", transport]
    if getattr(context, "store_type", None):
        args.extend(["--store", context.store_type])
    # Numeric option guards use `is not None` so an explicit 0 survives:
    # `--capacity-threshold 0` is the documented "disable" sentinel for
    # SolidSyslogStoreThresholdFunction (Core/Interface/SolidSyslogBlockStore.h).
    if getattr(context, "store_max_blocks", None) is not None:
        args.extend(["--max-blocks", str(context.store_max_blocks)])
    if getattr(context, "store_max_block_size", None) is not None:
        args.extend(["--max-block-size", str(context.store_max_block_size)])
    if getattr(context, "store_discard_policy", None):
        args.extend(["--discard-policy", context.store_discard_policy])
    if getattr(context, "security_policy", None):
        args.extend(["--security-policy", context.security_policy])
    if getattr(context, "capacity_threshold", None) is not None:
        args.extend(["--capacity-threshold", str(context.capacity_threshold)])
    if getattr(context, "message_body", None):
        args.extend(["--message", context.message_body])
    if no_sd:
        args.append("--no-sd")
    if getattr(context, "halt_exit", False):
        args.append("--halt-exit")
    return args


def start_bdd_target_process(context, extra_args):
    """Start the buffered BDD target and wait for the initial prompt.

    Single Popen path across native and QEMU backends — target_driver
    picks the spawn (subprocess on Linux/Windows, qemu-system-arm with
    -kernel on FreeRTOS) and apply_extra_args delivers the same
    --flag value pairs either as argv (native) or `set NAME VALUE` over
    the UART (FreeRTOS) after the prompt is up. Adding a new embedded
    platform reuses both helpers without touching this function.
    """
    binary = context.example_binary
    assert os.path.exists(binary), (
        f"BDD target binary not found at {binary} — build with cmake first"
    )

    context.interactive_process = spawn_example_process(
        context, extra_args=extra_args
    )
    context.example_pid = context.interactive_process.pid
    wait_for_prompt(context.interactive_process)
    settle_prompts(
        context.interactive_process,
        apply_extra_args(context, context.interactive_process, extra_args),
    )
    apply_tls_settings(context, context.interactive_process)


@given("the BDD target is running with transport {transport:w}")
def step_bdd_target_running_with_transport(context, transport):
    start_bdd_target_process(context, build_buffered_extra_args(context, transport))


@given("the BDD target is running with transport {transport:w} and no structured data")
def step_bdd_target_running_with_transport_no_sd(context, transport):
    start_bdd_target_process(
        context, build_buffered_extra_args(context, transport, no_sd=True)
    )


@given("the block store is enabled")
def step_block_store_enabled(context):
    context.store_type = "file"
    if os.path.exists(STORE_FILE_PATH):
        os.remove(STORE_FILE_PATH)


@given("the security policy is {policy}")
def step_security_policy(context, policy):
    # Selects the at-rest integrity policy for the block store (S17.02). On
    # FreeRTOS, build_buffered_extra_args emits `--security-policy <policy>`
    # which target_driver translates to `set security-policy ...` before
    # `set store file`. Today only the FreeRTOS target wires hmac-sha256, so
    # scenarios using it carry @hmac and run on the FreeRTOS-plustcp runner only.
    context.security_policy = policy


@given("the block store is enabled with max-blocks {max_blocks:d} and max-block-size {max_block_size:d} and discard-policy {policy}")
def step_block_store_enabled_with_config(context, max_blocks, max_block_size, policy):
    context.store_type = "file"
    context.store_max_blocks = max_blocks
    context.store_max_block_size = max_block_size
    context.store_discard_policy = policy
    # Size each MSG so several records pack per (clamped) block, ensuring at
    # least one discard event for the 10-message outage. The store_capacity
    # scenarios assert structural properties of the surviving seqIds (gap
    # at start for discard-oldest, contiguous head for discard-newest) — the
    # exact records-per-block count is platform-dependent (hostname / procid
    # widths differ between the Linux compose container and the Windows OTel
    # runner) but irrelevant to the policy under test. Production grows a
    # block below one worst-case record to that floor, so the per-record
    # budget tracks the message size; sizing the body off it yields several
    # records per block on the runners we ship.
    context.message_body = "X" * (SOLIDSYSLOG_MAX_MESSAGE_SIZE // 5 - 50)
    clean_store_files()


@given("the halt callback exits the process")
def step_halt_callback_exits(context):
    context.halt_exit = True


@given("the capacity threshold callback is enabled at {threshold:d} bytes")
def step_capacity_threshold_enabled(context, threshold):
    context.capacity_threshold = threshold
    try:
        os.remove(THRESHOLD_MARKER_PATH)
    except FileNotFoundError:
        pass


_THRESHOLD_STDOUT_TOKEN = b"[THRESHOLD-CROSSED]"


def _threshold_marker_present(context):
    """True if either marker channel reports a crossing.

    Linux and Windows binaries write a host file at THRESHOLD_MARKER_PATH.
    FreeRTOS-on-QEMU has no shared filesystem with the host, so its
    OnThresholdCrossed prints the _THRESHOLD_STDOUT_TOKEN to UART and the
    captured-stdout reader buffers it into process._solidsyslog_stdout_log.
    Both channels are accepted so the same step works across all targets
    without target branching at the assertion site.
    """
    if os.path.exists(THRESHOLD_MARKER_PATH) and os.path.getsize(THRESHOLD_MARKER_PATH) > 0:
        return True
    if hasattr(context, "interactive_process"):
        log = getattr(context.interactive_process, "_solidsyslog_stdout_log", None)
        if log and _THRESHOLD_STDOUT_TOKEN in bytes(log):
            return True
    return False


@then("the capacity threshold callback was invoked")
def step_threshold_callback_invoked(context):
    # The crossing is edge-triggered inside the Service task's drain loop, so
    # the marker appears asynchronously after the producing `send` returns. On
    # a host target the drain is effectively instant; on FreeRTOS-on-QEMU each
    # offline drain first burns a dead-connection send timeout, so the marker
    # can lag the assertion by a second or two. Poll a bounded deadline rather
    # than checking once — the negative case ("was not invoked") still asserts
    # immediately, so a genuinely-absent marker cannot be masked by this wait.
    deadline = time.time() + 10
    while time.time() < deadline:
        if _threshold_marker_present(context):
            break
        time.sleep(0.1)
    assert _threshold_marker_present(context), (
        f"Expected threshold marker at {THRESHOLD_MARKER_PATH} or "
        f"{_THRESHOLD_STDOUT_TOKEN.decode()} on captured stdout; found neither"
    )


@then("the capacity threshold callback was not invoked")
def step_threshold_callback_not_invoked(context):
    assert not _threshold_marker_present(context), (
        f"Expected no threshold marker but found one (file at "
        f"{THRESHOLD_MARKER_PATH} or {_THRESHOLD_STDOUT_TOKEN.decode()} on "
        f"captured stdout)"
    )


@given("the set of existing block files is recorded")
def step_record_block_files(context):
    context.recorded_block_files = set(glob.glob(STORE_PATH_PREFIX + "*.log"))


@then("no recorded block file has been disposed")
def step_no_block_disposed(context):
    missing = sorted(p for p in context.recorded_block_files if not os.path.exists(p))
    assert not missing, f"Block files disposed unexpectedly: {missing}"


@then("block file {index} has been disposed")
def step_block_file_disposed(context, index):
    path = f"{STORE_PATH_PREFIX}{index}.log"
    assert not os.path.exists(path), (
        f"Expected block file {path} to have been disposed but it is still on disk"
    )


@when("the client sends a message")
def step_client_sends_message(context):
    send_command(context.interactive_process, "send")
    # Allow time for the service thread to drain the buffer and send
    time.sleep(0.2)


def wait_for_tcp_port_closed(host="syslog-ng", port=5514, timeout=5):
    """Poll until the TCP port refuses connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((host, port))
            time.sleep(0.1)
        except (ConnectionRefusedError, OSError):
            return
    raise AssertionError(f"TCP port {port} still open after {timeout}s")


def wait_for_tcp_port_open(host="syslog-ng", port=5514, timeout=5):
    """Poll until the TCP port accepts connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((host, port))
            return
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
    raise AssertionError(f"TCP port {port} not open after {timeout}s")


def wait_for_connection_teardown(probe_socket, timeout=5):
    """Wait until an established TCP connection is broken by the server.

    Sends data on the probe socket until a broken pipe or reset indicates
    that syslog-ng has closed the connection after a config reload.
    """
    msg = b"<134>1 2026-01-01T00:00:00Z probe probe - - - probe"
    frame = f"{len(msg)} ".encode() + msg
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            probe_socket.sendall(frame)
            time.sleep(0.1)
        except (BrokenPipeError, ConnectionResetError, OSError):
            probe_socket.close()
            return
    probe_socket.close()
    raise AssertionError(f"Probe connection still alive after {timeout}s")


@when("the syslog oracle stops accepting TCP connections")
def step_oracle_stops_tcp(context):
    if context.oracle_format == "syslog-ng":
        # Linux: swap to a UDP-only config and RELOAD via the control socket.
        # Open a probe connection before the reload so we can detect teardown.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(1)
        probe.connect(("syslog-ng", 5514))

        # Set the restore flag *before* the swap so any failure inside
        # syslog_ng_swap_config (or the subsequent wait/probe-teardown)
        # still triggers after_scenario's config restore — otherwise a
        # half-applied swap would leave the on-disk config in UDP-only
        # mode and contaminate the next scenario.
        context.syslog_ng_config_changed = True
        syslog_ng_swap_config(SYSLOG_NG_UDP_ONLY_CONF)
        wait_for_tcp_port_closed()
        wait_for_connection_teardown(probe)
        # Allow time for the sender's existing connection to receive RST
        time.sleep(0.5)
    else:
        # Windows OTel: kill the otelcol-contrib process. The TCP listener
        # disappears as the process exits — the resume step will start a
        # fresh one. Side-effect: UDP/TLS/mTLS listeners also stop, but the
        # outage scenarios that drive this step only depend on TCP.
        otel_kill_oracle()
        wait_for_tcp_port_closed(host="127.0.0.1", port=5514, timeout=10)
        # Allow time for the sender's existing connection to receive RST
        time.sleep(0.5)
        context.otel_oracle_paused = True


@when("the syslog oracle resumes accepting TCP connections")
def step_oracle_resumes_tcp(context):
    if context.oracle_format == "syslog-ng":
        syslog_ng_swap_config(SYSLOG_NG_FULL_CONF)
        wait_for_tcp_port_open()
    else:
        otel_start_oracle()
        context.otel_oracle_paused = False


@when("the BDD target sends a syslog message")
def step_bdd_target_sends_message(context):
    run_example(context)


@when("the BDD target sends a custom syslog message")
def step_bdd_target_sends_custom_message(context):
    run_example(context, command="send-custom")


@when("the BDD target attempts to send a syslog message over {transport:w}")
def step_bdd_target_attempts_to_send(context, transport):
    """Send one message that is not expected to arrive.

    Nothing is waited for here and the target is left running, so the steps
    that follow read the decision it reached rather than a delivery.
    """
    start_bdd_target_process(context, ["--transport", transport])
    send_command(context.interactive_process, "send 1")


@when("the BDD target sends a syslog message with transport {transport}")
def step_bdd_target_sends_with_transport(context, transport):
    run_example(context, ["--transport", transport])


@when("the BDD target sends {count:d} syslog messages")
def step_bdd_target_sends_multiple(context, count):
    run_example(context, expected_messages=count)


@when("the BDD target sends a message with facility {facility:d} and severity {severity:d}")
def step_bdd_target_sends_with_facility_severity(context, facility, severity):
    run_example(context, ["--facility", str(facility), "--severity", str(severity)])


@when('the BDD target sends a message with message ID "{msgid}"')
def step_bdd_target_sends_with_msgid(context, msgid):
    run_example(context, ["--msgid", msgid])


@when('the BDD target sends a message with body "{body}"')
def step_bdd_target_sends_with_body(context, body):
    run_example(context, ["--message", body])


@when('the BDD target sends a complete message with message ID "{msgid}" and body "{body}"')
def step_bdd_target_sends_with_msgid_and_body(context, msgid, body):
    run_example(context, ["--msgid", msgid, "--message", body])


@when("the BDD target sends a UTF-8 message that fits the path MTU")
def step_bdd_target_sends_utf8_within_mtu(context):
    # Comfortably under the typical 1472-byte path payload, with multi-byte
    # UTF-8 mixed in. Tests the no-trim path: the message goes out whole.
    msg = "Hello, " + ("é" * 100) + " - mixed " + ("€" * 50) + " - end"
    context.sent_msg = msg
    run_example(context, ["--message", msg])


@when("the BDD target sends an oversize UTF-8 message")
def step_bdd_target_sends_oversize_utf8(context):
    # Build a message that overflows the path MTU. The ASCII prefix keeps
    # the prefix-equality assertion robust; the long run of '€' (3 bytes
    # each) ensures the trim point almost certainly lands mid-codepoint,
    # exercising the walk-back to a clean codepoint boundary.
    # ~1600 MSG bytes + ~80 RFC 5424 header = ~1680 wire bytes,
    # well above the docker-bridge path MTU's 1472-byte payload limit.
    msg = ("X" * 100) + ("€" * 500)
    context.sent_msg = msg
    run_example(context, ["--message", msg])


@then("the received message is byte-identical to the sent message")
def step_check_msg_byte_identical(context):
    received = context.fields.get("MSG", "")
    assert received == context.sent_msg, (
        f"Expected {len(context.sent_msg.encode('utf-8'))} bytes byte-identical, "
        f"got {len(received.encode('utf-8'))} bytes that differ"
    )


@then("the received message is shorter than the sent message")
def step_check_msg_shorter(context):
    received = context.fields.get("MSG", "")
    sent_bytes = len(context.sent_msg.encode("utf-8"))
    received_bytes = len(received.encode("utf-8"))
    assert received_bytes < sent_bytes, (
        f"Expected trim — sent {sent_bytes} bytes, received {received_bytes}"
    )


@then("the received message is a clean prefix of the sent message")
def step_check_msg_clean_prefix(context):
    received = context.fields.get("MSG", "")
    assert context.sent_msg.startswith(received), (
        "Received is not a clean prefix of sent — trim left orphan bytes "
        "or modified content. "
        f"Sent starts: {context.sent_msg[:60]!r}; "
        f"received starts: {received[:60]!r}; "
        f"received ends: {received[-40:]!r}"
    )


@then('the syslog oracle receives a message with priority "{priority}"')
def step_check_priority(context, priority):
    assert context.fields["PRIORITY"] == priority, (
        f"Expected priority {priority}, got {context.fields.get('PRIORITY')}"
    )


@then('the timestamp is "{timestamp}"')
def step_check_timestamp(context, timestamp):
    assert context.fields["TIMESTAMP"] == timestamp, (
        f"Expected timestamp {timestamp}, got {context.fields.get('TIMESTAMP')}"
    )


@then("the syslog oracle receives a message with a timestamp within {seconds:d} seconds of now")
def step_check_timestamp_within(context, seconds):
    raw = context.fields["TIMESTAMP"]
    received = datetime.fromisoformat(raw).astimezone(timezone.utc)
    now = datetime.now(timezone.utc)
    delta = abs((now - received).total_seconds())
    assert delta <= seconds, (
        f"Timestamp {raw} is {delta:.1f}s from now, expected within {seconds}s"
    )


@then("the syslog oracle receives a message with the system hostname")
def step_check_system_hostname(context):
    """Asserts the wire HOSTNAME is what RFC 5424 §6.2.4 says it should be
    for this target. The §6.2.4 preference order is FQDN → static IP →
    hostname → dynamic IP → NILVALUE; each runner emits the highest-
    preference value it can supply. Linux/Windows: gethostname() (rung 3,
    "hostname"). FreeRTOS reference: the configured static IPv4 (rung 2)
    because no FQDN, no integrator hostname, no DHCP."""
    if context.target == "freertos":
        expected = EXAMPLE_FREERTOS_STATIC_IP
    else:
        expected = socket.gethostname()
    assert context.fields["HOSTNAME"] == expected, (
        f"Expected hostname {expected}, got {context.fields.get('HOSTNAME')}"
    )


@then("the syslog oracle receives a message with the process ID of the BDD target")
def step_check_example_pid(context):
    """Asserts the wire PROCID matches what the originator can supply per
    RFC 5424 §6.2.6 (NILVALUE permitted "when no value is provided"). Each
    runner emits the most honest value it has: Linux/Windows the spawned
    example's PID; FreeRTOS NILVALUE because there is no process model on
    QEMU. The library emits NILVALUE when getProcessId is NULL — falls
    through NilStringFunction → empty field → FormatStringField writes "-"
    (Core/Source/SolidSyslog.c)."""
    if context.target == "freertos":
        # Explicit presence-then-value check: parse_syslog_ng_line's
        # PROCID=(\S*) captures wire NILVALUE as "" while leaving the key
        # absent if syslog-ng never emitted PROCID at all (template gap /
        # malformed message). Collapsing "absent" into "empty" via .get()
        # would let template breakage register as a NILVALUE pass.
        assert "PROCID" in context.fields, (
            "Expected PROCID field present in oracle output (NILVALUE captured as empty)"
        )
        actual = context.fields["PROCID"]
        assert actual == "", (
            f"Expected NILVALUE PROCID (empty), got {actual!r}"
        )
    else:
        expected = str(context.example_pid)
        assert context.fields["PROCID"] == expected, (
            f"Expected PID {expected}, got {context.fields.get('PROCID')}"
        )


@then('the hostname is "{hostname}"')
def step_check_hostname(context, hostname):
    assert context.fields["HOSTNAME"] == hostname, (
        f"Expected hostname {hostname}, got {context.fields.get('HOSTNAME')}"
    )


@then('the app name is "{app_name}"')
def step_check_app_name(context, app_name):
    assert context.fields["APP_NAME"] == app_name, (
        f"Expected app name {app_name}, got {context.fields.get('APP_NAME')}"
    )


@then('the process ID is "{procid}"')
def step_check_procid(context, procid):
    assert context.fields["PROCID"] == procid, (
        f"Expected process ID {procid}, got {context.fields.get('PROCID')}"
    )


@then('the message ID is "{msgid}"')
def step_check_msgid(context, msgid):
    assert context.fields["MSGID"] == msgid, (
        f"Expected message ID {msgid}, got {context.fields.get('MSGID')}"
    )


@then('the message is "{msg}"')
def step_check_msg(context, msg):
    assert context.fields["MSG"] == msg, (
        f"Expected message {msg}, got {context.fields.get('MSG')}"
    )


@then("the syslog oracle receives {count:d} message")
@then("the syslog oracle receives {count:d} messages")
def step_check_message_count(context, count):
    if hasattr(context, "interactive_process"):
        wait_for_messages(context, count)
    assert context.message_count == count, (
        f"Expected {count} messages, got {context.message_count}"
    )


@then("the syslog oracle receives no more messages")
def step_check_no_more_messages(context):
    before = oracle_record_count(context.received_log, context.oracle_format)
    time.sleep(5)
    after = oracle_record_count(context.received_log, context.oracle_format)
    assert after == before, (
        f"Expected no more messages, but received {after - before} additional"
    )


@then('the structured data contains sequenceId "{value}"')
def step_check_sequence_id(context, value):
    sd = context.fields.get("STRUCTURED_DATA", "")
    match = re.search(r'sequenceId="(\d+)"', sd)
    assert match, (
        f"No sequenceId found in structured data: {sd}"
    )
    assert match.group(1) == value, (
        f"Expected sequenceId {value}, got {match.group(1)}"
    )


@then('the structured data contains tzKnown "{value}"')
def step_check_tz_known(context, value):
    sd = context.fields.get("STRUCTURED_DATA", "")
    match = re.search(r'tzKnown="(\d+)"', sd)
    assert match, (
        f"No tzKnown found in structured data: {sd}"
    )
    assert match.group(1) == value, (
        f"Expected tzKnown {value}, got {match.group(1)}"
    )


@then('the structured data contains isSynced "{value}"')
def step_check_is_synced(context, value):
    sd = context.fields.get("STRUCTURED_DATA", "")
    match = re.search(r'isSynced="(\d+)"', sd)
    assert match, (
        f"No isSynced found in structured data: {sd}"
    )
    assert match.group(1) == value, (
        f"Expected isSynced {value}, got {match.group(1)}"
    )


@then('the structured data contains software "{value}"')
def step_check_software(context, value):
    sd = context.fields.get("STRUCTURED_DATA", "")
    match = re.search(r'software="([^"]*)"', sd)
    assert match, (
        f"No software found in structured data: {sd}"
    )
    assert match.group(1) == value, (
        f"Expected software {value}, got {match.group(1)}"
    )


@then('the structured data contains swVersion "{value}"')
def step_check_sw_version(context, value):
    sd = context.fields.get("STRUCTURED_DATA", "")
    match = re.search(r'swVersion="([^"]*)"', sd)
    assert match, (
        f"No swVersion found in structured data: {sd}"
    )
    assert match.group(1) == value, (
        f"Expected swVersion {value}, got {match.group(1)}"
    )


@then('the structured data contains enterpriseId "{value}"')
def step_check_enterprise_id(context, value):
    sd = context.fields.get("STRUCTURED_DATA", "")
    # SD-PARAM-VALUE escapes ", \ and ] with a backslash (RFC 5424 §6.3.3),
    # so the matcher must accept escape sequences inside the value rather
    # than terminating at the first inner quote.
    match = re.search(r'enterpriseId="((?:\\.|[^"])*)"', sd)
    assert match, (
        f"No enterpriseId found in structured data: {sd}"
    )
    actual = re.sub(r"\\(.)", r"\1", match.group(1))
    assert actual == value, (
        f"Expected enterpriseId {value}, got {actual}"
    )


@then('the structured data contains ip "{value}"')
def step_check_ip(context, value):
    sd = context.fields.get("STRUCTURED_DATA", "")
    matches = re.findall(r'ip="((?:\\.|[^"])*)"', sd)
    actuals = [re.sub(r"\\(.)", r"\1", m) for m in matches]
    assert value in actuals, (
        f"Expected ip {value} in structured data: {sd} (found ips: {actuals})"
    )


@then('the structured data contains language "{value}"')
def step_check_language(context, value):
    sd = context.fields.get("STRUCTURED_DATA", "")
    # SD-PARAM-VALUE escapes ", \ and ] with a backslash (RFC 5424 §6.3.3),
    # so the matcher must accept escape sequences inside the value rather
    # than terminating at the first inner quote.
    match = re.search(r'language="((?:\\.|[^"])*)"', sd)
    assert match, (
        f"No language found in structured data: {sd}"
    )
    actual = re.sub(r"\\(.)", r"\1", match.group(1))
    assert actual == value, (
        f"Expected language {value}, got {actual}"
    )


@then('the structured data contains detail "{value}"')
def step_check_detail(context, value):
    sd = context.fields.get("STRUCTURED_DATA", "")
    # Escape-aware like the language matcher (RFC 5424 §6.3.3), so the assertion
    # holds whether the oracle re-renders the value escaped or decoded.
    match = re.search(r'detail="((?:\\.|[^"])*)"', sd)
    assert match, (
        f"No detail found in structured data: {sd}"
    )
    actual = re.sub(r"\\(.)", r"\1", match.group(1))
    assert actual == value, (
        f"Expected detail {value}, got {actual}"
    )


@then("the structured data contains sysUpTime as a decimal integer")
def step_check_sys_up_time_shape(context):
    sd = context.fields.get("STRUCTURED_DATA", "")
    match = re.search(r'sysUpTime="(\d+)"', sd)
    assert match, (
        f"No sysUpTime found in structured data: {sd}"
    )
    # Live boot clocks (CLOCK_BOOTTIME / GetTickCount64) always read > 0 by the
    # time the BDD target runs. Pinning > 0 catches a regression where the
    # implementation collapses to a constant zero.
    assert int(match.group(1)) > 0, (
        f"Expected positive sysUpTime, got {match.group(1)} in structured data: {sd}"
    )


@then("the syslog oracle receives {count:d} messages with sequential sequenceId values")
def step_check_sequential_ids(context, count):
    assert context.message_count == count, (
        f"Expected {count} messages, got {context.message_count}"
    )
    for i, line in enumerate(context.all_lines, start=1):
        fields = parse_oracle_line(line, context.oracle_format)
        sd = fields.get("STRUCTURED_DATA", "")
        match = re.search(r'sequenceId="(\d+)"', sd)
        assert match, (
            f"Message {i}: no sequenceId in structured data: {sd}"
        )
        assert match.group(1) == str(i), (
            f"Message {i}: expected sequenceId {i}, got {match.group(1)}"
        )


@when("the client sends {count:d} messages")
def step_client_sends_n_messages(context, count):
    send_command(context.interactive_process, f"send {count}")
    # Allow time for the service thread to drain the buffer
    time.sleep(0.5)


@when("the client attempts to send it exits with code {code:d}")
def step_client_attempts_send_exits(context, code):
    process = context.interactive_process
    # Allow the service thread to drain the buffer and fill the store
    time.sleep(3)
    try:
        process.stdin.write("send\n")
        process.stdin.flush()
    except (BrokenPipeError, OSError):
        pass
    process.wait(timeout=10)
    assert process.returncode == code, (
        f"Expected exit code {code}, got {process.returncode}"
    )
    del context.interactive_process


@when("the client is killed")
def step_client_is_killed(context):
    process = context.interactive_process
    if getattr(context, "target", "linux") == "freertos":
        # FreeRTOS QEMU runs entirely in RAM; FatFs caches FAT and directory
        # entries in-RAM until f_sync / f_close / f_unmount touches them.
        # SIGKILL on QEMU drops those caches mid-flight and the next session's
        # f_mount sees stale or absent dir entries for STORE*.log. The
        # graceful path (Bdd/Targets/FreeRtos/main.c::ShutdownGracefully)
        # destroys our objects (which f_close the FILs) and f_unmounts before
        # SemihostingExit. Linux/Windows targets keep SIGKILL — the kernel
        # flushes page cache and file descriptors on process exit.
        try:
            process.stdin.write("set shutdown 1\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # SIGKILL should be immediate; if we still time out the OS
                # is in trouble — proceed so `del context.interactive_process`
                # still runs.
                pass
    else:
        # process.kill() is portable: TerminateProcess on Windows, SIGKILL on POSIX.
        # signal.SIGKILL is not defined on Windows.
        process.kill()
        process.wait(timeout=5)
    del context.interactive_process


@then("the messages have contiguous sequenceIds")
def step_check_contiguous_sequence_ids(context):
    ids = []
    for line in context.all_lines:
        fields = parse_oracle_line(line, context.oracle_format)
        sd = fields.get("STRUCTURED_DATA", "")
        match = re.search(r'sequenceId="(\d+)"', sd)
        assert match, (
            f"No sequenceId in structured data: {sd}"
        )
        ids.append(int(match.group(1)))
    for i in range(1, len(ids)):
        assert ids[i] == ids[i - 1] + 1, (
            f"Non-contiguous sequenceIds: {ids[i - 1]} followed by {ids[i]}"
        )


@then("the last {count:d} messages have contiguous sequenceIds starting from {start:d}")
def step_check_last_n_contiguous_ids(context, count, start):
    assert len(context.all_lines) >= count, (
        f"Expected at least {count} messages, got {len(context.all_lines)}"
    )
    last_n = context.all_lines[-count:]
    for i, line in enumerate(last_n):
        fields = parse_oracle_line(line, context.oracle_format)
        sd = fields.get("STRUCTURED_DATA", "")
        match = re.search(r'sequenceId="(\d+)"', sd)
        assert match, (
            f"Message {i + 1} of last {count}: no sequenceId in structured data: {sd}"
        )
        expected = start + i
        actual = int(match.group(1))
        assert actual == expected, (
            f"Message {i + 1} of last {count}: expected sequenceId {expected}, "
            f"got {actual}"
        )


@then("the replayed messages have sequenceIds {id_list}")
def step_check_replayed_sequence_ids(context, id_list):
    expected = [int(x.strip()) for x in id_list.split(",")]
    assert len(context.all_lines) >= len(expected), (
        f"Expected at least {len(expected)} messages, "
        f"got {len(context.all_lines)}"
    )
    # Replayed messages are the most recent batch excluding the first message
    # from the previous session (already verified)
    replayed = context.all_lines[-len(expected):]
    for i, line in enumerate(replayed):
        fields = parse_oracle_line(line, context.oracle_format)
        sd = fields.get("STRUCTURED_DATA", "")
        match = re.search(r'sequenceId="(\d+)"', sd)
        assert match, (
            f"Replayed message {i + 1}: no sequenceId in structured data: {sd}"
        )
        actual = int(match.group(1))
        assert actual == expected[i], (
            f"Replayed message {i + 1}: expected sequenceId {expected[i]}, "
            f"got {actual}"
        )


def _outage_seq_ids(context):
    """Collected sequenceIds in oracle log, excluding the pre-outage seqId 1.
    Used by the discard-policy structural assertions."""
    ids = []
    for line in context.all_lines:
        fields = parse_oracle_line(line, context.oracle_format)
        sd = fields.get("STRUCTURED_DATA", "")
        match = re.search(r'sequenceId="(\d+)"', sd)
        if match:
            value = int(match.group(1))
            if value != 1:
                ids.append(value)
    return ids


@then("the syslog oracle finishes draining")
def step_oracle_finishes_draining(context):
    """Wait for the oracle's record count to stabilise — used by discard-policy
    scenarios where we don't know in advance how many records will survive
    the store. Considered done when no new records arrive for 750 ms (half
    the service-thread iteration budget) or after 5 s wall-clock."""
    deadline = time.monotonic() + 5
    last_count = -1
    last_change = time.monotonic()
    while time.monotonic() < deadline:
        cur = oracle_record_count(context.received_log, context.oracle_format)
        if cur != last_count:
            last_count = cur
            last_change = time.monotonic()
        elif time.monotonic() - last_change > 0.75:
            break
        time.sleep(0.1)
    context.all_lines = read_new_oracle_records(
        context.received_log, context.oracle_format, context.lines_before
    )
    context.message_count = len(context.all_lines)


@then("the syslog oracle received sequenceId {value:d}")
def step_oracle_received_seqid(context, value):
    ids = []
    for line in context.all_lines:
        fields = parse_oracle_line(line, context.oracle_format)
        sd = fields.get("STRUCTURED_DATA", "")
        match = re.search(r'sequenceId="(\d+)"', sd)
        if match:
            ids.append(int(match.group(1)))
    assert value in ids, (
        f"Expected sequenceId {value} in oracle log; got {ids}"
    )


@then("the syslog oracle did not receive sequenceId {value:d}")
def step_oracle_did_not_receive_seqid(context, value):
    ids = []
    for line in context.all_lines:
        fields = parse_oracle_line(line, context.oracle_format)
        sd = fields.get("STRUCTURED_DATA", "")
        match = re.search(r'sequenceId="(\d+)"', sd)
        if match:
            ids.append(int(match.group(1)))
    assert value not in ids, (
        f"Did not expect sequenceId {value} in oracle log; got {ids}"
    )


@then("the outage messages have contiguous sequenceIds")
def step_outage_messages_contiguous(context):
    """Validate that the seqIds received from the outage period (everything
    except the pre-outage seqId 1) form a contiguous ascending run. Doesn't
    constrain the endpoints — that's what the per-policy 'received'/'did
    not receive' assertions are for."""
    ids = sorted(_outage_seq_ids(context))
    assert ids, "Expected at least one outage sequenceId; got none"
    expected = list(range(ids[0], ids[-1] + 1))
    assert ids == expected, (
        f"Expected contiguous outage sequenceIds {expected}, got {ids}"
    )


@then("the last message has sequenceId {value:d}")
def step_check_last_sequence_id(context, value):
    assert context.all_lines, "No messages received to check last sequenceId"
    fields = parse_oracle_line(context.all_lines[-1], context.oracle_format)
    sd = fields.get("STRUCTURED_DATA", "")
    match = re.search(r'sequenceId="(\d+)"', sd)
    assert match, (
        f"No sequenceId in last message structured data: {sd}"
    )
    actual = int(match.group(1))
    assert actual == value, (
        f"Last message: expected sequenceId {value}, got {actual}"
    )


# --- S20.1 SwitchingSender steps ------------------------------------------


@given("the BDD target is running with default transport {transport:w}")
def step_bdd_target_running_with_default_transport(context, transport):
    start_bdd_target_process(context, build_buffered_extra_args(context, transport))


@when('the client is given trust anchors "{anchors}"')
def step_client_given_trust_anchors(context, anchors):
    """Rotate the trust anchors on a target that is already running.

    The material a connection is made with is fetched at each Open, and what
    makes new material take effect is the version moving - which the target's
    own `set` handler does. That is what a rotation cell proves; with the
    version held still the next connection reuses what it had.
    """
    apply_tls_setting(context.interactive_process, "tls-ca", anchors)


@when('the client is given the pin of "{identity}"')
def step_client_given_pin(context, identity):
    """Replace the pinned fingerprints on a running target.

    `none` empties the set before the new pin goes in, so this is a rotation
    rather than an addition - a stale pin left alongside would keep authorising
    the peer it names.
    """
    apply_tls_setting(context.interactive_process, "tls-pin", "none")
    apply_tls_setting(context.interactive_process, "tls-pin", fingerprint_of(identity))


@when('the client expects the peer name "{name}"')
def step_client_expects_peer_name(context, name):
    apply_tls_setting(context.interactive_process, "tls-name", name)


@when('the client is redirected to "{identity}"')
def step_client_redirected(context, identity):
    """Move the destination only. What the device expects of the peer there is
    rotated separately, because whether the identity travels with the
    destination is the thing a redirect cell has to prove."""
    port, _ = listener(identity)
    apply_tls_setting(context.interactive_process, "tls-port", str(port))


@when('the client is given the client credential "{credential}"')
def step_client_given_client_credential(context, credential):
    apply_tls_setting(context.interactive_process, "tls-client", credential)


@when("the client switches to transport {transport:w}")
def step_client_switches_transport(context, transport):
    send_command(context.interactive_process, f"switch {transport}")
    # Let any in-flight messages drain before subsequent sends assume the new
    # selector is live. Matches the settle pattern used after `send`.
    time.sleep(0.2)


def wait_for_per_transport_messages(context, transport, expected):
    """Wait for `expected` new logical records in the per-transport oracle."""
    path = per_transport_log(context, transport)
    baseline = context.lines_before_per_transport.get(transport, 0)
    deadline = time.monotonic() + 5
    while oracle_record_count(path, context.oracle_format) - baseline < expected:
        if time.monotonic() > deadline:
            actual = oracle_record_count(path, context.oracle_format) - baseline
            raise AssertionError(
                f"{path} received {actual} of {expected} messages within 5 seconds"
            )
        time.sleep(0.1)


@then("the BDD target is still running")
def step_target_still_running(context):
    """The refusal ended the connection, not the application.

    A refused handshake is reported to the integrator's error handler, which
    decides what happens next; this target's handler keeps going when a cell
    has said a refusal is expected. Without this the cell would pass on a
    target that died at the first report, and prove nothing about delivery.
    """
    process = context.interactive_process
    assert process.poll() is None, (
        f"BDD target exited with {process.returncode} rather than carrying on"
    )


@then("the syslog oracle receives no message over {transport:w}")
def step_check_nothing_received(context, transport):
    """Nothing arrived over that transport, once the target has decided.

    The wait is on the target's own report rather than on a fixed delay - a
    report is what says a decision has been reached - and a message arriving
    ends it just as a report does, so what fails is this assertion rather than
    a timeout.
    """
    path = per_transport_log(context, transport)
    baseline = context.lines_before_per_transport.get(transport, 0)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        decided = bool(reported_details(context.interactive_process))
        delivered = oracle_record_count(path, context.oracle_format) - baseline
        if decided or delivered:
            break
        time.sleep(0.1)

    actual = oracle_record_count(path, context.oracle_format) - baseline
    assert actual == 0, (
        f"Expected no {transport} message, got {actual} in {path}"
    )


@then("the syslog oracle receives {count:d} message over {transport:w}")
@then("the syslog oracle receives {count:d} messages over {transport:w}")
def step_check_per_transport_count(context, count, transport):
    wait_for_per_transport_messages(context, transport, count)
    path = per_transport_log(context, transport)
    baseline = context.lines_before_per_transport.get(transport, 0)
    actual = oracle_record_count(path, context.oracle_format) - baseline
    assert actual == count, (
        f"Expected {count} {transport} message(s), got {actual} in {path}"
    )
