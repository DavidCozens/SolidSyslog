"""Target-driver abstraction for spawning the example-under-test.

The same Behave feature files run on multiple target platforms — Linux,
Windows, FreeRTOS-on-QEMU. The platforms differ only in how the
example-under-test is spawned: a native subprocess on Linux/Windows, or
qemu-system-arm with the cross-built ELF on FreeRTOS. Both backends
expose the same `SolidSyslog> ` prompt protocol over stdin/stdout
(printf-to-UART for FreeRTOS, printf-to-pipe for the native binaries),
so the existing wait_for_prompt / send_command helpers in
syslog_steps.py work unchanged once the spawn returns a Popen-like
object.

The active target is selected by the BDD_TARGET environment variable,
read in environment.before_all and stashed on context.target. Steps
call spawn_example_process(context, extra_args=...) instead of
subprocess.Popen directly. After wait_for_prompt, callers also invoke
apply_extra_args so any `--flag value` pairs are delivered to the
target — appended to argv on Linux/Windows (a no-op there because
spawn already did it), or translated into `set NAME VALUE` lines over
the UART on FreeRTOS.
"""

import os
import subprocess


# Mapping from cmdline flag to FreeRTOS interactive `set` name. Only the
# flags features currently pass to run_example are mapped — adding a new
# scenario that needs a new flag should fail loudly via the
# `_FREERTOS_SET_TRANSLATION` lookup so the gap is visible, rather than
# silently no-op'ing or printing a confusing "set: invalid" on the UART.
# `--message` -> `msg` is intentional: the FreeRTOS BDD target's global is
# g_msg (Bdd/Targets/FreeRtos/main.c) and renaming the set name
# would churn the target for cosmetic gain.
_FREERTOS_SET_TRANSLATION = {
    "--facility": "facility",
    "--severity": "severity",
    "--msgid": "msgid",
    "--message": "msg",
    # `--transport <udp|tcp>` lands as `set transport <value>` on the UART;
    # OnSet routes it through BddTargetSwitchConfig_SetByName to flip the
    # SolidSyslogSwitchingSender's active inner sender. Added in S08.09 with
    # the FreeRTOS TCP stream adapter.
    "--transport": "transport",
    # S08.05 store-and-forward keys. `--store file` is the rebuild trigger
    # — it must be emitted AFTER the four configuration keys so the rebuild
    # sees the final pending values (see apply_extra_args sorting below).
    # `--max-blocks`, `--max-block-size`, `--discard-policy`,
    # `--halt-exit`, and `--no-sd` update pending globals; `--store file`
    # consumes them.
    "--max-blocks": "max-blocks",
    "--max-block-size": "max-block-size",
    "--discard-policy": "discard-policy",
    "--halt-exit": "halt-exit",
    "--no-sd": "no-sd",
    # S08.07 slice 6c admits capacity_threshold.feature on FreeRTOS — the
    # threshold byte count must reach the rebuild path before `--store file`.
    "--capacity-threshold": "capacity-threshold",
    # S17.02 at-rest integrity policy selector — like the other store keys it
    # must reach the rebuild before `--store file` (the order key sorts it ahead).
    "--security-policy": "security-policy",
    "--store": "store",
    # S39.04 TLS matrix knobs. Each maps to a `set` name owned by
    # BddTargetTlsConfig, which the FreeRTOS OnSet falls through to.
    "--tls-host": "tls-host",
    "--tls-port": "tls-port",
    "--tls-ca": "tls-ca",
    "--tls-name": "tls-name",
    "--tls-pin": "tls-pin",
}

# Flags emitted as `set NAME 1` (with no separate value in the harness's
# original flag pair). Mirrors Linux's bare `no_argument` flags — the
# scenario passes the flag alone on Linux/Windows; on FreeRTOS the
# translation injects a synthetic "1" value so the UART set protocol
# (always NAME VALUE) is honoured.
_FREERTOS_BARE_FLAG_VALUE = {
    "--halt-exit": "1",
    "--no-sd": "1",
}

# Emit order for the FreeRTOS `set` translations. `--store` must be last
# because `set store file` is the rebuild trigger that consumes the
# preceding pending values (max-blocks, max-block-size, discard-policy,
# halt-exit). Other flags are order-independent — sorted by name for
# deterministic output.
def _freertos_set_order_key(flag):
    if flag == "--store":
        return (1, flag)
    return (0, flag)


# QEMU machine + UART config matches build-freertos-target's smoke run
# in .github/workflows/ci.yml: mps2-an385 / Cortex-M3 / 16 MiB / LAN9118
# NIC / -serial stdio for the polled CMSDK UART. -icount keeps virtual
# time decoupled from host load so timing-sensitive scenarios are
# deterministic under CI noise.
_QEMU_BASE_ARGS = [
    "qemu-system-arm",
    "-M", "mps2-an385",
    "-m", "16M",
    "-display", "none",
    "-serial", "stdio",
    "-icount", "shift=auto,sleep=off,align=off",
    "-netdev", "user,id=net0",
    "-net", "nic,netdev=net0,model=lan9118",
    # Semihosting opens the FatFs disk image and (when --halt-exit fires)
    # terminates QEMU. diskio.c issues BKPT 0xAB traps for SYS_OPEN /
    # SYS_SEEK / SYS_READ / SYS_WRITE / SYS_FLEN / SYS_CLOSE / SYS_EXIT.
    "-semihosting-config", "enable=on,target=native",
]


def spawn_example_process(context, extra_args=None, binary=None):
    """Spawn the example-under-test for the active target.

    Returns a subprocess.Popen with text-mode stdin/stdout/stderr pipes
    so the caller can use the existing prompt-protocol helpers
    (wait_for_prompt / send_command) without modification.

    extra_args are appended to the binary's command line on Linux and
    Windows (where the example-runner parses argv via getopt). FreeRTOS
    has no getopt port and consumes its config via interactive `set`
    commands instead — they are delivered via apply_extra_args after
    the prompt is up.

    binary defaults to context.example_binary. Each supported runner
    ships a single buffered example binary now — Linux's pthread
    Threaded example (S24.04), Windows's Win32 buffered example
    (S13.20), and the FreeRTOS CircularBuffer + Service-task .elf
    (S08.04) — so callers don't override the default in normal use.
    """
    target = getattr(context, "target", "linux")
    if binary is None:
        binary = context.example_binary

    if target == "freertos":
        cmd = list(_QEMU_BASE_ARGS) + ["-kernel", os.path.abspath(binary)]
    else:
        cmd = [os.path.abspath(binary)]
        if extra_args:
            cmd.extend(extra_args)

    # Stdout goes through PIPE because the prompt protocol reads it
    # byte-by-byte; _start_stdout_reader tees a copy into a sliding 16 KB
    # buffer that after_step dumps on failure.
    return subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def apply_extra_args(context, process, extra_args):
    """Deliver `--flag [value]` pairs to the example after the prompt is up.

    Linux and Windows are no-ops here — spawn already placed the flags
    in argv. FreeRTOS translates each pair via _FREERTOS_SET_TRANSLATION
    and writes one newline-terminated `set NAME VALUE` line to the UART
    per pair.

    Bare flags (no value, e.g. `--halt-exit`) are accepted on Linux because
    they map to getopt's `no_argument`; on FreeRTOS the UART protocol is
    always `NAME VALUE`, so _FREERTOS_BARE_FLAG_VALUE supplies a synthetic
    "1". Mixed bare-flag and key/value forms are tolerated.

    Pairs are emitted in deterministic order — `--store` last so the
    `set store file` rebuild trigger sees final values for the four
    pending globals (max-blocks, max-block-size, discard-policy,
    halt-exit). Other flags are sorted by name for stability.

    Raises ValueError if a flag is not in the translation table; the BDD
    scenario surfaces the gap immediately rather than silently no-op'ing
    or hitting a confusing UART-side `set: invalid` reply.

    Returns how many command lines were written. Each one draws a reply and a
    fresh prompt from the target, and the caller owns the reader, so the caller
    has to consume that many before any later step can read a reply of its own
    - without it every reply after this is one command behind.
    """
    if not extra_args:
        return 0
    target = getattr(context, "target", "linux")
    if target != "freertos":
        return 0

    # Walk extra_args sequentially; bare flags from _FREERTOS_BARE_FLAG_VALUE
    # don't consume the next arg, key/value flags do. Collect into a list
    # of (flag, value) pairs so we can sort before emission.
    pairs = []
    iterator = iter(extra_args)
    for flag in iterator:
        if flag not in _FREERTOS_SET_TRANSLATION:
            raise ValueError(
                f"Unknown cmdline flag for FreeRTOS target: {flag!r}. "
                "Add it to _FREERTOS_SET_TRANSLATION in target_driver.py "
                "if a corresponding `set` name exists in the FreeRTOS "
                "example's OnSet handler."
            )
        if flag in _FREERTOS_BARE_FLAG_VALUE:
            value = _FREERTOS_BARE_FLAG_VALUE[flag]
        else:
            try:
                value = next(iterator)
            except StopIteration as exc:
                raise ValueError(
                    f"FreeRTOS extra_args flag {flag!r} expects a value but "
                    "extra_args ended."
                ) from exc
            # Guard against the next-token-is-another-flag mistake:
            # `--facility --severity 6` would silently use `--severity` as
            # facility's value. Match against the known-flag set so that
            # legitimate hyphen-prefixed values (e.g. `--message -hello`)
            # aren't rejected. Fail fast so the scenario builder fixes it.
            if value in _FREERTOS_SET_TRANSLATION:
                raise ValueError(
                    f"FreeRTOS extra_args flag {flag!r} expects a value but "
                    f"got another flag {value!r}."
                )
        pairs.append((flag, value))

    pairs.sort(key=lambda fv: _freertos_set_order_key(fv[0]))

    for flag, value in pairs:
        name = _FREERTOS_SET_TRANSLATION[flag]
        process.stdin.write(f"set {name} {value}\n")
    process.stdin.flush()
    return len(pairs)


def stop_example_process(process, target, timeout=10):
    """Tear down the example process for the active target.

    Linux/Windows: the example exits cleanly on `quit`, so wait for the
    return code. FreeRTOS: `quit` only deletes the interactive task —
    the QEMU VM keeps idling (the FreeRTOS scheduler stays alive so a
    GDB attach works), so the only way to terminate is to kill QEMU
    directly. The BDD scenario has already verified the oracle
    received the frame, so the QEMU exit code carries no useful
    signal — return None for that path so callers don't assert on it.
    """
    if target == "freertos":
        process.kill()
        process.wait(timeout=timeout)
        return None

    process.stdin.write("quit\n")
    process.stdin.flush()
    process.wait(timeout=timeout)
    return process.returncode
