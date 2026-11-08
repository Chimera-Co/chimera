"""The CERT Polska tools (malduck, hfinger) as limited child processes, run before the analyzer hardens itself.

harden_process() forbids the analyzer any child process (RLIMIT_NPROC=0), so a parser exploit in the analyzer
cannot start one. malduck and hfinger are separate programs (GPL-3.0; only their JSON output is read), so they
run first, each as a child with its own limits: no core dumps, bounded CPU time, address space, output size and
open files, no new privileges; malduck may not start processes of its own either (hfinger has to start tshark).
The container's limits (no network, read-only root, no capabilities, unprivileged user, PID cap) hold for them as
for the analyzer. Their results are handed to analyze(); nothing else runs before hardening.
"""

from __future__ import annotations

import ctypes
import os
import resource
import sys
import time

from .identify import PCAP_MAGICS
from .plugins import malware_config, pcap

# Documents and archives: malduck's rules cannot match in them (see malware_config.SKIP_FORMATS)
NOT_BINARY = (b"%PDF", b"\xd0\xcf\x11\xe0", b"PK\x03\x04", b"{\\rtf", b"7z\xbc\xaf", b"Rar!", b"\x1f\x8b", b"MSCF")
SHARE = 0.4  # of the analyzer's time budget
CHILD_OUTPUT_BYTES = 16 * 1024 * 1024


def kind(path: str) -> str:
    """"pcap", "binary" (malduck) or "skip", from the first bytes only: nothing is parsed before hardening."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        head = os.read(fd, 8)
    finally:
        os.close(fd)
    if head[:4] in PCAP_MAGICS:
        return "pcap"
    if head.startswith(NOT_BINARY) or not head:
        return "skip"
    return "binary"


def limits(cpu_seconds: int, memory_bytes: int, no_children: bool):
    """preexec_fn for one tool: the child limits itself before exec."""

    def apply():
        for limit, value in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, cpu_seconds),
                             (resource.RLIMIT_AS, memory_bytes), (resource.RLIMIT_FSIZE, CHILD_OUTPUT_BYTES),
                             (resource.RLIMIT_NOFILE, 256)) + (((resource.RLIMIT_NPROC, 0),) if no_children else ()):
            try:
                resource.setrlimit(limit, (value, value))
            except (ValueError, OSError):
                pass
        if sys.platform.startswith("linux"):
            try:
                ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
            except OSError:
                pass

    return apply


def run_before_hardening(path: str, timeout_s: float, memory_bytes: int) -> dict:
    """{"pcap" | "malware_config": {"result": ..., "error": ..., "wall_s": ...}} for analyze(external=...)."""
    out = {}
    try:
        what = kind(path)
    except OSError:
        return out  # analyze() reports the unreadable sample itself
    budget = max(10.0, timeout_s * SHARE)
    started = time.monotonic()
    try:
        if what == "pcap":
            doc, _ = pcap.analyze_pcap(path, budget, preexec=limits(int(budget) + 5, memory_bytes, False))
            out["pcap"] = {"result": doc}
        elif what == "binary" and malware_config.available():
            configs = malware_config.extract(path, budget, preexec=limits(int(budget) + 5, memory_bytes, True))
            out["malware_config"] = {"result": configs}
    except Exception as exc:  # the analysis goes on without this tool
        out["pcap" if what == "pcap" else "malware_config"] = {"error": f"{type(exc).__name__}: {str(exc)[:300]}"}
    for entry in out.values():
        entry["wall_s"] = round(time.monotonic() - started, 3)
    return out
