"""HTTP request fingerprints of a run's traffic, with CERT Polska's hfinger.

A fingerprint describes how a client builds its requests (method, version, header order and values, URL and
payload features), so one malware family's requests share a fingerprint whatever server they go to: under the
simulated Internet the requests are still the sample's own. hfinger (GPL-3.0) runs as its own program over
tshark; only the JSON it prints is read here.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections import Counter

MAX_REQUESTS = 300
MODE = "2"  # hfinger's default report mode: the paper's optimum of collisions against fingerprints


def available() -> bool:
    return shutil.which("hfinger") is not None and shutil.which("tshark") is not None


def analyze_pcap(path: str, timeout_s: float, preexec=None) -> tuple[dict, list[dict]]:
    if not available():
        raise RuntimeError("hfinger or tshark is not installed")
    proc = subprocess.run(
        ["hfinger", "-f", path, "-m", MODE],
        capture_output=True,
        timeout=max(10.0, timeout_s),
        # tshark wants a writable home for its profile directory; /tmp is the container's only writable place
        env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": "/tmp",
             "PYTHONDONTWRITEBYTECODE": "1"},
        preexec_fn=preexec,
        stdin=subprocess.DEVNULL,
    )
    text = proc.stdout.decode("utf-8", "replace").strip()
    rows = json.loads(text) if text else []
    if not isinstance(rows, list):
        raise ValueError("unexpected hfinger output")
    requests = []
    for row in rows[:MAX_REQUESTS]:
        if not isinstance(row, dict) or not row.get("fingerprint"):
            continue
        try:
            time = round(float(row.get("epoch_time") or 0), 3)
        except ValueError:
            time = None
        requests.append({
            "time": time,
            "src": str(row.get("ip_src", ""))[:64],
            "dst": str(row.get("ip_dst", ""))[:64],
            "sport": str(row.get("port_src", ""))[:8],
            "dport": str(row.get("port_dst", ""))[:8],
            "fingerprint": str(row["fingerprint"])[:512],
        })
    if proc.returncode != 0 and not requests:
        raise RuntimeError(f"hfinger exited {proc.returncode}: {proc.stderr.decode('utf-8', 'replace')[-200:]}")
    counts = Counter(r["fingerprint"] for r in requests)
    doc = {
        "tool": "hfinger",
        "mode": int(MODE),
        "http_fingerprints": requests,
        "fingerprints": [{"fingerprint": f, "count": n} for f, n in counts.most_common()],
        "truncated": len(rows) > MAX_REQUESTS,
    }
    return doc, []
