"""MobSF Android dynamic analysis driver. Runs inside the MobSF container in the mobile VM, never on the host.

    python3 driver.py <sample> <run seconds> <device ip:port> <upload name> <deadline seconds>

Starts MobSF's server, waits for the Android guest's adbd, uploads and scans the app (MobSF's dynamic analyzer
needs its own static scan), then runs MobSF's dynamic analysis: install, Frida (API monitor, SSL pinning, root
and debugger check bypasses, emulator and adb detection bypasses), the exported-activity tester, a monkey run,
and screenshots while the app runs. Prints one JSON envelope on stdout: MobSF's dynamic report, a bounded
logcat, screenshots and a log of each step. Uses only the standard library and the image's requests.
"""

import base64
import json
import os
import subprocess
import sys
import time

import requests

BASE = "http://127.0.0.1:8000"
UPLOADS = os.path.join(os.path.expanduser("~"), ".MobSF", "uploads")
FRIDA_OTHERS = (
    "/home/mobsf/Mobile-Security-Framework-MobSF/mobsf/DynamicAnalyzer/tools/"
    "frida_scripts/android/others"
)
DEFAULT_HOOKS = "api_monitor,ssl_pinning_bypass,root_bypass,debugger_check_bypass"
EXTRA_SCRIPTS = ("bypass-emulator-detection.js", "bypass-adb-detection.js")
MAX_SCREENSHOTS = 12
MAX_SCREENSHOT_BYTES = 1536 * 1024
MAX_LOG_BYTES = 2 * 1024 * 1024
SCREENSHOT_EVERY_S = 20
MONKEY_THROTTLE_MS = 700


def run(argv, out):
    sample, run_s, device, upload_name, total_s = argv[1:6]
    run_s, deadline = float(run_s), time.time() + float(total_s)
    auth = {"Authorization": os.environ["MOBSF_API_KEY"]}
    steps, shots = out.setdefault("steps", []), out.setdefault("screenshots", [])
    out["device"] = device

    def left():
        return max(10.0, deadline - time.time())

    def step(name, ok, detail=""):
        steps.append(
            {
                "name": name,
                "ok": bool(ok),
                "t": round(time.time(), 1),
                "detail": str(detail)[:500],
            }
        )

    def adb(*args, timeout=60):
        return subprocess.run(
            ["adb", "-s", device, *args], capture_output=True, timeout=timeout
        )

    def post(path, **data):
        resp = requests.post(BASE + path, headers=auth, data=data, timeout=left())
        try:
            body = resp.json()
        except ValueError:
            body = {"text": resp.text[:500]}
        return resp.status_code < 400, body

    def screenshot(label):
        if len(shots) >= MAX_SCREENSHOTS:
            return
        try:
            png = adb("exec-out", "screencap", "-p", timeout=30).stdout
        except subprocess.SubprocessError:
            return
        if png.startswith(b"\x89PNG") and len(png) <= MAX_SCREENSHOT_BYTES:
            shots.append(
                {
                    "label": label,
                    "t": round(time.time(), 1),
                    "png": base64.b64encode(png).decode(),
                }
            )

    # 1. MobSF's server (started by the container command) and the guest's adbd.
    while True:
        try:
            resp = requests.get(BASE + "/api/v1/scans", headers=auth, timeout=5)
            if resp.status_code < 500:
                break
        except requests.RequestException:
            pass
        if time.time() > deadline:
            step("mobsf_start", False, "MobSF did not start in time")
            return
        time.sleep(2)
    step("mobsf_start", True)
    booted = False
    while time.time() < deadline - run_s:
        subprocess.run(["adb", "connect", device], capture_output=True, timeout=30)
        try:
            prop = adb("shell", "getprop", "sys.boot_completed", timeout=15).stdout
            booted = prop.strip() == b"1"
        except subprocess.SubprocessError:
            booted = False
        if booted:
            break
        time.sleep(3)
    step("device_boot", booted, device)
    if not booted:
        return
    out["device_props"] = {
        key: adb("shell", "getprop", key, timeout=15)
        .stdout.decode("utf-8", "replace")
        .strip()
        for key in (
            "ro.build.version.release",
            "ro.build.version.sdk",
            "ro.product.cpu.abi",
        )
    }

    # 2. The static scan in this MobSF instance, where its dynamic analyzer reads the package and activities.
    with open(sample, "rb") as fh:
        up = requests.post(
            BASE + "/api/v1/upload",
            headers=auth,
            timeout=left(),
            files={"file": (upload_name, fh, "application/octet-stream")},
        )
    if up.status_code >= 400:
        step("upload", False, up.text)
        return
    digest = up.json()["hash"]
    out["mobsf_hash"] = digest
    ok, body = post("/api/v1/scan", hash=digest)
    step("static_scan", ok, "" if ok else body)
    if not ok:
        return
    package = body.get("package_name")
    out["package"] = package

    # 3. MobSFy (frida-server, CA), install, proxy through adb reverse to MobSF's httptools, Frida hooks.
    ok, body = post("/api/v1/dynamic/start_analysis", hash=digest)
    step("start_analysis", ok, "" if ok else body)
    if not ok:
        return
    extra = []
    for name in EXTRA_SCRIPTS:
        try:
            with open(os.path.join(FRIDA_OTHERS, name), encoding="utf-8") as fh:
                extra.append(fh.read())
        except OSError:
            pass
    ok, body = post(
        "/api/v1/frida/instrument",
        hash=digest,
        default_hooks=DEFAULT_HOOKS,
        auxiliary_hooks="",
        frida_code="\n".join(extra),
        frida_action="spawn",
    )
    step("frida_instrument", ok, "" if ok else body)
    time.sleep(8)
    try:
        ps = adb("shell", "ps", "-A", "-o", "PID,NAME", timeout=20).stdout
        names = ps.decode("utf-8", "replace").split()
        step("frida_server", "fd_server" in names, "")
        step("app_running", bool(package) and package in names, package or "")
    except subprocess.SubprocessError as exc:
        step("frida_server", False, exc)
    screenshot("launch")

    # 4. Exercise the app: exported activities, then random UI events, until the run time is used up.
    started = time.time()
    ok, body = post("/api/v1/android/activity", hash=digest, test="exported")
    step("exported_activities", ok, "" if ok else body)
    screenshot("exported activities")
    if package:
        # Up to half the run (at most 4 min) of taps, one every 700 ms, with slack for monkey's own start-up.
        budget = max(30, min(240, run_s / 2))
        try:
            r = adb(
                "shell",
                "monkey",
                "-p",
                package,
                "--throttle",
                str(MONKEY_THROTTLE_MS),
                "--pct-syskeys",
                "0",
                "-v",
                str(int(budget * 1000 / MONKEY_THROTTLE_MS * 0.8)),
                timeout=budget + 30,
            )
            step(
                "monkey", r.returncode == 0, r.stderr.decode("utf-8", "replace")[-300:]
            )
        except subprocess.SubprocessError as exc:
            step("monkey", False, exc)
    while time.time() - started < run_s and time.time() < deadline - 120:
        screenshot("running")
        time.sleep(min(SCREENSHOT_EVERY_S, max(1, run_s - (time.time() - started))))
    ok, body = post("/api/v1/frida/api_monitor", hash=digest)
    out["api_monitor"] = body.get("data") if ok else None
    step("api_monitor", ok, "" if ok else body)

    # 5. Stop (collects logcat, dumpsys and the app's data directory), then MobSF's dynamic report.
    ok, body = post("/api/v1/dynamic/stop_analysis", hash=digest)
    step("stop_analysis", ok, "" if ok else body)
    ok, body = post("/api/v1/dynamic/report_json", hash=digest)
    step("report", ok, "" if ok else body)
    if ok:
        out["report"] = body
    try:
        with open(os.path.join(UPLOADS, digest, "logcat.txt"), "rb") as fh:
            out["logcat"] = fh.read()[-MAX_LOG_BYTES:].decode("utf-8", "replace")
    except OSError:
        pass


if __name__ == "__main__":
    envelope = {}
    try:
        run(sys.argv, envelope)
    except Exception as exc:  # report, never die: the host reads whatever was collected
        envelope["error"] = f"{type(exc).__name__}: {exc}"[:500]
    sys.stdout.write(json.dumps(envelope))
