"""Android dynamic analysis, dom0's side: one network, two domains, one MobSF job.

    drak<vm_id> (drakrun network: dnsmasq, INetSim as DNS, CHIMERA_GUARD lets it reach INetSim only)
      ├─ chimera-android  Android-x86 9.0 HVM guest, a throwaway qcow2 overlay of the golden image, 10.13.N.2
      └─ chimera-mobile   the static VM image booted with chimera.role=mobile and one NIC, 10.13.N.3

dom0 never talks to either guest over the network. It hands the mobile VM one job through the static VM's
disk protocol (vm_backend.write_job_disk / read_result_disk): a podman step that starts MobSF in the VM's
host network and runs driver.py, which reaches the Android guest's adbd on the bridge and drives MobSF's dynamic
analyzer. Both domains and the overlay are destroyed afterwards, whatever happened; tcpdump on the bridge keeps
the run's traffic as dump.pcap, as for Windows and Linux runs.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import secrets
import subprocess
import time
import uuid
from pathlib import Path
from typing import Optional

from drakrun.analyzer.static import vm_backend
from drakrun.lib.config import load_config
from drakrun.lib.memory_admission import memory_admission, xen_free_memory_mb
from drakrun.lib.networking import (
    start_tcpdump_collector,
    start_vm_network,
    stop_vm_network,
)

logger = logging.getLogger(__name__)

ANDROID_DOMAIN = "chimera-android"
MOBILE_DOMAIN = "chimera-mobile"
ANDROID_SRC = "android-9.0-r2"
GOLDEN = "android-golden.qcow2"
STATIC_VM_DIR = Path("/var/lib/chimera-static-vm")
ADB_PORT = 5555
MOBSF_UID = 9901
DRIVER = Path(__file__).with_name("driver.py")
ANDROID_MAC = "00:1b:21:4d:7e:09"  # Intel OUI, as the Windows guests
MOBILE_MAC = "00:16:3e:4d:7e:0a"
VNC_DISPLAY = 9
STATIC_IDLE_FOR_MOBILE_S = (
    30  # an idle static VM is stopped this soon when an Android run needs its memory
)
ADMISSION_RETRY_S = 60

ANDROID_CFG = """\
# CHIMERA Android guest (generated per run by drakrun/analyzer/mobile/runner.py)
name = "{name}"
type = "hvm"
memory = {memory}
maxmem = {memory}
vcpus = {vcpus}
kernel = "{store}/android-kernel"
ramdisk = "{store}/android-initrd.img"
cmdline = "root=/dev/ram0 androidboot.selinux=permissive buildvariant=userdebug SRC=/{src} quiet"
disk = [ "format=qcow2,vdev=hda,access=rw,backendtype=qdisk,target={overlay}" ]
vif = [ "type=ioemu,model=e1000,mac={mac},bridge={bridge}" ]
xen_platform_pci = 0
viridian = 0
vga = "stdvga"
videoram = 16
usb = 1
usbdevice = "tablet"
vnc = 1
vnclisten = "127.0.0.1:{vnc}"
on_poweroff = "destroy"
on_reboot = "destroy"
on_crash = "destroy"
"""

MOBILE_CFG = """\
# CHIMERA mobile VM: the static VM image with one NIC (generated per run by drakrun/analyzer/mobile/runner.py)
name = "{name}"
type = "pvh"
kernel = "{static}/vmlinuz"
ramdisk = "{static}/initrd.img"
cmdline = "root=/dev/xvda ro console=hvc0 quiet systemd.show_status=0 panic=10 chimera.role=mobile net.ifnames=0 \
ip={ip}::{gw}:255.255.255.0::eth0:off"
memory = {memory}
maxmem = {memory}
vcpus = 2
vif = [ "mac={mac},bridge={bridge}" ]
disk = [
    "format=raw,vdev=xvda,access=ro,backendtype=phy,target={static}/root.img",
    "format=raw,vdev=xvde,access=rw,backendtype=phy,target={scratch}",
]
on_poweroff = "destroy"
on_reboot = "destroy"
on_crash = "destroy"
"""


class MobileUnavailable(RuntimeError):
    pass


class _VmSettings:
    """What vm_backend's disk helpers need to address the mobile VM instead of the static one."""

    def __init__(self, name: str):
        self.vm_name = name


def addresses(vm_id: int) -> tuple[str, str, str]:
    """Gateway (dom0's bridge address), Android guest (dnsmasq's one lease) and mobile VM addresses."""
    prefix = f"10.13.{vm_id}"
    return f"{prefix}.1", f"{prefix}.2", f"{prefix}.3"


def android_cfg(settings, overlay: Path, bridge: str) -> str:
    return ANDROID_CFG.format(
        name=ANDROID_DOMAIN,
        memory=settings.android_memory_mb,
        vcpus=settings.android_vcpus,
        store=settings.store,
        src=ANDROID_SRC,
        overlay=overlay,
        mac=ANDROID_MAC,
        bridge=bridge,
        vnc=VNC_DISPLAY,
    )


def mobile_cfg(settings, scratch: Path, bridge: str) -> str:
    gateway, _, address = addresses(settings.vm_id)
    return MOBILE_CFG.format(
        name=MOBILE_DOMAIN,
        static=STATIC_VM_DIR,
        ip=address,
        gw=gateway,
        memory=settings.mobsf_vm_memory_mb,
        mac=MOBILE_MAC,
        bridge=bridge,
        scratch=scratch,
    )


def podman_step(
    settings, analysis_id: str, run_s: int, total_s: int, upload_name: str, gid: int
) -> dict:
    """The one step the mobile VM's agent runs: MobSF in the VM's host network (the VM is the boundary),
    otherwise with the static MobSF step's flags; driver.py's envelope lands in out/mobile.json.
    """
    _, android, _ = addresses(settings.vm_id)
    memory = f"{settings.mobsf_container_memory_mb}m"
    work = vm_backend.GUEST_WORK
    name = f"chimera-mobile-{analysis_id}"
    argv = [
        "podman", "run", "--rm", "--name", name,
        "--network", "host",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "2048",
        "--memory", memory, "--memory-swap", memory,
        "--cpus", "2",
        "--ulimit", "core=0",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=512m",
        "--user", f"{MOBSF_UID}:{MOBSF_UID}",
        "--group-add", str(gid),
        "--volume", f"{work / 'in'}:/input:ro,noexec,nosuid,nodev",
        "--volume", f"{work / 'out'}:/out:rw,noexec,nosuid,nodev",
        "--volume", f"{work / 'android'}:/home/mobsf/.android:rw,noexec,nosuid,nodev",
        "--volume", f"{work / 'resolv.conf'}:/etc/resolv.conf:ro",
        "--volume", f"{work / 'driver.py'}:/job/driver.py:ro",
        "--env", f"MOBSF_API_KEY={secrets.token_hex(32)}",
        "--env", f"MOBSF_ANALYZER_IDENTIFIER={android}:{ADB_PORT}",
        "--entrypoint", "/bin/sh",
        settings.mobsf_image,
        "-c",
        # MobSF holds each Frida session open on sys.stdin.read() (upstream runs it with -it): an open pipe,
        # not the /dev/null a background job gets, or the hooks unload as soon as they load.
        'sleep infinity | scripts/entrypoint.sh >/out/mobsf.log 2>&1 &'
        ' python3 /job/driver.py "$@" > /out/mobile.json',
        "chimera-mobile",
        "/input/sample", str(run_s), f"{android}:{ADB_PORT}", upload_name, str(total_s),
    ]  # fmt: skip
    store = Path(settings.store)
    return {
        "name": "mobsf-dynamic",
        "container": name,
        "argv": argv,
        "timeout_s": total_s + 60,
        "outputs": ["out/mobile.json", "out/mobsf.log"],
        "prepare": {
            "dirs": ["out", "android"],
            "files": {
                "driver.py": DRIVER.read_text(encoding="utf-8"),
                "resolv.conf": "nameserver 10.99.0.2\n",
                "android/adbkey": (store / "adbkey").read_text(encoding="utf-8"),
                "android/adbkey.pub": (store / "adbkey.pub").read_text(
                    encoding="utf-8"
                ),
            },
        },
    }


def _xl(*args, timeout=120, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["xl", *args], capture_output=True, text=True, timeout=timeout, check=check
    )


def _destroy(name: str) -> None:
    if vm_backend.domid(name) is not None:
        _xl("destroy", name, check=False)


def _create(cfg_text: str, path: Path) -> None:
    path.write_text(cfg_text, encoding="utf-8")
    _xl("create", str(path))


def _start_domains(config, overlay: Path, scratch: Path, bridge: str, workdir: Path):
    """Create both domains under memory admission. The static VM boots on demand outside admission (an Android
    upload's own static scan starts it), so it can take the memory between the check and the second create:
    then both are destroyed and admission runs again. While memory is short and the static VM sits idle, it
    is stopped early; its next job boots it again."""
    settings = config.mobile
    needed = settings.android_memory_mb + settings.mobsf_vm_memory_mb
    deadline = time.monotonic() + config.worker.memory_admission_timeout
    worker = config.worker.model_copy(
        update={"memory_admission_timeout": ADMISSION_RETRY_S}
    )
    while True:
        try:
            if xen_free_memory_mb() < needed + config.worker.memory_admission_margin_mb:
                vm_backend.stop_if_idle(config.static, idle_s=STATIC_IDLE_FOR_MOBILE_S)
            with memory_admission(needed, worker):
                _destroy(ANDROID_DOMAIN)
                _destroy(MOBILE_DOMAIN)
                _create(android_cfg(settings, overlay, bridge), workdir / "android.cfg")
                _create(mobile_cfg(settings, scratch, bridge), workdir / "mobile.cfg")
                return
        except (TimeoutError, subprocess.CalledProcessError) as exc:
            _destroy(MOBILE_DOMAIN)
            _destroy(ANDROID_DOMAIN)
            detail = getattr(exc, "stderr", None) or str(exc)
            detail = detail.strip().splitlines()[-1][:300] if detail.strip() else ""
            if time.monotonic() >= deadline:
                raise MobileUnavailable(f"the Android guests could not start: {detail}")
            logger.info("Android guests not started yet (%s); trying again", detail)
            time.sleep(10)


def _wait_ready(name: str, timeout_s: float) -> int:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        dom = vm_backend.domid(name)
        if dom is None:
            raise MobileUnavailable(f"{name} stopped while booting")
        if vm_backend.xs_read(dom, "ready") == "1":
            return dom
        time.sleep(1)
    raise MobileUnavailable(f"{name} did not become ready in {timeout_s:.0f}s")


def _job(settings, dom: int, step: dict, sample: Path, gid: int, workdir: Path) -> dict:
    vm = _VmSettings(MOBILE_DOMAIN)
    job_id = uuid.uuid4().hex
    digest = hashlib.sha256()
    with sample.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            digest.update(chunk)
    spec = {
        "job": job_id,
        "sample_size": sample.stat().st_size,
        "sample_sha256": digest.hexdigest(),
        "uid": MOBSF_UID,
        "gid": gid,
        "steps": [step],
    }
    job_disk, result_disk = workdir / "job.img", workdir / "result.img"
    vm_backend.write_job_disk(job_disk, spec, sample)
    fd = os.open(
        result_disk, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    os.ftruncate(fd, settings.result_disk_mb << 20)
    os.close(fd)
    vm_backend._attach(vm, vm_backend.JOB_DISK, job_disk, "ro")
    vm_backend._attach(vm, vm_backend.RESULT_DISK, result_disk, "rw")
    vm_backend.xs_write(dom, "request", job_id)
    deadline = time.monotonic() + float(step["timeout_s"]) + vm_backend.JOB_SLACK_S
    while vm_backend.xs_read(dom, "done") != job_id:
        if time.monotonic() > deadline:
            return {"error": "mobile VM job timed out"}
        if vm_backend.domid(MOBILE_DOMAIN) != dom:
            return {"error": "mobile VM stopped during the job"}
        time.sleep(0.5)
    vm_backend._detach(vm, vm_backend.JOB_DISK)
    vm_backend._detach(vm, vm_backend.RESULT_DISK)
    return vm_backend.read_result_disk(result_disk, settings.result_disk_mb << 20)


def run_dynamic(
    analysis_id: str,
    sample: Path,
    upload_name: str,
    outdir: Path,
    run_s: Optional[int] = None,
) -> dict:
    """Run one APK; return the mobile VM's envelope (or {"error": ...}). dump.pcap is written to outdir."""
    config = load_config()
    settings = config.mobile
    run_s = int(run_s or settings.default_run_s)
    total_s = run_s + settings.overhead_s
    store = Path(settings.store)
    golden = store / GOLDEN
    if not golden.is_file() or not (STATIC_VM_DIR / "root.img").is_file():
        raise MobileUnavailable(
            "the Android golden image or the static VM image is missing"
        )
    workdir = store / "runs" / str(uuid.UUID(analysis_id))
    workdir.mkdir(mode=0o700, parents=True)
    overlay, scratch = workdir / "android.qcow2", store / "scratch.img"
    if not scratch.exists():
        subprocess.run(["truncate", "-s", "8G", str(scratch)], check=True)
    gid = config.static.container_gid
    tcpdump = None
    try:
        network = start_vm_network(settings.vm_id, config.network)
        # adb between the two guests (frida-server push, screenshots) is the lab's own traffic; the app's
        # proxied HTTP(S) leaves the mobile VM through mitmproxy towards INetSim, so it stays in the capture
        _, android, mobile = addresses(settings.vm_id)
        tcpdump = start_tcpdump_collector(
            network.bridge_name,
            outdir / "dump.pcap",
            f"not (host {android} and host {mobile})",
        )
        subprocess.run(
            ["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2"]
            + ["-b", str(golden), str(overlay)],
            check=True,
            timeout=60,
        )
        _start_domains(config, overlay, scratch, network.bridge_name, workdir)
        dom = _wait_ready(MOBILE_DOMAIN, settings.vm_boot_timeout_s)
        step = podman_step(settings, analysis_id, run_s, total_s, upload_name, gid)
        return _job(settings, dom, step, sample, gid, workdir)
    finally:
        _destroy(MOBILE_DOMAIN)
        _destroy(ANDROID_DOMAIN)
        if tcpdump is not None:
            tcpdump.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                tcpdump.wait(10)
        with contextlib.suppress(Exception):
            stop_vm_network(settings.vm_id)
        for path in workdir.iterdir():
            with contextlib.suppress(OSError):
                path.unlink()
        with contextlib.suppress(OSError):
            workdir.rmdir()
