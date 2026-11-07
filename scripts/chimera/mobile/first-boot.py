#!/usr/bin/env python3
"""Boot the Android base disk once, configure it, and turn it into the golden image.

    sudo /opt/chimera/venv/bin/python scripts/chimera/mobile/first-boot.py

Run after build-android-image.sh. Android builds /data on this first boot; over the serial console (a root shell
on userdebug builds, used only here, never during an analysis) this script then:
  - skips the setup wizard, the lock screen and the launcher chooser, keeps the screen on, turns animations and
    the package verifier off;
  - trusts the adb key MobSF uses (/data/misc/adb/adb_keys);
  - joins the "VirtWifi" network: Android-x86 9 wraps the NIC as a virtual Wi-Fi, so apps see a phone on Wi-Fi
    rather than Ethernet. The saved network makes every later boot connect by itself;
then powers off cleanly and writes android-golden.qcow2. The guest sits on the mobile drakrun network (INetSim
only) while this runs, so the Wi-Fi join is checked against a real DHCP lease.
"""

import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

from drakrun.lib.config import load_config
from drakrun.lib.networking import start_vm_network, stop_vm_network

STORE = Path(load_config().mobile.store)
BASE, GOLDEN = STORE / "android-base.img", STORE / "android-golden.qcow2"
SOCK, CFG = STORE / "first-boot.sock", STORE / "first-boot.cfg"
NAME = "chimera-android-build"
CFG_TEXT = """\
name = "{name}"
type = "hvm"
memory = 3072
maxmem = 3072
vcpus = 2
kernel = "{store}/android-kernel"
ramdisk = "{store}/android-initrd.img"
cmdline = "root=/dev/ram0 androidboot.selinux=permissive buildvariant=userdebug SRC=/android-9.0-r2 \
console=ttyS0 androidboot.console=ttyS0"
disk = [ "format=raw,vdev=hda,access=rw,backendtype=qdisk,target={base}" ]
vif = [ "type=ioemu,model=e1000,mac=00:1b:21:4d:7e:09,bridge={bridge}" ]
xen_platform_pci = 0
viridian = 0
vga = "stdvga"
videoram = 16
usb = 1
usbdevice = "tablet"
vnc = 1
vnclisten = "127.0.0.1:9"
serial = [ "unix:{sock},server,nowait" ]
on_poweroff = "destroy"
on_reboot = "destroy"
on_crash = "destroy"
"""
SETTINGS = [
    "settings put global device_provisioned 1",
    "settings put secure user_setup_complete 1",
    "pm disable com.google.android.setupwizard",
    "pm disable com.farmerbb.taskbar.androidx86",
    "pm disable org.android_x86.analytics",
    "cmd package set-home-activity com.android.launcher3/.Launcher",
    "settings put global stay_on_while_plugged_in 7",
    "settings put system screen_off_timeout 2147483647",
    "locksettings set-disabled true",
    "settings put global package_verifier_enable 0",
    "settings put global verifier_verify_adb_installs 0",
    "settings put global window_animation_scale 0",
    "settings put global transition_animation_scale 0",
    "settings put global animator_duration_scale 0",
]
VIRTWIFI_ROW = (217, 182)  # "VirtWifi" in Settings > Wi-Fi at the guest's 1024x768


class Console:
    """The guest's serial console shell. Each command ends with a unique marker so its output is complete."""

    def __init__(self, path: Path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(str(path))
        self.sock.settimeout(0.5)

    def _read(self, seconds: float) -> bytes:
        end, buf = time.time() + seconds, b""
        while time.time() < end:
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not data:
                break
            buf += data
        return buf

    def run(self, command: str, timeout: float = 30) -> str:
        self._read(0.3)
        tag = f"END{uuid.uuid4().hex[:8]}"
        self.sock.sendall(f"\n{command}; echo {tag}\n".encode())
        buf, end = b"", time.time() + timeout
        while time.time() < end:
            buf += self._read(0.5)
            text = buf.decode("utf-8", "replace").replace("\r", "")
            if f"\n{tag}\n" in text:
                return text.split(f"\n{tag}\n")[0].rsplit(f"echo {tag}", 1)[-1]
        raise TimeoutError(f"no answer to {command!r}")


def xl(*args, check=True):
    return subprocess.run(["xl", *args], capture_output=True, text=True, check=check)


def main() -> int:
    config = load_config()
    if not BASE.is_file():
        sys.exit(f"{BASE} is missing: run build-android-image.sh first")
    network = start_vm_network(config.mobile.vm_id, config.network)
    try:
        CFG.write_text(
            CFG_TEXT.format(
                name=NAME,
                store=STORE,
                base=BASE,
                bridge=network.bridge_name,
                sock=SOCK,
            )
        )
        xl("create", str(CFG))
        time.sleep(5)
        console = Console(SOCK)
        deadline = time.time() + 600
        while True:
            try:  # the console shell starts a few seconds into the boot
                if console.run("getprop sys.boot_completed", 15).strip() == "1":
                    break
            except TimeoutError:
                pass
            if time.time() > deadline:
                sys.exit("Android did not finish booting in 10 minutes")
            time.sleep(5)
        print("booted; configuring")
        console.run("; ".join(SETTINGS), 120)
        key = (STORE / "adbkey.pub").read_text().split()[0]
        console.run(
            "mkdir -p /data/misc/adb"
            f" && echo '{key}' > /data/misc/adb/adb_keys"
            " && chown system:shell /data/misc/adb/adb_keys"
            " && chmod 640 /data/misc/adb/adb_keys"
        )
        console.run("svc wifi enable; sleep 5; am start -a android.settings.WIFI_SETTINGS")
        time.sleep(8)
        address = ""
        for _ in range(6):
            console.run(f"input tap {VIRTWIFI_ROW[0]} {VIRTWIFI_ROW[1]}")
            time.sleep(10)
            address = console.run(
                "ip -4 addr show wlan0 | grep -o 'inet [0-9.]*'"
            ).strip()
            if address:
                break
        if not address:
            sys.exit("Android did not get a DHCP lease on VirtWifi")
        print(f"VirtWifi: {address}")
        console.run("input keyevent KEYCODE_HOME; sync")
        console.run("reboot -p", 10)
        for _ in range(60):
            if xl("domid", NAME, check=False).returncode != 0:
                break
            time.sleep(2)
        else:
            sys.exit("Android did not power off; golden image not written")
    finally:
        if xl("domid", NAME, check=False).returncode == 0:
            xl("destroy", NAME, check=False)
        stop_vm_network(config.mobile.vm_id)
    GOLDEN.unlink(missing_ok=True)
    subprocess.run(
        ["qemu-img", "convert", "-O", "qcow2", str(BASE), str(GOLDEN)], check=True
    )
    GOLDEN.chmod(0o444)
    print(f"wrote {GOLDEN}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
