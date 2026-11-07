# Android dynamic analysis

An Android app uploaded in **Combined** mode is analysed twice: statically (MobSF in the network-less static VM,
see [static-analysis.md](static-analysis.md)) and dynamically, by running it in an Android guest under Xen with
MobSF's dynamic analyzer and Frida. iOS apps stay static only (see [iOS](#ios) below).

## Why it looks like this

dom0 is itself a Xen guest, so there is no `/dev/kvm`: the Android emulator, Genymotion and Cuttlefish cannot run.
The guest is **Android-x86 9.0-r2** (API 28, x86_64, userdebug) as a Xen HVM domain, booted directly from the
ISO's kernel and initrd. API 28 is inside MobSF's supported range (≤ 30), and the userdebug build gives `adb root`
and a writable `/system`, which MobSF needs to install its CA and frida-server.

## Layout of one run

```
drak9 bridge (drakrun network vm_id 9, 10.13.9.0/24; dnsmasq; DNS and every connection go to INetSim only)
  ├─ chimera-android  Android-x86 HVM guest, a throwaway qcow2 overlay of android-golden.qcow2, 10.13.9.2
  └─ chimera-mobile   the static VM's root.img (read-only) booted with chimera.role=mobile, 10.13.9.3
       └─ podman (host network of the VM, --cap-drop ALL, no-new-privileges, memory/PID caps)
            MobSF 4.5.3 + frida-server 17.18.0 + mitmproxy CA, driven by driver.py
```

- dom0 never talks to either guest over the network. It hands the mobile VM one job through the static VM's
  disk protocol (job disk, result disk, xenstore signals), exactly as for static analysis.
- The mobile VM uses the same image as the static VM. systemd-networkd only starts there when the kernel command
  line has `chimera.role=mobile`, so the static VM keeps no network.
- CHIMERA_GUARD lets the bridge reach INetSim only. MobSF's proxy reaches the guest through `adb reverse`, so
  the app's HTTP(S) goes through mitmproxy and then to INetSim.
- `tcpdump` on the bridge stores the run's traffic as the analysis's `dump.pcap`, minus the adb traffic between
  the two guests. The app's proxied HTTP(S) appears there as mitmproxy's connections from 10.13.9.3 to INetSim;
  anything the app sends around the proxy comes from 10.13.9.2.
- Both domains, the overlay and the network are destroyed after every run, whatever happened.
- Memory admission reserves Android 3072 MB plus the mobile VM 3584 MB before either starts. That does not fit
  beside the static VM (3584 MB) on a 16 GB host, and the upload's own static scan boots it, so while memory is
  short the run stops the static VM once it has been idle for 30 s (its next job boots it again). The static VM
  starts outside admission: if it takes the memory between the check and the second create, both Android-side
  domains are destroyed and admission runs again.

## What the run does

`drakrun/analyzer/mobile/driver.py`, inside the container:

1. Starts MobSF, waits for the guest's adbd (`10.13.9.2:5555`, key in `/var/lib/chimera-mobile/adbkey`).
2. Uploads the APK and runs MobSF's static scan (its dynamic analyzer needs it).
3. `start_analysis`: installs the app, frida-server and the CA, sets the proxy.
4. Frida, spawn mode: API monitor, SSL-pinning, root and debugger-check bypasses, emulator- and adb-detection
   bypasses.
5. Exported-activity tester, then `monkey` taps for up to half the run (at most 4 minutes), screenshots every
   20 s until the run time (60–1800 s, default `[mobile] default_run_s` = 180) is used up.
6. Reads the API monitor, stops the analysis (logcat, dumpsys, the app's data directory) and fetches MobSF's
   dynamic report.

The worker stores `mobile-dynamic.json` (schema `chimera-mobile-dynamic/1`) and `mobile-screens/NN.png` next to
the analysis. The console's **Android dynamic** tab shows the run steps, screenshots, domains, URLs, Frida API
calls, files the app wrote and the logcat tail, with a link to the PCAP. `GET /api/mobile/<id>` returns the JSON;
it says `queued` or `running` until the run ends.

## Build

```bash
# 1. Android disk from the ISO (md5 checked); adb key generated in a network-less container
sudo scripts/chimera/mobile/build-android-image.sh /var/lib/chimera-mobile/downloads/android-x86_64-9.0-r2.iso
# 2. first boot over the serial console: skip setup, trust the adb key, join VirtWifi, write the golden image
sudo PYTHONPATH=. /opt/chimera/venv/bin/python scripts/chimera/mobile/first-boot.py
# 3. MobSF image with the verified frida-server and the mitmproxy CA baked in
sudo scripts/chimera/mobile/build-mobsf-dynamic.sh
# 4. static VM image with the dynamic MobSF image and the mobile-role networkd drop-ins
sudo scripts/chimera/static-vm/build-image.sh --images
```

Android-x86 9 presents its NIC as a virtual Wi-Fi network called **VirtWifi**; `first-boot.py` joins it once and
the saved network connects on every later boot.

Then enable it:

```toml
# /etc/drakrun/config.toml
[mobile]
enabled = true
```

```bash
sudo cp scripts/chimera/systemd/drakrun-mobile-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now drakrun-mobile-worker
sudo systemctl restart drakrun-web
```

All `[mobile]` settings are in `drakrun/lib/config.py` (`MobileConfigSection`): memory of each domain, the
container's memory cap, run-time limits, the boot timeout and the result-disk size.

## Limits

- Android 9 x86_64. Apps that ship only ARM native libraries do not install or crash at start (no ARM
  translation in the image). Apps that need Google Play services find none.
- One Android run at a time (one bridge, one guest name). Runs queue on `chimera-mobile`.
- MobSF's dynamic analyzer drives the app generically (exported activities, random taps). Behaviour behind a
  login or a specific user flow may not be reached.
- The classifier does not score mobile apps.

## iOS

iOS apps cannot be run under Xen: there is no iOS for x86, and MobSF's iOS dynamic analyzer needs Corellium
virtual devices. That path is planned as an opt-in cloud option (the app leaves the host and goes to Corellium)
and needs a Corellium account and API key. Until then iOS apps get MobSF's static analysis only.
