"""malduck config extraction and hfinger HTTP fingerprints (CERT Polska tools, run as separate programs)."""

import pathlib
import shutil
import struct

import pytest

from chimera_static.analyze import analyze
from chimera_static.identify import identify
from chimera_static.plugins import malware_config
from chimera_static.plugins.pcap import analyze_pcap

# What `malduck extract` prints for one config (synthetic values; the layout is malduck's)
MALDUCK_OUTPUT = """[+] Ripped 'remcos' from sample
{
    "family": "remcos",
    "c2": [
        {"host": "c2.example.test:2404", "password": "0"}
    ],
    "mutex": "Rmc-TEST01",
    "raw_cfg": {"in-blob": "deadbeef"},
    "urls": ["http://drop.example.test/a.bin"]
}
noise line
{
    "not_a_config": true
}
"""


def test_parse_output_keeps_only_family_blocks():
    configs = malware_config.parse_output(MALDUCK_OUTPUT)
    assert [c["family"] for c in configs] == ["remcos"]


def test_summarize_finds_c2_and_drops_raw_blobs():
    doc = malware_config.summarize(malware_config.parse_output(MALDUCK_OUTPUT)[0])
    assert doc["family"] == "remcos"
    assert "c2.example.test:2404" in doc["c2"]
    assert "http://drop.example.test/a.bin" in doc["c2"]
    assert doc["iocs"]["domains"] == ["c2.example.test", "drop.example.test"]
    assert doc["iocs"]["urls"] == ["http://drop.example.test/a.bin"]
    assert "raw_cfg" not in doc["fields"]
    assert doc["fields"]["mutex"] == "Rmc-TEST01"


def test_file_names_are_not_hosts():
    iocs = {"urls": set(), "domains": set(), "ips": set()}
    assert malware_config._endpoint("payload.exe", iocs) is None
    assert malware_config._endpoint("10.1.2.3:443", iocs) == "10.1.2.3:443"
    assert iocs["ips"] == {"10.1.2.3"}


def test_findings_are_high_with_c2_evidence():
    doc = malware_config.summarize(malware_config.parse_output(MALDUCK_OUTPUT)[0])
    (f,) = malware_config.findings([doc])
    assert f["severity"] == "high" and f["attack"] == ["T1071"] and "c2.example.test" in f["evidence"]


def test_documents_and_pcaps_skip_config_extraction():
    assert not malware_config.wanted("pdf")
    assert not malware_config.wanted("pcap")
    assert not malware_config.wanted("script:powershell")
    assert malware_config.wanted("pe") and malware_config.wanted("unknown")


def _pcap(payload: bytes) -> bytes:
    """One Ethernet/IPv4/TCP packet to port 80 carrying `payload` (tshark does not check checksums)."""
    tcp = struct.pack("!HHIIBBHHH", 49152, 80, 1, 0, 5 << 4, 0x18, 65535, 0, 0)
    ip_len = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 1, 0, 64, 6, 0,
                     bytes([10, 99, 0, 5]), bytes([10, 99, 0, 2]))
    frame = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + ip + tcp + payload
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    return header + struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)) + frame


HTTP = (b"GET /gate.php?id=1 HTTP/1.1\r\nHost: c2.example.test\r\nUser-Agent: Mozilla/4.0\r\n"
        b"Accept: */*\r\nConnection: close\r\n\r\n")


def test_pcap_is_identified():
    assert identify(_pcap(HTTP))["format"] == "pcap"


@pytest.mark.skipif(shutil.which("hfinger") is None or shutil.which("tshark") is None,
                    reason="hfinger/tshark only in the image")
def test_hfinger_fingerprints_an_http_request(tmp_path):
    path = tmp_path / "dump.pcap"
    path.write_bytes(_pcap(HTTP))
    doc, findings = analyze_pcap(str(path), 60)
    assert findings == []
    assert len(doc["http_fingerprints"]) == 1
    req = doc["http_fingerprints"][0]
    assert (req["src"], req["dst"], req["dport"]) == ("10.99.0.5", "10.99.0.2", "80")
    assert req["fingerprint"]
    assert doc["fingerprints"] == [{"fingerprint": req["fingerprint"], "count": 1}]


@pytest.mark.skipif(shutil.which("malduck") is None, reason="malduck only in the image")
def test_malduck_runs_on_a_clean_pe_without_configs():
    sample = pathlib.Path(__file__).parent / "fixtures" / "test.exe"
    r = analyze(str(sample), file_name="test.exe", ember=False, verify_signature=False)
    assert "malware_configs" not in r
    assert "malware_config" not in r.get("coverage", {}).get("failed_stages", [])


def _main(tmp_path, name, data):
    """The container's entry point, hardening included (the analyzer may start no process once hardened)."""
    import json
    import subprocess
    import sys

    sample, out = tmp_path / name, tmp_path / "out"
    sample.write_bytes(data)
    out.mkdir()
    proc = subprocess.run([sys.executable, "-I", "-m", "chimera_static", str(sample), str(out), "--name", name,
                           "--timeout", "60", "--no-ember"], capture_output=True, timeout=180)
    assert proc.returncode == 0, proc.stderr[-500:]
    return json.loads((out / "static.json").read_text())


def test_external_kind_reads_magic_only(tmp_path):
    from chimera_static.external import kind

    for name, data, want in (("a.pcap", _pcap(HTTP), "pcap"), ("a.pdf", b"%PDF-1.7\n", "skip"),
                             ("a.zip", b"PK\x03\x04rest", "skip"), ("a.bin", b"MZ\x90\x00", "binary"),
                             ("empty", b"", "skip")):
        (tmp_path / name).write_bytes(data)
        assert kind(str(tmp_path / name)) == want, name


@pytest.mark.skipif(shutil.which("hfinger") is None or shutil.which("tshark") is None,
                    reason="hfinger/tshark only in the image")
def test_hardened_entry_point_still_fingerprints_pcaps(tmp_path):
    r = _main(tmp_path, "dump.pcap", _pcap(HTTP))
    assert r["hardening"]["nproc"] is True  # the analyzer itself still may not start processes
    assert r["type"]["format"] == "pcap"
    assert len(r["pcap"]["http_fingerprints"]) == 1, r["errors"]
    assert "pcap" in r["timings_s"]


@pytest.mark.skipif(shutil.which("malduck") is None, reason="malduck only in the image")
def test_hardened_entry_point_runs_malduck(tmp_path):
    data = (pathlib.Path(__file__).parent / "fixtures" / "test.exe").read_bytes()
    r = _main(tmp_path, "test.exe", data)
    assert r["hardening"]["nproc"] is True
    assert not [e for e in r["errors"] if e["stage"] == "malware_config"], r["errors"]
    assert "malware_config" in r["timings_s"]
