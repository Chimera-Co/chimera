"""Android dynamic analysis: the stored view of a run, the mobile VM's job, the upload path and the endpoints.

None of this boots a guest: the runner is checked through the configs and the podman step it generates, the
worker through the envelope the driver prints.
"""

import base64
import contextlib
import importlib
import subprocess
import io
import json
import sys
import uuid
from unittest.mock import Mock

import pytest
from flask_openapi3 import Info, OpenAPI

from drakrun.analyzer.mobile import runner
from drakrun.analyzer.mobile import worker as mobile
from drakrun.analyzer.static import worker as static_worker

PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 32


def _envelope(**extra):
    doc = {
        "package": "com.example.app",
        "device_props": {"ro.build.version.release": "9", "ro.build.version.sdk": "28"},
        "steps": [
            {"name": "device_boot", "ok": True, "detail": "10.13.9.2:5555", "t": 1},
            {"name": "report", "ok": True, "detail": ""},
            "not a step",
        ],
        "report": {
            "domains": {"example.com": {"geolocation": {}}},
            "urls": ["http://example.com/a", {"nested": "dropped"}],
            "sqlite": ["databases/app.db"],
            "tls_tests": {"tls_misconfigured": False},
        },
        "api_monitor": {
            "Crypto": [
                {"class": "javax.crypto.Cipher", "method": "doFinal", "arguments": ["a"]}
            ],
            "Bad": "not a list",
        },
        "logcat": "x" * 300_000,
    }
    doc.update(extra)
    return doc


def test_summarise_bounds_and_flattens():
    doc = mobile.summarise(_envelope())
    assert doc["package"] == "com.example.app"
    assert doc["device"]["ro.build.version.sdk"] == "28"
    assert [s["name"] for s in doc["steps"]] == ["device_boot", "report"]
    assert doc["domains"] == ["example.com"]
    assert doc["urls"] == ["http://example.com/a"]
    assert doc["sqlite"] == ["databases/app.db"]
    assert doc["api_calls"] == [
        {
            "api": "Crypto",
            "class": "javax.crypto.Cipher",
            "method": "doFinal",
            "arguments": '["a"]',
            "result": "",
        }
    ]
    assert doc["tls_tests"] == {"tls_misconfigured": False}
    assert len(doc["logcat_tail"]) == 200_000
    assert doc["error"] is None


def test_summarise_survives_garbage():
    doc = mobile.summarise({"report": "nope", "device_props": [], "api_monitor": 5})
    assert doc["steps"] == [] and doc["device"] == {} and doc["api_calls"] == []
    assert doc["domains"] == [] and doc["tls_tests"] is None


def test_store_screens_keeps_png_only(tmp_path):
    good = base64.b64encode(PNG).decode()
    shots = [
        {"label": "launch", "png": good},
        {"label": "not png", "png": base64.b64encode(b"GIF89a").decode()},
        {"label": "not base64", "png": "%%%"},
        "junk",
        {"label": "running", "png": good},
    ]
    kept = mobile.store_screens({"screenshots": shots}, tmp_path)
    assert kept == [
        {"file": "00.png", "label": "launch"},
        {"file": "04.png", "label": "running"},
    ]
    assert (tmp_path / "mobile-screens" / "04.png").read_bytes() == PNG


def test_mobsf_envelope_reads_step_output():
    doc = {"package": "p"}
    ok = {"steps": [{"files": {"out/mobile.json": json.dumps(doc)}}]}
    assert mobile.mobsf_envelope(ok) == doc
    timed_out = mobile.mobsf_envelope({"steps": [{"timed_out": True}]})
    assert "timed out" in timed_out["error"]
    assert mobile.mobsf_envelope({"error": "boom"}) == {"error": "boom"}
    bad = {"steps": [{"files": {"out/mobile.json": "[1]"}}]}
    assert mobile.mobsf_envelope(bad)["error"] == "MobSF step output is not an object"


def test_analysis_dir_rejects_paths(tmp_path):
    with pytest.raises(ValueError):
        mobile.analysis_dir("../../etc", tmp_path)


def test_run_mobile_job_writes_result(tmp_path, monkeypatch, base_config):
    aid = str(uuid.uuid4())
    base_config.mobile.store = str(tmp_path / "store")
    staged = mobile.sample_path(aid, base_config.mobile.store)
    staged.parent.mkdir(parents=True)
    staged.write_bytes(b"PK")
    monkeypatch.setattr(mobile, "load_config", lambda: base_config)
    monkeypatch.setattr(mobile, "ANALYSES_DIR", tmp_path / "analyses")
    shot = {"label": "launch", "png": base64.b64encode(PNG).decode()}
    result = {
        "steps": [{"files": {"out/mobile.json": json.dumps(_envelope(screenshots=[shot]))}}]
    }
    monkeypatch.setattr(runner, "run_dynamic", lambda *a: result)
    assert mobile.run_mobile_job(aid, "app.apk", 120) == {"status": "finished"}
    doc = mobile.load_mobile(aid, tmp_path / "analyses")
    assert doc["schema"] == mobile.SCHEMA and doc["run_s"] == 120
    assert doc["screenshots"] == [{"file": "00.png", "label": "launch"}]
    assert not staged.exists()

    staged.write_bytes(b"PK")
    monkeypatch.setattr(runner, "run_dynamic", Mock(side_effect=RuntimeError("no VM")))
    assert mobile.run_mobile_job(aid, "app.apk", 120) == {"status": "failed"}
    doc = mobile.load_mobile(aid, tmp_path / "analyses")
    assert doc["error"] == "RuntimeError: no VM" and not staged.exists()


def test_runner_configs_and_step(tmp_path, base_config):
    settings = base_config.mobile
    settings.store = str(tmp_path)
    (tmp_path / "adbkey").write_text("private")
    (tmp_path / "adbkey.pub").write_text("public")
    android = runner.android_cfg(settings, tmp_path / "overlay.qcow2", "drak9")
    assert "bridge=drak9" in android and "xen_platform_pci = 0" in android
    assert f"memory = {settings.android_memory_mb}" in android
    vm = runner.mobile_cfg(settings, tmp_path / "scratch.img", "drak9")
    assert "chimera.role=mobile" in vm and "ip=10.13.9.3::10.13.9.1:" in vm
    assert "access=ro" in vm and "root.img" in vm

    step = runner.podman_step(settings, "a" * 8, 180, 1080, "app.apk", 1234)
    argv = step["argv"]
    assert argv[argv.index("--network") + 1] == "host"
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--privileged" not in argv
    assert "MOBSF_ANALYZER_IDENTIFIER=10.13.9.2:5555" in argv
    assert argv[argv.index("-c") + 1].startswith("sleep infinity | ")
    assert argv[-5:] == ["/input/sample", "180", "10.13.9.2:5555", "app.apk", "1080"]
    files = step["prepare"]["files"]
    assert files["resolv.conf"] == "nameserver 10.99.0.2\n"
    assert files["android/adbkey"] == "private"
    assert "def run(argv, out)" in files["driver.py"]


def test_start_domains_retries_when_the_static_vm_takes_the_memory(
    tmp_path, monkeypatch, base_config
):
    created, destroyed, stops = [], [], []
    failures = [subprocess.CalledProcessError(3, ["xl"], stderr="out of memory\n")]

    def create(text, path):
        created.append(path.name)
        if path.name == "mobile.cfg" and failures:
            raise failures.pop()

    monkeypatch.setattr(runner, "_create", create)
    monkeypatch.setattr(runner, "_destroy", destroyed.append)
    monkeypatch.setattr(runner, "xen_free_memory_mb", lambda: 1000)
    monkeypatch.setattr(
        runner.vm_backend, "stop_if_idle", lambda s, idle_s: stops.append(idle_s)
    )
    monkeypatch.setattr(
        runner, "memory_admission", lambda *a, **kw: contextlib.nullcontext()
    )
    monkeypatch.setattr(runner.time, "sleep", lambda s: None)
    base_config.mobile.store = str(tmp_path)
    runner._start_domains(base_config, tmp_path / "o", tmp_path / "s", "drak9", tmp_path)
    assert created == ["android.cfg", "mobile.cfg", "android.cfg", "mobile.cfg"]
    assert stops == [runner.STATIC_IDLE_FOR_MOBILE_S] * 2
    assert destroyed.count(runner.MOBILE_DOMAIN) == 3

    failures.append(subprocess.CalledProcessError(3, ["xl"], stderr="no\n"))
    base_config.worker.memory_admission_timeout = 0
    with pytest.raises(runner.MobileUnavailable, match="could not start: no"):
        runner._start_domains(
            base_config, tmp_path / "o", tmp_path / "s", "drak9", tmp_path
        )


@pytest.fixture
def upload(tmp_path, monkeypatch, base_config):
    base_config.static.enabled = True
    base_config.mobile.store = str(tmp_path / "store")
    monkeypatch.setattr("drakrun.lib.config.load_config", lambda: base_config)
    sys.modules.pop("drakrun.web.api", None)
    api = importlib.import_module("drakrun.web.api")
    monkeypatch.setattr(api, "UPLOADS_DIR", tmp_path / "uploads")
    monkeypatch.setattr(api, "ANALYSES_DIR", tmp_path / "analyses")
    monkeypatch.setattr(mobile, "ANALYSES_DIR", tmp_path / "analyses")
    monkeypatch.setattr(static_worker, "STATIC_DIR", tmp_path / "static")
    monkeypatch.setattr(api, "truncate_analysis_list", Mock())
    monkeypatch.setattr(
        "drakrun.analyzer.analysis_metadata.magic.from_file", lambda _: "data"
    )
    dynamic, static, queue, mobile_queue = Mock(), Mock(), Mock(), Mock()
    monkeypatch.setattr(api, "enqueue_analysis", dynamic)
    monkeypatch.setattr(api, "stage_and_enqueue", static)
    monkeypatch.setattr(static_worker, "Queue", queue)
    monkeypatch.setattr(mobile, "Queue", mobile_queue)
    app = OpenAPI(__name__, info=Info(title="test", version="0"))
    app.register_api(api.api)
    yield app.test_client(), api, base_config, dynamic, static, mobile_queue
    sys.modules.pop("drakrun.web.api", None)


def _post(client, **form):
    data = {"file": (io.BytesIO(b"PK"), "app.apk"), "guest_os": "android"}
    data.update(form)
    return client.post("/api/upload", data=data)


def test_android_combined_needs_mobile_enabled(upload):
    client, api, config, dynamic, static, mobile_queue = upload
    config.mobile.enabled = False
    response = _post(client, mode="combined")
    assert response.status_code == 400
    assert "not enabled" in response.json["error"]
    mobile_queue.assert_not_called()


def test_android_combined_queues_static_and_mobile(upload, tmp_path):
    client, api, config, dynamic, static, mobile_queue = upload
    config.mobile.enabled = True
    assert _post(client, mode="combined", timeout="30").status_code == 400
    response = _post(client, mode="combined", timeout="240")
    assert response.status_code == 200, response.json
    aid = response.json["task_uid"]
    assert dynamic.call_count == 0 and static.call_count == 0
    mobile_queue.assert_called_once_with(name="chimera-mobile", connection=api.redis)
    call = mobile_queue.return_value.enqueue.call_args
    assert call.args == (mobile.run_mobile_job, aid, "app.apk", 240)
    assert call.kwargs["job_id"] == f"mobile-{aid}"
    staged = mobile.sample_path(aid, config.mobile.store)
    assert staged.read_bytes() == b"PK" and staged.stat().st_mode & 0o777 == 0o400

    status = client.get(f"/api/mobile/{aid}")
    assert status.status_code == 200 and status.json["status"] == "queued"
    screens = tmp_path / "analyses" / aid / "mobile-screens"
    screens.mkdir()
    (screens / "00.png").write_bytes(PNG)
    shot = client.get(f"/api/mobile/{aid}/screen/00.png")
    assert shot.status_code == 200 and shot.mimetype == "image/png"
    assert client.get(f"/api/mobile/{aid}/screen/..%2Fx.png").status_code == 404
    assert client.get(f"/api/mobile/{aid}/screen/1.png").status_code == 404


def test_mobile_endpoint_missing(upload):
    client, *_ = upload
    assert client.get(f"/api/mobile/{uuid.uuid4()}").status_code == 404


def test_ios_stays_static_only(upload):
    client, api, config, *_ = upload
    config.mobile.enabled = True
    response = _post(client, mode="combined", guest_os="ios")
    assert response.status_code == 400 and "iOS" in response.json["error"]
