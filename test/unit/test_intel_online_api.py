"""Online inventory, refresh and upload option API contracts."""

import io
import json
import uuid
from unittest.mock import Mock

import pytest

from .test_analysis_modes import upload  # noqa: F401
from .test_classifier_api import api_client  # noqa: F401


def test_inventory_no_secrets(api_client, base_config, tmp_path):
    base_config.intel.keys_dir = tmp_path / "keys"
    base_config.intel.keys_dir.mkdir()
    (base_config.intel.keys_dir / "virustotal").write_text("secret-never-exposed")
    response = api_client.get("/api/intel/providers")
    assert response.status_code == 200
    assert len(response.json["providers"]) == 11
    assert "secret-never-exposed" not in response.text
    assert response.json["providers"][0]["configured"] is True


def test_refresh(api_client, base_config, tmp_path, monkeypatch):
    uid = str(uuid.uuid4())
    assert api_client.post(f"/api/intel/{uid}/refresh").status_code == 409
    base_config.intel.online_enabled = True
    assert api_client.post(f"/api/intel/{uid}/refresh").status_code == 404
    directory = tmp_path / uid
    directory.mkdir()
    (directory / "chimera-report.json").write_text(json.dumps({"stages": {}}))
    queue = Mock()
    monkeypatch.setattr("drakrun.lib.intel.online.run.enqueue", queue)
    state = {"state": "none"}
    monkeypatch.setattr("drakrun.lib.intel.online.run.job_status", lambda uid, conn: state)
    assert api_client.post(f"/api/intel/{uid}/refresh").status_code == 202
    assert queue.call_args.args[2] == {"intel_online": True}
    # a lookup already queued or running is followed, not queued twice
    queue.reset_mock()
    state = {"state": "started"}
    response = api_client.post(f"/api/intel/{uid}/refresh")
    assert response.status_code == 202 and response.json == {"status": "started", "already": True}
    queue.assert_not_called()


def test_online_status_reads_the_job_progress(monkeypatch):
    from datetime import datetime, timezone
    from types import SimpleNamespace

    from rq.exceptions import NoSuchJobError
    from rq.job import Job

    from drakrun.lib.intel.online.run import job_status

    uid = str(uuid.uuid4())

    def missing(job_id, connection):
        raise NoSuchJobError(job_id)

    monkeypatch.setattr(Job, "fetch", staticmethod(missing))
    assert job_status(uid, None) == {"state": "none"}
    job = SimpleNamespace(
        args=(uid, None),
        enqueued_at=datetime(2026, 11, 8, tzinfo=timezone.utc),
        started_at=None,
        ended_at=None,
        meta={"progress": {"phase": "lookups", "done": 2, "total": 5}},
        get_status=lambda refresh=True: SimpleNamespace(value="queued"),
        get_position=lambda: 3,
    )
    fetched = []
    monkeypatch.setattr(
        Job, "fetch", staticmethod(lambda job_id, connection: fetched.append(job_id) or job)
    )
    got = job_status(uid, None)
    assert fetched == [f"intel-online-{uid}"]
    assert got["state"] == "queued" and got["queue_position"] == 3 and got["scope"] == "all"
    assert got["progress"]["done"] == 2 and got["enqueued_at"].startswith("2026-11-08")


def test_offline_recheck_queues_a_report_rebuild(api_client, tmp_path, monkeypatch):
    uid = str(uuid.uuid4())
    assert api_client.post(f"/api/intel/{uid}/recheck").status_code == 404
    directory = tmp_path / uid
    directory.mkdir()
    (directory / "chimera-report.json").write_text(json.dumps({"stages": {}}))
    queue = Mock()
    monkeypatch.setattr("rq.Queue", queue)
    assert api_client.post(f"/api/intel/{uid}/recheck").status_code == 202
    assert queue.return_value.enqueue.call_args.kwargs["job_id"] == f"intel-recheck-{uid}"


@pytest.mark.parametrize("mode", ["combined", "static-only"])
@pytest.mark.parametrize("choice", [None, "true", "false"])
def test_upload_online_option(upload, mode, choice):
    client, api, dynamic, static, queue = upload
    api.config.intel.online_enabled = True
    data = {"file": (io.BytesIO(b"fixture"), "x.bin"), "mode": mode}
    if choice is not None:
        data["intel_online"] = choice
    response = client.post("/api/upload", data=data)
    assert response.status_code == 200, response.json
    expected = choice != "false"
    if mode == "static-only":
        options = queue.return_value.enqueue.call_args.kwargs["meta"]["options"]
    else:
        options = (
            dynamic.call_args.kwargs["options"].to_dict()
            if "options" in dynamic.call_args.kwargs
            else dynamic.call_args.args[0].to_dict()
        )
    assert options["intel_online"] is expected
    from drakrun.analyzer.static.worker import job_dir

    stored = json.loads(
        (job_dir(response.json["task_uid"]) / "online-options.json").read_text()
    )
    assert stored == {"intel_online": expected}
