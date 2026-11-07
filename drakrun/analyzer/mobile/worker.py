"""Android dynamic analysis queue: staged at upload, run by runner.py, stored beside the static result.

    upload (api.py) ──enqueue_mobile()──> <store>/samples/<id> (0400) + RQ queue "chimera-mobile"
    drakrun mobile-worker ──run_mobile_job()──> runner.run_dynamic()
        ──> /var/lib/drakrun/analyses/<id>/mobile-dynamic.json, mobile-screens/NN.png, dump.pcap

mobile-dynamic.json (schema chimera-mobile-dynamic/1) carries a status the console polls: queued, running,
finished or failed. The worker never parses the app: everything it stores comes from the mobile VM's envelope,
validated and bounded by summarise().
"""

from __future__ import annotations

import base64
import binascii
import datetime
import json
import logging
import os
import shutil
import uuid
from pathlib import Path
from typing import Optional

from redis import Redis
from rq import Queue, Worker

from drakrun.lib.config import load_config
from drakrun.lib.paths import ANALYSES_DIR

logger = logging.getLogger(__name__)
MOBILE_QUEUE_NAME = "chimera-mobile"
SCHEMA = "chimera-mobile-dynamic/1"
RESULT_NAME = "mobile-dynamic.json"
SCREENS_DIR = "mobile-screens"
MAX_ITEMS = 200
MAX_TEXT = 2000
MAX_SCREENS = 12
MAX_PNG_BYTES = 1536 * 1024


def analysis_dir(analysis_id: str, base: Optional[Path] = None) -> Path:
    # uuid.UUID also rejects path tricks
    return Path(base or ANALYSES_DIR) / str(uuid.UUID(analysis_id))


def sample_path(analysis_id: str, store: str) -> Path:
    return Path(store) / "samples" / str(uuid.UUID(analysis_id))


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write_status(directory: Path, doc: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    tmp = directory / f".{RESULT_NAME}.tmp"
    tmp.write_text(json.dumps(doc, indent=2, allow_nan=False), encoding="utf-8")
    os.replace(tmp, directory / RESULT_NAME)


def load_mobile(analysis_id: str, base: Optional[Path] = None) -> Optional[dict]:
    try:
        text = (analysis_dir(analysis_id, base) / RESULT_NAME).read_text()
        doc = json.loads(text)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def enqueue_mobile(
    analysis_id: str, upload: Path, upload_name: str, run_s: int, connection, config
):
    """Stage a copy of the upload (the static path deletes its own) and queue the dynamic run."""
    staged = sample_path(analysis_id, config.mobile.store)
    staged.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(upload, staged)
    staged.chmod(0o400)
    write_status(
        analysis_dir(analysis_id),
        {"schema": SCHEMA, "status": "queued", "run_s": run_s, "queued": _now()},
    )
    return Queue(name=MOBILE_QUEUE_NAME, connection=connection).enqueue(
        run_mobile_job,
        analysis_id,
        upload_name,
        run_s,
        job_id=f"mobile-{analysis_id}",
        job_timeout=int(
            run_s
            + config.mobile.overhead_s
            + config.worker.memory_admission_timeout
            + 300
        ),
        result_ttl=config.drakrun.result_ttl,
    )


def _text(value, limit: int = MAX_TEXT) -> str:
    if isinstance(
        value, (list, dict)
    ):  # Frida's API monitor sends arguments as JSON arrays
        return json.dumps(value, default=str)[:limit]
    return str(value if value is not None else "")[:limit]


def _strings(value, limit: int = MAX_ITEMS) -> list:
    if isinstance(value, dict):
        value = list(value)
    if not isinstance(value, list):
        return []
    return [_text(v, 500) for v in value[:limit] if isinstance(v, (str, int, float))]


def _api_calls(value) -> list:
    """Frida API monitor entries: API group, class, method, arguments, return value (bounded)."""
    if isinstance(value, dict):
        value = [
            dict(item, api=group)
            for group, items in value.items()
            for item in (items if isinstance(items, list) else [])
            if isinstance(item, dict)
        ]
    calls = []
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict):
            continue
        calls.append(
            {
                "api": _text(item.get("api") or item.get("name"), 200),
                "class": _text(item.get("class"), 300),
                "method": _text(item.get("method"), 200),
                "arguments": _text(item.get("arguments"), 1000),
                "result": _text(item.get("result") or item.get("returnValue"), 500),
            }
        )
        if len(calls) >= MAX_ITEMS:
            break
    return calls


def summarise(envelope: dict) -> dict:
    """The stored view of one run: steps, device, MobSF's dynamic findings, logcat tail. Screenshots go to
    files (see store_screens)."""
    report = envelope.get("report")
    report = report if isinstance(report, dict) else {}
    steps = [
        {
            "name": _text(s.get("name"), 64),
            "ok": bool(s.get("ok")),
            "detail": _text(s.get("detail"), 500),
        }
        for s in envelope.get("steps", [])
        if isinstance(s, dict)
    ][:40]
    props = envelope.get("device_props")
    tls = report.get("tls_tests")
    return {
        "package": _text(envelope.get("package"), 300),
        "device": (
            {str(k)[:64]: _text(v, 200) for k, v in props.items()}
            if isinstance(props, dict)
            else {}
        ),
        "steps": steps,
        "error": _text(envelope.get("error"), 500) or None,
        "domains": _strings(report.get("domains")),
        "urls": _strings(report.get("urls")),
        "emails": _strings(report.get("emails")),
        "api_calls": _api_calls(
            envelope.get("api_monitor") or report.get("api_monitor")
        ),
        "base64_strings": _strings(report.get("base64_strings"), 50),
        "sqlite": _strings(report.get("sqlite"), 50),
        "xml_files": _strings(report.get("xml"), 50),
        "other_files": _strings(report.get("others"), 100),
        "tls_tests": tls if isinstance(tls, dict) else None,
        "activities_tested": _strings(report.get("exported_activities"), 100),
        "logcat_tail": _text(envelope.get("logcat"), 200_000),
    }


def store_screens(envelope: dict, directory: Path) -> list:
    """Decode the screenshots the driver took (PNG only, bounded) into mobile-screens/NN.png."""
    out = directory / SCREENS_DIR
    kept = []
    for index, shot in enumerate(envelope.get("screenshots", [])[:MAX_SCREENS]):
        if not isinstance(shot, dict):
            continue
        try:
            png = base64.b64decode(shot.get("png", ""), validate=True)
        except (binascii.Error, ValueError):
            continue
        if not png.startswith(b"\x89PNG\r\n\x1a\n") or len(png) > MAX_PNG_BYTES:
            continue
        out.mkdir(exist_ok=True)
        name = f"{index:02d}.png"
        (out / name).write_bytes(png)
        kept.append({"file": name, "label": _text(shot.get("label"), 64)})
    return kept


def mobsf_envelope(result: dict) -> dict:
    """The driver's JSON from the agent's result (one step, out/mobile.json), or an error."""
    if result.get("error"):
        return {"error": _text(result["error"], 500)}
    steps = result.get("steps") or []
    step = steps[0] if steps and isinstance(steps[0], dict) else {}
    text = (step.get("files") or {}).get("out/mobile.json")
    if not text:
        detail = (
            "timed out" if step.get("timed_out") else f"exit {step.get('exit_code')}"
        )
        stderr = _text(step.get("stderr"), 400)
        return {"error": f"MobSF step produced no report ({detail}): {stderr}"}
    try:
        doc = json.loads(text)
    except ValueError:
        return {"error": "MobSF step output is not JSON"}
    if not isinstance(doc, dict):
        return {"error": "MobSF step output is not an object"}
    return doc


def run_mobile_job(analysis_id: str, upload_name: str, run_s: int) -> dict:
    from .runner import run_dynamic

    config = load_config()
    staged = sample_path(analysis_id, config.mobile.store)
    directory = analysis_dir(analysis_id)
    doc = {"schema": SCHEMA, "status": "running", "run_s": run_s, "started": _now()}
    write_status(directory, doc)
    try:
        result = run_dynamic(analysis_id, staged, upload_name, directory, run_s)
        envelope = mobsf_envelope(result)
        doc.update(summarise(envelope))
        doc["screenshots"] = store_screens(envelope, directory)
        report_ok = any(s["name"] == "report" and s["ok"] for s in doc["steps"])
        doc["status"] = "finished" if report_ok else "failed"
    except Exception as exc:
        logger.exception("Android dynamic analysis failed for %s", analysis_id)
        doc.update(status="failed", error=f"{type(exc).__name__}: {exc}"[:500])
    finally:
        staged.unlink(missing_ok=True)
    doc["finished"] = _now()
    write_status(directory, doc)
    return {"status": doc["status"]}


def mobile_worker_main(burst: bool = False):
    config = load_config()
    if not config.mobile.enabled:
        logger.warning("[mobile] enabled = false in config.toml; the worker will idle")
    worker = Worker(
        queues=[MOBILE_QUEUE_NAME],
        name=f"chimera-mobile@{os.uname().nodename}",
        connection=Redis(
            host=config.redis.host,
            port=config.redis.port,
            username=config.redis.username,
            password=config.redis.password,
        ),
    )
    worker.work(burst=burst)
