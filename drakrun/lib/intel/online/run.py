"""Host background orchestration: reads JSON artifacts only."""

import ipaddress
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from drakrun.lib.intel import normalize
from drakrun.lib.intel.report import observations, sample_scope

from . import inventory, providers
from .base import HASHES
from .cache import Cache
from .noise import background, non_public, string_artifact
from .resolve import public_ipv4
from .resolve import resolve as resolve_domains


def read_json(path):
    try:
        value = json.loads(Path(path).read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def collect(directory, static_directory, config, network=None, resolve=None):
    """(kind, value, origin) to look up: the sample's hash, then what its own processes contacted, then what
    nobody can attribute, then strings in the file. Other guest processes' traffic is not looked up.
    """
    metadata = read_json(directory / "metadata.json")
    static = read_json(static_directory / "static.json")
    report = read_json(directory / "report.json")
    scope = sample_scope(report)
    candidates = observations(
        metadata,
        report,
        static,
        read_json(directory / "tls_sessions.json"),
        scope=scope or None,
    )
    # Strings from memory dumps of the sample's own processes (unpacked code); other processes' dumps are
    # Windows talking to its own services.
    for row in read_json(static_directory / "memdumps.json").get("scanned", []):
        if not row.get("sample_tree"):
            continue
        candidates += [
            (kind, value, "memory")
            for kind, value, _ in observations(
                {}, {}, {"universal": {"iocs": row.get("iocs") or {}}}, {}
            )
        ]
    # C2 endpoints decoded from malware configurations (malduck): the sample's real infrastructure, which the
    # contained network never let it reach. From any dump: a config in another process is injected code.
    memdumps = read_json(static_directory / "memdumps.json")
    for malware_config in (memdumps.get("malware_configs") or []) + (
        static.get("malware_configs") or []
    ):
        candidates += [
            (kind, value, "config")
            for kind, value, _ in observations(
                {}, {}, {"universal": {"iocs": malware_config.get("iocs") or {}}}, {}
            )
        ]
    excluded = []
    if network is not None:
        values = (
            network.model_dump() if hasattr(network, "model_dump") else vars(network)
        )
        for value in values.values():
            try:
                excluded.append(ipaddress.ip_network(str(value), strict=False))
            except ValueError:
                pass
    # Most telling first: the sample's own hash, then indicators seen at run time, then strings in the file.
    origin_rank = {
        "sample": 0,
        "config": 1,
        "dynamic": 1,
        "memory": 2,
        "resolved": 3,
        "unattributed": 4,
        "static": 5,
    }
    kind_rank = {"sha256": 0, "sha1": 1, "md5": 2, "domain": 3, "url": 4, "ip": 5}
    candidates = sorted(
        candidates, key=lambda c: (origin_rank.get(c[2], 3), kind_rank.get(c[0], 9))
    )
    # One lookup per file: sha1/md5 of the sample only when there is no sha256.
    sample_sha256 = any(k == "sha256" and o == "sample" for k, _, o in candidates)
    selected, seen, counts = [], set(), Counter()
    for kind, value, origin in candidates:
        if kind not in kind_rank or origin not in origin_rank:
            continue
        if origin == "sample" and kind in ("sha1", "md5") and sample_sha256:
            continue
        try:
            value = normalize(kind, value)
            host = urlsplit(value).hostname if kind == "url" else value
            if kind in {"ip", "url", "domain"}:
                try:
                    ipaddress.ip_address(host)
                    host_kind = "ip"
                except ValueError:
                    host_kind = "domain"
                if origin in ("static", "memory") and string_artifact(
                    host_kind, host or ""
                ):
                    continue
                try:
                    address = ipaddress.ip_address(host)
                    if (
                        not address.is_global
                        or address.is_multicast
                        or address.is_reserved
                        or any(address in subnet for subnet in excluded)
                    ):
                        continue
                except ValueError:
                    if kind == "ip" or non_public(host):
                        continue
                    # Domain verdicts for Windows' own services say nothing; a URL the sample itself
                    # fetched from one (payload hosting) still does.
                    if background(host) and (kind == "domain" or origin != "dynamic"):
                        continue
            if (kind, value) in seen or counts[kind] >= config.max_observables:
                continue
        except (ValueError, TypeError, UnicodeError):
            continue
        selected.append((kind, value, origin))
        counts[kind] += 1
        seen.add((kind, value))
    if resolve is not None:
        domains = [
            v for k, v, o in selected if k == "domain" and o in {"dynamic", "config"}
        ]
        for _, ip in resolve(domains[: config.resolve_max]):
            if (
                public_ipv4(ip)
                and not any(ipaddress.ip_address(ip) in subnet for subnet in excluded)
                and ("ip", ip) not in seen
                and counts["ip"] < config.max_observables
            ):
                selected.append(("ip", ip, "resolved"))
                seen.add(("ip", ip))
                counts["ip"] += 1
        selected.sort(key=lambda c: (origin_rank[c[2]], kind_rank[c[0]]))
    return selected


def plan(items, config, scope=None):
    """(provider, info, observables it will be asked about), in query order."""
    planned = []
    for provider, info in zip(providers(), inventory(config)):
        if scope == "sample-hash" and provider.id not in config.hash_providers:
            continue
        wanted = []
        # A provider without its key is reported once in `providers`, not once per observable.
        if info["enabled"] and info["configured"]:
            wanted = [item for item in items if item[0] in provider.types][
                : provider.max_lookups
            ]
        planned.append((provider, info, wanted))
    return planned


def progress_doc(planned, done, current=None, phase="lookups"):
    """What the console's progress bar shows: per provider how many lookups are planned and done."""
    return dict(
        phase=phase,
        total=sum(len(w) for _, _, w in planned),
        done=sum(done.values()),
        current=current,
        providers=[
            dict(
                id=p.id,
                label=p.label,
                planned=len(w),
                done=done.get(p.id, 0),
                skipped=(
                    "disabled"
                    if not i["enabled"]
                    else (
                        "no API key"
                        if not i["configured"]
                        else "nothing to look up" if not w else None
                    )
                ),
            )
            for p, i, w in planned
        ],
        updated_at=datetime.now(timezone.utc).isoformat(),
    )


def run(directory, static_directory, config, network=None, scope=None, progress=None):
    """scope="sample-hash": only the sample's own hash, only with `config.hash_providers` (the lookup every
    analysis gets when online intel was not asked for). `progress(doc)` is called before each lookup and at
    the end (see progress_doc)."""
    report = progress or (lambda doc: None)
    report(dict(phase="collecting", total=0, done=0, current=None, providers=[]))
    cache = Cache(config.cache_path)
    resolved = {}

    def resolving(domains):
        report(
            dict(phase="resolving domains", total=0, done=0, current=None, providers=[])
        )
        pairs = resolve_domains(domains, config, cache)
        for domain, ip in pairs:
            if ip not in resolved.setdefault(domain, []):
                resolved[domain].append(ip)
        return pairs

    items = collect(
        directory,
        static_directory,
        config,
        network,
        resolve=(
            resolving if scope != "sample-hash" and config.resolve_domains else None
        ),
    )
    if scope == "sample-hash":
        items = [item for item in items if item[2] == "sample"]
    results, states = [], []
    planned = plan(items, config, scope)
    done = Counter()
    for provider, info, wanted in planned:
        rows = []
        for kind, value, origin in wanted:
            report(
                progress_doc(
                    planned,
                    done,
                    dict(
                        provider=provider.id,
                        label=provider.label,
                        type=kind,
                        value=value,
                    ),
                )
            )
            rows.append(
                {**provider.lookup(kind, value, config, cache), "origin": origin}
            )
            if origin == "resolved":
                rows[-1]["resolved_from"] = next(
                    d for d, ips in resolved.items() if value in ips
                )
            done[provider.id] += 1
        statuses = Counter(row["status"] for row in rows)
        status = (
            "disabled"
            if not info["enabled"]
            else (
                "not_configured"
                if not info["configured"]
                else (
                    "unsupported"
                    if not rows
                    else next(
                        (
                            s
                            for s in (
                                "error",
                                "offline",
                                "rate_limited",
                                "not_configured",
                                "unsupported",
                            )
                            if statuses[s]
                        ),
                        "ok",
                    )
                )
            )
        )
        states.append(
            dict(
                id=provider.id,
                configured=info["configured"],
                status=status,
                queried=sum(statuses[s] for s in ("ok", "not_found")),
                errors=[
                    dict(status=s, count=n)
                    for s, n in statuses.items()
                    if s not in ("ok", "not_found")
                ],
            )
        )
        results.extend(rows)
    report(progress_doc(planned, done, phase="writing report"))
    ran = any(
        r["status"] in {"ok", "not_found", "error", "rate_limited"} for r in results
    )
    offline = any(s["status"] == "offline" for s in states)
    return dict(
        schema="chimera-intel-online/1",
        analysis_id=directory.name,
        generated_at=datetime.now(timezone.utc).isoformat(),
        scope=scope or "all",
        connectivity="partial" if ran and offline else "online" if ran else "offline",
        providers=states,
        results=results,
        resolved=[dict(domain=d, ips=ips) for d, ips in resolved.items()],
        summary=dict(
            observables=len(items),
            # A match is a provider calling it malicious or suspicious; "seen" only means the provider
            # knows the value (a urlscan search hit, a known-good file).
            matches=sum(
                r.get("verdict") in ("malicious", "suspicious") for r in results
            ),
            malicious=sum(r.get("verdict") == "malicious" for r in results),
            known_good=sum(r.get("verdict") == "harmless" for r in results),
            seen=sum(r["status"] == "ok" for r in results),
            lookups=sum(r["status"] in ("ok", "not_found") for r in results),
        ),
    )


def enqueue(analysis_id, connection, options=None, depends_on=None):
    from rq import Queue

    from drakrun.analyzer.static.worker import INTEL_QUEUE_NAME
    from drakrun.lib.config import load_config

    settings = load_config().intel
    if not settings.online_enabled:
        return None
    # Without online intel the sample's hash is still looked up with `hash_providers`; nothing else leaves the host.
    full = (options or {}).get("intel_online", settings.online_default)
    if not full and not settings.hash_providers:
        return None
    return Queue(name=INTEL_QUEUE_NAME, connection=connection).enqueue(
        run_online_intel_job,
        analysis_id,
        None if full else "sample-hash",
        job_id=f"intel-online-{analysis_id}",
        job_timeout=3600,
        result_ttl=3600,
        depends_on=depends_on,
    )


def run_online_intel_job(analysis_id, scope=None):
    from drakrun.analyzer.static.worker import _refresh_report, _write_json, job_dir
    from drakrun.lib.config import load_config
    from drakrun.lib.paths import ANALYSES_DIR

    config = load_config()
    if not config.intel.online_enabled:
        return
    target = job_dir(analysis_id)
    target.mkdir(parents=True, exist_ok=True)
    try:
        doc = run(
            ANALYSES_DIR / target.name,
            target,
            config.intel,
            config.network,
            scope,
            progress=_job_progress(),
        )
    except Exception:
        doc = dict(
            schema="chimera-intel-online/1",
            analysis_id=target.name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            scope=scope or "all",
            connectivity="offline",
            providers=[
                dict(
                    id=p.id,
                    configured=i["configured"],
                    status="error",
                    queried=0,
                    errors=["cache or artifact unavailable"],
                )
                for p, i in zip(providers(), inventory(config.intel))
            ],
            results=[],
            summary={},
        )
    _write_json(target, "intel-online.json", doc)
    _refresh_report(analysis_id)
    return doc["summary"]


def _job_progress():
    """Progress into the RQ job's meta (read by GET /api/intel/<id>/online/status); a no-op outside a worker."""
    from rq import get_current_job

    job = get_current_job()
    if job is None:
        return None

    def save(doc):
        job.meta["progress"] = doc
        try:
            job.save_meta()
        except Exception:  # progress is cosmetic: never fail the lookups over it
            pass

    return save


def job_status(analysis_id, connection):
    """State of the analysis's online-intel job for the console: none, queued, deferred (waiting for the
    memory-dump scan), started, finished or failed, with the progress the job last saved.
    """
    from rq.exceptions import NoSuchJobError
    from rq.job import Job

    try:
        job = Job.fetch(f"intel-online-{analysis_id}", connection=connection)
    except NoSuchJobError:
        return dict(state="none")
    state = job.get_status(refresh=True)
    state = getattr(state, "value", state)
    out = dict(
        state=str(state),
        scope=(job.args[1] if len(job.args) > 1 else None) or "all",
        enqueued_at=job.enqueued_at.isoformat() if job.enqueued_at else None,
        started_at=job.started_at.isoformat() if job.started_at else None,
        ended_at=job.ended_at.isoformat() if job.ended_at else None,
        progress=(job.meta or {}).get("progress"),
    )
    if state == "queued":
        try:
            out["queue_position"] = job.get_position()
        except Exception:
            pass
    return out


def virustotal_reason(results):
    """What VirusTotal said about the sample's own hash, in one line (None when it was not asked)."""
    for row in results:
        if row.get("provider") != "virustotal" or row.get("type") not in HASHES:
            continue
        if row.get("status") == "not_found":
            return "VirusTotal does not know the sample's hash"
        if row.get("status") == "ok":
            counts = row.get("detections") or {}
            engines = sum(
                counts.get(k, 0)
                for k in ("malicious", "suspicious", "harmless", "undetected")
            )
            family = f" ({row['family']})" if row.get("family") else ""
            return f"VirusTotal: {counts.get('malicious', 0)} of {engines} engines flag the sample{family}"
    return None


def assessment(label, results, config_families=()):
    """Precedence: known malware hashes, a decoded malware configuration, engine consensus, known software,
    model.

    Engine consensus counts only the sample's own hash: a contacted domain or IP that VirusTotal flags is
    evidence about the run, not a verdict on the file. VirusTotal's view of the hash is added to every basis.
    """
    hits = [r for r in results if r.get("status") == "ok"]
    reason = virustotal_reason(results)
    vt = [reason] if reason else []
    for row in hits:
        if row["provider"] in {"malwarebazaar", "threatfox"} and row["type"] in HASHES:
            return dict(
                label="malicious",
                basis="known malware",
                reasons=[
                    f"{row['provider']} hash match: {row.get('family') or 'unknown family'}"
                ]
                + vt,
            )
    if config_families:
        # malduck only decodes a config when the family's own structure is there: as strong as a hash match
        return dict(
            label="malicious",
            basis="malware config",
            reasons=[
                "Configuration of "
                + ", ".join(config_families)
                + " decoded from the run"
            ]
            + vt,
        )
    engines = max(
        [
            r.get("detections", {}).get("malicious", 0)
            for r in hits
            if r["provider"] == "virustotal" and r["type"] in HASHES
        ]
        or [0]
    )
    if engines >= 3:
        return dict(
            label=(
                "malicious" if engines >= 10 or label == "malicious" else "suspicious"
            ),
            basis="engine consensus",
            reasons=vt,
        )
    if label != "malicious" and any(
        r["provider"] == "hashlookup" and r["verdict"] == "harmless" for r in hits
    ):
        return dict(
            label="benign",
            basis="known software",
            reasons=["CIRCL known software hash match"] + vt,
        )
    return dict(
        label=label,
        basis="behaviour model",
        reasons=["Classifier verdict retained"] + vt,
    )


def run_offline_recheck_job(analysis_id):
    """Match an existing analysis against the offline feeds now installed (rebuilds its report)."""
    from drakrun.analyzer.static.worker import _refresh_report

    _refresh_report(analysis_id)
