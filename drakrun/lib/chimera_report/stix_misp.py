"""Portable indicator exports from the normalized CHIMERA report."""

import ipaddress
import json
import re
from datetime import datetime, timezone
from uuid import UUID, uuid5

_NAMESPACE = UUID("8e171fc1-a527-5f36-a6d2-4e20a731657b")
_HASHES = {"sha256": ("SHA-256", 64), "sha1": ("SHA-1", 40), "md5": ("MD5", 32)}


def _id(kind, value):
    return f"{kind}--{uuid5(_NAMESPACE, kind + ':' + value)}"


def _time(report):
    dynamic = (report.get("stages") or {}).get("dynamic") or {}
    for value in (
        dynamic.get("started_at"),
        dynamic.get("finished_at"),
        report.get("generated_at"),
    ):
        if not value:
            continue
        try:
            date = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return (
                date.replace(tzinfo=date.tzinfo or timezone.utc)
                .astimezone(timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )
        except (ValueError, TypeError, AttributeError):
            continue
    # Older partial reports may have no time; never substitute the export time.
    return "1970-01-01T00:00:00.000Z"


def _verdict(report):
    label = (report.get("assessment") or {}).get("label") or (
        report.get("provenance") or {}
    ).get("verdict_label")
    return label if label in {"malicious", "suspicious", "benign"} else "unknown"


def _quote(value):
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _observable(ioc):
    """Return (MISP type, value, STIX expression), or None for unsupported/invalid IOCs."""
    kind, value = ioc.get("type"), ioc.get("value")
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        return None
    if kind in _HASHES:
        algorithm, length = _HASHES[kind]
        if not re.fullmatch(f"[a-fA-F0-9]{{{length}}}", value):
            return None
        return kind, value, f"file:hashes.{_quote(algorithm)} = {_quote(value)}"
    if kind in {"endpoint", "ip_port", "ip:port"}:
        host, separator, port = value.rpartition(":")
        if (
            not separator
            or "%" in host
            or len(port) > 5
            or not port.isascii()
            or not port.isdigit()
            or not 1 <= int(port) <= 65535
        ):
            return None
        try:
            address = ipaddress.ip_address(
                host[1:-1] if host.startswith("[") and host.endswith("]") else host
            )
        except ValueError:
            return None
        expression = (
            f"network-traffic:dst_ref.type = 'ipv{address.version}-addr' AND "
            f"network-traffic:dst_ref.value = {_quote(str(address))} AND "
            f"network-traffic:dst_port = {int(port)}"
        )
        return "ip-dst|port", f"{address}|{int(port)}", expression
    if kind in {"ip", "ipv4", "ipv6"}:
        if "%" in value:
            return None
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        return (
            "ip-dst",
            str(address),
            f"ipv{address.version}-addr:value = {_quote(str(address))}",
        )
    if kind in {"domain", "url"}:
        path = "domain-name" if kind == "domain" else "url"
        return kind, value, f"{path}:value = {_quote(value)}"
    return None


def _families(report):
    """Map named intel families to the indicator values supporting the attribution."""
    payload = ((report.get("stages") or {}).get("intel") or {}).get("payload") or {}
    families = {}

    def add(name, values):
        if isinstance(name, str) and name.strip():
            families.setdefault(name.strip(), set()).update(
                v for v in values if isinstance(v, str)
            )

    for row in payload.get("matches") or []:
        add(row.get("malware_family"), [row.get("indicator")])
    attribution = payload.get("attribution") or {}
    for row in attribution.get("families") or []:
        if not row.get("apt") and row.get("category") != "suspicious":
            add(row.get("family"), row.get("indicators") or [])
    # configurations decoded from memory (malduck): the family is certain, its C2s support it
    memdumps = ((report.get("stages") or {}).get("memdumps") or {}).get("payload") or {}
    for config in memdumps.get("malware_configs") or []:
        iocs = config.get("iocs") or {}
        add(
            config.get("family"),
            [v for k in ("urls", "domains", "ips") for v in iocs.get(k) or []],
        )
    for row in (payload.get("online") or {}).get("results") or []:
        if row.get("status") == "ok":
            add(row.get("family"), [row.get("observable")])
            for name in row.get("families") or []:
                add(name, [row.get("observable")])
    return families


def stix_bundle(report: dict) -> dict:
    """Build a deterministic STIX 2.1 bundle without extracting indicators again."""
    timestamp = _time(report)
    identity_id = _id("identity", "CHIMERA")

    def obj(kind, key, **fields):
        return dict(
            type=kind,
            spec_version="2.1",
            id=_id(kind, key),
            created=timestamp,
            modified=timestamp,
            **fields,
        )

    identity = obj("identity", "CHIMERA", name="CHIMERA", identity_class="organization")
    key = str(
        report.get("analysis_id")
        or (report.get("sample") or {}).get("sha256")
        or "unknown"
    )
    analysis = obj(
        "malware-analysis",
        key,
        product="chimera",
        result=_verdict(report),
        analysis_started=timestamp,
        created_by_ref=identity_id,
    )
    objects = [identity, analysis]

    def relate(source, relationship, target):
        objects.append(
            obj(
                "relationship",
                f"{source}:{relationship}:{target}",
                relationship_type=relationship,
                source_ref=source,
                target_ref=target,
                created_by_ref=identity_id,
            )
        )

    families = _families(report)
    for name in sorted(families):
        malware = obj(
            "malware", name, name=name, is_family=True, created_by_ref=identity_id
        )
        objects.append(malware)
        relate(analysis["id"], "analysis-of", malware["id"])
    indicators = {}
    for ioc in report.get("iocs") or []:
        observable = _observable(ioc)
        if observable is None:
            continue
        pattern = f"[{observable[2]}]"
        if pattern not in indicators:
            indicator = obj(
                "indicator",
                pattern,
                pattern=pattern,
                pattern_type="stix",
                pattern_version="2.1",
                valid_from=timestamp,
                description=str(ioc.get("source") or "Report indicator"),
                created_by_ref=identity_id,
            )
            indicators[pattern] = indicator
            objects.append(indicator)
        for name, values in sorted(families.items()):
            if ioc["value"] in values:
                relate(indicators[pattern]["id"], "indicates", _id("malware", name))
    objects = list({o["id"]: o for o in objects}.values())
    return {"type": "bundle", "id": _id("bundle", key), "objects": objects}


def misp_event(report: dict) -> dict:
    """Build a private MISP event using the report's normalized indicators."""
    verdict = _verdict(report)
    attributes = []
    for ioc in report.get("iocs") or []:
        observable = _observable(ioc)
        if observable is None:
            continue
        kind, value, _ = observable
        source = str(ioc.get("source") or "")
        attributes.append(
            dict(
                type=kind,
                value=value,
                # a string merely present in the file or a dump is context, not something to alert on
                to_ids="not observed in use" not in source,
                distribution="0",
                comment=str(
                    ioc.get("source") or ioc.get("observed_in") or "Report indicator"
                ),
            )
        )
    tags = [{"name": "tlp:amber"}]
    tags.extend(
        {"name": "chimera:family=" + json.dumps(name, ensure_ascii=False)}
        for name in sorted(_families(report))
    )
    return {
        "Event": dict(
            info=f"CHIMERA analysis {report.get('analysis_id') or 'unknown'} ({verdict})",
            date=_time(report)[:10],
            threat_level_id={
                "malicious": "1",
                "suspicious": "2",
                "benign": "4",
                "unknown": "4",
            }[verdict],
            analysis="2",
            distribution="0",
            Attribute=attributes,
            Tag=tags,
        )
    }
