"""Portable exports use only synthetic report indicators and intel."""

import copy
import importlib
import json
import sys
from uuid import UUID

import pytest

from drakrun.lib.chimera_report.stix_misp import misp_event, stix_bundle


@pytest.fixture
def report():
    values = [
        ("sha256", "a" * 64),
        ("sha1", "b" * 40),
        ("md5", "c" * 32),
        ("domain", "example.test"),
        ("ip", "192.0.2.1"),
        ("ip", "2001:db8::1"),
        ("url", "https://example.test/a?x='quoted'\\value"),
        ("endpoint", "192.0.2.1:443"),
        ("ip_port", "[2001:db8::1]:8443"),
    ]
    return {
        "analysis_id": "10000000-0000-4000-8000-000000000001",
        "generated_at": "2026-11-08T12:00:00Z",
        "assessment": {"label": "malicious"},
        "iocs": [
            dict(type=kind, value=value, source="observed by the sample")
            for kind, value in values
        ],
        "stages": {
            "dynamic": {"started_at": "2026-11-07T10:15:20.123456+05:30"},
            "intel": {
                "payload": {
                    "matches": [
                        {"malware_family": "OfflineFamily", "indicator": "example.test"}
                    ],
                    "attribution": {
                        "families": [
                            {
                                "family": "TrailFamily",
                                "category": "malware",
                                "indicators": ["192.0.2.1"],
                            },
                            {"family": "Parking", "category": "suspicious"},
                            {"family": "Group", "apt": True},
                        ]
                    },
                    "online": {
                        "results": [
                            {
                                "status": "ok",
                                "family": "OnlineFamily",
                                "observable": "a" * 64,
                                "tags": ["trojan"],
                            },
                            {"status": "error", "family": "Ignored"},
                        ]
                    },
                }
            },
        },
    }


def test_stix_patterns(report):
    patterns = [
        o["pattern"] for o in stix_bundle(report)["objects"] if o["type"] == "indicator"
    ]
    assert patterns == [
        "[file:hashes.'SHA-256' = '" + "a" * 64 + "']",
        "[file:hashes.'SHA-1' = '" + "b" * 40 + "']",
        "[file:hashes.'MD5' = '" + "c" * 32 + "']",
        "[domain-name:value = 'example.test']",
        "[ipv4-addr:value = '192.0.2.1']",
        "[ipv6-addr:value = '2001:db8::1']",
        "[url:value = 'https://example.test/a?x=\\'quoted\\'\\\\value']",
        "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '192.0.2.1' AND network-traffic:dst_port = 443]",
        "[network-traffic:dst_ref.type = 'ipv6-addr' AND network-traffic:dst_ref.value = '2001:db8::1' AND network-traffic:dst_port = 8443]",
    ]


def test_stix_fields_relationships_and_stability(report):
    before = copy.deepcopy(report)
    bundle = stix_bundle(report)
    assert bundle == stix_bundle(copy.deepcopy(report))
    assert report == before
    assert bundle["type"] == "bundle"
    objects = {o["id"]: o for o in bundle["objects"]}
    for obj in objects.values():
        assert obj["spec_version"] == "2.1"
        assert obj["id"].startswith(obj["type"] + "--")
        assert UUID(obj["id"].split("--")[1]).version == 5
        assert obj["created"] == obj["modified"] == "2026-11-07T04:45:20.123Z"
    assert {o["name"] for o in objects.values() if o["type"] == "malware"} == {
        "OfflineFamily",
        "TrailFamily",
        "OnlineFamily",
    }
    relations = [o for o in objects.values() if o["type"] == "relationship"]
    assert len(relations) == 6
    for relation in relations:
        source, target = (
            objects[relation["source_ref"]],
            objects[relation["target_ref"]],
        )
        assert target["type"] == "malware"
        assert (source["type"], relation["relationship_type"]) in {
            ("indicator", "indicates"),
            ("malware-analysis", "analysis-of"),
        }
    report["iocs"].append(report["iocs"][3])
    assert stix_bundle(report) == bundle


@pytest.mark.parametrize(
    "verdict", ["malicious", "suspicious", "benign", "unknown", "invalid"]
)
def test_verdict_mapping(report, verdict):
    report["assessment"]["label"] = verdict
    analysis = next(
        o for o in stix_bundle(report)["objects"] if o["type"] == "malware-analysis"
    )
    assert analysis["product"] == "chimera"
    assert analysis["result"] == ("unknown" if verdict == "invalid" else verdict)


@pytest.mark.parametrize(
    "kind,value",
    [
        ("endpoint", "host.test:443"),
        ("ip_port", "192.0.2.1:0"),
        ("endpoint", "192.0.2.1:65536"),
        ("endpoint", "192.0.2.1:None"),
        ("endpoint", "None:443"),
        ("ip", "invalid"),
        ("sha256", "invalid"),
        ("domain", None),
        ("url", "https://example.test/\n"),
        ("unsupported", "x"),
    ],
)
def test_invalid_observables_are_omitted(kind, value):
    report = {"iocs": [{"type": kind, "value": value}]}
    assert not any(o["type"] == "indicator" for o in stix_bundle(report)["objects"])
    assert misp_event(report)["Event"]["Attribute"] == []


def test_misp_event(report):
    before = copy.deepcopy(report)
    event = misp_event(report)["Event"]
    assert report == before
    assert event["distribution"] == "0"
    assert event["date"] == "2026-11-07"
    assert event["threat_level_id"] == "1" and event["analysis"] == "2"
    assert report["analysis_id"] in event["info"]
    attributes = event["Attribute"]
    assert [a["type"] for a in attributes] == [
        "sha256",
        "sha1",
        "md5",
        "domain",
        "ip-dst",
        "ip-dst",
        "url",
        "ip-dst|port",
        "ip-dst|port",
    ]
    assert attributes[-1]["value"] == "2001:db8::1|8443"
    assert all(
        a["to_ids"] is True and a["comment"] == "observed by the sample"
        for a in attributes
    )
    assert {t["name"] for t in event["Tag"]} == {
        "tlp:amber",
        'chimera:family="OfflineFamily"',
        'chimera:family="TrailFamily"',
        'chimera:family="OnlineFamily"',
    }


def test_missing_time_is_deterministic():
    assert misp_event({})["Event"]["date"] == "1970-01-01"
    assert stix_bundle({}) == stix_bundle({})


@pytest.fixture
def api_client(monkeypatch, base_config, tmp_path):
    monkeypatch.setattr("drakrun.lib.config.load_config", lambda: base_config)
    monkeypatch.setattr("drakrun.web.storage.ANALYSES_DIR", tmp_path)
    sys.modules.pop("drakrun.web.api", None)
    module = importlib.import_module("drakrun.web.api")
    from flask_openapi3 import Info, OpenAPI

    app = OpenAPI(__name__, info=Info(title="test", version="0"))
    app.register_api(module.api)
    yield app.test_client()
    sys.modules.pop("drakrun.web.api", None)


@pytest.mark.parametrize("export,build", [("stix", stix_bundle), ("misp", misp_event)])
def test_export_endpoints(api_client, tmp_path, report, export, build):
    uid = report["analysis_id"]
    route = f"/api/chimera_report/{uid}/{export}.json"
    missing = api_client.get(route)
    assert missing.status_code == 404
    assert missing.json == {"error": "Data not found"}
    directory = tmp_path / uid
    directory.mkdir()
    (directory / "chimera-report.json").write_text(json.dumps(report))
    response = api_client.get(route)
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    assert (
        response.headers["Content-Disposition"]
        == f"attachment; filename={export}-{uid}.json"
    )
    assert response.json == build(report)


def test_strings_are_not_ids_and_config_families_are_named():
    from drakrun.lib.chimera_report.stix_misp import misp_event, stix_bundle

    report = {
        "analysis_id": "a",
        "iocs": [
            {
                "type": "domain",
                "value": "c2.example.org",
                "source": "remcos malware configuration (memory)",
            },
            {
                "type": "domain",
                "value": "str.example.org",
                "source": "string in the file (not observed in use)",
            },
        ],
        "stages": {
            "memdumps": {
                "payload": {
                    "malware_configs": [
                        {"family": "remcos", "iocs": {"domains": ["c2.example.org"]}}
                    ]
                }
            }
        },
    }
    attrs = {a["value"]: a["to_ids"] for a in misp_event(report)["Event"]["Attribute"]}
    assert attrs == {"c2.example.org": True, "str.example.org": False}
    objects = stix_bundle(report)["objects"]
    malware = [o for o in objects if o["type"] == "malware"]
    assert [m["name"] for m in malware] == ["remcos"]
    assert any(
        o["type"] == "relationship"
        and o["relationship_type"] == "indicates"
        and o["target_ref"] == malware[0]["id"]
        for o in objects
    )
