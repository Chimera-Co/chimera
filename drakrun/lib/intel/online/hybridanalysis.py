"""Hybrid Analysis observable lookup adapter.

The API moved from www.hybrid-analysis.com to hybrid-analysis.com (the old host answers 301, which lookups
refuse). Hash search is ``GET /api/v2/search/hash?hash=...`` and answers
``{"sha256s": [...], "reports": [{"id", "environment_description", "state", "verdict", ...}]}``;
the earlier POST form and its list-of-reports answer were retired. Family names and threat scores now
live in each report's summary, which would cost one more call per report, so they are not fetched.
"""

from collections import Counter
from urllib.parse import quote

from .base import HASHES, Provider

# Hybrid Analysis verdicts of finished reports, worst first.
SEVERITY = {"malicious": 3, "suspicious": 2, "no specific threat": 1, "whitelisted": 0}


class Adapter(Provider):
    id = "hybridanalysis"
    label = "Hybrid Analysis"
    host = "hybrid-analysis.com"
    types = HASHES
    header = "api-key"
    optional_key = False
    interval = 2
    max_lookups = 3

    def request(self, kind, value):

        return (
            f"https://{self.host}/api/v2/search/hash?hash={quote(value, safe='')}",
            None,
            {"User-Agent": "Falcon Sandbox", "Accept": "application/json"},
        )

    def parse(self, doc, kind, value):

        reports = doc.get("reports") if isinstance(doc, dict) else None
        if not reports:
            return {"status": "not_found"}
        done = [r for r in reports if r.get("state") == "SUCCESS" and r.get("verdict")]
        worst = max(done, key=lambda r: SEVERITY.get(r["verdict"], -1), default=None)
        top = worst["verdict"] if worst else None
        sha256 = (doc.get("sha256s") or [value])[0]
        return dict(
            verdict=(
                top
                if top in ("malicious", "suspicious")
                else "harmless" if top == "whitelisted" else "unknown"
            ),
            permalink=f"https://hybrid-analysis.com/sample/{sha256}",
            details={
                "reports": len(reports),
                "finished": len(done),
                "verdicts": dict(Counter(r["verdict"] for r in done)),
                "environments": sorted(
                    {
                        r["environment_description"]
                        for r in done
                        if r.get("environment_description")
                    }
                )[:10],
            },
        )
