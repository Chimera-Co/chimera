"""RIPEstat routing context for public IP addresses."""

from urllib.parse import urlencode

from .base import Provider


class Adapter(Provider):
    id = "ripestat"
    label = "RIPEstat"
    host = "stat.ripe.net"
    types = ("ip",)
    optional_key = True
    header = None
    interval = 1
    daily_cap = 1000

    def request(self, kind, value):
        return (
            f"https://{self.host}/data/prefix-overview/data.json?"
            + urlencode({"resource": value, "sourceapp": "chimera"}),
            None,
            {},
        )

    def parse(self, doc, kind, value):
        data = doc.get("data") or {}
        asns = data.get("asns") or []
        if not data.get("announced") or not asns or not data.get("resource"):
            return dict(status="not_found")
        asn = asns[0]["asn"]
        return dict(
            verdict="unknown",
            tags=[f"AS{asn}"],
            details=dict(
                asn=asn,
                holder=asns[0].get("holder"),
                prefix=data["resource"],
                announced=data["announced"],
            ),
        )
