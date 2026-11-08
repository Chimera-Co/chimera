"""Bounded public IPv4 resolution outside the simulated guest network."""

import ipaddress
import json
import ssl
import urllib.request
from urllib.parse import urlencode, urlsplit

from . import base

HOST = "cloudflare-dns.com"
MAX_RESPONSE = 2 * 1024 * 1024


def public_ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
        return (
            address.is_global and not address.is_multicast and not address.is_reserved
        )
    except (ValueError, TypeError):
        return False


def resolve(domains, config, cache):
    resolved = []
    for domain in domains:
        try:
            ips = cache.get("doh", "domain", domain)
            if ips is None:
                url = f"https://{HOST}/dns-query?" + urlencode(
                    {"name": domain, "type": "A"}
                )
                parsed = urlsplit(url)
                if (
                    parsed.scheme != "https"
                    or parsed.hostname != HOST
                    or parsed.username
                    or parsed.password
                ):
                    raise ValueError("invalid endpoint")
                if not base.probe(HOST) or not cache.reserve("doh", 0, 500):
                    continue
                opener = urllib.request.build_opener(
                    base.NoRedirect(),
                    urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                )
                with opener.open(
                    urllib.request.Request(
                        url, headers={"accept": "application/dns-json"}
                    ),
                    timeout=min(config.request_timeout_s, 10),
                ) as response:
                    raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise ValueError("response too large")
                doc = json.loads(raw)
                if doc.get("Status") != 0:
                    continue
                ips = list(
                    dict.fromkeys(
                        row.get("data")
                        for row in doc.get("Answer", [])
                        if row.get("type") == 1 and public_ipv4(row.get("data"))
                    )
                )[: config.max_observables]
                cache.put("doh", "domain", domain, ips)
            resolved.extend((domain, ip) for ip in ips if public_ipv4(ip))
        except (OSError, ValueError, TypeError, AttributeError):
            continue
    return resolved
