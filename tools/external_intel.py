from __future__ import annotations

import ipaddress
from typing import Any

import dns.resolver
import httpx


def _json_get(url: str, timeout: float = 8, headers: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers) as client:
            response = client.get(url)
            return {
                "ok": response.is_success,
                "status_code": response.status_code,
                "url": url,
                "data": response.json() if response.content else None,
            }
    except Exception as exc:
        return {"ok": False, "url": url, "error": str(exc)}


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_first_ip(domain: str) -> str | None:
    for record_type in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for answer in answers:
                return str(answer)
        except Exception:
            continue
    return None


def geoip_lookup(target: str, timeout: float = 8) -> dict[str, Any]:
    # ip-api.com supports both IP and domain names for basic lookup.
    fields = "status,message,continent,country,regionName,city,lat,lon,timezone,isp,org,as,asname,query,hosting,proxy,mobile"
    return _json_get(f"http://ip-api.com/json/{target}?fields={fields}", timeout=timeout)


def rdap_lookup(target: str, target_type: str, timeout: float = 8) -> dict[str, Any]:
    if target_type == "ip":
        return _json_get(f"https://rdap.org/ip/{target}", timeout=timeout)
    if target_type == "domain":
        return _json_get(f"https://rdap.org/domain/{target}", timeout=timeout)
    if target_type == "asn":
        asn_number = target.upper().replace("AS", "")
        return _json_get(f"https://rdap.org/autnum/{asn_number}", timeout=timeout)
    return {"ok": False, "error": f"Unsupported target_type: {target_type}"}


def ripe_network_info(target: str, target_type: str, timeout: float = 8) -> dict[str, Any]:
    resource = target
    if target_type == "domain":
        resolved = resolve_first_ip(target)
        if not resolved:
            return {"ok": False, "error": "Could not resolve domain to IP for RIPEstat lookup"}
        resource = resolved

    if target_type == "asn":
        resource = target.upper()

    network_info = _json_get(f"https://stat.ripe.net/data/network-info/data.json?resource={resource}", timeout=timeout)
    announced_prefixes = None
    if target_type == "asn":
        announced_prefixes = _json_get(f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={resource}", timeout=timeout)

    return {
        "ok": network_info.get("ok", False),
        "resource": resource,
        "network_info": network_info,
        "announced_prefixes": announced_prefixes,
    }


def dnsbl_check(ip: str) -> dict[str, Any]:
    if not _is_ip(ip):
        return {"ok": False, "error": "DNSBL check requires IP address"}

    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.version != 4:
        return {"ok": False, "ip": ip, "error": "DNSBL demo checks IPv4 only"}

    zones = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
    ]
    reversed_ip = ".".join(reversed(ip.split(".")))
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3

    listed = []
    for zone in zones:
        query = f"{reversed_ip}.{zone}"
        try:
            answers = resolver.resolve(query, "A")
            listed.append({"zone": zone, "answers": [str(a) for a in answers]})
        except Exception:
            pass

    return {
        "ok": True,
        "ip": ip,
        "listed": listed,
        "listed_count": len(listed),
        "note": "DNSBL is a risk signal, not a final proof of abuse.",
    }


def abuseipdb_lookup(ip: str, api_key: str | None, timeout: float = 8) -> dict[str, Any]:
    if not api_key:
        return {"ok": False, "skipped": True, "reason": "ABUSEIPDB_API_KEY is not configured"}
    if not _is_ip(ip):
        return {"ok": False, "error": "AbuseIPDB requires IP address"}

    headers = {"Key": api_key, "Accept": "application/json"}
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose=true"
    return _json_get(url, timeout=timeout, headers=headers)
