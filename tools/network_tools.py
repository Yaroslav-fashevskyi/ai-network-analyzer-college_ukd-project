from __future__ import annotations

import platform
import re
import shutil
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

import dns.resolver
import dns.reversename

from core.security import clip_text


COMMON_PORTS = [
    22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    3306, 5432, 6379, 8080, 8443, 25565, 27015,
]


def _run_command(args: list[str], timeout: float = 10) -> dict[str, Any]:
    started = time.time()
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "duration_seconds": round(time.time() - started, 3),
            "stdout": clip_text(completed.stdout, 5000),
            "stderr": clip_text(completed.stderr, 2000),
            "command": args,
        }
    except FileNotFoundError:
        return {"ok": False, "error": f"Command not found: {args[0]}", "command": args}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Command timed out", "command": args, "timeout": timeout}


def ping_target(target: str, count: int = 4) -> dict[str, Any]:
    system = platform.system().lower()
    if "windows" in system:
        args = ["ping", "-n", str(count), target]
    else:
        args = ["ping", "-c", str(count), "-W", "2", target]

    result = _run_command(args, timeout=max(6, count * 3))
    output = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"

    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", output)
    avg_match = re.search(r"=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+\s*ms", output)
    windows_avg = re.search(r"Average\s*=\s*(\d+)ms", output, re.IGNORECASE)

    result["parsed"] = {
        "packet_loss_percent": float(loss_match.group(1)) if loss_match else None,
        "avg_rtt_ms": float(avg_match.group(1)) if avg_match else (float(windows_avg.group(1)) if windows_avg else None),
    }
    return result


def traceroute_target(target: str) -> dict[str, Any]:
    system = platform.system().lower()
    if "windows" in system:
        args = ["tracert", "-d", target]
    else:
        command = shutil.which("traceroute") or shutil.which("tracepath")
        if not command:
            return {"ok": False, "error": "traceroute/tracepath not installed"}
        args = [command, target]
    return _run_command(args, timeout=25)


def dns_lookup(domain: str) -> dict[str, Any]:
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 3
    results: dict[str, Any] = {"ok": True, "domain": domain, "records": {}}

    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            values = []
            for answer in answers:
                values.append(str(answer).strip())
            results["records"][record_type] = values
        except Exception as exc:
            results["records"][record_type] = {"error": exc.__class__.__name__}
    return results


def reverse_dns(ip: str) -> dict[str, Any]:
    try:
        reverse_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(reverse_name, "PTR")
        return {"ok": True, "ip": ip, "ptr": [str(a).rstrip(".") for a in answers]}
    except Exception as exc:
        return {"ok": False, "ip": ip, "error": str(exc)}


def _probe_single_port(host: str, port: int, timeout: float) -> dict[str, Any]:
    started = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"port": port, "open": True, "latency_ms": round((time.time() - started) * 1000, 2)}
    except Exception as exc:
        return {"port": port, "open": False, "error": exc.__class__.__name__}


def common_port_probe(host: str, ports: list[int] | None = None, timeout: float = 1.2, max_ports: int = 18) -> dict[str, Any]:
    selected_ports = (ports or COMMON_PORTS)[:max_ports]
    results = []
    with ThreadPoolExecutor(max_workers=min(8, len(selected_ports))) as pool:
        futures = [pool.submit(_probe_single_port, host, port, timeout) for port in selected_ports]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: item["port"])
    return {
        "ok": True,
        "host": host,
        "safe_note": "Lightweight connectivity check, not a full security scan.",
        "ports": results,
    }


def tls_certificate_info(domain: str, port: int = 443) -> dict[str, Any]:
    context = ssl.create_default_context()
    started = time.time()
    try:
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
        return {
            "ok": True,
            "domain": domain,
            "port": port,
            "duration_seconds": round(time.time() - started, 3),
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "subject_alt_name": cert.get("subjectAltName"),
            "cipher": cipher,
            "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        return {"ok": False, "domain": domain, "port": port, "error": str(exc)}
