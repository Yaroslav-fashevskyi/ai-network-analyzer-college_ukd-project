from __future__ import annotations

import os
from dataclasses import dataclass


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass
class Settings:
    gemini_api_key: str | None
    gemini_model: str
    abuseipdb_api_key: str | None
    request_timeout_seconds: float
    ping_count: int
    port_timeout_seconds: float
    max_ports_to_check: int
    enable_traceroute: bool

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            gemini_api_key=os.getenv("GEMINI_API_KEY") or None,
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY") or None,
            request_timeout_seconds=float(os.getenv("REQUEST_TIMEOUT_SECONDS", "8")),
            ping_count=int(os.getenv("PING_COUNT", "4")),
            port_timeout_seconds=float(os.getenv("PORT_TIMEOUT_SECONDS", "1.2")),
            max_ports_to_check=int(os.getenv("MAX_PORTS_TO_CHECK", "18")),
            enable_traceroute=_bool_env("ENABLE_TRACEROUTE", False),
        )
