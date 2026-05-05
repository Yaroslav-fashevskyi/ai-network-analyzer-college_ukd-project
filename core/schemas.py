from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TargetInfo:
    raw: str
    normalized: str
    target_type: str  # ip, domain, asn

    @property
    def safe_name(self) -> str:
        return self.normalized.replace("/", "_").replace(":", "_").replace(".", "_")
