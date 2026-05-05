from __future__ import annotations

import ipaddress
import re

from core.schemas import TargetInfo


class InputValidationError(ValueError):
    """Raised when user input is not a valid IP, domain, or ASN."""


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)
ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)

PROMPT_INJECTION_MARKERS = (
    "ignore previous instructions",
    "system prompt",
    "developer message",
    "jailbreak",
    "forget your rules",
    "act as",
)


def normalize_target(raw: str) -> TargetInfo:
    if raw is None:
        raise InputValidationError("Порожній ввід.")

    value = raw.strip()
    if not value:
        raise InputValidationError("Потрібно ввести IP, домен або ASN.")

    lowered = value.lower()
    if any(marker in lowered for marker in PROMPT_INJECTION_MARKERS):
        raise InputValidationError("Схоже на prompt injection, а не на мережеву ціль.")

    # IP address
    try:
        ip = ipaddress.ip_address(value)
        return TargetInfo(raw=raw, normalized=str(ip), target_type="ip")
    except ValueError:
        pass

    # ASN: AS15169 or 15169
    asn_match = ASN_RE.match(value)
    if asn_match:
        asn_number = int(asn_match.group(1))
        if asn_number <= 0:
            raise InputValidationError("ASN має бути додатним числом.")
        return TargetInfo(raw=raw, normalized=f"AS{asn_number}", target_type="asn")

    # Domain
    domain = value.rstrip(".").lower()
    if DOMAIN_RE.match(domain):
        return TargetInfo(raw=raw, normalized=domain, target_type="domain")

    raise InputValidationError("Ввід не схожий на IP-адресу, домен або ASN.")


def clip_text(text: str, limit: int = 6000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"
