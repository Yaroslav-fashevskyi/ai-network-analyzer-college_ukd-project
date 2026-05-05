from __future__ import annotations

import ipaddress
from typing import Any, Callable

from core.config import Settings
from core.gemini_client import GeminiNetworkClient, GeminiUnavailable
from core.rag import LocalKnowledgeBase
from core.schemas import TargetInfo
from tools.external_intel import abuseipdb_lookup, dnsbl_check, geoip_lookup, rdap_lookup, ripe_network_info, resolve_first_ip
from tools.network_tools import common_port_probe, dns_lookup, ping_target, reverse_dns, tls_certificate_info, traceroute_target


class NetworkIntelligenceAgent:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.gemini = GeminiNetworkClient(settings)
        self.kb = LocalKnowledgeBase()

    def analyze_target(
        self,
        target_info: TargetInfo,
        use_ai_planner: bool = True,
        enable_traceroute: bool = False,
        safe_mode: bool = True,
    ) -> dict[str, Any]:
        tool_plan = self._build_tool_plan(target_info, use_ai_planner=use_ai_planner)
        if enable_traceroute and target_info.target_type in {"ip", "domain"}:
            tool_plan.append({"name": "traceroute", "args": {"target": target_info.normalized}, "source": "ui_option"})

        tool_results = self._execute_plan(target_info, tool_plan, safe_mode=safe_mode)

        rag_query = self._build_rag_query(target_info, tool_results)
        rag_chunks = self.kb.retrieve(rag_query, k=5)
        rag_context = [chunk.__dict__ for chunk in rag_chunks]

        ai_analysis = self.gemini.analyze(
            target=target_info.normalized,
            target_type=target_info.target_type,
            tool_results=tool_results,
            rag_context=rag_context,
        )

        return {
            "summary": {
                "target": target_info.normalized,
                "target_type": target_info.target_type,
                "tools_executed": len(tool_results),
                "rag_chunks": len(rag_context),
                "ai_mode": "gemini" if self.gemini.available else "offline_fallback",
            },
            "target": target_info.__dict__,
            "tool_plan": tool_plan,
            "tool_results": tool_results,
            "rag_context": rag_context,
            "ai_analysis": ai_analysis,
            "security": {
                "input_was_validated": True,
                "accepted_target_type": target_info.target_type,
                "shell_execution": "subprocess uses shell=False; user input is passed as an argument, not as shell code",
                "prompt_injection_defense": "Only validated technical target is accepted; final prompt separates evidence JSON from system instruction",
                "safe_mode": safe_mode,
            },
        }

    def _build_tool_plan(self, target_info: TargetInfo, use_ai_planner: bool) -> list[dict[str, Any]]:
        if use_ai_planner and self.gemini.available:
            try:
                calls = self.gemini.choose_tools(target_info.normalized, target_info.target_type)
                cleaned = self._clean_ai_calls(calls, target_info)
                if cleaned:
                    return cleaned
            except GeminiUnavailable:
                pass
            except Exception as exc:
                # Fallback keeps live demo stable even when API/tool-calling fails.
                return self._default_tool_plan(target_info, reason=f"ai_planner_failed: {exc.__class__.__name__}")
        return self._default_tool_plan(target_info, reason="deterministic_fallback")

    def _clean_ai_calls(self, calls: list[dict[str, Any]], target_info: TargetInfo) -> list[dict[str, Any]]:
        allowed = set(self._allowed_tools(target_info.target_type))
        cleaned = []
        seen = set()
        for call in calls:
            name = call.get("name")
            if name not in allowed or name in seen:
                continue
            cleaned.append({"name": name, "args": {"target": target_info.normalized}, "source": call.get("source", "gemini")})
            seen.add(name)
        # Ensure critical baseline tools are present even if the model under-selects.
        for baseline in self._baseline_tools(target_info.target_type):
            if baseline not in seen:
                cleaned.append({"name": baseline, "args": {"target": target_info.normalized}, "source": "baseline_enforced"})
                seen.add(baseline)
        return cleaned

    def _baseline_tools(self, target_type: str) -> list[str]:
        if target_type == "domain":
            return ["dns_lookup", "ping", "geoip", "rdap", "ripe_bgp"]
        if target_type == "ip":
            return ["ping", "reverse_dns", "geoip", "rdap", "ripe_bgp"]
        if target_type == "asn":
            return ["rdap", "ripe_bgp"]
        return []

    def _allowed_tools(self, target_type: str) -> list[str]:
        if target_type == "domain":
            return ["dns_lookup", "ping", "geoip", "rdap", "ripe_bgp", "tls_certificate", "common_port_probe"]
        if target_type == "ip":
            return ["ping", "reverse_dns", "geoip", "rdap", "ripe_bgp", "dnsbl", "abuseipdb", "common_port_probe"]
        if target_type == "asn":
            return ["rdap", "ripe_bgp"]
        return []

    def _default_tool_plan(self, target_info: TargetInfo, reason: str) -> list[dict[str, Any]]:
        return [
            {"name": name, "args": {"target": target_info.normalized}, "source": reason}
            for name in self._allowed_tools(target_info.target_type)
        ]

    def _execute_plan(self, target_info: TargetInfo, plan: list[dict[str, Any]], safe_mode: bool) -> dict[str, Any]:
        results: dict[str, Any] = {}
        for item in plan:
            name = item["name"]
            target = item.get("args", {}).get("target", target_info.normalized)
            try:
                results[name] = self._execute_tool(name, target, target_info, safe_mode=safe_mode)
            except Exception as exc:
                results[name] = {"ok": False, "error": str(exc), "error_type": exc.__class__.__name__}
        return results

    def _execute_tool(self, name: str, target: str, target_info: TargetInfo, safe_mode: bool) -> dict[str, Any]:
        if name == "dns_lookup":
            return dns_lookup(target)
        if name == "ping":
            return ping_target(target, count=self.settings.ping_count)
        if name == "reverse_dns":
            return reverse_dns(target)
        if name == "geoip":
            return geoip_lookup(target, timeout=self.settings.request_timeout_seconds)
        if name == "rdap":
            return rdap_lookup(target, target_info.target_type, timeout=self.settings.request_timeout_seconds)
        if name == "ripe_bgp":
            return ripe_network_info(target, target_info.target_type, timeout=self.settings.request_timeout_seconds)
        if name == "tls_certificate":
            return tls_certificate_info(target)
        if name == "dnsbl":
            return dnsbl_check(target)
        if name == "abuseipdb":
            return abuseipdb_lookup(target, api_key=self.settings.abuseipdb_api_key, timeout=self.settings.request_timeout_seconds)
        if name == "common_port_probe":
            return common_port_probe(
                target,
                timeout=self.settings.port_timeout_seconds,
                max_ports=min(self.settings.max_ports_to_check, 18 if safe_mode else 32),
            )
        if name == "traceroute":
            return traceroute_target(target)
        return {"ok": False, "error": f"Unknown tool: {name}"}

    def _build_rag_query(self, target_info: TargetInfo, tool_results: dict[str, Any]) -> str:
        words = [target_info.target_type, target_info.normalized, "network risk analysis"]
        geo_data = tool_results.get("geoip", {}).get("data", {}) if isinstance(tool_results.get("geoip"), dict) else {}
        for key in ["as", "asname", "isp", "org", "hosting", "proxy"]:
            value = geo_data.get(key)
            if value is not None:
                words.append(str(value))
        if target_info.target_type == "domain":
            words.extend(["DNS", "TLS", "domain reputation"])
        if target_info.target_type == "ip":
            words.extend(["RDAP", "DNSBL", "reverse DNS", "latency"])
        if target_info.target_type == "asn":
            words.extend(["BGP", "prefixes", "autonomous system"])
        return " ".join(words)
