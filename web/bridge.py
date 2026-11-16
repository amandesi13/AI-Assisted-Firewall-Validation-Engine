"""Entry points for the browser demo.

The page loads the real `firewall_validation_engine` package into Pyodide
(Python compiled to WebAssembly) and calls these two functions. Both take and
return JSON strings so the JavaScript side never touches Python objects.
"""

from __future__ import annotations

import json

from firewall_validation_engine.advisor import build_review
from firewall_validation_engine.analyzer import analyze_policy, summarize_by_severity
from firewall_validation_engine.evaluator import evaluate_packet
from firewall_validation_engine.models import Packet, Policy, Rule


def _load(policy_json: str) -> Policy:
    data = json.loads(policy_json)
    if not isinstance(data, dict):
        raise ValueError("policy must be a JSON object")
    return Policy.from_dict(data)


def _rule_dict(rule: Rule) -> dict[str, object]:
    return {
        "id": rule.id,
        "action": rule.action,
        "source": str(rule.source),
        "destination": str(rule.destination),
        "protocol": rule.protocol,
        "ports": "any" if rule.ports == "any" else sorted(rule.ports),
        "description": rule.description,
    }


def _error(exc: Exception) -> str:
    return json.dumps({"ok": False, "error": str(exc)})


def validate(policy_json: str) -> str:
    """Analyze a policy: findings sorted by severity plus the review summary."""
    try:
        policy = _load(policy_json)
    except (ValueError, TypeError) as exc:
        return _error(exc)
    findings = analyze_policy(policy)
    return json.dumps(
        {
            "ok": True,
            "policy": policy.name,
            "default_action": policy.default_action,
            "rules": [_rule_dict(rule) for rule in policy.rules],
            "summary": summarize_by_severity(findings),
            "findings": [finding.to_dict() for finding in findings],
            "review": build_review(policy, findings),
        }
    )


def simulate(policy_json: str, src: str, dst: str, protocol: str, port: str) -> str:
    """Run one packet through first-match evaluation."""
    try:
        policy = _load(policy_json)
        port_number = int(port) if str(port).strip() else None
        packet = Packet.single_host(src.strip(), dst.strip(), protocol, port_number)
    except (ValueError, TypeError) as exc:
        return _error(exc)
    result = evaluate_packet(policy, packet)
    return json.dumps(
        {
            "ok": True,
            "action": result.action,
            "matched_rule": result.matched_rule.id if result.matched_rule else None,
            "reason": result.reason,
        }
    )
