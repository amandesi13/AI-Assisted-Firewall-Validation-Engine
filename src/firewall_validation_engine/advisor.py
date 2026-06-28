from __future__ import annotations

from .analyzer import summarize_by_severity
from .models import Finding, Policy


def build_review(policy: Policy, findings: list[Finding]) -> str:
    if not findings:
        return (
            f"AI review for {policy.name}: no anomalies were detected. "
            "Keep monitoring future changes with automated validation before deployment."
        )

    summary = summarize_by_severity(findings)
    ordered = ", ".join(f"{severity}: {count}" for severity, count in sorted(summary.items()))
    top = findings[0]

    return (
        f"AI review for {policy.name}: detected {len(findings)} finding(s) ({ordered}). "
        f"The highest priority issue is '{top.title}'"
        f"{' in rule ' + top.rule_id if top.rule_id else ''}. "
        f"Suggested next action: {top.recommendation}"
    )
