from __future__ import annotations

from collections import defaultdict

from .evaluator import rule_covers_rule
from .models import Finding, Policy, Rule

ADMIN_PORTS = {
    22: "SSH",
    3389: "RDP",
    5900: "VNC",
    5432: "PostgreSQL",
    3306: "MySQL",
    6379: "Redis",
}


def is_any_network(rule_network) -> bool:
    return str(rule_network) == "0.0.0.0/0"


def has_admin_port(rule: Rule) -> tuple[int, str] | None:
    if rule.ports == "any":
        return 22, "admin services"
    for port, label in ADMIN_PORTS.items():
        if port in rule.ports:
            return port, label
    return None


def analyze_policy(policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(find_duplicate_rules(policy))
    findings.extend(find_shadowed_rules(policy))
    findings.extend(find_broad_allows(policy))
    findings.extend(find_public_admin_exposure(policy))
    findings.extend(find_missing_default_deny(policy))
    return sorted(findings, key=severity_rank, reverse=True)


def severity_rank(finding: Finding) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}[finding.severity]


def find_duplicate_rules(policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    seen: dict[tuple[object, ...], Rule] = {}
    for rule in policy.rules:
        signature = rule.signature()
        if signature in seen:
            previous = seen[signature]
            findings.append(
                Finding(
                    severity="low",
                    title="Duplicate rule",
                    rule_id=rule.id,
                    message=f"Rule {rule.id} duplicates behavior already defined by {previous.id}.",
                    recommendation="Remove the duplicate or document why both rules are required.",
                )
            )
        else:
            seen[signature] = rule
    return findings


def find_shadowed_rules(policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    previous_rules: list[Rule] = []
    for rule in policy.rules:
        for previous in previous_rules:
            if rule_covers_rule(previous, rule):
                severity = "high" if previous.action != rule.action else "medium"
                findings.append(
                    Finding(
                        severity=severity,
                        title="Shadowed rule",
                        rule_id=rule.id,
                        message=f"Rule {rule.id} is shadowed by earlier rule {previous.id}.",
                        recommendation="Move the more specific rule earlier or narrow the broader rule.",
                    )
                )
                break
        previous_rules.append(rule)
    return findings


def find_broad_allows(policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    for rule in policy.rules:
        if rule.action != "allow":
            continue
        if is_any_network(rule.source) and is_any_network(rule.destination):
            findings.append(
                Finding(
                    severity="critical",
                    title="Any-to-any allow",
                    rule_id=rule.id,
                    message=f"Rule {rule.id} allows traffic from any source to any destination.",
                    recommendation="Replace this rule with explicit source, destination, protocol, and port constraints.",
                )
            )
        elif is_any_network(rule.source) and rule.ports == "any":
            findings.append(
                Finding(
                    severity="high",
                    title="Broad public allow",
                    rule_id=rule.id,
                    message=f"Rule {rule.id} allows all ports from the public internet.",
                    recommendation="Restrict ports and source networks to the smallest operationally required scope.",
                )
            )
    return findings


def find_public_admin_exposure(policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    for rule in policy.rules:
        if rule.action != "allow" or not is_any_network(rule.source):
            continue
        admin = has_admin_port(rule)
        if admin is None:
            continue
        port, label = admin
        findings.append(
            Finding(
                severity="high",
                title="Public admin exposure",
                rule_id=rule.id,
                message=f"Rule {rule.id} exposes {label} on port {port} from 0.0.0.0/0.",
                recommendation="Limit admin access to a VPN, bastion host, or trusted management subnet.",
            )
        )
    return findings


def find_missing_default_deny(policy: Policy) -> list[Finding]:
    if policy.default_action == "deny":
        return []
    return [
        Finding(
            severity="high",
            title="Permissive default action",
            rule_id=None,
            message="The policy default action is allow.",
            recommendation="Use default deny and explicitly allow only required traffic.",
        )
    ]


def summarize_by_severity(findings: list[Finding]) -> dict[str, int]:
    summary: dict[str, int] = defaultdict(int)
    for finding in findings:
        summary[finding.severity] += 1
    return dict(summary)
