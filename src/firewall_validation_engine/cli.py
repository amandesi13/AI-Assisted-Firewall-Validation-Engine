from __future__ import annotations

import argparse
import json
from pathlib import Path

from .advisor import build_review
from .analyzer import analyze_policy
from .evaluator import evaluate_packet
from .models import Packet
from .parser import load_policy


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:
        print(f"error: {exc}")
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="firewall-validate",
        description="Validate firewall policies and simulate first-match rule flow.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="Analyze a firewall policy")
    validate.add_argument("policy", type=Path)
    validate.add_argument("--format", choices=["text", "json"], default="text")
    validate.set_defaults(func=run_validate)

    simulate = subparsers.add_parser("simulate", help="Simulate a packet against a policy")
    simulate.add_argument("policy", type=Path)
    simulate.add_argument("--src", required=True)
    simulate.add_argument("--dst", required=True)
    simulate.add_argument("--protocol", required=True, choices=["tcp", "udp", "icmp", "any"])
    simulate.add_argument("--port", type=int)
    simulate.set_defaults(func=run_simulate)

    return parser


def run_validate(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    findings = analyze_policy(policy)
    if args.format == "json":
        print(
            json.dumps(
                {
                    "policy": policy.name,
                    "default_action": policy.default_action,
                    "rules": len(policy.rules),
                    "findings": [finding.to_dict() for finding in findings],
                    "review": build_review(policy, findings),
                },
                indent=2,
            )
        )
    else:
        print_text_report(policy, findings)
    return 1 if any(f.severity in ("high", "critical") for f in findings) else 0


def run_simulate(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    packet = Packet.single_host(args.src, args.dst, args.protocol, args.port)
    result = evaluate_packet(policy, packet)
    matched = result.matched_rule.id if result.matched_rule else "default"
    print(f"action={result.action}")
    print(f"matched_rule={matched}")
    print(f"reason={result.reason}")
    return 0


def print_text_report(policy, findings) -> None:
    print(f"Policy: {policy.name}")
    print(f"Default action: {policy.default_action}")
    print(f"Rules: {len(policy.rules)}")
    print(f"Findings: {len(findings)}")
    print()
    for finding in findings:
        rule = f" ({finding.rule_id})" if finding.rule_id else ""
        print(f"[{finding.severity.upper()}] {finding.title}{rule}")
        print(finding.message)
        print(f"Recommendation: {finding.recommendation}")
        print()
    print(build_review(policy, findings))
