from firewall_validation_engine.analyzer import analyze_policy
from firewall_validation_engine.evaluator import evaluate_packet
from firewall_validation_engine.models import Packet
from firewall_validation_engine.parser import load_policy


def test_sample_policy_detects_expected_risks():
    policy = load_policy("samples/policy.json")
    findings = analyze_policy(policy)
    titles = {finding.title for finding in findings}

    assert "Public admin exposure" in titles
    assert "Shadowed rule" in titles
    assert "Duplicate rule" in titles


def test_first_match_allows_web_packet():
    policy = load_policy("samples/policy.json")
    packet = Packet.single_host("203.0.113.10", "10.10.2.15", "tcp", 443)

    result = evaluate_packet(policy, packet)

    assert result.action == "allow"
    assert result.matched_rule is not None
    assert result.matched_rule.id == "allow-web-public"


def test_default_deny_blocks_unknown_flow():
    policy = load_policy("samples/policy.json")
    packet = Packet.single_host("203.0.113.10", "10.99.1.10", "tcp", 8443)

    result = evaluate_packet(policy, packet)

    assert result.action == "deny"
    assert result.matched_rule is not None
    assert result.matched_rule.id == "deny-all"
