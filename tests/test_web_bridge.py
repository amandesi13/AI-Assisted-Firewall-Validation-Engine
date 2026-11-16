"""The browser demo calls web/bridge.py; keep its JSON contract tested."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "web"))

import bridge  # noqa: E402

SAMPLE = (ROOT / "samples" / "policy.json").read_text(encoding="utf-8")


def test_validate_sample_policy():
    result = json.loads(bridge.validate(SAMPLE))

    assert result["ok"] is True
    assert result["policy"] == "sample-telecom-edge"
    assert len(result["rules"]) == 7
    assert result["rules"][0]["ports"] == [80, 443]
    assert result["rules"][-1]["ports"] == "any"
    titles = {finding["title"] for finding in result["findings"]}
    assert {"Public admin exposure", "Shadowed rule", "Duplicate rule"} <= titles
    assert sum(result["summary"].values()) == len(result["findings"])
    assert result["review"].startswith("AI review for sample-telecom-edge")


def test_validate_reports_bad_input_instead_of_raising():
    for text in ["not json", "[]", '{"rules": []}', '{"rules": [{"id": "x"}]}']:
        result = json.loads(bridge.validate(text))
        assert result["ok"] is False
        assert result["error"]


def test_simulate_first_match_and_default():
    hit = json.loads(bridge.simulate(SAMPLE, "203.0.113.10", "10.10.2.15", "tcp", "443"))
    assert hit == {
        "ok": True,
        "action": "allow",
        "matched_rule": "allow-web-public",
        "reason": "matched first applicable rule: allow-web-public",
    }

    miss = json.loads(bridge.simulate(SAMPLE, "203.0.113.10", "10.99.1.10", "tcp", "8443"))
    assert miss["matched_rule"] == "deny-all"


def test_simulate_rejects_bad_packet():
    assert json.loads(bridge.simulate(SAMPLE, "not-an-ip", "10.0.0.1", "tcp", "80"))["ok"] is False
    assert json.loads(bridge.simulate(SAMPLE, "10.0.0.2", "10.0.0.1", "tcp", "99999"))["ok"] is False
