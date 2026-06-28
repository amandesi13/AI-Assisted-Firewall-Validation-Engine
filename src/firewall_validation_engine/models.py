from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Network, ip_network
from typing import Any, Literal

Action = Literal["allow", "deny"]
Protocol = Literal["tcp", "udp", "icmp", "any"]
Severity = Literal["low", "medium", "high", "critical"]


def parse_network(value: str) -> IPv4Network:
    if value == "any":
        return ip_network("0.0.0.0/0")
    return ip_network(value, strict=False)


def normalize_ports(value: Any) -> frozenset[int] | Literal["any"]:
    if value in (None, "any"):
        return "any"
    if not isinstance(value, list):
        raise ValueError("ports must be a list of integers or 'any'")
    ports = set()
    for port in value:
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ValueError(f"invalid port: {port!r}")
        ports.add(port)
    return frozenset(ports)


@dataclass(frozen=True)
class Rule:
    id: str
    action: Action
    source: IPv4Network
    destination: IPv4Network
    protocol: Protocol
    ports: frozenset[int] | Literal["any"] = "any"
    description: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rule":
        required = ["id", "action", "source", "destination", "protocol"]
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError(f"rule missing required fields: {', '.join(missing)}")

        action = data["action"]
        if action not in ("allow", "deny"):
            raise ValueError(f"rule {data['id']} has invalid action: {action}")

        protocol = data["protocol"]
        if protocol not in ("tcp", "udp", "icmp", "any"):
            raise ValueError(f"rule {data['id']} has invalid protocol: {protocol}")

        return cls(
            id=str(data["id"]),
            action=action,
            source=parse_network(str(data["source"])),
            destination=parse_network(str(data["destination"])),
            protocol=protocol,
            ports=normalize_ports(data.get("ports", "any")),
            description=str(data.get("description", "")),
        )

    def signature(self) -> tuple[object, ...]:
        return (
            self.action,
            self.source,
            self.destination,
            self.protocol,
            self.ports,
        )


@dataclass(frozen=True)
class Policy:
    name: str
    default_action: Action
    rules: tuple[Rule, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        default_action = data.get("default_action", "deny")
        if default_action not in ("allow", "deny"):
            raise ValueError("default_action must be 'allow' or 'deny'")

        rules = tuple(Rule.from_dict(item) for item in data.get("rules", []))
        if not rules:
            raise ValueError("policy must contain at least one rule")

        return cls(
            name=str(data.get("name", "unnamed-policy")),
            default_action=default_action,
            rules=rules,
        )


@dataclass(frozen=True)
class Packet:
    source: IPv4Network
    destination: IPv4Network
    protocol: Protocol
    port: int | None = None

    @classmethod
    def single_host(
        cls,
        source: str,
        destination: str,
        protocol: Protocol,
        port: int | None,
    ) -> "Packet":
        if protocol not in ("tcp", "udp", "icmp", "any"):
            raise ValueError(f"invalid protocol: {protocol}")
        if port is not None and (port < 1 or port > 65535):
            raise ValueError(f"invalid port: {port}")
        return cls(
            source=parse_network(f"{source}/32"),
            destination=parse_network(f"{destination}/32"),
            protocol=protocol,
            port=port,
        )


@dataclass(frozen=True)
class Evaluation:
    action: Action
    matched_rule: Rule | None
    reason: str


@dataclass(frozen=True)
class Finding:
    severity: Severity
    title: str
    rule_id: str | None
    message: str
    recommendation: str

    def to_dict(self) -> dict[str, str | None]:
        return {
            "severity": self.severity,
            "title": self.title,
            "rule_id": self.rule_id,
            "message": self.message,
            "recommendation": self.recommendation,
        }
