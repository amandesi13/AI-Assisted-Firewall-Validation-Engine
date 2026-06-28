from __future__ import annotations

from .models import Evaluation, Packet, Policy, Rule


def network_contains(rule_network, packet_network) -> bool:
    return packet_network.subnet_of(rule_network)


def protocol_matches(rule: Rule, packet: Packet) -> bool:
    return rule.protocol == "any" or packet.protocol == "any" or rule.protocol == packet.protocol


def port_matches(rule: Rule, packet: Packet) -> bool:
    if rule.protocol == "icmp":
        return True
    if rule.ports == "any":
        return True
    return packet.port in rule.ports


def rule_matches_packet(rule: Rule, packet: Packet) -> bool:
    return (
        network_contains(rule.source, packet.source)
        and network_contains(rule.destination, packet.destination)
        and protocol_matches(rule, packet)
        and port_matches(rule, packet)
    )


def rule_covers_rule(earlier: Rule, later: Rule) -> bool:
    protocol_covers = earlier.protocol == "any" or earlier.protocol == later.protocol
    if not protocol_covers:
        return False

    if earlier.ports != "any":
        if later.ports == "any":
            return False
        if not later.ports.issubset(earlier.ports):
            return False

    return (
        later.source.subnet_of(earlier.source)
        and later.destination.subnet_of(earlier.destination)
    )


def evaluate_packet(policy: Policy, packet: Packet) -> Evaluation:
    for rule in policy.rules:
        if rule_matches_packet(rule, packet):
            return Evaluation(
                action=rule.action,
                matched_rule=rule,
                reason=f"matched first applicable rule: {rule.id}",
            )
    return Evaluation(
        action=policy.default_action,
        matched_rule=None,
        reason=f"no rule matched; used default action: {policy.default_action}",
    )
