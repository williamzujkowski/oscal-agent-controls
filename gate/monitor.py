from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
import re
from pathlib import Path
from typing import Any, Literal

import yaml


DecisionValue = Literal["allow", "deny"]


@dataclass(frozen=True)
class ToolCall:
    principal: str
    tool: str
    action: str
    resource: str
    destination: str
    payload: str
    timestamp: str


@dataclass(frozen=True)
class Decision:
    decision: DecisionValue
    reason: str


@dataclass(frozen=True)
class ToolRule:
    name: str
    actions: tuple[str, ...]
    resources: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: str


@dataclass(frozen=True)
class EgressPolicy:
    allowed_destinations: tuple[str, ...]
    secret_patterns: tuple[SecretPattern, ...]


@dataclass(frozen=True)
class AuditPolicy:
    required_fields: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    default_decision: DecisionValue
    allowed_tools: tuple[ToolRule, ...]
    egress: EgressPolicy
    audit: AuditPolicy


class AuditLog:
    def __init__(self, required_fields: tuple[str, ...]) -> None:
        self.required_fields = required_fields
        self.records: list[dict[str, str]] = []

    def record(self, request: ToolCall, decision: Decision) -> dict[str, str]:
        record = {
            "timestamp": request.timestamp,
            "principal": request.principal,
            "tool": request.tool,
            "action": request.action,
            "resource": request.resource,
            "destination": request.destination,
            "decision": decision.decision,
            "reason": decision.reason,
        }
        self.records.append({field: record[field] for field in self.required_fields})
        return self.records[-1]


def load_policy(path: str | Path) -> Policy:
    with Path(path).open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    return _parse_policy(raw)


def decide(request: ToolCall, policy: Policy) -> Decision:
    rule = _find_tool_rule(request.tool, policy)
    if rule is None:
        return Decision("deny", "tool-not-allowlisted")

    if request.action not in rule.actions:
        return Decision("deny", "action-not-permitted")

    if not _resource_or_destination_permitted(request, rule):
        return Decision("deny", "destination-not-permitted")

    if _payload_contains_secret(request.payload, policy.egress.secret_patterns):
        if request.destination not in policy.egress.allowed_destinations:
            return Decision("deny", "secret-egress-blocked")

    if policy.default_decision != "deny":
        return Decision("deny", "invalid-policy-default")

    return Decision("allow", "matched-allow-rule")


def enforce(request: ToolCall, policy: Policy, audit_log: AuditLog) -> Decision:
    decision = decide(request, policy)
    audit_log.record(request, decision)
    return decision


def _find_tool_rule(tool: str, policy: Policy) -> ToolRule | None:
    for rule in policy.allowed_tools:
        if rule.name == tool:
            return rule
    return None


def _resource_or_destination_permitted(request: ToolCall, rule: ToolRule) -> bool:
    if rule.resources:
        return any(fnmatchcase(request.resource, pattern) for pattern in rule.resources)
    if rule.destinations:
        return request.destination in rule.destinations
    return False


def _payload_contains_secret(payload: str, patterns: tuple[SecretPattern, ...]) -> bool:
    return any(re.search(pattern.regex, payload) is not None for pattern in patterns)


def _parse_policy(raw: dict[str, Any]) -> Policy:
    allowed_tools = tuple(
        ToolRule(
            name=str(rule["name"]),
            actions=tuple(str(action) for action in rule.get("actions", ())),
            resources=tuple(str(resource) for resource in rule.get("resources", ())),
            destinations=tuple(str(destination) for destination in rule.get("destinations", ())),
        )
        for rule in raw.get("allowed_tools", ())
    )
    egress_raw = raw.get("egress", {})
    egress = EgressPolicy(
        allowed_destinations=tuple(
            str(destination) for destination in egress_raw.get("allowed_destinations", ())
        ),
        secret_patterns=tuple(
            SecretPattern(name=str(pattern["name"]), regex=str(pattern["regex"]))
            for pattern in egress_raw.get("secret_patterns", ())
        ),
    )
    audit = AuditPolicy(
        required_fields=tuple(str(field) for field in raw.get("audit", {}).get("required_fields", ()))
    )
    default_decision = raw.get("default_decision", "deny")
    if default_decision not in {"allow", "deny"}:
        default_decision = "deny"
    return Policy(
        default_decision=default_decision,
        allowed_tools=allowed_tools,
        egress=egress,
        audit=audit,
    )
