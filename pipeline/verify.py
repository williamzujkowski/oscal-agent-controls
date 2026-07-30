from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from gate.monitor import AuditLog, Decision, ToolCall, enforce, load_policy


ROOT = Path(__file__).resolve().parents[1]
COMPONENT_DEFINITION = ROOT / "oscal" / "component-definition.json"
POLICY_FILE = ROOT / "policy" / "agent-policy.yaml"
ASSESSMENT_RESULTS = ROOT / "oscal" / "assessment-results.json"
NS = "https://example.local/ns/agent-controls"


def main() -> int:
    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []

    component = _load_json(COMPONENT_DEFINITION)
    present_controls = _implemented_controls(component)
    missing_controls = {"ac-6", "ac-4", "au-12"} - present_controls
    _add_finding(
        findings,
        title="component-definition declares required controls",
        target_id="ac-6",
        passed=not missing_controls,
        description=(
            "component-definition contains ac-6, ac-4, and au-12"
            if not missing_controls
            else f"component-definition missing {sorted(missing_controls)}"
        ),
    )

    policy = load_policy(POLICY_FILE)
    _add_finding(
        findings,
        title="policy source loads",
        target_id="ac-6",
        passed=policy.default_decision == "deny",
        description="agent-policy.yaml loaded and default_decision is deny",
    )

    audit_log = AuditLog(policy.audit.required_fields)
    cases = [
        (
            "deny unlisted tool",
            "ac-6",
            ToolCall(
                principal="synthetic-user",
                tool="shell.exec",
                action="execute",
                resource="workspace/notes.txt",
                destination="",
                payload="",
                timestamp="2026-07-30T00:00:01Z",
            ),
            Decision("deny", "tool-not-allowlisted"),
        ),
        (
            "deny unpermitted action",
            "ac-6",
            ToolCall(
                principal="synthetic-user",
                tool="fs.read",
                action="write",
                resource="workspace/notes.txt",
                destination="",
                payload="",
                timestamp="2026-07-30T00:00:02Z",
            ),
            Decision("deny", "action-not-permitted"),
        ),
        (
            "deny unpermitted destination",
            "ac-4",
            ToolCall(
                principal="synthetic-user",
                tool="http.get",
                action="get",
                resource="",
                destination="evil.example.com",
                payload="",
                timestamp="2026-07-30T00:00:03Z",
            ),
            Decision("deny", "destination-not-permitted"),
        ),
        (
            "deny secret egress",
            "ac-4",
            ToolCall(
                principal="synthetic-user",
                tool="http.get",
                action="get",
                resource="",
                destination="api.internal.example.local",
                payload="synthetic credential AKIA0000000000000000",
                timestamp="2026-07-30T00:00:04Z",
            ),
            Decision("deny", "secret-egress-blocked"),
        ),
        (
            "allow workspace read",
            "ac-6",
            ToolCall(
                principal="synthetic-user",
                tool="fs.read",
                action="read",
                resource="workspace/notes.txt",
                destination="",
                payload="",
                timestamp="2026-07-30T00:00:05Z",
            ),
            Decision("allow", "matched-allow-rule"),
        ),
        (
            "allow clean internal get",
            "ac-4",
            ToolCall(
                principal="synthetic-user",
                tool="http.get",
                action="get",
                resource="",
                destination="api.internal.example.local",
                payload="synthetic clean payload",
                timestamp="2026-07-30T00:00:06Z",
            ),
            Decision("allow", "matched-allow-rule"),
        ),
    ]

    for title, control_id, call, expected in cases:
        before = len(audit_log.records)
        actual = enforce(call, policy, audit_log)
        passed = actual == expected and len(audit_log.records) == before + 1
        _add_observation(observations, title, control_id, call, actual, audit_log.records[-1])
        _add_finding(
            findings,
            title=title,
            target_id=control_id,
            passed=passed,
            description=f"expected {expected.decision}/{expected.reason}, got {actual.decision}/{actual.reason}",
        )

    required = set(policy.audit.required_fields)
    audit_shape_passed = (
        len(audit_log.records) == len(cases)
        and all(set(record) == required for record in audit_log.records)
    )
    _add_finding(
        findings,
        title="every decision has required audit fields",
        target_id="au-12",
        passed=audit_shape_passed,
        description="audit records contain exactly the policy-required fields for every decision",
    )

    output = _assessment_results(findings, observations)
    ASSESSMENT_RESULTS.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")

    failed = [finding for finding in findings if finding["target"]["status"]["state"] != "pass"]
    print(f"findings: {len(findings)} total, {len(failed)} failed")
    for finding in findings:
        state = finding["target"]["status"]["state"]
        print(f"{state.upper()}: {finding['title']}")
    return 0 if not failed else 1


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _implemented_controls(component: dict[str, Any]) -> set[str]:
    controls: set[str] = set()
    for runtime in component["component-definition"].get("components", []):
        for implementation in runtime.get("control-implementations", []):
            for requirement in implementation.get("implemented-requirements", []):
                controls.add(str(requirement.get("control-id", "")))
    return controls


def _add_finding(
    findings: list[dict[str, Any]],
    *,
    title: str,
    target_id: str,
    passed: bool,
    description: str,
) -> None:
    sequence = len(findings) + 1
    findings.append(
        {
            "uuid": f"70000000-0000-4000-8000-{sequence:012d}",
            "title": title,
            "description": description,
            "target": {
                "target-id": target_id,
                "type": "objective-id",
                "status": {
                    "state": "pass" if passed else "fail",
                    "reason": "satisfied" if passed else "not-satisfied",
                },
            },
            "props": [
                {
                    "name": "evidence-kind",
                    "ns": NS,
                    "value": "pipeline-check",
                }
            ],
        }
    )


def _add_observation(
    observations: list[dict[str, Any]],
    title: str,
    control_id: str,
    call: ToolCall,
    decision: Decision,
    audit_record: dict[str, str],
) -> None:
    sequence = len(observations) + 1
    observations.append(
        {
            "uuid": f"80000000-0000-4000-8000-{sequence:012d}",
            "title": title,
            "description": "Synthetic tool-call evidence produced by the reference monitor.",
            "methods": ["TEST"],
            "subjects": [
                {
                    "subject-uuid": "22222222-2222-4222-8222-222222222222",
                    "type": "component",
                    "title": "example-agent-runtime",
                }
            ],
            "relevant-evidence": [
                {
                    "description": json.dumps(
                        {
                            "control-id": control_id,
                            "tool-call": asdict(call),
                            "decision": asdict(decision),
                            "audit-record": audit_record,
                        },
                        sort_keys=True,
                    )
                }
            ],
        }
    )


def _assessment_results(
    findings: list[dict[str, Any]], observations: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "assessment-results": {
            "uuid": "99999999-9999-4999-8999-999999999999",
            "metadata": {
                "title": "Synthetic Agent Runtime Assessment Results",
                "last-modified": "2026-07-30T00:00:00Z",
                "version": "0.1.0",
                "oscal-version": "1.1.2",
            },
            "import-ap": {"href": "component-definition.json"},
            "results": [
                {
                    "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "title": "Reference monitor pipeline proof",
                    "description": "Deterministic pipeline evidence for synthetic agent controls.",
                    "start": "2026-07-30T00:00:00Z",
                    "end": "2026-07-30T00:00:06Z",
                    "findings": findings,
                    "observations": observations,
                }
            ],
        }
    }


if __name__ == "__main__":
    sys.exit(main())
