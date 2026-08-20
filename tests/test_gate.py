from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from gate.monitor import AuditLog, Decision, ToolCall, decide, enforce, load_policy


ROOT = Path(__file__).resolve().parents[1]
POLICY_FILE = ROOT / "policy" / "agent-policy.yaml"
ASSESSMENT_RESULTS = ROOT / "oscal" / "assessment-results.json"


def call(**overrides: str) -> ToolCall:
    values = {
        "principal": "synthetic-user",
        "tool": "fs.read",
        "action": "read",
        "resource": "workspace/notes.txt",
        "destination": "",
        "payload": "",
        "timestamp": "2026-07-30T00:00:00Z",
    }
    values.update(overrides)
    return ToolCall(**values)


def policy():
    return load_policy(POLICY_FILE)


def test_denies_unlisted_tool():
    assert decide(call(tool="shell.exec", action="execute"), policy()) == Decision(
        "deny", "tool-not-allowlisted"
    )


def test_denies_unlisted_tool_before_secret_egress_check():
    assert decide(
        call(
            tool="shell.exec",
            action="execute",
            destination="evil.example.test",
            payload="synthetic credential AKIA0000000000000000",
        ),
        policy(),
    ) == Decision("deny", "tool-not-allowlisted")


def test_denies_unpermitted_action():
    assert decide(call(tool="fs.read", action="write"), policy()) == Decision(
        "deny", "action-not-permitted"
    )


def test_denies_unpermitted_destination():
    assert decide(
        call(
            tool="http.get",
            action="get",
            resource="",
            destination="evil.example.com",
        ),
        policy(),
    ) == Decision("deny", "destination-not-permitted")


def test_denies_secret_egress_even_when_tool_destination_allowed():
    assert decide(
        call(
            tool="http.get",
            action="get",
            resource="",
            destination="api.internal.example.local",
            payload="synthetic credential AKIA0000000000000000",
        ),
        policy(),
    ) == Decision("deny", "secret-egress-blocked")


def test_allows_workspace_read():
    assert decide(call(), policy()) == Decision("allow", "matched-allow-rule")


def test_allows_clean_internal_get():
    assert decide(
        call(
            tool="http.get",
            action="get",
            resource="",
            destination="api.internal.example.local",
            payload="synthetic clean payload",
        ),
        policy(),
    ) == Decision("allow", "matched-allow-rule")


def test_audit_record_shape_for_allow_and_deny():
    loaded_policy = policy()
    audit_log = AuditLog(loaded_policy.audit.required_fields)

    enforce(call(), loaded_policy, audit_log)
    enforce(call(tool="shell.exec", action="execute"), loaded_policy, audit_log)

    assert len(audit_log.records) == 2
    assert all(set(record) == set(loaded_policy.audit.required_fields) for record in audit_log.records)
    assert audit_log.records[0]["decision"] == "allow"
    assert audit_log.records[1]["decision"] == "deny"


def test_pipeline_exits_zero_and_writes_passing_assessment_results():
    if ASSESSMENT_RESULTS.exists():
        ASSESSMENT_RESULTS.unlink()

    completed = subprocess.run(
        [sys.executable, "-m", "pipeline.verify"],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert ASSESSMENT_RESULTS.exists()
    payload = json.loads(ASSESSMENT_RESULTS.read_text(encoding="utf-8"))
    findings = payload["assessment-results"]["results"][0]["findings"]
    assert findings
    assert all(finding["target"]["status"]["state"] == "pass" for finding in findings)


def test_demotion_narrows_without_revoking():
    """An agent that fails review stays useful at a lower mode."""
    from gate.monitor import Authority, ModeRule, decide_bound, demote, policy_digest

    policy = load_policy(POLICY_FILE)
    digest = policy_digest(policy)
    rules = [ModeRule("fs.read", "suggest")]
    call = ToolCall(
        principal="synthetic-user", tool="fs.read", action="read",
        resource="workspace/notes.md", destination="", payload="",
        timestamp="2026-08-18T00:00:00Z",
    )

    enforce_auth = Authority("enforce", digest)
    assert decide_bound(enforce_auth, call, policy, digest, rules).decision == "allow"

    observing = demote(enforce_auth, "observe")
    result = decide_bound(observing, call, policy, digest, rules)
    assert result.decision == "deny"
    assert result.reason == "above-current-authority"


def test_demotion_cannot_raise_authority():
    from gate.monitor import Authority, demote

    import pytest

    with pytest.raises(ValueError):
        demote(Authority("observe", "sha256:x"), "enforce")


def test_grant_is_bound_to_policy_body_not_its_name():
    """The defect a bare policy_id cannot express."""
    from gate.monitor import Authority, ModeRule, decide_bound, policy_digest

    policy = load_policy(POLICY_FILE)
    digest = policy_digest(policy)
    call = ToolCall(
        principal="synthetic-user", tool="fs.read", action="read",
        resource="workspace/notes.md", destination="", payload="",
        timestamp="2026-08-18T00:00:00Z",
    )
    auth = Authority("enforce", digest)
    rules = [ModeRule("fs.read", "observe")]

    assert decide_bound(auth, call, policy, digest, rules).decision == "allow"

    rotated = decide_bound(auth, call, policy, "sha256:rotated", rules)
    assert rotated.decision == "deny"
    assert rotated.reason == "policy-body-mismatch"


def test_unlisted_tool_requires_the_highest_mode():
    from gate.monitor import Authority, decide_bound, policy_digest

    policy = load_policy(POLICY_FILE)
    digest = policy_digest(policy)
    call = ToolCall(
        principal="synthetic-user", tool="fs.read", action="read",
        resource="workspace/notes.md", destination="", payload="",
        timestamp="2026-08-18T00:00:00Z",
    )
    result = decide_bound(Authority("suggest", digest), call, policy, digest, [])
    assert result.reason == "above-current-authority"
