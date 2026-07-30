from __future__ import annotations

import importlib
import itertools
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verify"
DAFNY = VERIFY / "bin" / "dafny-4.11.0" / "dafny" / "dafny"
OPA = VERIFY / "bin" / "opa"
GATE_DFY = VERIFY / "Gate.dfy"
GATE_REGO = VERIFY / "gate.rego"
GATE_PY = VERIFY / "Gate-py"
POLICY_FILE = ROOT / "policy" / "agent-policy.yaml"

sys.path.insert(0, str(ROOT))

from gate.monitor import Policy, ToolCall, decide, load_policy  # noqa: E402


def find_dafny() -> str:
    candidates = [
        os.environ.get("DAFNY"),
        shutil.which("dafny"),
        str(DAFNY),
        str(ROOT / ".tools" / "dafny-4.11.0" / "dafny" / "dafny"),
    ]
    for candidate in candidates:
        if candidate:
            path = Path(candidate)
            if not path.is_absolute():
                path = ROOT / path
            if path.exists():
                return str(path)
    raise RuntimeError("dafny not found on PATH, in $DAFNY, verify/bin, or .tools")


def policy_to_input(policy: Policy) -> dict[str, Any]:
    return {
        "default_decision": policy.default_decision,
        "allowed_tools": [
            {
                "name": rule.name,
                "actions": list(rule.actions),
                "resources": list(rule.resources),
                "destinations": list(rule.destinations),
            }
            for rule in policy.allowed_tools
        ],
        "egress": {
            "allowed_destinations": list(policy.egress.allowed_destinations),
            "secret_patterns": [asdict(pattern) for pattern in policy.egress.secret_patterns],
        },
        "audit": {"required_fields": list(policy.audit.required_fields)},
    }


def corpus() -> list[ToolCall]:
    tools = ("fs.read", "http.get", "shell.exec")
    actions = ("read", "get", "write")
    destinations = ("", "api.internal.example.local", "evil.example.test")
    resources = ("workspace/notes.txt", "workspace/team/runbook.md", "outside/notes.txt", "")
    payloads = (
        "",
        "synthetic clean payload",
        "synthetic credential AKIA0000000000000000",
        "synthetic bearer sk-live-0000000000000000",
    )

    return [
        ToolCall(
            principal="synthetic-user",
            tool=tool,
            action=action,
            resource=resource,
            destination=destination,
            payload=payload,
            timestamp="2026-07-30T00:00:00Z",
        )
        for tool, action, destination, resource, payload in itertools.product(
            tools, actions, destinations, resources, payloads
        )
    ]


def build_dafny() -> tuple[Any, Any]:
    subprocess.run(
        [find_dafny(), "build", "--target:py", str(GATE_DFY)],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    sys.path.insert(0, str(GATE_PY))
    return importlib.import_module("Gate"), importlib.import_module("_dafny")


def dafny_string(runtime: Any, value: str) -> Any:
    return runtime.SeqWithoutIsStrInference(map(runtime.CodePoint, value))


def decide_dafny(gate_module: Any, runtime: Any, call: ToolCall) -> dict[str, str]:
    result = gate_module.default__.DecideSynthetic(
        dafny_string(runtime, call.tool),
        dafny_string(runtime, call.action),
        dafny_string(runtime, call.resource),
        dafny_string(runtime, call.destination),
        dafny_string(runtime, call.payload),
    )
    return {
        "decision": "allow" if result.is_Allow else "deny",
        "reason": result.reason.VerbatimString(False),
    }


def decide_opa(call: ToolCall, policy_input: dict[str, Any]) -> dict[str, str]:
    completed = subprocess.run(
        [
            str(OPA),
            "eval",
            "--format=json",
            "--data",
            str(GATE_REGO),
            "--stdin-input",
            "data.agent.gate.decision",
        ],
        cwd=ROOT,
        input=json.dumps({"call": asdict(call), "policy": policy_input}),
        check=True,
        text=True,
        capture_output=True,
    )
    payload = json.loads(completed.stdout)
    if "result" not in payload:
        raise RuntimeError(f"OPA returned no decision for call: {asdict(call)}")
    return payload["result"][0]["expressions"][0]["value"]


def main() -> int:
    policy = load_policy(POLICY_FILE)
    policy_input = policy_to_input(policy)
    gate_module, runtime = build_dafny()
    disagreements: list[str] = []
    counts: Counter[tuple[str, str]] = Counter()
    calls = corpus()

    for index, call in enumerate(calls):
        python_decision = asdict(decide(call, policy))
        dafny_decision = decide_dafny(gate_module, runtime, call)
        opa_decision = decide_opa(call, policy_input)
        if not (python_decision == dafny_decision == opa_decision):
            disagreements.append(
                json.dumps(
                    {
                        "case": index,
                        "call": asdict(call),
                        "python": python_decision,
                        "dafny": dafny_decision,
                        "opa": opa_decision,
                    },
                    sort_keys=True,
                )
            )
        counts[(python_decision["decision"], python_decision["reason"])] += 1

    print("decision,reason,count")
    for (decision, reason), count in sorted(counts.items()):
        print(f"{decision},{reason},{count}")
    print(f"checked {len(calls)} synthetic calls")

    if disagreements:
        print("\n".join(disagreements))
        print(f"{len(calls)} cases, {len(disagreements)} disagreements")
        return 1

    print("all engines agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
