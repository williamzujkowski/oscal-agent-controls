"""Differential test for authority that changes during operation.

Same discipline as difftest/run.py, applied to the moving target: the Dafny
model, the Rego twin and the Python monitor must agree on every combination of
authority mode, policy-digest match, and per-tool mode requirement.

A divergence here is the interesting kind. The three implementations were
written separately, so agreement is evidence and disagreement is a bug in
whichever one is wrong.
"""
from __future__ import annotations

import importlib
import itertools
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verify"
OPA = VERIFY / "bin" / "opa"
AUTH_DFY = VERIFY / "Authority.dfy"
AUTH_PY = VERIFY / "Authority-py"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate.monitor import (  # noqa: E402
    Authority,
    ModeRule,
    ToolCall,
    decide_bound,
    load_policy,
)
from run import find_dafny, policy_to_input  # noqa: E402

BOUND_DIGEST = "sha256:bound"
POLICY = load_policy(ROOT / "policy" / "agent-policy.yaml")

MODES = ("observe", "suggest", "enforce")
PRESENTED = (BOUND_DIGEST, "sha256:rotated")
RULE_MODES = ("observe", "suggest", "enforce")
# "" means the tool is absent from the mode table -- the forgotten case.
RULE_TOOLS = ("", "fs.read", "http.get")

CALLS = [
    ToolCall("synthetic-user", tool, action, resource, destination, payload,
             "2026-08-18T00:00:00Z")
    for tool, action, resource, destination, payload in [
        ("fs.read", "read", "workspace/notes.md", "", ""),
        ("fs.read", "write", "workspace/notes.md", "", ""),
        ("http.get", "get", "", "api.internal.example.local", ""),
        ("http.get", "get", "", "evil.example.test", ""),
        ("shell.exec", "run", "workspace/x", "", ""),
        ("http.get", "get", "", "api.internal.example.local",
         "synthetic credential AKIA0000000000000000"),
    ]
]


def build_dafny() -> tuple[Any, Any]:
    subprocess.run(
        [find_dafny(), "build", "--target:py", "--output", str(VERIFY / "Authority"),
         str(VERIFY / "Gate.dfy"), str(AUTH_DFY)],
        cwd=ROOT, check=True, text=True, capture_output=True,
    )
    sys.path.insert(0, str(AUTH_PY))
    return importlib.import_module("Authority"), importlib.import_module("_dafny")


def dstr(rt: Any, value: str) -> Any:
    return rt.SeqWithoutIsStrInference(map(rt.CodePoint, value))


def decide_dafny(mod, rt, mode, presented, call, rule_tool, rule_mode):
    r = mod.default__.DecideBoundSynthetic(
        dstr(rt, mode), dstr(rt, BOUND_DIGEST), dstr(rt, presented),
        dstr(rt, call.tool), dstr(rt, call.action), dstr(rt, call.resource),
        dstr(rt, call.destination), dstr(rt, call.payload),
        dstr(rt, rule_tool), dstr(rt, rule_mode),
    )
    return {"decision": "allow" if r.is_Allow else "deny",
            "reason": r.reason.VerbatimString(False)}


def decide_opa(mode, presented, call, rule_tool, rule_mode):
    payload = {
        "authority": {"mode": mode, "policy_digest": BOUND_DIGEST},
        "presented_digest": presented,
        "mode_rules": ([] if rule_tool == ""
                       else [{"tool": rule_tool, "required": rule_mode}]),
        "policy": policy_to_input(POLICY),
        "call": {
            "principal": call.principal, "tool": call.tool, "action": call.action,
            "resource": call.resource, "destination": call.destination,
            "payload": call.payload, "timestamp": call.timestamp,
        },
    }
    completed = subprocess.run(
        [str(OPA), "eval", "--format=json", "--data", str(VERIFY),
         "--stdin-input", "data.agent.authority.decision"],
        input=json.dumps(payload), cwd=ROOT, check=True, text=True, capture_output=True,
    )
    return json.loads(completed.stdout)["result"][0]["expressions"][0]["value"]


def decide_python(mode, presented, call, rule_tool, rule_mode):
    rules = [] if rule_tool == "" else [ModeRule(rule_tool, rule_mode)]
    d = decide_bound(Authority(mode, BOUND_DIGEST), call, POLICY, presented, rules)
    return {"decision": d.decision, "reason": d.reason}


def main() -> int:
    mod, rt = build_dafny()
    cases = list(itertools.product(MODES, PRESENTED, CALLS, RULE_TOOLS, RULE_MODES))
    mismatches = []
    for mode, presented, call, rule_tool, rule_mode in cases:
        args = (mode, presented, call, rule_tool, rule_mode)
        d, o, p = decide_dafny(mod, rt, *args), decide_opa(*args), decide_python(*args)
        if not (d == o == p):
            mismatches.append({"mode": mode, "presented": presented,
                               "tool": call.tool, "action": call.action,
                               "rule": (rule_tool, rule_mode),
                               "dafny": d, "opa": o, "python": p})
    print(f"authority difftest: {len(cases)} cases across "
          f"{len(MODES)} modes x {len(PRESENTED)} digests x {len(CALLS)} calls "
          f"x {len(RULE_TOOLS)} mode-tables")
    if mismatches:
        print(f"MISMATCHES: {len(mismatches)}")
        for m in mismatches[:5]:
            print("  ", json.dumps(m))
        return 1
    print("all three implementations agree on every case")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
