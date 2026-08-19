package agent.authority_test

import data.agent.authority

policy := {
	"default_decision": "deny",
	"allowed_tools": [{
		"name": "fs.read",
		"actions": ["read"],
		"resources": ["workspace/**"],
		"destinations": [],
	}],
	"egress": {"allowed_destinations": [], "secret_patterns": []},
	"audit": {"required_fields": []},
}

call := {
	"principal": "synthetic-user",
	"tool": "fs.read",
	"action": "read",
	"resource": "workspace/notes.md",
	"destination": "",
	"payload": "",
	"timestamp": "2026-08-18T00:00:00Z",
}

mode_rules := [{"tool": "fs.read", "required": "suggest"}]

test_digest_mismatch_denies_before_anything_else if {
	result := authority.decision with input as {
		"authority": {"mode": "enforce", "policy_digest": "sha256:aaa"},
		"presented_digest": "sha256:bbb",
		"mode_rules": mode_rules,
		"policy": policy,
		"call": call,
	}
	result.reason == "policy-body-mismatch"
}

test_below_required_mode_denies if {
	result := authority.decision with input as {
		"authority": {"mode": "observe", "policy_digest": "sha256:aaa"},
		"presented_digest": "sha256:aaa",
		"mode_rules": mode_rules,
		"policy": policy,
		"call": call,
	}
	result.reason == "above-current-authority"
}

test_at_required_mode_allows if {
	result := authority.decision with input as {
		"authority": {"mode": "suggest", "policy_digest": "sha256:aaa"},
		"presented_digest": "sha256:aaa",
		"mode_rules": mode_rules,
		"policy": policy,
		"call": call,
	}
	result.decision == "allow"
}

test_unlisted_tool_requires_enforce if {
	result := authority.decision with input as {
		"authority": {"mode": "suggest", "policy_digest": "sha256:aaa"},
		"presented_digest": "sha256:aaa",
		"mode_rules": [],
		"policy": policy,
		"call": call,
	}
	result.reason == "above-current-authority"
}

test_demotion_narrows_an_allow_to_a_deny if {
	allowed := authority.decision with input as {
		"authority": {"mode": "enforce", "policy_digest": "sha256:aaa"},
		"presented_digest": "sha256:aaa",
		"mode_rules": mode_rules,
		"policy": policy,
		"call": call,
	}
	demoted := authority.decision with input as {
		"authority": {"mode": "observe", "policy_digest": "sha256:aaa"},
		"presented_digest": "sha256:aaa",
		"mode_rules": mode_rules,
		"policy": policy,
		"call": call,
	}
	allowed.decision == "allow"
	demoted.decision == "deny"
}
