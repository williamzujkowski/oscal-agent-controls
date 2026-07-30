package agent.gate

policy := {
	"default_decision": "deny",
	"allowed_tools": [
		{
			"name": "fs.read",
			"actions": ["read"],
			"resources": ["workspace/**"],
		},
		{
			"name": "http.get",
			"actions": ["get"],
			"destinations": ["api.internal.example.local"],
		},
	],
	"egress": {
		"allowed_destinations": [],
		"secret_patterns": [
			{
				"name": "fake-access-key",
				"regex": "AKIA[0-9A-Z]{16}",
			},
			{
				"name": "fake-bearer",
				"regex": "sk-live-[A-Za-z0-9]{16}",
			},
		],
	},
}

base_call := {
	"principal": "synthetic-user",
	"tool": "fs.read",
	"action": "read",
	"resource": "workspace/notes.txt",
	"destination": "",
	"payload": "",
	"timestamp": "2026-07-30T00:00:00Z",
}

make_input(overrides) := request if {
	request := {
		"call": object.union(base_call, overrides),
		"policy": policy,
	}
}

test_denies_unlisted_tool if {
	decision with input as make_input({"tool": "shell.exec", "action": "execute"}) == {
		"decision": "deny",
		"reason": "tool-not-allowlisted",
	}
}

test_denies_unpermitted_action if {
	decision with input as make_input({"tool": "fs.read", "action": "write"}) == {
		"decision": "deny",
		"reason": "action-not-permitted",
	}
}

test_denies_unpermitted_destination if {
	decision with input as make_input({
		"tool": "http.get",
		"action": "get",
		"resource": "",
		"destination": "evil.example.com",
	}) == {
		"decision": "deny",
		"reason": "destination-not-permitted",
	}
}

test_denies_secret_egress if {
	decision with input as make_input({
		"tool": "http.get",
		"action": "get",
		"resource": "",
		"destination": "api.internal.example.local",
		"payload": "synthetic credential AKIA0000000000000000",
	}) == {
		"decision": "deny",
		"reason": "secret-egress-blocked",
	}
}

test_allows_workspace_read if {
	decision with input as make_input({}) == {
		"decision": "allow",
		"reason": "matched-allow-rule",
	}
}

test_allows_clean_internal_get if {
	decision with input as make_input({
		"tool": "http.get",
		"action": "get",
		"resource": "",
		"destination": "api.internal.example.local",
		"payload": "synthetic clean payload",
	}) == {
		"decision": "allow",
		"reason": "matched-allow-rule",
	}
}

test_secret_egress_dominates_allow_rule if {
	decision with input as make_input({
		"tool": "fs.read",
		"action": "read",
		"resource": "workspace/notes.txt",
		"destination": "",
		"payload": "synthetic bearer sk-live-0000000000000000",
	}) == {
		"decision": "deny",
		"reason": "secret-egress-blocked",
	}
}
