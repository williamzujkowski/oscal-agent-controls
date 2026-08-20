# Rego twin of Authority.dfy.
#
# Same decision, independently written, so differential testing can catch a
# divergence between the model and something deployable. Ordering mirrors the
# Dafny: digest first, then mode, then the underlying gate.
package agent.authority

import data.agent.gate

mode_rank := {"observe": 0, "suggest": 1, "enforce": 2}

# An unlisted tool requires the highest mode. The forgotten case must be the
# restrictive one.
required_mode := m if {
	some rule in object.get(input, "mode_rules", [])
	rule.tool == input.call.tool
	m := rule.required
} else := "enforce"

held_rank := mode_rank[input.authority.mode]

required_rank := mode_rank[required_mode]

mode_satisfied if {
	required_rank <= held_rank
}

digest_matches if {
	input.presented_digest == input.authority.policy_digest
}

decision := {"decision": "deny", "reason": "policy-body-mismatch"} if {
	not digest_matches
} else := {"decision": "deny", "reason": "above-current-authority"} if {
	not mode_satisfied
} else := gate.decision
