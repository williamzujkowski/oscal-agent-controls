package agent.gate

default decision := {"decision": "deny", "reason": "tool-not-allowlisted"}

decision := {"decision": "deny", "reason": "tool-not-allowlisted"} if {
	not has_tool_rule
} else := {"decision": "deny", "reason": "action-not-permitted"} if {
	has_tool_rule
	not action_permitted
} else := {"decision": "deny", "reason": "destination-not-permitted"} if {
	action_permitted
	not resource_or_destination_permitted
} else := {"decision": "deny", "reason": "secret-egress-blocked"} if {
	resource_or_destination_permitted
	payload_contains_secret
	not egress_allowed
} else := {"decision": "deny", "reason": "invalid-policy-default"} if {
	not input.policy.default_decision == "deny"
} else := {"decision": "allow", "reason": "matched-allow-rule"} if {
	true
}

tool_rule := rule if {
	some rule in input.policy.allowed_tools
	rule.name == input.call.tool
}

has_tool_rule if {
	tool_rule
}

action_permitted if {
	some action in object.get(tool_rule, "actions", [])
	action == input.call.action
}

resource_or_destination_permitted if {
	resources := object.get(tool_rule, "resources", [])
	count(resources) > 0
	some pattern in resources
	resource_pattern_matches(pattern, input.call.resource)
}

resource_or_destination_permitted if {
	resources := object.get(tool_rule, "resources", [])
	count(resources) == 0
	destinations := object.get(tool_rule, "destinations", [])
	count(destinations) > 0
	some destination in destinations
	destination == input.call.destination
}

resource_pattern_matches(pattern, resource) if {
	pattern == resource
}

resource_pattern_matches(pattern, resource) if {
	pattern == "workspace/**"
	startswith(resource, "workspace/")
}

payload_contains_secret if {
	some pattern in input.policy.egress.secret_patterns
	regex.match(pattern.regex, input.call.payload)
}

egress_allowed if {
	some destination in input.policy.egress.allowed_destinations
	destination == input.call.destination
}
