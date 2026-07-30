module Gate {
  datatype Decision = Allow(reason: string) | Deny(reason: string)

  datatype ToolCall = ToolCall(
    principal: string,
    tool: string,
    action: string,
    resource: string,
    destination: string,
    payload: string,
    timestamp: string
  )

  datatype ToolRule = ToolRule(
    name: string,
    actions: seq<string>,
    resources: seq<string>,
    destinations: seq<string>
  )

  datatype SecretPattern = SecretPattern(name: string, regex: string)

  datatype EgressPolicy = EgressPolicy(
    allowedDestinations: seq<string>,
    secretPatterns: seq<SecretPattern>
  )

  datatype AuditPolicy = AuditPolicy(requiredFields: seq<string>)

  datatype Policy = Policy(
    defaultDecision: string,
    allowedTools: seq<ToolRule>,
    egress: EgressPolicy,
    audit: AuditPolicy
  )

  datatype RuleLookup = NoRule | Found(rule: ToolRule)

  function InString(value: string, values: seq<string>): bool
    decreases |values|
  {
    if |values| == 0 then
      false
    else
      values[0] == value || InString(value, values[1..])
  }

  function StartsWith(value: string, prefix: string): bool
  {
    |prefix| <= |value| && value[..|prefix|] == prefix
  }

  function IsDigit(c: char): bool
  {
    '0' <= c && c <= '9'
  }

  function IsUpperAscii(c: char): bool
  {
    'A' <= c && c <= 'Z'
  }

  function IsLowerAscii(c: char): bool
  {
    'a' <= c && c <= 'z'
  }

  function IsAlphaAscii(c: char): bool
  {
    IsUpperAscii(c) || IsLowerAscii(c)
  }

  function IsAccessKeyChar(c: char): bool
  {
    IsDigit(c) || IsUpperAscii(c)
  }

  function IsBearerChar(c: char): bool
  {
    IsDigit(c) || IsAlphaAscii(c)
  }

  function AllAccessKeyChars(chars: seq<char>): bool
    decreases |chars|
  {
    if |chars| == 0 then
      true
    else
      IsAccessKeyChar(chars[0]) && AllAccessKeyChars(chars[1..])
  }

  function AllBearerChars(chars: seq<char>): bool
    decreases |chars|
  {
    if |chars| == 0 then
      true
    else
      IsBearerChar(chars[0]) && AllBearerChars(chars[1..])
  }

  function MatchesAccessKeyPrefix(payload: string): bool
  {
    20 <= |payload| &&
    payload[..4] == "AKIA" &&
    AllAccessKeyChars(payload[4..20])
  }

  function MatchesBearerPrefix(payload: string): bool
  {
    24 <= |payload| &&
    payload[..8] == "sk-live-" &&
    AllBearerChars(payload[8..24])
  }

  function ContainsAccessKey(payload: string): bool
    decreases |payload|
  {
    if |payload| < 20 then
      false
    else
      MatchesAccessKeyPrefix(payload) || ContainsAccessKey(payload[1..])
  }

  function ContainsBearer(payload: string): bool
    decreases |payload|
  {
    if |payload| < 24 then
      false
    else
      MatchesBearerPrefix(payload) || ContainsBearer(payload[1..])
  }

  function SecretPatternMatches(pattern: SecretPattern, payload: string): bool
  {
    if pattern.regex == "AKIA[0-9A-Z]{16}" then
      ContainsAccessKey(payload)
    else if pattern.regex == "sk-live-[A-Za-z0-9]{16}" then
      ContainsBearer(payload)
    else
      false
  }

  function AnySecretPatternMatches(payload: string, patterns: seq<SecretPattern>): bool
    decreases |patterns|
  {
    if |patterns| == 0 then
      false
    else
      SecretPatternMatches(patterns[0], payload) ||
      AnySecretPatternMatches(payload, patterns[1..])
  }

  function HasSecret(call: ToolCall, policy: Policy): bool
  {
    AnySecretPatternMatches(call.payload, policy.egress.secretPatterns)
  }

  function EgressAllowed(call: ToolCall, policy: Policy): bool
  {
    InString(call.destination, policy.egress.allowedDestinations)
  }

  function FindToolRule(tool: string, rules: seq<ToolRule>): RuleLookup
    decreases |rules|
  {
    if |rules| == 0 then
      NoRule
    else if rules[0].name == tool then
      Found(rules[0])
    else
      FindToolRule(tool, rules[1..])
  }

  function ResourcePatternMatches(pattern: string, resource: string): bool
  {
    pattern == resource ||
    (pattern == "workspace/**" && StartsWith(resource, "workspace/"))
  }

  function ResourcePermitted(resource: string, patterns: seq<string>): bool
    decreases |patterns|
  {
    if |patterns| == 0 then
      false
    else
      ResourcePatternMatches(patterns[0], resource) ||
      ResourcePermitted(resource, patterns[1..])
  }

  function ResourceOrDestinationPermitted(call: ToolCall, rule: ToolRule): bool
  {
    if |rule.resources| > 0 then
      ResourcePermitted(call.resource, rule.resources)
    else if |rule.destinations| > 0 then
      InString(call.destination, rule.destinations)
    else
      false
  }

  function MatchesSomeAllowRule(call: ToolCall, policy: Policy): bool
  {
    match FindToolRule(call.tool, policy.allowedTools)
    case NoRule => false
    case Found(rule) =>
      InString(call.action, rule.actions) &&
      ResourceOrDestinationPermitted(call, rule)
  }

  function Decide(call: ToolCall, policy: Policy): Decision
  {
    match FindToolRule(call.tool, policy.allowedTools)
    case NoRule => Deny("tool-not-allowlisted")
    case Found(rule) =>
      if !InString(call.action, rule.actions) then
        Deny("action-not-permitted")
      else if !ResourceOrDestinationPermitted(call, rule) then
        Deny("destination-not-permitted")
      else if HasSecret(call, policy) && !EgressAllowed(call, policy) then
        Deny("secret-egress-blocked")
      else if policy.defaultDecision != "deny" then
        Deny("invalid-policy-default")
      else
        Allow("matched-allow-rule")
  }

  function SyntheticPolicy(): Policy
  {
    Policy(
      "deny",
      [
        ToolRule("fs.read", ["read"], ["workspace/**"], []),
        ToolRule("http.get", ["get"], [], ["api.internal.example.local"])
      ],
      EgressPolicy(
        [],
        [
          SecretPattern("fake-access-key", "AKIA[0-9A-Z]{16}"),
          SecretPattern("fake-bearer", "sk-live-[A-Za-z0-9]{16}")
        ]
      ),
      AuditPolicy([
        "timestamp",
        "principal",
        "tool",
        "action",
        "resource",
        "destination",
        "decision",
        "reason"
      ])
    )
  }

  function DecideSynthetic(
    tool: string,
    action: string,
    resource: string,
    destination: string,
    payload: string
  ): Decision
  {
    Decide(
      ToolCall(
        "synthetic-user",
        tool,
        action,
        resource,
        destination,
        payload,
        "2026-07-30T00:00:00Z"
      ),
      SyntheticPolicy()
    )
  }

  lemma Totality(call: ToolCall, policy: Policy)
    ensures Decide(call, policy).Allow? || Decide(call, policy).Deny?
  {
  }

  lemma DenyByDefault(call: ToolCall, policy: Policy)
    ensures !MatchesSomeAllowRule(call, policy) ==> Decide(call, policy).Deny?
  {
  }

  lemma EgressDominance(call: ToolCall, policy: Policy)
    ensures HasSecret(call, policy) && !EgressAllowed(call, policy) ==> Decide(call, policy).Deny?
  {
  }

  lemma AllowRequiresRule(call: ToolCall, policy: Policy)
    ensures Decide(call, policy).Allow? ==> MatchesSomeAllowRule(call, policy)
  {
  }
}
