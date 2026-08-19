// Authority that changes while the agent is running.
//
// Gate.dfy proves the gate is correct for every input against a FIXED policy.
// This module drops that assumption. Two things move at runtime:
//
//   1. the agent's authority MODE, which can be reduced without being revoked
//   2. the POLICY BODY itself, which a grant must be bound to by content
//      rather than by name
//
// Both are modelled here, and the properties that must survive them are proved.
module Authority {
  import opened Gate

  // ---------------------------------------------------------------------
  // Authority modes
  //
  // Scope answers "which resource". Mode answers "how hard may you push on
  // it". Delegation models generally constrain the first and say nothing
  // about the second, which is how "recommend a patch" and "rewrite the file"
  // end up indistinguishable to a policy engine.
  // ---------------------------------------------------------------------
  datatype Mode = Observe | Suggest | Enforce

  function ModeRank(m: Mode): nat
  {
    match m
    case Observe => 0
    case Suggest => 1
    case Enforce => 2
  }

  ghost predicate ModeAtLeast(held: Mode, required: Mode)
  {
    ModeRank(required) <= ModeRank(held)
  }

  function ModeAtLeastF(held: Mode, required: Mode): bool
  {
    ModeRank(required) <= ModeRank(held)
  }

  // ---------------------------------------------------------------------
  // A grant is bound to a policy BODY, not a policy NAME.
  //
  // This is the defect the current agent-authorization drafts share with
  // OSCAL: a token carries a policy identifier, the signature covers the
  // token, and nothing covers the policy text that identifier resolves to.
  // The audit record then attests to a name whose meaning can be edited
  // afterwards. Binding the digest is what closes it.
  // ---------------------------------------------------------------------
  datatype Authority = Authority(mode: Mode, policyDigest: string)

  // A per-tool minimum authority. Absent an entry, a tool requires Enforce:
  // the unlisted case must be the most restrictive, not the least.
  datatype ModeRule = ModeRule(tool: string, required: Mode)

  function FindModeRule(tool: string, rules: seq<ModeRule>): Mode
    decreases |rules|
  {
    if |rules| == 0 then
      Enforce
    else if rules[0].tool == tool then
      rules[0].required
    else
      FindModeRule(tool, rules[1..])
  }

  // ---------------------------------------------------------------------
  // The bound decision.
  //
  // Order matters and is deliberate. The digest check runs first: a grant
  // issued against a policy body that is no longer the one in force cannot
  // authorize anything, whatever it says about modes or tools.
  // ---------------------------------------------------------------------
  function DecideBound(
    auth: Authority,
    policy: Policy,
    presentedDigest: string,
    modeRules: seq<ModeRule>,
    call: ToolCall
  ): Decision
  {
    if presentedDigest != auth.policyDigest then
      Deny("policy-body-mismatch")
    else if !ModeAtLeastF(auth.mode, FindModeRule(call.tool, modeRules)) then
      Deny("above-current-authority")
    else
      Decide(call, policy)
  }

  // ---------------------------------------------------------------------
  // Demotion: the middle the drafts don't model.
  //
  // Revocation destroys the grant. Demotion keeps the agent working at a
  // lower authority. Note there is no timestamp and no validity window --
  // the demoted authority IS the authority, so there is no interval during
  // which a stale-but-unexpired grant still answers.
  // ---------------------------------------------------------------------
  function Demote(a: Authority, to: Mode): Authority
    requires ModeRank(to) <= ModeRank(a.mode)
  {
    Authority(to, a.policyDigest)
  }

  // Synthetic entry point for differential testing, mirroring
  // Gate.DecideSynthetic. Fake tools and namespaces throughout.
  function DecideBoundSynthetic(
    mode: string,
    boundDigest: string,
    presentedDigest: string,
    tool: string,
    action: string,
    resource: string,
    destination: string,
    payload: string,
    ruleTool: string,
    ruleMode: string
  ): Decision
  {
    var m := if mode == "observe" then Observe
             else if mode == "suggest" then Suggest
             else Enforce;
    var rm := if ruleMode == "observe" then Observe
              else if ruleMode == "suggest" then Suggest
              else Enforce;
    var rules := if ruleTool == "" then [] else [ModeRule(ruleTool, rm)];
    DecideBound(
      Authority(m, boundDigest),
      SyntheticPolicy(),
      presentedDigest,
      rules,
      ToolCall("synthetic-user", tool, action, resource, destination, payload,
               "2026-08-18T00:00:00Z")
    )
  }

  // =====================================================================
  // Properties
  // =====================================================================

  // An agent never acts above the authority it currently holds.
  lemma NeverActsAboveAuthority(
    auth: Authority, policy: Policy, digest: string,
    modeRules: seq<ModeRule>, call: ToolCall
  )
    ensures DecideBound(auth, policy, digest, modeRules, call).Allow?
            ==> ModeAtLeast(auth.mode, FindModeRule(call.tool, modeRules))
  {
  }

  // A demotion takes effect before the next decision. There is no window in
  // which the pre-demotion mode still authorizes anything: the very next
  // call evaluated against the demoted authority is denied if it needed more.
  lemma DemotionTakesEffectImmediately(
    auth: Authority, policy: Policy, digest: string,
    modeRules: seq<ModeRule>, call: ToolCall, to: Mode
  )
    // The digest check runs first, so this property only holds once the
    // presented policy body is the bound one. Dafny rejected the lemma
    // without this precondition, which is the proof doing its job: a
    // mismatched digest denies for a different reason entirely.
    requires digest == auth.policyDigest
    requires ModeRank(to) <= ModeRank(auth.mode)
    requires !ModeAtLeastF(to, FindModeRule(call.tool, modeRules))
    ensures DecideBound(Demote(auth, to), policy, digest, modeRules, call)
            == Deny("above-current-authority")
  {
  }

  // Demotion can only ever narrow. Anything denied for authority reasons
  // before a demotion is still denied after it -- demotion is not a
  // re-grant wearing a smaller number.
  lemma DemotionCannotWiden(
    auth: Authority, policy: Policy, digest: string,
    modeRules: seq<ModeRule>, call: ToolCall, to: Mode
  )
    requires ModeRank(to) <= ModeRank(auth.mode)
    ensures DecideBound(Demote(auth, to), policy, digest, modeRules, call).Allow?
            ==> DecideBound(auth, policy, digest, modeRules, call).Allow?
  {
  }

  // A grant is bound to the exact policy body it was issued against. If the
  // body in force at decision time is not that body, nothing is authorized.
  // This is the property a bare `policy_id` cannot express.
  lemma GrantBoundToPolicyBody(
    auth: Authority, policy: Policy, presentedDigest: string,
    modeRules: seq<ModeRule>, call: ToolCall
  )
    ensures presentedDigest != auth.policyDigest
            ==> DecideBound(auth, policy, presentedDigest, modeRules, call)
                == Deny("policy-body-mismatch")
  {
  }

  // The mode gate is strictly additional: it can turn an Allow into a Deny
  // and can never turn a Deny into an Allow. Adding authority modes cannot
  // widen what Gate.dfy already proved.
  lemma ModeGateOnlyRestricts(
    auth: Authority, policy: Policy, digest: string,
    modeRules: seq<ModeRule>, call: ToolCall
  )
    ensures DecideBound(auth, policy, digest, modeRules, call).Allow?
            ==> Decide(call, policy).Allow?
  {
  }

  // An unlisted tool requires the highest mode, so an agent below Enforce
  // cannot reach anything the mode table forgot to mention.
  lemma UnlistedToolRequiresEnforce(tool: string)
    ensures FindModeRule(tool, []) == Enforce
  {
  }

  lemma ObserverCannotReachUnlistedTool(
    auth: Authority, policy: Policy, digest: string, call: ToolCall
  )
    requires auth.mode == Observe
    requires auth.policyDigest == digest
    ensures DecideBound(auth, policy, digest, [], call)
            == Deny("above-current-authority")
  {
  }
}
