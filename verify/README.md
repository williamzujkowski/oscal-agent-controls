# Gate Verification

This directory verifies the tool-call gate, not the agent. The goal is to keep the enforcement boundary small enough to prove directly, then check that the proved model, the Rego policy, and the production Python monitor all agree on the same synthetic policy and synthetic calls.

The shape is Cedar-style: a compact authorization model, explicit deny reasons, deny-by-default behavior, and a deterministic differential test corpus that compares independent implementations.

## Toolchain

Local tool paths:

- Dafny: `verify/bin/dafny-4.11.0/dafny/dafny`
- OPA: `verify/bin/opa`

These are local tools and are ignored by Git.

Exact local install commands used:

```sh
mkdir -p verify/bin
curl -L https://github.com/dafny-lang/dafny/releases/download/v4.11.0/dafny-4.11.0-x64-ubuntu-22.04.zip -o verify/bin/dafny-4.11.0-x64-ubuntu-22.04.zip
sha256sum verify/bin/dafny-4.11.0-x64-ubuntu-22.04.zip
unzip -q verify/bin/dafny-4.11.0-x64-ubuntu-22.04.zip -d verify/bin/dafny-4.11.0
chmod +x verify/bin/dafny-4.11.0/dafny/dafny
verify/bin/dafny-4.11.0/dafny/dafny --version

curl -L https://github.com/open-policy-agent/opa/releases/download/v1.18.2/opa_linux_amd64_static -o verify/bin/opa
sha256sum verify/bin/opa
chmod +x verify/bin/opa
verify/bin/opa version
```

Expected checksums:

```text
a46a9ff7cdd720f7955854c78e95df13f4cfe6b80691b05f8654fe19e8267179  verify/bin/dafny-4.11.0-x64-ubuntu-22.04.zip
9903e5125ac281104f2c4b7371d10cc3b74a98933743fcbfc174f9bf0ab20de8  verify/bin/opa
```

## Run

```sh
verify/bin/dafny-4.11.0/dafny/dafny verify verify/Gate.dfy
verify/bin/opa test verify/
python verify/difftest/run.py
```

Or run the formal suite through Make:

```sh
make verify-formal
```

## Proofs

`Gate.dfy` mirrors `gate.monitor.decide` for the synthetic policy:

1. Totality: `Decide` always returns either `Allow(reason)` or `Deny(reason)`.
2. Deny-by-default: a call that does not match an allow rule is denied.
3. Egress dominance: a call containing a configured synthetic secret and using a destination outside `egress.allowed_destinations` is denied.
4. Allow requires a rule: any allow decision implies a matched allow rule.

The executable comparison is in `verify/difftest/run.py`. It enumerates a fixed synthetic corpus and compares the Python monitor, Dafny-compiled Python, and OPA results for both decision and reason.
