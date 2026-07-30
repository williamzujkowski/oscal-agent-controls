# OSCAL Agent Controls

This repository is a small runnable reference implementation for a two-part blog
series on expressing AI-agent security controls as OSCAL and proving the gate
with deterministic pipeline evidence.

The core idea is that an agent control is only real when it is enforced outside
the model path. The reference monitor in `gate/monitor.py` mediates every
synthetic tool call, denies by default, and writes a structured audit record for
both allow and deny decisions. Secret egress dominates the tool allowlist: a
call can match an allow rule and still be denied when its payload matches a
synthetic secret pattern and its destination is not approved for secret egress.

Everything here is synthetic. Tool names, destinations, namespace values,
principals, payloads, and secret patterns are invented for the reference
implementation.

## Run

Install dependencies:

```sh
python -m pip install -r requirements.txt
```

Run unit and pipeline tests:

```sh
make test
```

Run the evidence pipeline:

```sh
make verify
```

`make verify` writes `oscal/assessment-results.json` and exits non-zero if any
finding fails.

## Formal verification (post 2)

You cannot formally verify a non-deterministic model. You can verify the
deterministic gate that mediates it. `verify/` does exactly that, mirroring the
approach AWS used for Cedar — a formally-modeled decision function plus
differential testing against the deployable engine:

- **`verify/Gate.dfy`** — a Dafny model of the same `Decide` function, with
  machine-checked proofs of totality, deny-by-default, egress dominance, and
  "allow requires a matching rule." `dafny verify` discharges every obligation.
- **`verify/gate.rego` + `verify/gate_test.rego`** — the same decision as a
  deployable OPA/Rego policy, exercised by `opa test`.
- **`verify/difftest/run.py`** — a differential harness over a deterministic
  synthetic corpus that asserts the Python gate, the Dafny-proved model, and the
  Rego policy all return the same decision and reason for every input.

See `verify/README.md` for toolchain setup (Dafny, OPA) and how to run each step.
The toolchain binaries and Dafny build output are gitignored; CI installs pinned
versions.
