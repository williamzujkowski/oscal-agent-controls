# OSCAL Agent Controls

This is a compact reference implementation for expressing AI-agent controls as OSCAL and proving the deterministic gate that enforces them. It backs a two-part series: [post 1, expressing controls as OSCAL](https://williamzujkowski.github.io/posts/2026-07-23-agent-controls-as-oscal/), and [post 2, proving the gate rather than the agent](https://williamzujkowski.github.io/posts/2026-07-30-prove-the-gate-not-the-agent/). The post links may 404 until their publish dates.

## Start Here

### Read post 1: express controls as OSCAL

Install the package, run the evidence pipeline, then inspect the generated assessment results:

```sh
python -m pip install -e .
make verify
```

Open `oscal/assessment-results.json`. The pipeline writes 9 findings and exits non-zero if any finding fails. The core pieces are `gate/monitor.py` for the reference monitor, `oscal/` for OSCAL component and assessment artifacts, and `pipeline/` for the deterministic evidence run.

### Read post 2: prove the gate

Run the formal suite:

```sh
make verify-formal
```

That verifies the Dafny proofs, runs `opa test`, and executes the differential test across the Python monitor, Dafny-compiled model, and Rego policy. The relevant files are `verify/Gate.dfy`, `verify/gate.rego`, and `verify/difftest/`.

## Repo Layout

| Path | Contents |
| --- | --- |
| `gate/` | Python reference monitor, policy loader, decisions, and audit records. |
| `pipeline/` | OSCAL assessment-results generator and verification entry point. |
| `policy/` | Synthetic YAML policy consumed by the monitor. |
| `oscal/` | Component definition and generated assessment results. |
| `tests/` | Pytest coverage for gate behavior and pipeline output. |
| `verify/` | Dafny model, Rego policy, OPA tests, and differential harness. |
| `.github/workflows/` | CI that installs Python deps plus pinned Dafny and OPA tools. |

## Reference Monitor

The model path is not the enforcement boundary; the gate is. `gate/monitor.py` mediates every synthetic tool call, denies by default, and records allow and deny decisions with the required audit fields. Secret egress dominates the allowlist: a tool call can match an allow rule and still be denied when its payload matches a synthetic secret pattern and its destination is not approved for secret egress.

Everything here is synthetic. Tool names, destinations, namespace values, principals, payloads, and secret patterns are invented for the reference implementation.

## Quickstart

```sh
python -m pip install -e '.[dev]'
python -m pytest
make verify
make verify-formal
```

`make verify` runs the pipeline and then the formal suite. `make verify-formal` expects Dafny at `verify/bin/dafny-4.11.0/dafny/dafny` or on `PATH`, and OPA at `verify/bin/opa` or on `PATH`; see `verify/README.md` for exact local install commands.

## Contributing

This is a demo-sized reference repo for the blog series. Keep changes small, reproducible, and backed by `python -m pytest`, `make verify`, and `make verify-formal`.
