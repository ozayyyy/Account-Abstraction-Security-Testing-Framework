---
name: account-abstraction-security-testing-framework
description: Test whether a modular smart account's permission model holds — validation, execution, modules, session keys and EIP-7702 delegation — with the Foundry harness in this repo. Use when checking account-abstraction permission boundaries or running the scenario suite.
---

# Account Abstraction Security Testing Framework

## What this is

A Foundry test harness for account-abstraction systems. It models a
modular smart account, a validator, an executor, installed modules,
a session-key validator, a minimal local EntryPoint, and EIP-7702
delegation, then tests whether each component can reach only what it
is supposed to reach.

The suite has 28 scenarios and 45 tests. Every scenario is written
the same way: the correct account must block the forbidden action,
and a vulnerable reference account must allow it. A passing run
means the harness correctly distinguishes the two — it does not mean
"no bugs". The six vulnerable reference accounts in `src/reference/`
are intentionally exploitable, and their tests prove the exploit
works.

Scenario groups:

- `VAL-*` — UserOperation validation: signature, nonce, expiry,
  EntryPoint-only validation, validator changes, owner self-call.
- `EXE-*` — Executor permissions: allowlisted target, no direct
  privileged calls, no self-call, no delegatecall, atomic batches.
- `MOD-*` — Module controls: owner-only install, module execution,
  module limits.
- `VULN-*` — The six reference defects, each proven as an exploit on
  its variant and a block on the correct account.
- `SK-*` — Session keys: expiry, spending limit, allowed target,
  revocation.
- `DEL-*` — EIP-7702 delegation: legitimate delegation, malicious
  delegation, revocation, replay.

## Setup

Foundry is required. Nothing else needs installing: `lib/forge-std`
is vendored in the repository, so the tests run offline with no
download step. Local chain only.

```bash
forge test
```

## Running it

```bash
# Full suite: 45 tests, 28 scenarios
forge test

# One area
forge test --match-contract PermissionsTest
forge test --match-contract SessionKeyTest
forge test --match-contract DelegationTest

# Verbose, with traces
forge test -vvv --match-test test_VulnSessionKey_OverspendExecutes

# Permission-decision report (JSON + Markdown in examples/)
python3 scripts/run_report.py
```

## Reading the output

`forge test` prints one line per test: `[PASS]` or `[FAIL]` with the
test name. A run is green only when all 45 pass.

`python3 scripts/run_report.py` writes `examples/report.json` and
`examples/report.md`. Each scenario lists its mapped tests and a
`pass` / `fail` status. A scenario passes only when every test
mapped to it passes. For the vulnerable variants, "pass" means the
test proved the defect: the forbidden action succeeds on the
vulnerable account and is blocked on the correct account.

`docs/EVALUATION.md` holds the measured results table and what the
numbers do and do not mean. `docs/permission-model.md` holds the
expected permission matrix, trust boundaries, invariants, and the
six reference defects.

## How to add an account or a scenario

1. Add the account in `src/reference/`, inheriting
   `ModularAccount` and overriding exactly one check. Name it after
   the defect and document the defect, the invariant it breaks, and
   the impact in the contract header.
2. Add tests in `test/` that prove two things: the forbidden action
   succeeds on the new account, and the same action is blocked on
   the correct account. A test that shows only one side does not
   prove the defect is both reachable and fixed.
3. Add the scenario to `SCENARIOS` in `scripts/run_report.py` so
   the report covers it.
4. Add a row to the defect table in `docs/permission-model.md` and
   to the evaluation table in `docs/EVALUATION.md`.

## Safety rules, in plain words

- Everything runs on your own machine, on a local chain. Nothing
  talks to the network, and no transaction is ever broadcast.
- The test keys are fixed constants in `test/Base.t.sol`. Never
  point this framework at real keys, real funds, or a live network.
- The EntryPoint here is a minimal local model, not the production
  EntryPoint. Results about validation and permission boundaries
  transfer; results about gas or bundler behaviour do not. A run
  against the real canonical EntryPoint v0.7 has not been done: the
  source is not on disk in this project and fetching is paused, so
  no real-EntryPoint results exist here.
- The vulnerable reference accounts are intentionally exploitable.
  They are test fixtures, not code to deploy or copy.
- Delegation tests use a funded test account on a local chain. A
  delegation to a hostile implementation hands that account's whole
  balance to whoever calls it — that is the point of the test, and
  the reason delegation must only ever be signed for an
  implementation that has been checked first.

## What it must never be used for

- Never use it on a live network, a real account, or real funds.
- Never reuse the fixed test keys anywhere real.
- Never present lab figures as claims about production code: passing
  tests show the harness distinguishes the six known defects from
  the correct implementation on the paths tested. They do not show
  that any account is secure in general.
- Never deploy the vulnerable reference accounts, the hostile
  module, the hostile delegate target, or the hostile delegation
  implementation outside this test setup.
- Never treat the local EntryPoint model as the production
  EntryPoint.
