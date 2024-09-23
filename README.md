# Account Abstraction Security Testing Framework

A Foundry test harness for account-abstraction systems, focused on
one question: does the separation between validation, execution and
administration actually hold, on every path?

It models a modular smart account, a validator, an executor, installed
modules and a minimal local EntryPoint, then tests whether each
component can reach only what it is supposed to reach — through
direct calls, batched calls, self-calls and delegatecall.

## Reading the test results correctly

`forge test` passing does **not** mean "no bugs". The suite passes
by asserting the expected decision for each scenario: the correct
account blocks a forbidden action, and each vulnerable reference
account allows it. A passing run means the harness correctly
distinguishes the two. The five vulnerable accounts are intentionally
exploitable, and their tests prove the exploit works.

## What is in here

- `src/MinimalEntryPoint.sol` — local EntryPoint for testing only.
  No gas accounting, stake, paymaster, factory or bundler economics.
  It validates an operation, then executes it. Not the production
  EntryPoint.
- `src/ModularAccount.sol` — the correct modular account. Owner,
  validator, executors and modules, with explicit permission checks.
- `src/SimpleValidator.sol` — single-signer signature check.
- `src/Target.sol` — harmless external target, the non-privileged
  baseline for execution tests.
- `src/Modules.sol` — a well-behaved module, a hostile module, and a
  hostile delegate target, for tests only.
- `src/reference/` — five vulnerable accounts, each with exactly one
  permission-model defect:
  - `VulnDirectPrivileged` — `setOwner` has no check.
  - `VulnModuleInstall` — anyone can install a module.
  - `VulnDelegatecall` — an executor may delegatecall.
  - `VulnReplay` — the nonce is never checked or consumed.
  - `VulnSelfCall` — an executor may self-call the account.
- `test/` — Foundry tests: validation, permissions, replay.
- `scripts/run_report.py` — runs the suite and writes a
  permission-decision report to `examples/`.
- `docs/permission-model.md` — the expected permission matrix, trust
  boundaries, invariants, and the research questions answered from
  the test results.
- `docs/EVALUATION.md` — measured scenario coverage and detection
  results.

## Setup

```bash
forge test
```

Requires Foundry. The project uses solc 0.8.24 and a vendored
`lib/forge-std` (included in the repository so the tests run
offline, with no download step). Local chain only: no network, no
broadcast transactions, no real keys. Test keys are fixed constants
in `test/Base.t.sol`.

## Usage

```bash
# Full suite
forge test

# One area
forge test --match-contract PermissionsTest

# Verbose, with traces
forge test -vvv --match-test test_VulnSelfCall

# Permission-decision report (JSON + Markdown in examples/)
python3 scripts/run_report.py
```

## How to add an account or a scenario

1. Add the account in `src/reference/`, inheriting `ModularAccount`
   and overriding exactly one check. Name it after the defect and
   document the defect, the invariant it breaks, and the impact in
   the contract header.
2. Add tests in `test/` that prove two things: the forbidden action
   succeeds on the new account, and the same action is blocked on
   the correct account. A test that shows only one side does not
   prove the defect is both reachable and fixed.
3. Add the scenario to `SCENARIOS` in `scripts/run_report.py` so the
   report covers it.
4. Add a row to the defect table in `docs/permission-model.md` and
   to the evaluation table in `docs/EVALUATION.md`.

## Architecture

```
UserOperation
  -> MinimalEntryPoint.handleOps
    -> account.validateUserOp   (EntryPoint only; nonce, expiry, signature)
    -> account.execute*         (callData, after validation)
         -> Target / account itself / delegate target

Roles: owner (all) | EntryPoint (validated ops) |
       executor (allowlisted target only) |
       installed module (moduleExecute, never self-call) |
       validator (signatures only)
```

## Limitations

- The EntryPoint is a local test model, not the production
  EntryPoint: no gas, stake, paymaster, factory, or account
  creation. Results about validation and permission boundaries
  transfer; results about gas or bundler behaviour do not.
- Signatures are checked over the raw operation hash, with no
  EIP-191 prefix. A production validator must follow the account's
  documented signing scheme.
- One validator per account, one executor allowlist (a single
  target contract). Multi-validator and per-executor allowlists are
  not modelled.
- No paymaster is included. Paymaster trust boundaries are out of
  scope for this version.
- Tests run on a local Foundry chain with fixed keys. No live
  network testing was done.

## **Note:** This repository was originally a private project and has been made public for portfolio and educational purposes. Feel free to explore, use, and adapt the code.
