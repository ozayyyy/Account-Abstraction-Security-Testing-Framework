# Evaluation

Measured on the reference accounts in this repository, on a local
Foundry chain. Reproduce with:

```bash
forge test
python3 scripts/run_report.py
```

## Results

| Scenario | Expected decision | Observed | Status |
| --- | --- | --- | --- |
| VAL-01 Valid UserOperation executes | Executes, nonce consumed | Executes, nonce 0 → 1 | pass |
| VAL-02 Bad signature rejected | Rejected, nothing executes | Rejected, counter 0 | pass |
| VAL-03 Wrong nonce rejected | Rejected | Rejected | pass |
| VAL-04 Expiry enforced | Expired rejected, unexpired accepted | Both as expected | pass |
| VAL-05 Validation is EntryPoint-only | Direct/validator/executor validation attempts revert | All revert | pass |
| VAL-06 Validator change is owner-only | Only owner can change it; no validator means validation fails | Both as expected | pass |
| VAL-07 Owner self-call through UserOperation | Owner admin work in a validated op succeeds | Owner changed via op | pass |
| EXE-01 Executor may use the allowlisted target | Succeeds | Target value set | pass |
| EXE-02 Executor may not call privileged functions directly | Reverts, owner unchanged | Reverts | pass |
| EXE-03 Executor may not self-call | Reverts | Reverts | pass |
| EXE-04 Executor may not delegatecall | Reverts, owner unchanged | Reverts | pass |
| EXE-05 Batch authorisation is atomic | Allowed batch succeeds; mixed batch reverts with no partial effects | Both as expected | pass |
| MOD-01 Module installation is owner-only | Non-owner reverts; owner succeeds | Both as expected | pass |
| MOD-02 Installed module may execute the target | Succeeds | Target value set | pass |
| MOD-03 Module limits hold | No self-call, no installing others, no execution after uninstall | All revert | pass |
| VULN-A Direct privileged call | Attacker sets owner on vulnerable account; blocked on correct account | Owner changed on variant A, blocked on correct | pass |
| VULN-B Unrestricted module install | Attacker installs hostile module and drains 1 ether on vulnerable account; blocked on correct account | Drain succeeded on variant B, install blocked on correct | pass |
| VULN-C Delegatecall by executor | Executor overwrites owner on vulnerable account; blocked on correct account | Owner set to executor on variant C, blocked on correct | pass |
| VULN-D Nonce replay | Same operation executes twice on vulnerable account; second rejected on correct account | Counter 2 on variant D, 1 on correct; bad signature still rejected on variant D | pass |
| VULN-E Self-call by executor | Executor sets owner via self-call on vulnerable account; blocked on correct account; direct call still blocked on the variant | All three as expected | pass |

Totals: **20/20 scenarios pass, 31/31 Foundry tests pass, 0 failed,
0 skipped.** Suite time ~29 ms (local chain, in-process).

## Coverage

- Permission paths covered: direct, batched, self-call, delegated,
  module execution, validation.
- Roles covered: owner, EntryPoint, validator, executor, installed
  module, uninstalled module, random address.
- Each of the five reference defects has a dedicated scenario that
  proves both the exploit (on the vulnerable account) and the block
  (on the correct account). Detection accuracy on the reference set
  is therefore 5/5 defects demonstrated and 5/5 fixes verified.
- Regression effectiveness: every scenario is a regression test —
  re-running `forge test` after any change to the account re-checks
  all five defects and all permission boundaries. A change that
  re-opens a defect fails its scenario.

## What these numbers do and do not mean

These are **lab-only figures on the reference accounts**. They show
the harness distinguishes the five known defects from the correct
implementation, on the paths tested. They do not show that the
correct account is secure in general: a defect in a path not
modelled here (paymaster, multi-validator, cross-module calls, gas
griefing) would not be caught, and the correct account has not been
tested against a production EntryPoint or a live network.
