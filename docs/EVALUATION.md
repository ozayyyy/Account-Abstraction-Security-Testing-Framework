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
| SK-01 Session key expiry enforced | Expired key rejected; same expired key executes on variant F | Rejected on correct, executes on variant F | pass |
| SK-02 Session key spending limit enforced | Within-limit calls succeed, spend accumulates; overspend rejected; overspend executes on variant F | Two 0.4 ether calls succeed, third rejected at 0.8 spent; single 2 ether call rejected; 5 ether call executes on variant F | pass |
| SK-03 Session key target enforced | Call outside the key's allowlist rejected; executes on variant F | Rejected on correct, executes on variant F | pass |
| SK-04 Session key revocation enforced | Revoked key rejected; same revoked key executes on variant F | Rejected on correct, executes on variant F | pass |
| DEL-01 Legitimate delegation executes | EOA delegated to a benign implementation runs its code | Counter increments, delegator has code | pass |
| DEL-02 Malicious delegation drains the EOA | EOA delegated to a hostile implementation loses its whole balance | Attacker gains 10 ether, delegator balance 0 | pass |
| DEL-03 Delegation revocation clears the code | Delegating to address(0) removes the code; implementation no longer runs | Code length 0 after revoke, counter unchanged | pass |
| DEL-04 Delegation authorisation cannot be replayed | Attaching the same signed authorisation twice is rejected | Second attach reverts (invalid nonce) | pass |

Totals: **28/28 scenarios pass, 45/45 Foundry tests pass, 0 failed,
0 skipped.** Suite time ~29 ms (local chain, in-process).

## Real EntryPoint check — blocked

The scenarios above run against `MinimalEntryPoint`, the local
model in this repository. A run against the real canonical
EntryPoint v0.7 has **not** been done: the canonical source is not
on disk anywhere in this project, and fetching it is paused, so no
real-EntryPoint results exist and none are claimed here. The
session-key and delegation scenarios likewise run against the local
model. Until that run happens, every figure on this page is a
local-model figure.

## Coverage

- Permission paths covered: direct, batched, self-call, delegated,
  module execution, validation, session-key execution, EIP-7702
  delegation.
- Roles covered: owner, EntryPoint, validator, executor, installed
  module, uninstalled module, random address, session-key holder,
  delegated EOA.
- Each of the six reference defects has a dedicated scenario that
  proves both the exploit (on the vulnerable account) and the block
  (on the correct account). Detection accuracy on the reference set
  is therefore 6/6 defects demonstrated and 6/6 fixes verified.
- Regression effectiveness: every scenario is a regression test —
  re-running `forge test` after any change to the account re-checks
  all six defects and all permission boundaries. A change that
  re-opens a defect fails its scenario.

## What these numbers do and do not mean

These are **lab-only figures on the reference accounts**. They show
the harness distinguishes the six known defects from the correct
implementation, on the paths tested. They do not show that the
correct account is secure in general: a defect in a path not
modelled here (paymaster, multi-validator, cross-module calls, gas
griefing) would not be caught, and the correct account has not been
tested against a production EntryPoint or a live network. The
delegation tests likewise show what delegation does on a local
chain, not what any real delegation setup will do.
