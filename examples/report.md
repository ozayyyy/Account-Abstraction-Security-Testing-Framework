# Account abstraction permission-decision report

Foundry suite: 31 passed, 0 failed, 0 skipped (exit code 0).
Scenarios: 20/20 pass.

A scenario passes only when every Foundry test mapped to it passes. For the vulnerable variants, 'pass' means the test proved the defect: the forbidden action succeeds on the vulnerable account and is blocked on the correct account.

| Scenario | Title | Status |
| --- | --- | --- |
| EXE-01 | Executor may use the allowlisted target | pass |
| EXE-02 | Executor may not call privileged functions directly | pass |
| EXE-03 | Executor may not self-call | pass |
| EXE-04 | Executor may not delegatecall | pass |
| EXE-05 | Batch authorisation is atomic | pass |
| MOD-01 | Module installation is owner-only | pass |
| MOD-02 | Installed module may execute the target | pass |
| MOD-03 | Module limits hold | pass |
| VAL-01 | Valid UserOperation executes | pass |
| VAL-02 | Bad signature rejected | pass |
| VAL-03 | Wrong nonce rejected | pass |
| VAL-04 | Expiry enforced | pass |
| VAL-05 | Validation is EntryPoint-only | pass |
| VAL-06 | Validator change is owner-only | pass |
| VAL-07 | Owner self-call through UserOperation | pass |
| VULN-A | Variant A: direct privileged call | pass |
| VULN-B | Variant B: unrestricted module install | pass |
| VULN-C | Variant C: delegatecall by executor | pass |
| VULN-D | Variant D: nonce replay | pass |
| VULN-E | Variant E: self-call by executor | pass |

## Per-scenario detail

### EXE-01 — Executor may use the allowlisted target

Expected: Executor call to the allowlisted target succeeds

- `test_ExecutorCanExecuteAllowedTarget`: PASS

### EXE-02 — Executor may not call privileged functions directly

Expected: Executor setOwner call reverts, owner unchanged

- `test_ExecutorCannotSetOwnerDirect`: PASS

### EXE-03 — Executor may not self-call

Expected: Executor execute() to the account itself reverts

- `test_ExecutorCannotSelfCall`: PASS

### EXE-04 — Executor may not delegatecall

Expected: Executor executeDelegate call reverts, owner unchanged

- `test_ExecutorCannotDelegatecall`: PASS

### EXE-05 — Batch authorisation is atomic

Expected: Allowed batch succeeds; mixed batch reverts with no partial effects; owner batch with self-call succeeds

- `test_ExecutorBatchAllowedSucceeds`: PASS
- `test_ExecutorBatchMixedRevertsAtomically`: PASS
- `test_OwnerBatchWithSelfCallSucceeds`: PASS

### MOD-01 — Module installation is owner-only

Expected: Non-owner install reverts; owner install succeeds

- `test_ModuleInstallOwnerOnly`: PASS

### MOD-02 — Installed module may execute the target

Expected: Installed module call to the target succeeds

- `test_InstalledModuleCanExecuteTarget`: PASS

### MOD-03 — Module limits hold

Expected: Module cannot self-call, cannot install another module, loses execution on uninstall

- `test_ModuleCannotSelfCall`: PASS
- `test_ModuleCannotInstallAnotherModule`: PASS
- `test_UninstalledModuleLosesExecution`: PASS

### VAL-01 — Valid UserOperation executes

Expected: Validated owner operation executes, nonce consumed

- `test_ValidUserOpExecutes`: PASS

### VAL-02 — Bad signature rejected

Expected: Operation signed by a non-owner is rejected, nothing executes

- `test_BadSignatureRejected`: PASS

### VAL-03 — Wrong nonce rejected

Expected: Operation with a non-current nonce is rejected

- `test_WrongNonceRejected`: PASS

### VAL-04 — Expiry enforced

Expected: Expired operation rejected, unexpired operation accepted

- `test_ExpiredUserOpRejected`: PASS
- `test_UnexpiredUserOpAccepted`: PASS

### VAL-05 — Validation is EntryPoint-only

Expected: Direct validateUserOp calls and validator/executor validation attempts revert

- `test_ValidateDirectCallReverts`: PASS
- `test_ExecutorCannotValidate`: PASS
- `test_ValidatorCannotExecute`: PASS
- `test_DirectExecuteByRandomReverts`: PASS

### VAL-06 — Validator change is owner-only

Expected: Only the owner can change the validator; with no validator, validation fails

- `test_ValidatorChangeIsOwnerOnly`: PASS

### VAL-07 — Owner self-call through UserOperation

Expected: Owner admin work inside a validated operation succeeds

- `test_OwnerCanSelfCallThroughUserOp`: PASS

### VULN-A — Variant A: direct privileged call

Expected: Attacker sets owner directly on the vulnerable account; blocked on the correct account

- `test_VulnDirectPrivileged_AttackerSetsOwner`: PASS

### VULN-B — Variant B: unrestricted module install

Expected: Attacker installs a hostile module and drains funds on the vulnerable account; blocked on the correct account

- `test_VulnModuleInstall_AttackerInstallsAndDrains`: PASS

### VULN-C — Variant C: delegatecall by executor

Expected: Executor overwrites the owner via delegatecall on the vulnerable account; blocked on the correct account

- `test_VulnDelegatecall_ExecutorPwnsOwner`: PASS

### VULN-D — Variant D: nonce replay

Expected: Same signed operation executes twice on the vulnerable account; second execution rejected on the correct account

- `test_VulnReplay_SameUserOpExecutesTwice`: PASS
- `test_VulnReplay_BadSignatureStillRejected`: PASS
- `test_ReplayRejectedOnCorrectAccount`: PASS
- `test_NonceIncrementsOnValidOp`: PASS

### VULN-E — Variant E: self-call by executor

Expected: Executor sets owner via self-call on the vulnerable account; blocked on the correct account, and the direct call is still blocked on the variant itself

- `test_VulnSelfCall_ExecutorSelfCallsSetOwner`: PASS
