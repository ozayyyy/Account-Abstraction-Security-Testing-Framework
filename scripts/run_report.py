#!/usr/bin/env python3
"""Run the Foundry suite and produce a permission-decision report.

Reads nothing but the output of `forge test` and a scenario table
declared below. A scenario passes only when every Foundry test mapped
to it passes. The report therefore cannot claim a scenario is covered
unless the tests actually ran and passed.

Usage, from the repository root:
    python3 scripts/run_report.py [--output-dir examples]

Outputs:
    <output-dir>/report.json  machine-readable per-scenario summary
    <output-dir>/report.md    the same summary as Markdown
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# scenario id -> (title, expected decision, [test names])
SCENARIOS = {
    "VAL-01": ("Valid UserOperation executes",
               "Validated owner operation executes, nonce consumed",
               ["test_ValidUserOpExecutes"]),
    "VAL-02": ("Bad signature rejected",
               "Operation signed by a non-owner is rejected, nothing executes",
               ["test_BadSignatureRejected"]),
    "VAL-03": ("Wrong nonce rejected",
               "Operation with a non-current nonce is rejected",
               ["test_WrongNonceRejected"]),
    "VAL-04": ("Expiry enforced",
               "Expired operation rejected, unexpired operation accepted",
               ["test_ExpiredUserOpRejected", "test_UnexpiredUserOpAccepted"]),
    "VAL-05": ("Validation is EntryPoint-only",
               "Direct validateUserOp calls and validator/executor validation attempts revert",
               ["test_ValidateDirectCallReverts", "test_ExecutorCannotValidate",
                "test_ValidatorCannotExecute", "test_DirectExecuteByRandomReverts"]),
    "VAL-06": ("Validator change is owner-only",
               "Only the owner can change the validator; with no validator, validation fails",
               ["test_ValidatorChangeIsOwnerOnly"]),
    "VAL-07": ("Owner self-call through UserOperation",
               "Owner admin work inside a validated operation succeeds",
               ["test_OwnerCanSelfCallThroughUserOp"]),
    "EXE-01": ("Executor may use the allowlisted target",
               "Executor call to the allowlisted target succeeds",
               ["test_ExecutorCanExecuteAllowedTarget"]),
    "EXE-02": ("Executor may not call privileged functions directly",
               "Executor setOwner call reverts, owner unchanged",
               ["test_ExecutorCannotSetOwnerDirect"]),
    "EXE-03": ("Executor may not self-call",
               "Executor execute() to the account itself reverts",
               ["test_ExecutorCannotSelfCall"]),
    "EXE-04": ("Executor may not delegatecall",
               "Executor executeDelegate call reverts, owner unchanged",
               ["test_ExecutorCannotDelegatecall"]),
    "EXE-05": ("Batch authorisation is atomic",
               "Allowed batch succeeds; mixed batch reverts with no partial effects; owner batch with self-call succeeds",
               ["test_ExecutorBatchAllowedSucceeds", "test_ExecutorBatchMixedRevertsAtomically",
                "test_OwnerBatchWithSelfCallSucceeds"]),
    "MOD-01": ("Module installation is owner-only",
               "Non-owner install reverts; owner install succeeds",
               ["test_ModuleInstallOwnerOnly"]),
    "MOD-02": ("Installed module may execute the target",
               "Installed module call to the target succeeds",
               ["test_InstalledModuleCanExecuteTarget"]),
    "MOD-03": ("Module limits hold",
               "Module cannot self-call, cannot install another module, loses execution on uninstall",
               ["test_ModuleCannotSelfCall", "test_ModuleCannotInstallAnotherModule",
                "test_UninstalledModuleLosesExecution"]),
    "VULN-A": ("Variant A: direct privileged call",
               "Attacker sets owner directly on the vulnerable account; blocked on the correct account",
               ["test_VulnDirectPrivileged_AttackerSetsOwner"]),
    "VULN-B": ("Variant B: unrestricted module install",
               "Attacker installs a hostile module and drains funds on the vulnerable account; blocked on the correct account",
               ["test_VulnModuleInstall_AttackerInstallsAndDrains"]),
    "VULN-C": ("Variant C: delegatecall by executor",
               "Executor overwrites the owner via delegatecall on the vulnerable account; blocked on the correct account",
               ["test_VulnDelegatecall_ExecutorPwnsOwner"]),
    "VULN-D": ("Variant D: nonce replay",
               "Same signed operation executes twice on the vulnerable account; second execution rejected on the correct account",
               ["test_VulnReplay_SameUserOpExecutesTwice", "test_VulnReplay_BadSignatureStillRejected",
                "test_ReplayRejectedOnCorrectAccount", "test_NonceIncrementsOnValidOp"]),
    "VULN-E": ("Variant E: self-call by executor",
               "Executor sets owner via self-call on the vulnerable account; blocked on the correct account, and the direct call is still blocked on the variant itself",
               ["test_VulnSelfCall_ExecutorSelfCallsSetOwner"]),
}

TEST_RE = re.compile(r"\[(PASS|FAIL|SKIP)\]\s+(test_\w+)\(\)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="examples")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        ["forge", "test"], cwd=root, capture_output=True, text=True,
    )
    output = proc.stdout + proc.stderr

    results = {}
    for status, name in TEST_RE.findall(output):
        results[name] = status
    total_match = re.search(r"(\d+) tests? passed, (\d+) failed, (\d+) skipped", output)
    totals = {
        "passed": int(total_match.group(1)) if total_match else 0,
        "failed": int(total_match.group(2)) if total_match else 0,
        "skipped": int(total_match.group(3)) if total_match else 0,
    }

    scenarios = []
    for sid in sorted(SCENARIOS):
        title, expected, tests = SCENARIOS[sid]
        statuses = {t: results.get(t, "NOT RUN") for t in tests}
        passed = all(s == "PASS" for s in statuses.values())
        scenarios.append({
            "id": sid,
            "title": title,
            "expected_decision": expected,
            "tests": statuses,
            "status": "pass" if passed else "fail",
        })

    report = {
        "forge_exit_code": proc.returncode,
        "forge_totals": totals,
        "scenarios_passed": sum(1 for s in scenarios if s["status"] == "pass"),
        "scenarios_total": len(scenarios),
        "scenarios": scenarios,
    }

    out_dir = root / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    lines = ["# Account abstraction permission-decision report",
             "",
             f"Foundry suite: {totals['passed']} passed, {totals['failed']} failed, "
             f"{totals['skipped']} skipped (exit code {proc.returncode}).",
             f"Scenarios: {report['scenarios_passed']}/{report['scenarios_total']} pass.",
             "",
             "A scenario passes only when every Foundry test mapped to it passes. "
             "For the vulnerable variants, 'pass' means the test proved the defect: "
             "the forbidden action succeeds on the vulnerable account and is blocked "
             "on the correct account.",
             "",
             "| Scenario | Title | Status |",
             "| --- | --- | --- |"]
    for s in scenarios:
        lines.append(f"| {s['id']} | {s['title']} | {s['status']} |")
    lines += ["",
              "## Per-scenario detail",
              ""]
    for s in scenarios:
        lines.append(f"### {s['id']} — {s['title']}")
        lines.append("")
        lines.append(f"Expected: {s['expected_decision']}")
        lines.append("")
        for t, st in s["tests"].items():
            lines.append(f"- `{t}`: {st}")
        lines.append("")
    (out_dir / "report.md").write_text("\n".join(lines))

    print(f"scenarios: {report['scenarios_passed']}/{report['scenarios_total']} pass")
    print(f"forge: {totals['passed']} passed, {totals['failed']} failed")
    failed = [s["id"] for s in scenarios if s["status"] != "pass"]
    if failed:
        print("failing scenarios:", ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
