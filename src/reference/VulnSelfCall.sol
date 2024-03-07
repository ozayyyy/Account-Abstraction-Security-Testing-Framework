// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ModularAccount} from "../ModularAccount.sol";

/// @notice Vulnerable variant E — self-call reachable by an executor.
/// Defect: the execute authorisation check allows an executor to call
/// the account itself (dest == address(this)), in addition to the
/// allowlisted target. A self-call runs with msg.sender == the account,
/// which the privileged functions accept, so the executor can invoke
/// setOwner through execute() even though a direct setOwner call by
/// the same executor still reverts.
/// The correct account allows self-calls only from the owner or the
/// EntryPoint. This variant is distinct from variant A: the direct
/// privileged call is still blocked here; only the indirect path
/// through execute() is open.
/// Impact: a limited executor takes over the account via a self-call.
contract VulnSelfCall is ModularAccount {
    constructor(address _owner, address _entryPoint, address _validator, address _allowedTarget)
        ModularAccount(_owner, _entryPoint, _validator, _allowedTarget)
    {}

    function _authorizeExecute(address caller, address dest) internal view override {
        if (caller == owner || caller == entryPoint) return;
        if (isExecutor[caller]) {
            require(
                dest == allowedTarget || dest == address(this), "executor: target not allowed"
            );
            return;
        }
        revert("not authorized");
    }
}
