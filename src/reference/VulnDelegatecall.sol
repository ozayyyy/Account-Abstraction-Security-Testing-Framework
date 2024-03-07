// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ModularAccount} from "../ModularAccount.sol";

/// @notice Vulnerable variant C — delegatecall reachable by an executor.
/// Defect: executeDelegate is open to executors as well as the owner.
/// Delegatecalled code runs in the account's storage context, so a
/// hostile delegate target can overwrite the owner (storage slot 0).
/// The correct account restricts delegatecall to owner / EntryPoint.
/// Impact: a limited executor takes over the account in one call.
contract VulnDelegatecall is ModularAccount {
    constructor(address _owner, address _entryPoint, address _validator, address _allowedTarget)
        ModularAccount(_owner, _entryPoint, _validator, _allowedTarget)
    {}

    function executeDelegate(address target, bytes calldata data) external override {
        require(
            msg.sender == owner || msg.sender == entryPoint || isExecutor[msg.sender],
            "delegate: only owner"
        );
        (bool ok,) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
