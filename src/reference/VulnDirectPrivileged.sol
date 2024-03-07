// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ModularAccount} from "../ModularAccount.sol";

/// @notice Vulnerable variant A — direct privileged call.
/// Defect: setOwner performs no authorisation check at all, so any
/// address can take over the account in a single direct call.
/// The correct account requires owner / EntryPoint / self-call.
/// Impact: full account takeover, no UserOperation or signature needed.
contract VulnDirectPrivileged is ModularAccount {
    constructor(address _owner, address _entryPoint, address _validator, address _allowedTarget)
        ModularAccount(_owner, _entryPoint, _validator, _allowedTarget)
    {}

    function setOwner(address newOwner) external override {
        owner = newOwner;
        emit OwnerSet(newOwner);
    }
}
