// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ModularAccount} from "../ModularAccount.sol";

/// @notice Vulnerable variant F — session-key policy never enforced.
/// Defect: _useSessionKey is a no-op, so when a session validator is
/// set the executor path has no check at all: _authorizeExecute
/// defers to the session policy, and the policy is never consulted.
/// Expiry, spending limit, allowed target and revocation are all
/// ignored, and the executor can call any destination with any value.
/// The correct account enforces the per-key policy on every executor
/// call, direct and batched.
/// Impact: a limited session key becomes an unrestricted executor.
contract VulnSessionKey is ModularAccount {
    constructor(address _owner, address _entryPoint, address _validator, address _allowedTarget)
        ModularAccount(_owner, _entryPoint, _validator, _allowedTarget)
    {}

    function _useSessionKey(address, address, uint256) internal override {}
}
