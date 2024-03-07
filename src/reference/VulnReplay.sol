// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UserOperation} from "../Types.sol";
import {SimpleValidator} from "../SimpleValidator.sol";
import {ModularAccount} from "../ModularAccount.sol";

/// @notice Vulnerable variant D — nonce never checked or consumed.
/// Defect: validateUserOp checks the signature and expiry but ignores
/// the nonce entirely and never increments it, so a validated
/// UserOperation can be replayed through the EntryPoint any number of
/// times. The correct account requires nonce == current nonce and
/// increments it on every successful validation.
/// Impact: any state-changing UserOperation (transfer, counter
/// increment, module install) executes repeatedly from one signature.
contract VulnReplay is ModularAccount {
    constructor(address _owner, address _entryPoint, address _validator, address _allowedTarget)
        ModularAccount(_owner, _entryPoint, _validator, _allowedTarget)
    {}

    function validateUserOp(UserOperation calldata op, bytes32 opHash, uint256)
        external
        override
        returns (uint256)
    {
        require(msg.sender == entryPoint, "only EntryPoint");
        if (op.validUntil != 0 && block.timestamp > op.validUntil) return 1;
        if (validator == address(0)) return 1;
        if (!SimpleValidator(validator).validate(owner, opHash, op.signature)) return 1;
        return 0; // defect: nonce never checked, never consumed
    }
}
