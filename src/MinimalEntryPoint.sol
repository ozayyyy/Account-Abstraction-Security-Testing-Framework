// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UserOperation, IAccount} from "./Types.sol";

/// @notice Minimal local EntryPoint for testing only.
/// It is NOT the production ERC-4337 EntryPoint: there is no gas
/// accounting, no stake, no paymaster, no factory, no sender-creation
/// and no bundler economics. It exists so the trust boundary between
/// EntryPoint and account can be tested on a local chain:
///   1. compute the operation hash over (sender, nonce, callData, validUntil)
///   2. ask the account to validate it (only the EntryPoint may do so)
///   3. if validation returns 0, execute the operation's callData on the
///      account; anything else reverts the whole operation.
/// The beneficiary argument is accepted and ignored in this model.
contract MinimalEntryPoint {
    function getUserOpHash(UserOperation calldata op) public pure returns (bytes32) {
        return keccak256(abi.encode(op.sender, op.nonce, op.callData, op.validUntil));
    }

    function handleOps(UserOperation[] calldata ops, address payable beneficiary) external {
        beneficiary; // ignored in this test model
        for (uint256 i = 0; i < ops.length; i++) {
            UserOperation calldata op = ops[i];
            bytes32 opHash = getUserOpHash(op);
            uint256 validationData = IAccount(op.sender).validateUserOp(op, opHash, 0);
            require(validationData == 0, "validation failed");
            (bool ok,) = op.sender.call(op.callData);
            require(ok, "execution failed");
        }
    }
}
