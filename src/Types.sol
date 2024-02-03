// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal UserOperation shape used by this test model.
/// Only the fields the local EntryPoint and account actually check are
/// present: sender, nonce, callData, signature and an optional expiry.
/// This is not the full ERC-4337 UserOperation (no gas fields, no
/// paymaster fields, no factory fields).
struct UserOperation {
    address sender;
    uint256 nonce;
    bytes callData;
    bytes signature;
    uint48 validUntil; // 0 = no expiry
}

struct Call {
    address target;
    uint256 value;
    bytes data;
}

interface IAccount {
    function validateUserOp(UserOperation calldata op, bytes32 opHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData);
}
