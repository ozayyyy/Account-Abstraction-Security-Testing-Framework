// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Single-signer validator used by the test accounts.
/// A signature is valid when it recovers to the expected signer over
/// the exact operation hash, with no EIP-191 prefix. That prefix-free
/// signing is a deliberate simplification of this local test model:
/// production validators must follow the account's documented signing
/// scheme, and a validator that checked a different hash would accept
/// signatures the account never intended.
contract SimpleValidator {
    function validate(address expectedSigner, bytes32 hash, bytes calldata signature)
        external
        pure
        returns (bool)
    {
        if (signature.length != 65) return false;
        bytes32 r;
        bytes32 s;
        uint8 v;
        bytes memory sig = signature;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        address signer = ecrecover(hash, v, r, s);
        return signer != address(0) && signer == expectedSigner;
    }
}
