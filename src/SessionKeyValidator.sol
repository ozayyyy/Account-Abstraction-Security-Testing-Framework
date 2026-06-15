// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal interface the account uses to check a session key.
interface ISessionKeyValidator {
    function authorize(address key, address target, uint256 value) external returns (bool);
}

/// @notice Per-key session policy: expiry, spending limit, allowed
/// target, revocation. The account owner grants and revokes keys; the
/// account is the only caller of authorize(), and authorize() records
/// spend, so a limit is enforced across calls, not per call. A key
/// with validUntil == 0 never expires. Granting a key twice replaces
/// the previous key (spent resets to zero).
contract SessionKeyValidator {
    struct SessionKey {
        address allowedTarget;
        uint256 spendingLimit;
        uint256 spent;
        uint48 validUntil; // 0 = no expiry
        bool revoked;
        bool exists;
    }

    address public immutable account;
    address public immutable admin;

    mapping(address => SessionKey) public sessionKeys;

    event SessionKeyGranted(
        address indexed key, address indexed allowedTarget, uint256 spendingLimit, uint48 validUntil
    );
    event SessionKeyRevoked(address indexed key);

    constructor(address _account, address _admin) {
        account = _account;
        admin = _admin;
    }

    function grantSessionKey(address key, address allowedTarget, uint256 spendingLimit, uint48 validUntil)
        external
    {
        require(msg.sender == admin, "only admin");
        require(key != address(0) && allowedTarget != address(0), "zero address");
        sessionKeys[key] =
            SessionKey(allowedTarget, spendingLimit, 0, validUntil, false, true);
        emit SessionKeyGranted(key, allowedTarget, spendingLimit, validUntil);
    }

    function revokeSessionKey(address key) external {
        require(msg.sender == admin, "only admin");
        require(sessionKeys[key].exists, "no such key");
        sessionKeys[key].revoked = true;
        emit SessionKeyRevoked(key);
    }

    /// @notice Returns true and records the spend when the key may
    /// make this call; false otherwise. Only the account may call it,
    /// so a key's allowance can only be consumed by a real execution.
    function authorize(address key, address target, uint256 value) external returns (bool) {
        require(msg.sender == account, "only account");
        SessionKey storage k = sessionKeys[key];
        if (!k.exists) return false;
        if (k.revoked) return false;
        if (k.validUntil != 0 && block.timestamp > k.validUntil) return false;
        if (target != k.allowedTarget) return false;
        if (k.spent + value > k.spendingLimit) return false;
        k.spent += value;
        return true;
    }
}
