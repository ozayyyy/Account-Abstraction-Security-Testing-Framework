// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ModularAccount} from "./ModularAccount.sol";

/// @notice Well-behaved module: forwards a call through the account's
/// moduleExecute path. Used to show what an installed module may do.
contract MockModule {
    function doExecute(address account, address dest, uint256 value, bytes calldata data)
        external
    {
        ModularAccount(payable(account)).moduleExecute(dest, value, data);
    }
}

/// @notice Hostile module, used only in tests. If it ever becomes an
/// installed module it can move the account's funds through
/// moduleExecute, because an installed module is trusted. That is why
/// installing a module is privileged: the defect under test is never
/// the module's power, it is who may install it. Note the module still
/// cannot self-call the account (moduleExecute rejects dest == the
/// account), so its impact here is fund movement, not a direct
/// setOwner call.
contract MaliciousModule {
    function drain(address account, address to, uint256 amount) external {
        ModularAccount(payable(account)).moduleExecute(to, amount, "");
    }
}

/// @notice Hostile delegate target, used only in tests. When run with
/// delegatecall from the account, this code writes to the account's
/// storage. The account's owner lives in storage slot 0, so pwn()
/// sets the account owner to whoever called executeDelegate.
contract MaliciousDelegate {
    function pwn() external {
        address attacker = msg.sender;
        assembly {
            sstore(0, attacker)
        }
    }
}
