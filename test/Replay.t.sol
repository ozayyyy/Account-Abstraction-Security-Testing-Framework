// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UserOperation} from "../src/Types.sol";
import {AATestBase} from "./Base.t.sol";

/// @notice Nonce handling, replay protection and operation lifecycle.
/// The replay test is the only one that needs two identical operations:
/// on the correct account the second is rejected, on the replay
/// variant both execute and the counter advances twice.
contract ReplayTest is AATestBase {
    function test_NonceIncrementsOnValidOp() public {
        UserOperation memory op =
            _signedOp(address(account), 0, _incrementCallData(), 0, OWNER_PK);
        _handle(op);
        assertEq(account.nonce(), 1);
        UserOperation memory op2 =
            _signedOp(address(account), 1, _incrementCallData(), 0, OWNER_PK);
        _handle(op2);
        assertEq(account.nonce(), 2);
        assertEq(target.counter(), 2);
    }

    function test_ReplayRejectedOnCorrectAccount() public {
        UserOperation memory op =
            _signedOp(address(account), 0, _incrementCallData(), 0, OWNER_PK);
        _handle(op);
        assertEq(target.counter(), 1);
        vm.expectRevert("validation failed");
        _handle(op);
        assertEq(target.counter(), 1);
        assertEq(account.nonce(), 1);
    }

    function test_VulnReplay_SameUserOpExecutesTwice() public {
        UserOperation memory op =
            _signedOp(address(vulnReplay), 0, _incrementCallData(), 0, OWNER_PK);
        _handle(op);
        assertEq(target.counter(), 1);
        _handle(op);
        assertEq(target.counter(), 2);
        assertEq(vulnReplay.nonce(), 0);
    }

    function test_VulnReplay_BadSignatureStillRejected() public {
        // The replay defect is nonce-only: a forged signature must
        // still fail on the vulnerable account.
        UserOperation memory op =
            _signedOp(address(vulnReplay), 0, _incrementCallData(), 0, ATTACKER_PK);
        vm.expectRevert("validation failed");
        _handle(op);
        assertEq(target.counter(), 0);
    }
}
