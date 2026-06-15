// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {AATestBase} from "./Base.t.sol";

/// @notice EIP-7702 delegation of an externally owned account, using
/// Foundry's delegation cheatcodes on a local chain. The tests show
/// the three properties that matter: delegation to a benign
/// implementation works, delegation to a hostile implementation gives
/// it full control of the account, delegation can be revoked by
/// delegating to address(0), and a signed authorisation cannot be
/// replayed once its nonce is consumed.
contract DelegationTest is AATestBase {
    function test_LegitimateDelegationExecutes() public {
        Vm.SignedDelegation memory sd = vm.signDelegation(address(benignImpl), DELEGATOR_PK);
        vm.attachDelegation(sd);
        (bool ok,) = delegator.call(abi.encodeWithSignature("bump(address)", address(target)));
        assertTrue(ok, "delegated call should succeed");
        assertEq(target.counter(), 1);
        assertGt(delegator.code.length, 0, "delegator should have code after attach");
    }

    function test_MaliciousDelegationDrainsEOA() public {
        uint256 before = attacker.balance;
        Vm.SignedDelegation memory sd = vm.signDelegation(address(malImpl), DELEGATOR_PK);
        vm.attachDelegation(sd);
        (bool ok,) = delegator.call(abi.encodeWithSignature("drain(address)", attacker));
        assertTrue(ok, "delegated call should succeed");
        assertEq(attacker.balance, before + 10 ether);
        assertEq(delegator.balance, 0);
    }

    function test_DelegationRevocationClearsCode() public {
        Vm.SignedDelegation memory sd = vm.signDelegation(address(benignImpl), DELEGATOR_PK);
        vm.attachDelegation(sd);
        (bool ok,) = delegator.call(abi.encodeWithSignature("bump(address)", address(target)));
        assertTrue(ok);
        assertEq(target.counter(), 1);

        Vm.SignedDelegation memory sd0 = vm.signDelegation(address(0), DELEGATOR_PK);
        vm.attachDelegation(sd0);
        (ok,) = delegator.call("");
        assertTrue(ok);
        assertEq(delegator.code.length, 0, "code should be cleared after revoke");
        (ok,) = delegator.call(abi.encodeWithSignature("bump(address)", address(target)));
        assertTrue(ok, "call to a plain EOA returns success");
        assertEq(target.counter(), 1, "bump must no longer run after revoke");
    }

    function test_DelegationReplayRejected() public {
        Vm.SignedDelegation memory sd = vm.signDelegation(address(benignImpl), DELEGATOR_PK);
        vm.attachDelegation(sd);
        (bool ok,) = delegator.call(abi.encodeWithSignature("bump(address)", address(target)));
        assertTrue(ok);
        assertEq(target.counter(), 1);
        // Re-attaching the same signed authorisation must fail: its
        // nonce is already spent. expectRevert cannot catch a revert
        // from a cheatcode call itself, so the re-attach runs through
        // an external call and the revert is caught there.
        try this.attachDelegationExternal(sd) {
            revert("replay should have been rejected");
        } catch {}
    }

    /// @notice External wrapper so a failing attachDelegation can be
    /// caught with try/catch. Test helper only.
    function attachDelegationExternal(Vm.SignedDelegation calldata sd) external {
        vm.attachDelegation(sd);
    }
}
