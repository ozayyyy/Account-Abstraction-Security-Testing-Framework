// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Call} from "../src/Types.sol";
import {ModularAccount} from "../src/ModularAccount.sol";
import {AATestBase} from "./Base.t.sol";

/// @notice Permission checks across direct, batched, self and delegated
/// paths, module controls, and validator/executor separation.
/// Each vulnerable-variant test proves two things: the exploit works
/// on the vulnerable account, and the same action is blocked on the
/// correct account. A test that only showed the block would not prove
/// the defect is reachable; a test that only showed the exploit would
/// not prove the fix works.
contract PermissionsTest is AATestBase {
    // --- correct account: executor separation ---

    function test_ExecutorCanExecuteAllowedTarget() public {
        vm.prank(executor);
        account.execute(address(target), 0, _setValueCallData(7));
        assertEq(target.value(), 7);
    }

    function test_ExecutorCannotSetOwnerDirect() public {
        vm.prank(executor);
        vm.expectRevert("not privileged");
        account.setOwner(attacker);
        assertEq(account.owner(), owner);
    }

    function test_ExecutorCannotSelfCall() public {
        vm.prank(executor);
        vm.expectRevert("executor: target not allowed");
        account.execute(
            address(account), 0, abi.encodeWithSignature("setOwner(address)", attacker)
        );
        assertEq(account.owner(), owner);
    }

    function test_ExecutorCannotDelegatecall() public {
        vm.prank(executor);
        vm.expectRevert("delegate: only owner");
        account.executeDelegate(address(malDelegate), abi.encodeWithSignature("pwn()"));
        assertEq(account.owner(), owner);
    }

    function test_ExecutorBatchAllowedSucceeds() public {
        Call[] memory calls = new Call[](2);
        calls[0] = Call(address(target), 0, _setValueCallData(1));
        calls[1] = Call(address(target), 0, abi.encodeWithSignature("increment()"));
        vm.prank(executor);
        account.executeBatch(calls);
        assertEq(target.value(), 1);
        assertEq(target.counter(), 1);
    }

    function test_ExecutorBatchMixedRevertsAtomically() public {
        Call[] memory calls = new Call[](2);
        calls[0] = Call(address(target), 0, _setValueCallData(1));
        calls[1] = Call(address(account), 0, abi.encodeWithSignature("setOwner(address)", attacker));
        vm.prank(executor);
        vm.expectRevert("executor: target not allowed");
        account.executeBatch(calls);
        // Nothing in the batch executed, including the allowed call.
        assertEq(target.value(), 0);
        assertEq(account.owner(), owner);
    }

    function test_OwnerBatchWithSelfCallSucceeds() public {
        Call[] memory calls = new Call[](2);
        calls[0] = Call(address(target), 0, _setValueCallData(3));
        calls[1] = Call(address(account), 0, abi.encodeWithSignature("setOwner(address)", attacker));
        vm.prank(owner);
        account.executeBatch(calls);
        assertEq(target.value(), 3);
        assertEq(account.owner(), attacker);
    }

    // --- correct account: module controls ---

    function test_ModuleInstallOwnerOnly() public {
        vm.prank(attacker);
        vm.expectRevert("not privileged");
        account.installModule(address(mockModule));
        assertFalse(account.isModule(address(mockModule)));
        vm.prank(owner);
        account.installModule(address(mockModule));
        assertTrue(account.isModule(address(mockModule)));
    }

    function test_InstalledModuleCanExecuteTarget() public {
        vm.prank(owner);
        account.installModule(address(mockModule));
        mockModule.doExecute(address(account), address(target), 0, _setValueCallData(9));
        assertEq(target.value(), 9);
    }

    function test_ModuleCannotSelfCall() public {
        vm.prank(owner);
        account.installModule(address(mockModule));
        vm.expectRevert("module: self-call not allowed");
        mockModule.doExecute(
            address(account),
            address(account),
            0,
            abi.encodeWithSignature("setOwner(address)", attacker)
        );
        assertEq(account.owner(), owner);
    }

    function test_ModuleCannotInstallAnotherModule() public {
        vm.prank(owner);
        account.installModule(address(mockModule));
        vm.prank(address(mockModule));
        vm.expectRevert("not privileged");
        account.installModule(address(malModule));
    }

    function test_UninstalledModuleLosesExecution() public {
        vm.prank(owner);
        account.installModule(address(mockModule));
        vm.prank(owner);
        account.uninstallModule(address(mockModule));
        vm.expectRevert("module: not installed");
        mockModule.doExecute(address(account), address(target), 0, _setValueCallData(1));
    }

    // --- vulnerable variant A: direct privileged call ---

    function test_VulnDirectPrivileged_AttackerSetsOwner() public {
        vm.prank(attacker);
        vulnDirect.setOwner(attacker);
        assertEq(vulnDirect.owner(), attacker);
        // Same action on the correct account is blocked.
        vm.prank(attacker);
        vm.expectRevert("not privileged");
        account.setOwner(attacker);
        assertEq(account.owner(), owner);
    }

    // --- vulnerable variant B: unrestricted module install ---

    function test_VulnModuleInstall_AttackerInstallsAndDrains() public {
        uint256 before = attacker.balance;
        vm.prank(attacker);
        vulnModule.installModule(address(malModule));
        assertTrue(vulnModule.isModule(address(malModule)));
        malModule.drain(address(vulnModule), attacker, 1 ether);
        assertEq(attacker.balance, before + 1 ether);
        assertEq(address(vulnModule).balance, 9 ether);
        // Same action on the correct account is blocked at install.
        vm.prank(attacker);
        vm.expectRevert("not privileged");
        account.installModule(address(malModule));
        assertFalse(account.isModule(address(malModule)));
    }

    // --- vulnerable variant C: delegatecall by executor ---

    function test_VulnDelegatecall_ExecutorPwnsOwner() public {
        vm.prank(executor);
        vulnDelegate.executeDelegate(address(malDelegate), abi.encodeWithSignature("pwn()"));
        assertEq(vulnDelegate.owner(), executor);
        // Same action on the correct account is blocked.
        vm.prank(executor);
        vm.expectRevert("delegate: only owner");
        account.executeDelegate(address(malDelegate), abi.encodeWithSignature("pwn()"));
        assertEq(account.owner(), owner);
    }

    // --- vulnerable variant E: self-call by executor ---

    function test_VulnSelfCall_ExecutorSelfCallsSetOwner() public {
        vm.prank(executor);
        vulnSelfCall.execute(
            address(vulnSelfCall), 0, abi.encodeWithSignature("setOwner(address)", attacker)
        );
        assertEq(vulnSelfCall.owner(), attacker);
        // Same action on the correct account is blocked.
        vm.prank(executor);
        vm.expectRevert("executor: target not allowed");
        account.execute(
            address(account), 0, abi.encodeWithSignature("setOwner(address)", attacker)
        );
        assertEq(account.owner(), owner);
        // Distinctness from variant A: the direct call is still blocked
        // on the self-call variant itself.
        vm.prank(executor);
        vm.expectRevert("not privileged");
        vulnSelfCall.setOwner(attacker);
    }
}
