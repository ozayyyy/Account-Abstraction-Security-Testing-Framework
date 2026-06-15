// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ModularAccount} from "../src/ModularAccount.sol";
import {SessionKeyValidator} from "../src/SessionKeyValidator.sol";
import {AATestBase} from "./Base.t.sol";

/// @notice Session-key policy: expiry, spending limit, allowed target
/// and revocation, on the correct account and on variant F, which
/// never enforces the policy. Each variant test proves the bypass
/// works on the vulnerable account; the matching correct-account test
/// proves the same action is blocked. The key holder is also an
/// executor: the session policy is the executor's authorisation when
/// a session validator is set.
contract SessionKeyTest is AATestBase {
    uint256 internal constant LIMIT = 1 ether;

    // --- correct account: policy enforced ---

    function test_SessionKeyValidCallSucceeds() public {
        _grantSessionKey(sessionAccount, sessionValidator, executor, address(target), LIMIT, 0);
        vm.prank(executor);
        sessionAccount.execute(address(target), 0.4 ether, _depositCallData());
        assertEq(target.counter(), 1);
        (, , uint256 spent, , , ) = sessionValidator.sessionKeys(executor);
        assertEq(spent, 0.4 ether);
    }

    function test_SessionKeySpendAccumulatesToLimit() public {
        _grantSessionKey(sessionAccount, sessionValidator, executor, address(target), LIMIT, 0);
        vm.prank(executor);
        sessionAccount.execute(address(target), 0.4 ether, _depositCallData());
        vm.prank(executor);
        sessionAccount.execute(address(target), 0.4 ether, _depositCallData());
        assertEq(target.counter(), 2);
        // 0.8 spent, 0.2 left: a third 0.4 call exceeds the limit.
        vm.prank(executor);
        vm.expectRevert("session: not authorized");
        sessionAccount.execute(address(target), 0.4 ether, _depositCallData());
        assertEq(target.counter(), 2);
        (, , uint256 spent, , , ) = sessionValidator.sessionKeys(executor);
        assertEq(spent, 0.8 ether);
    }

    function test_SessionKeyOverspendRejected() public {
        _grantSessionKey(sessionAccount, sessionValidator, executor, address(target), LIMIT, 0);
        vm.prank(executor);
        vm.expectRevert("session: not authorized");
        sessionAccount.execute(address(target), 2 ether, _depositCallData());
        assertEq(target.counter(), 0);
        (, , uint256 spent, , , ) = sessionValidator.sessionKeys(executor);
        assertEq(spent, 0);
    }

    function test_SessionKeyExpiredRejected() public {
        _grantSessionKey(
            sessionAccount,
            sessionValidator,
            executor,
            address(target),
            LIMIT,
            uint48(block.timestamp + 1 hours)
        );
        vm.warp(block.timestamp + 2 hours);
        vm.prank(executor);
        vm.expectRevert("session: not authorized");
        sessionAccount.execute(address(target), 0.1 ether, _depositCallData());
        assertEq(target.counter(), 0);
    }

    function test_SessionKeyWrongTargetRejected() public {
        _grantSessionKey(sessionAccount, sessionValidator, executor, address(target), LIMIT, 0);
        vm.prank(executor);
        vm.expectRevert("session: not authorized");
        sessionAccount.execute(address(target2), 0.1 ether, _depositCallData());
        assertEq(target2.counter(), 0);
    }

    function test_SessionKeyRevokedRejected() public {
        _grantSessionKey(sessionAccount, sessionValidator, executor, address(target), LIMIT, 0);
        vm.prank(owner);
        sessionValidator.revokeSessionKey(executor);
        vm.prank(executor);
        vm.expectRevert("session: not authorized");
        sessionAccount.execute(address(target), 0.1 ether, _depositCallData());
        assertEq(target.counter(), 0);
    }

    // --- vulnerable variant F: policy never enforced ---

    function test_VulnSessionKey_ExpiredKeyExecutes() public {
        _grantSessionKey(
            vulnSession,
            vulnSessionValidator,
            executor,
            address(target),
            LIMIT,
            uint48(block.timestamp + 1 hours)
        );
        vm.warp(block.timestamp + 2 hours);
        vm.prank(executor);
        vulnSession.execute(address(target), 0.1 ether, _depositCallData());
        assertEq(target.counter(), 1);
    }

    function test_VulnSessionKey_OverspendExecutes() public {
        _grantSessionKey(vulnSession, vulnSessionValidator, executor, address(target), LIMIT, 0);
        vm.prank(executor);
        vulnSession.execute(address(target), 5 ether, _depositCallData());
        assertEq(target.counter(), 1);
        assertEq(address(vulnSession).balance, 5 ether);
    }

    function test_VulnSessionKey_WrongTargetExecutes() public {
        _grantSessionKey(vulnSession, vulnSessionValidator, executor, address(target), LIMIT, 0);
        vm.prank(executor);
        vulnSession.execute(address(target2), 0.1 ether, _depositCallData());
        assertEq(target2.counter(), 1);
    }

    function test_VulnSessionKey_RevokedKeyExecutes() public {
        _grantSessionKey(vulnSession, vulnSessionValidator, executor, address(target), LIMIT, 0);
        vm.prank(owner);
        vulnSessionValidator.revokeSessionKey(executor);
        vm.prank(executor);
        vulnSession.execute(address(target), 0.1 ether, _depositCallData());
        assertEq(target.counter(), 1);
    }
}
