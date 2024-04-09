// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UserOperation, Call} from "../src/Types.sol";
import {ModularAccount} from "../src/ModularAccount.sol";
import {AATestBase} from "./Base.t.sol";

/// @notice Validation and signature handling, plus EntryPoint/account
/// trust boundaries. Every test states the expected decision first:
/// a valid operation executes, anything else is rejected.
contract ValidationTest is AATestBase {
    function test_ValidUserOpExecutes() public {
        UserOperation memory op =
            _signedOp(address(account), 0, _incrementCallData(), 0, OWNER_PK);
        _handle(op);
        assertEq(target.counter(), 1);
        assertEq(account.nonce(), 1);
    }

    function test_BadSignatureRejected() public {
        UserOperation memory op =
            _signedOp(address(account), 0, _incrementCallData(), 0, ATTACKER_PK);
        vm.expectRevert("validation failed");
        _handle(op);
        assertEq(target.counter(), 0);
        assertEq(account.nonce(), 0);
    }

    function test_WrongNonceRejected() public {
        UserOperation memory op =
            _signedOp(address(account), 99, _incrementCallData(), 0, OWNER_PK);
        vm.expectRevert("validation failed");
        _handle(op);
        assertEq(target.counter(), 0);
    }

    function test_ExpiredUserOpRejected() public {
        UserOperation memory op =
            _signedOp(address(account), 0, _incrementCallData(), 1, OWNER_PK);
        vm.warp(1000);
        vm.expectRevert("validation failed");
        _handle(op);
        assertEq(target.counter(), 0);
    }

    function test_UnexpiredUserOpAccepted() public {
        UserOperation memory op =
            _signedOp(address(account), 0, _incrementCallData(), uint48(block.timestamp + 1000), OWNER_PK);
        _handle(op);
        assertEq(target.counter(), 1);
    }

    function test_ValidateDirectCallReverts() public {
        UserOperation memory op =
            _signedOp(address(account), 0, _incrementCallData(), 0, OWNER_PK);
        bytes32 h = _opHash(address(account), 0, _incrementCallData(), 0);
        vm.prank(attacker);
        vm.expectRevert("only EntryPoint");
        account.validateUserOp(op, h, 0);
    }

    function test_ValidatorCannotExecute() public {
        vm.prank(address(validator));
        vm.expectRevert("not authorized");
        account.execute(address(target), 0, _setValueCallData(1));
    }

    function test_ExecutorCannotValidate() public {
        UserOperation memory op =
            _signedOp(address(account), 0, _incrementCallData(), 0, OWNER_PK);
        bytes32 h = _opHash(address(account), 0, _incrementCallData(), 0);
        vm.prank(executor);
        vm.expectRevert("only EntryPoint");
        account.validateUserOp(op, h, 0);
    }

    function test_DirectExecuteByRandomReverts() public {
        vm.prank(attacker);
        vm.expectRevert("not authorized");
        account.execute(address(target), 0, _setValueCallData(1));
        assertEq(target.value(), 0);
    }

    function test_ValidatorChangeIsOwnerOnly() public {
        vm.prank(attacker);
        vm.expectRevert("not privileged");
        account.setValidator(address(0));
        vm.prank(owner);
        account.setValidator(address(0));
        assertEq(account.validator(), address(0));
        // With no validator configured, a signed operation must fail.
        UserOperation memory op =
            _signedOp(address(account), 0, _incrementCallData(), 0, OWNER_PK);
        vm.expectRevert("validation failed");
        _handle(op);
    }

    function test_OwnerCanSelfCallThroughUserOp() public {
        // Owner performs admin work inside a UserOperation: execute()
        // calls the account, so setOwner runs with msg.sender == account.
        bytes memory callData = abi.encodeCall(
            ModularAccount.execute,
            (address(account), uint256(0), abi.encodeWithSignature("setOwner(address)", attacker))
        );
        UserOperation memory op = _signedOp(address(account), 0, callData, 0, OWNER_PK);
        _handle(op);
        assertEq(account.owner(), attacker);
    }
}
