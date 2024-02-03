// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UserOperation, Call} from "./Types.sol";
import {SimpleValidator} from "./SimpleValidator.sol";

/// @notice Correct modular smart account (reference implementation).
///
/// Roles, and what each may do:
///   - owner: everything, directly or through a validated UserOperation.
///   - EntryPoint: may call validateUserOp and may execute any callData
///     that a validated UserOperation carries (the signature proved the
///     owner authorised it).
///   - executor: may call execute()/executeBatch() ONLY for the
///     allowlisted target (the `allowedTarget` contract). Never for the
///     account itself, never for any other destination, never
///     delegatecall. An executor is a limited session key, not an owner.
///   - installed module: may call moduleExecute() to any destination
///     EXCEPT the account itself. A module is trusted once installed,
///     so installing a module is itself a privileged operation.
///   - validator: validates signatures only. It has no execution rights.
///
/// Privileged functions (setOwner, installModule, uninstallModule,
/// setValidator, setExecutor) accept calls from the owner, from the
/// EntryPoint (a validated UserOperation), or from the account itself
/// (a self-call made through execute() by the owner or the EntryPoint).
/// A self-call is how an owner performs admin work inside a UserOp:
/// execute() calls the account, so msg.sender inside the privileged
/// function is address(this).
///
/// Storage layout note: `owner` is storage slot 0. The delegatecall
/// reference test relies on that: a delegatecalled contract writes to
/// the account's storage, so a delegatecall that an executor can reach
/// is an owner-takeover primitive.
contract ModularAccount {
    address public owner; // slot 0
    address public entryPoint; // slot 1
    address public validator; // slot 2
    address public allowedTarget; // slot 3
    uint256 public nonce; // slot 4

    mapping(address => bool) public isExecutor;
    mapping(address => bool) public isModule;

    event ModuleInstalled(address indexed module);
    event ModuleUninstalled(address indexed module);
    event ValidatorSet(address indexed validator);
    event ExecutorSet(address indexed executor, bool allowed);
    event OwnerSet(address indexed owner);

    constructor(address _owner, address _entryPoint, address _validator, address _allowedTarget) {
        owner = _owner;
        entryPoint = _entryPoint;
        validator = _validator;
        allowedTarget = _allowedTarget;
    }

    receive() external payable {}

    // --- validation (EntryPoint only) ---

    function validateUserOp(UserOperation calldata op, bytes32 opHash, uint256)
        external
        virtual
        returns (uint256)
    {
        require(msg.sender == entryPoint, "only EntryPoint");
        if (op.nonce != nonce) return 1;
        if (op.validUntil != 0 && block.timestamp > op.validUntil) return 1;
        if (validator == address(0)) return 1;
        if (!SimpleValidator(validator).validate(owner, opHash, op.signature)) return 1;
        nonce++;
        return 0;
    }

    // --- execution ---

    function execute(address dest, uint256 value, bytes calldata data) external payable virtual {
        _authorizeExecute(msg.sender, dest);
        (bool ok,) = dest.call{value: value}(data);
        require(ok, "execute failed");
    }

    function executeBatch(Call[] calldata calls) external payable virtual {
        for (uint256 i = 0; i < calls.length; i++) {
            _authorizeExecute(msg.sender, calls[i].target);
        }
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok,) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            require(ok, "batch execute failed");
        }
    }

    function executeDelegate(address target, bytes calldata data) external virtual {
        require(msg.sender == owner || msg.sender == entryPoint, "delegate: only owner");
        (bool ok,) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    function moduleExecute(address dest, uint256 value, bytes calldata data) external virtual {
        require(isModule[msg.sender], "module: not installed");
        require(dest != address(this), "module: self-call not allowed");
        (bool ok,) = dest.call{value: value}(data);
        require(ok, "module execute failed");
    }

    // --- administration (privileged) ---

    function installModule(address module) external virtual {
        _authorizePrivileged(msg.sender);
        isModule[module] = true;
        emit ModuleInstalled(module);
    }

    function uninstallModule(address module) external virtual {
        _authorizePrivileged(msg.sender);
        isModule[module] = false;
        emit ModuleUninstalled(module);
    }

    function setValidator(address newValidator) external virtual {
        _authorizePrivileged(msg.sender);
        validator = newValidator;
        emit ValidatorSet(newValidator);
    }

    function setExecutor(address executor, bool allowed) external virtual {
        _authorizePrivileged(msg.sender);
        isExecutor[executor] = allowed;
        emit ExecutorSet(executor, allowed);
    }

    function setOwner(address newOwner) external virtual {
        _authorizePrivileged(msg.sender);
        owner = newOwner;
        emit OwnerSet(newOwner);
    }

    // --- internal authorisation ---

    function _authorizePrivileged(address caller) internal view {
        require(
            caller == owner || caller == entryPoint || caller == address(this), "not privileged"
        );
    }

    function _authorizeExecute(address caller, address dest) internal view virtual {
        if (caller == owner || caller == entryPoint) return;
        if (isExecutor[caller]) {
            require(dest == allowedTarget, "executor: target not allowed");
            return;
        }
        revert("not authorized");
    }
}
