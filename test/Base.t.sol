// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {UserOperation, Call} from "../src/Types.sol";
import {SimpleValidator} from "../src/SimpleValidator.sol";
import {MinimalEntryPoint} from "../src/MinimalEntryPoint.sol";
import {ModularAccount} from "../src/ModularAccount.sol";
import {Target} from "../src/Target.sol";
import {MockModule, MaliciousModule, MaliciousDelegate} from "../src/Modules.sol";
import {VulnDirectPrivileged} from "../src/reference/VulnDirectPrivileged.sol";
import {VulnModuleInstall} from "../src/reference/VulnModuleInstall.sol";
import {VulnDelegatecall} from "../src/reference/VulnDelegatecall.sol";
import {VulnReplay} from "../src/reference/VulnReplay.sol";
import {VulnSelfCall} from "../src/reference/VulnSelfCall.sol";
import {VulnSessionKey} from "../src/reference/VulnSessionKey.sol";
import {SessionKeyValidator} from "../src/SessionKeyValidator.sol";
import {BenignImplementation, MaliciousImplementation} from "../src/DelegationTargets.sol";

/// @notice Shared fixture. Fixed keys, local chain only, every account
/// funded with 10 ether so fund-movement tests have observable state.
abstract contract AATestBase is Test {
    uint256 internal constant OWNER_PK = 0xA11CE;
    uint256 internal constant ATTACKER_PK = 0xB0B;
    uint256 internal constant DELEGATOR_PK = 0xDE1E6A70;

    address internal owner;
    address internal attacker;
    address internal executor;
    address internal delegator;

    Target internal target;
    Target internal target2;
    SessionKeyValidator internal sessionValidator;
    SessionKeyValidator internal vulnSessionValidator;
    BenignImplementation internal benignImpl;
    MaliciousImplementation internal malImpl;
    SimpleValidator internal validator;
    MinimalEntryPoint internal entryPoint;
    MockModule internal mockModule;
    MaliciousModule internal malModule;
    MaliciousDelegate internal malDelegate;

    ModularAccount internal account;
    VulnDirectPrivileged internal vulnDirect;
    VulnModuleInstall internal vulnModule;
    VulnDelegatecall internal vulnDelegate;
    VulnReplay internal vulnReplay;
    VulnSelfCall internal vulnSelfCall;
    ModularAccount internal sessionAccount;
    VulnSessionKey internal vulnSession;

    function setUp() public virtual {
        owner = vm.addr(OWNER_PK);
        attacker = vm.addr(ATTACKER_PK);
        executor = makeAddr("executor");
        delegator = vm.addr(DELEGATOR_PK);

        target = new Target();
        target2 = new Target();
        benignImpl = new BenignImplementation();
        malImpl = new MaliciousImplementation();
        validator = new SimpleValidator();
        entryPoint = new MinimalEntryPoint();
        mockModule = new MockModule();
        malModule = new MaliciousModule();
        malDelegate = new MaliciousDelegate();

        account = new ModularAccount(owner, address(entryPoint), address(validator), address(target));
        vulnDirect = new VulnDirectPrivileged(
            owner, address(entryPoint), address(validator), address(target)
        );
        vulnModule = new VulnModuleInstall(
            owner, address(entryPoint), address(validator), address(target)
        );
        vulnDelegate = new VulnDelegatecall(
            owner, address(entryPoint), address(validator), address(target)
        );
        vulnReplay = new VulnReplay(
            owner, address(entryPoint), address(validator), address(target)
        );
        vulnSelfCall = new VulnSelfCall(
            owner, address(entryPoint), address(validator), address(target)
        );
        sessionAccount = new ModularAccount(
            owner, address(entryPoint), address(validator), address(target)
        );
        vulnSession = new VulnSessionKey(
            owner, address(entryPoint), address(validator), address(target)
        );
        sessionValidator = new SessionKeyValidator(address(sessionAccount), owner);
        vulnSessionValidator = new SessionKeyValidator(address(vulnSession), owner);
        vm.prank(owner);
        sessionAccount.setSessionValidator(address(sessionValidator));
        vm.prank(owner);
        vulnSession.setSessionValidator(address(vulnSessionValidator));
        vm.deal(address(sessionAccount), 10 ether);
        vm.deal(address(vulnSession), 10 ether);
        vm.deal(delegator, 10 ether);

        ModularAccount[6] memory accounts = [
            account,
            ModularAccount(payable(address(vulnDirect))),
            ModularAccount(payable(address(vulnModule))),
            ModularAccount(payable(address(vulnDelegate))),
            ModularAccount(payable(address(vulnReplay))),
            ModularAccount(payable(address(vulnSelfCall)))
        ];
        for (uint256 i = 0; i < accounts.length; i++) {
            vm.deal(address(accounts[i]), 10 ether);
            vm.prank(owner);
            accounts[i].setExecutor(executor, true);
        }
    }

    function _opHash(address sender, uint256 nonce_, bytes memory callData, uint48 validUntil)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(sender, nonce_, callData, validUntil));
    }

    function _signedOp(
        address sender,
        uint256 nonce_,
        bytes memory callData,
        uint48 validUntil,
        uint256 pk
    ) internal returns (UserOperation memory op) {
        bytes32 h = _opHash(sender, nonce_, callData, validUntil);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        op = UserOperation(sender, nonce_, callData, abi.encodePacked(r, s, v), validUntil);
    }

    function _handle(UserOperation memory op) internal {
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, payable(address(0)));
    }

    /// @notice callData for an account.execute(target, increment()) call,
    /// i.e. a UserOperation that increments the target counter by one.
    function _incrementCallData() internal view returns (bytes memory) {
        return abi.encodeCall(
            ModularAccount.execute,
            (address(target), uint256(0), abi.encodeWithSignature("increment()"))
        );
    }

    function _setValueCallData(uint256 v) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("setValue(uint256)", v);
    }

    function _depositCallData() internal pure returns (bytes memory) {
        return abi.encodeWithSignature("deposit()");
    }

    /// @notice Grant an executor role on an account and a session key
    /// for that key holder on the matching validator. The caller is
    /// the owner in both steps.
    function _grantSessionKey(
        ModularAccount acct,
        SessionKeyValidator val,
        address key,
        address allowedTarget,
        uint256 spendingLimit,
        uint48 validUntil
    ) internal {
        vm.prank(owner);
        acct.setExecutor(key, true);
        vm.prank(owner);
        val.grantSessionKey(key, allowedTarget, spendingLimit, validUntil);
    }
}
