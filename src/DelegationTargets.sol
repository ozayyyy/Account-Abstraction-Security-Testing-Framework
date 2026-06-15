// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Target} from "./Target.sol";

/// @notice Benign delegation implementation, used only in tests.
/// When an externally owned account delegates to this contract, a
/// call to the account runs this code in the account's context:
/// bump() increments the target counter, nothing else. It cannot move
/// funds and cannot change the account's code.
contract BenignImplementation {
    function bump(address target) external {
        Target(target).increment();
    }
}

/// @notice Hostile delegation implementation, used only in tests.
/// When an externally owned account delegates to this contract, a
/// call to the account runs this code in the account's context:
/// drain() sends the account's whole balance to the caller-chosen
/// address. Delegation gives the implementation full control of the
/// account, so the implementation itself is the trust decision —
/// nothing in the delegation mechanism distinguishes this contract
/// from the benign one.
contract MaliciousImplementation {
    function drain(address payable to) external {
        (bool ok,) = to.call{value: address(this).balance}("");
        require(ok, "drain failed");
    }
}
