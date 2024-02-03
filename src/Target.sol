// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Harmless external target for execution tests.
/// Executors and modules may call setValue/increment on this contract;
/// it holds no funds and no privileges, so a call to it is the
/// non-privileged baseline against which privileged calls are compared.
contract Target {
    uint256 public value;
    uint256 public counter;

    function setValue(uint256 v) external {
        value = v;
    }

    function increment() external {
        counter++;
    }
}
