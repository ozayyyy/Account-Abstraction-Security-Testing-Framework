// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ModularAccount} from "../ModularAccount.sol";

/// @notice Vulnerable variant B — unrestricted module installation.
/// Defect: installModule / uninstallModule perform no authorisation
/// check, so anyone can install a module of their choice. An installed
/// module is trusted by moduleExecute, so the attacker's module can
/// then move the account's funds. The correct account restricts
/// installation to the owner / EntryPoint / self-call.
/// Impact: attacker installs MaliciousModule and drains account funds.
contract VulnModuleInstall is ModularAccount {
    constructor(address _owner, address _entryPoint, address _validator, address _allowedTarget)
        ModularAccount(_owner, _entryPoint, _validator, _allowedTarget)
    {}

    function installModule(address module) external override {
        isModule[module] = true;
        emit ModuleInstalled(module);
    }

    function uninstallModule(address module) external override {
        isModule[module] = false;
        emit ModuleUninstalled(module);
    }
}
