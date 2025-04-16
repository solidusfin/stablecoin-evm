// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

import {AccessControlDefaultAdminRulesUpgradeable} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";

/**
 * @title RoleManager
 * @dev Contract that manages role-based access control for the stablecoin system.
 * Inherits from OpenZeppelin's AccessControlDefaultAdminRulesUpgradeable to provide
 * secure role management with admin transfer security features.
 */
abstract contract RoleManager is AccessControlDefaultAdminRulesUpgradeable {
    /**
     * @dev Role that allows upgrading the implementation of proxy contracts
     */
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /**
     * @dev Role that allows pausing contract functionality in emergency situations
     */
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /**
     * @dev Role that allows rescuing tokens accidentally sent to the contract
     */
    bytes32 public constant RESCUER_ROLE = keccak256("RESCUER_ROLE");

    /**
     * @dev Role that allows blacklisting addresses from using the contract
     */
    bytes32 public constant BLACKLISTER_ROLE = keccak256("BLACKLISTER_ROLE");

    /**
     * @dev Role that manages minting permissions and can assign MINTER_ROLE
     */
    bytes32 public constant MAIN_MINTER_ROLE = keccak256("MAIN_MINTER_ROLE");

    /**
     * @dev Role that allows minting new tokens
     */
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
}
