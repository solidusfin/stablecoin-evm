// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

import {ERC20PermitUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";

import {RoleManager} from "./RoleManager.sol";
import {IMintManager} from "../interfaces/IMintManager.sol";

/**
 * @title MintManager
 * @dev Contract for managing token minting and burning.
 * The MintManager contract inherits from ERC20PermitUpgradeable, RoleManager, and IMintManager.
 * It provides methods for managing minters, minting new tokens, and burning tokens.
 * The contract also provides methods for checking if an account has minter privileges, retrieving
 * the amount a minter is allowed to mint, configuring a minter with a specific allowance, and removing
 * a minter from the system.
 */
abstract contract MintManager is
    ERC20PermitUpgradeable,
    RoleManager,
    IMintManager
{
    /// @dev Mapping of minter addresses to their allowed minting amounts
    mapping(address => uint256) private _minterAllowed;

    /**
     * @notice Checks if an account has minter privileges
     * @param account Address to check for minter role
     * @return bool True if the account has minter role, false otherwise
     */
    function isMinter(address account) public view returns (bool) {
        return hasRole(MINTER_ROLE, account);
    }

    /**
     * @notice Returns the amount a minter is allowed to mint
     * @param minter Address of the minter to check
     * @return uint256 The amount the minter is allowed to mint
     */
    function minterAllowance(address minter) public view returns (uint256) {
        return _minterAllowed[minter];
    }

    /**
     * @notice Configures a minter with a specific allowance
     * @dev Can only be called by an account with MAIN_MINTER_ROLE
     * @param minter Address to configure as a minter
     * @param minterAllowedAmount Amount the minter is allowed to mint
     * @return bool True if the operation was successful
     */
    function configureMinter(
        address minter,
        uint256 minterAllowedAmount
    ) public virtual onlyRole(MAIN_MINTER_ROLE) returns (bool) {
        _grantRole(MINTER_ROLE, minter);
        _minterAllowed[minter] = minterAllowedAmount;
        emit MinterConfigured(minter, minterAllowedAmount);
        return true;
    }

    /**
     * @notice Removes a minter from the system
     * @dev Can only be called by an account with MAIN_MINTER_ROLE
     * @param minter Address of the minter to remove
     * @return bool True if the operation was successful
     */
    function removeMinter(
        address minter
    ) public virtual onlyRole(MAIN_MINTER_ROLE) returns (bool) {
        _revokeRole(MINTER_ROLE, minter);
        _minterAllowed[minter] = 0;
        emit MinterRemoved(minter);
        return true;
    }

    /**
     * @notice Mints new tokens to the specified address
     * @dev Can only be called by an account with MINTER_ROLE
     * @param to The address to mint tokens to
     * @param amount The amount of tokens to mint
     */
    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        if (amount == 0) {
            revert InvalidAmount(0);
        }
        _mint(to, amount);
        _minterAllowed[msg.sender] -= amount;
        emit Mint(msg.sender, to, amount);
    }

    /**
     * @notice Burns tokens from the caller's account
     * @dev Can only be called by an account with MINTER_ROLE
     * @param amount The amount of tokens to burn
     */
    function burn(uint256 amount) public onlyRole(MINTER_ROLE) {
        if (amount == 0) {
            revert InvalidAmount(0);
        }
        _burn(msg.sender, amount);
        emit Burn(msg.sender, amount);
    }
}
