// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

import {RoleManager} from "./RoleManager.sol";

/**
 * @title Blacklistable
 * @dev Contract module that allows for blacklisting of addresses.
 * Addresses in the blacklist are restricted from certain operations.
 * Only accounts with BLACKLISTER_ROLE can add or remove addresses from the blacklist.
 */
abstract contract Blacklistable is RoleManager {
    /**
     * @dev Mapping to track blacklisted addresses.
     * If an address maps to true, it is blacklisted.
     */
    mapping(address => bool) private _isBlacklisted;

    /**
     * @dev Emitted when an account is added to the blacklist.
     * @param account The address that was blacklisted.
     */
    event Blacklisted(address indexed account);

    /**
     * @dev Emitted when an account is removed from the blacklist.
     * @param account The address that was removed from the blacklist.
     */
    event UnBlacklisted(address indexed account);

    /**
     * @dev Error thrown when an operation is attempted with a blacklisted address.
     * @param account The blacklisted address.
     */
    error InBlacklist(address account);

    /**
     * @dev Modifier to check if an account is blacklisted.
     * Reverts if the account is blacklisted.
     * @param account The address to check.
     */
    modifier notBlacklisted(address account) {
        if (_isBlacklisted[account]) revert InBlacklist(account);
        _;
    }

    /**
     * @notice Checks if account is blacklisted.
     * @param account The address to check.
     * @return True if the account is blacklisted, false if the account is not blacklisted.
     */
    function isBlacklisted(address account) public view returns (bool) {
        return _isBlacklisted[account];
    }

    /**
     * @notice Adds account to blacklist.
     * @param account The address to blacklist.
     * @dev Only callable by accounts with BLACKLISTER_ROLE.
     */
    function blacklist(address account) public onlyRole(BLACKLISTER_ROLE) {
        _isBlacklisted[account] = true;
        emit Blacklisted(account);
    }

    /**
     * @notice Removes account from blacklist.
     * @param account The address to remove from the blacklist.
     * @dev Only callable by accounts with BLACKLISTER_ROLE.
     */
    function unBlacklist(address account) public onlyRole(BLACKLISTER_ROLE) {
        _isBlacklisted[account] = false;
        emit UnBlacklisted(account);
    }
}
