// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

/**
 * @title IMintManager
 * @dev Interface for managing minters of a stablecoin system.
 * The interface provides methods for checking if an account is a minter, retrieving the remaining
 * allowance for a minter, configuring a minter with a specific allowance, and removing a minter
 * from the system.
 */
interface IMintManager {
    /**
     * @dev Emitted when a minter is configured with a specific allowance amount.
     * @param minter The address of the configured minter
     * @param minterAllowedAmount The maximum amount the minter is allowed to mint
     */
    event MinterConfigured(address indexed minter, uint256 minterAllowedAmount);

    /**
     * @dev Emitted when a minter is removed from the system.
     * @param oldMinter The address of the removed minter
     */
    event MinterRemoved(address indexed oldMinter);

    /**
     * @notice Emitted when tokens are minted
     * @param minter Address that initiated the mint
     * @param to Address that received the minted tokens
     * @param amount Amount of tokens minted
     */
    event Mint(address indexed minter, address indexed to, uint256 amount);

    /**
     * @notice Emitted when tokens are burned
     * @param burner Address that burned the tokens
     * @param amount Amount of tokens burned
     */
    event Burn(address indexed burner, uint256 amount);

    /**
     * @notice Error thrown when an invalid amount is provided for mint or burn
     * @param amount The invalid amount
     */
    error InvalidAmount(uint256 amount);

    /**
     * @dev Checks if an account is a registered minter.
     * @param account The address to check
     * @return bool True if the account is a minter, false otherwise
     */
    function isMinter(address account) external view returns (bool);

    /**
     * @dev Returns the remaining amount a minter is allowed to mint.
     * @param minter The address of the minter
     * @return uint256 The remaining allowance for the minter
     */
    function minterAllowance(address minter) external view returns (uint256);

    /**
     * @dev Configures an address as a minter with a specific allowance.
     * @param minter The address to configure as a minter
     * @param minterAllowedAmount The maximum amount the minter is allowed to mint
     * @return bool True if the operation was successful
     */
    function configureMinter(
        address minter,
        uint256 minterAllowedAmount
    ) external returns (bool);

    /**
     * @dev Removes a minter from the system.
     * @param minter The address of the minter to remove
     * @return bool True if the operation was successful
     */
    function removeMinter(address minter) external returns (bool);

    /**
     * @notice Mints new tokens to the specified address
     * @dev Can only be called by an account with MINTER_ROLE
     * @param to The address to mint tokens to
     * @param amount The amount of tokens to mint
     */
    function mint(address to, uint256 amount) external;

    /**
     * @notice Burns tokens from the caller's account
     * @dev Can only be called by an account with MINTER_ROLE
     * @param amount The amount of tokens to burn
     */
    function burn(uint256 amount) external;
}
