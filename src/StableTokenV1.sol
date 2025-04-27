// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {Blacklistable} from "./libraries/Blacklistable.sol";
import {MintManager} from "./libraries/MintManager.sol";
import {EIP3009} from "./libraries/EIP3009.sol";
import {Utils} from "./libraries/Utils.sol";

/**
 * @title StableTokenV1
 * @dev Implementation of a stablecoin with minting, burning, blacklisting, and EIP-3009 capabilities.
 * This contract is upgradeable using the UUPS pattern and implements ERC20 with permit functionality.
 */
contract StableTokenV1 is
    Initializable,
    UUPSUpgradeable,
    PausableUpgradeable,
    Blacklistable,
    MintManager,
    EIP3009
{
    using SafeERC20 for IERC20;
    using Utils for bytes;

    /// @notice Version of the contract
    string private constant _version = "1";

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the contract with required parameters
     * @dev Sets up roles, token metadata, and initializes inherited contracts
     * @param name Name of the token
     * @param symbol Symbol of the token
     * @param defaultAdmin Address of the default admin
     * @param mainMinter Address with permission to manage minters
     */
    function initialize(
        string calldata name,
        string calldata symbol,
        address defaultAdmin,
        address mainMinter
    ) public initializer {
        assert(defaultAdmin != address(0));
        assert(mainMinter != address(0));

        __UUPSUpgradeable_init();
        __Pausable_init();
        __ERC20_init(name, symbol);
        __ERC20Permit_init(name);
        __AccessControlDefaultAdminRules_init(3 days, defaultAdmin);

        _grantRole(MAIN_MINTER_ROLE, mainMinter);
        _setRoleAdmin(MINTER_ROLE, MAIN_MINTER_ROLE);
    }

    /**
     * @dev Authorizes an upgrade to a new implementation
     * @param newImplementation Address of the new implementation
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    /**
     * @dev Returns the EIP712 name for this contract
     * @return The name string
     */
    function _EIP712Name()
        internal
        view
        virtual
        override
        returns (string memory)
    {
        return name();
    }

    /**
     * @dev Returns the EIP712 version for this contract
     * @return The version string
     */
    function _EIP712Version()
        internal
        pure
        virtual
        override
        returns (string memory)
    {
        return _version;
    }

    /**
     * @notice Returns the version of the contract
     * @return The version string
     */
    function version() public pure virtual returns (string memory) {
        return _version;
    }

    /**
     * @notice Returns the number of decimals used for token amounts
     * @return The number of decimals (6)
     */
    function decimals() public pure override returns (uint8) {
        return 6;
    }

    /**
     * @notice Pauses all token transfers and operations
     * @dev Can only be called by an account with PAUSER_ROLE
     */
    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @notice Unpauses token transfers and operations
     * @dev Can only be called by an account with PAUSER_ROLE
     */
    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
     * @notice Rescues ERC20 tokens sent to this contract by mistake
     * @dev Can only be called by an account with RESCUER_ROLE
     * @param tokenContract The ERC20 token contract address
     * @param to The address to send the tokens to
     * @param amount The amount of tokens to rescue
     */
    function rescueERC20(
        IERC20 tokenContract,
        address to,
        uint256 amount
    ) public onlyRole(RESCUER_ROLE) {
        tokenContract.safeTransfer(to, amount);
    }

    /**
     * @notice Configures a minter with a specific allowance
     * @dev Can only be called by an account with MAIN_MINTER_ROLE when contract is not paused
     * @param minter Address to configure as a minter
     * @param minterAllowedAmount Amount the minter is allowed to mint
     * @return bool True if the operation was successful
     */
    function configureMinter(
        address minter,
        uint256 minterAllowedAmount
    ) public override whenNotPaused returns (bool) {
        return super.configureMinter(minter, minterAllowedAmount);
    }

    /**
     * @notice Updates token balances during transfers.
     * @dev Overrides the ERC20 _update function to add blacklist and pause checks.
     * @param from The address tokens are transferred from.
     * @param to The address tokens are transferred to.
     * @param value The amount of tokens to transfer.
     */
    function _update(
        address from,
        address to,
        uint256 value
    )
        internal
        virtual
        override
        whenNotPaused
        notBlacklisted(from)
        notBlacklisted(to)
    {
        super._update(from, to, value);
    }

    /**
     * @notice Internal function to set the allowance of tokens that a spender can use from an owner's account
     * @dev Overrides the parent contract's _approve function to add pause and blacklist check
     * @param owner The address that owns the tokens
     * @param spender The address authorized to spend the tokens
     * @param value The amount of tokens to allow
     * @param emitEvent If true, emits an Approval event
     */
    function _approve(
        address owner,
        address spender,
        uint256 value,
        bool emitEvent
    )
        internal
        override
        whenNotPaused
        notBlacklisted(owner)
        notBlacklisted(spender)
    {
        super._approve(owner, spender, value, emitEvent);
    }

    /**
     * @notice Increases the allowance granted to the spender
     * @param spender The address authorized to spend
     * @param increment The amount to increase the allowance by
     * @return True if the operation was successful
     */
    function increaseAllowance(
        address spender,
        uint256 increment
    ) public returns (bool) {
        return approve(spender, allowance(msg.sender, spender) + increment);
    }

    /**
     * @notice Decreases the allowance granted to the spender
     * @param spender The address authorized to spend
     * @param decrement The amount to decrease the allowance by
     * @return True if the operation was successful
     */
    function decreaseAllowance(
        address spender,
        uint256 decrement
    ) public returns (bool) {
        return approve(spender, allowance(msg.sender, spender) - decrement);
    }

    /**
     * @notice Approves spending via EIP-2612 permit with signature as bytes
     * @dev Decodes the signature and calls the parent permit function
     * @param owner The owner of the tokens
     * @param spender The address authorized to spend
     * @param value The amount of tokens to allow
     * @param deadline The time at which the signature expires
     * @param signature The authorization signature as bytes
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        bytes calldata signature
    ) public {
        (bytes32 r, bytes32 s, uint8 v) = signature.decodeRSV();

        permit(owner, spender, value, deadline, v, r, s);
    }

    /**
     * @notice Cancels an authorization via signature as bytes (EIP-3009)
     * @param authorizer The address that authorized the transfer
     * @param nonce The nonce of the authorization to cancel
     * @param signature The authorization signature as bytes
     */
    function cancelAuthorization(
        address authorizer,
        bytes32 nonce,
        bytes calldata signature
    ) public override whenNotPaused {
        super.cancelAuthorization(authorizer, nonce, signature);
    }
}
