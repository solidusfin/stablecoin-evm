// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

/**
 * @title MultiSigWallet
 * @dev Contract for multi-signature wallet functionality that requires multiple confirmations for transactions
 * @notice This wallet allows multiple owners to collectively manage funds and execute transactions
 * @custom:security Transactions require a minimum number of confirmations before execution
 */
contract MultiSigWallet {
    /**
     * @dev Transaction structure to store transaction details
     * @param destination Address where transaction is directed
     * @param value Amount of ether to be sent
     * @param data Transaction data payload
     * @param executed Boolean indicating if transaction has been executed
     */
    struct Transaction {
        address destination;
        uint256 value;
        bytes data;
        bool executed;
    }

    // Maximum number of wallet owners allowed
    uint256 public constant MAX_OWNER_COUNT = 50;

    // Array of all transactions
    Transaction[] public transactions;
    // Mapping of transaction ID to owner address to confirmation status
    mapping(uint256 => mapping(address => bool)) public confirmations;
    // Mapping of owner address to boolean indicating if address is owner
    mapping(address => bool) public isOwner;
    // Array of owner addresses
    address[] public owners;
    // Number of required confirmations for a transaction to execute
    uint256 public required;

    // Events
    event Confirmation(address indexed sender, uint256 indexed transactionId);
    event Revocation(address indexed sender, uint256 indexed transactionId);
    event Submission(
        uint256 indexed transactionId,
        address indexed destination,
        uint256 value,
        bytes data
    );
    event Execution(uint256 indexed transactionId);
    event ExecutionFailure(uint256 indexed transactionId);
    event Deposit(address indexed sender, uint256 value);
    event OwnerAddition(address indexed owner);
    event OwnerRemoval(address indexed owner);
    event RequirementChange(uint256 required);

    // Custom errors
    error UnauthorizedWallet(address account);
    error UnauthorizedOwner(address account);
    error InvalidOwner(address account);
    error NoExistOwner(address account);
    error NoExistTransaction(uint256 transactionId);
    error InvalidDestination(address destination);
    error ConfirmedTransaction(uint256 transactionId);
    error NotConfirmedTransaction(uint256 transactionId);
    error ExecutedTransaction(uint256 transactionId);
    error InvalidRequirement(uint256 ownerCount, uint256 required);

    /**
     * @dev Modifier to restrict function access to the wallet contract itself
     * @notice Functions with this modifier can only be called through confirmed transactions
     */
    modifier onlyWallet() {
        if (msg.sender != address(this)) {
            revert UnauthorizedWallet(msg.sender);
        }
        _;
    }

    /**
     * @dev Modifier to restrict function access to owners
     * @notice Functions with this modifier can only be called by wallet owners
     */
    modifier onlyOwner() {
        if (!isOwner[msg.sender]) {
            revert UnauthorizedOwner(msg.sender);
        }
        _;
    }

    /**
     * @dev Constructor sets initial owners and required confirmations
     * @param owners_ Array of initial owner addresses
     * @param required_ Number of required confirmations
     */
    constructor(address[] memory owners_, uint256 required_) {
        _validRequirement(owners_.length, required_);

        for (uint256 i = 0; i < owners_.length; i++) {
            address owner = owners_[i];
            if (owner == address(0) || isOwner[owner]) {
                revert InvalidOwner(owner);
            }
            isOwner[owner] = true;
            emit OwnerAddition(owner);
        }
        owners = owners_;
        required = required_;
        emit RequirementChange(required_);
    }

    /**
     * @dev Fallback function to handle ETH deposits
     */
    receive() external payable {
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @dev Adds a new owner to the wallet
     * @param owner Address of new owner
     */
    function addOwner(address owner) public onlyWallet {
        if (owner == address(0) || isOwner[owner]) {
            revert InvalidOwner(owner);
        }
        _validRequirement(owners.length + 1, required);

        isOwner[owner] = true;
        owners.push(owner);
        emit OwnerAddition(owner);
    }

    /**
     * @dev Allows to remove an owner. Transaction has to be sent by wallet.
     * @param owner Address of owner to be removed
     */
    function removeOwner(address owner) public onlyWallet {
        if (!isOwner[owner]) {
            revert NoExistOwner(owner);
        }

        isOwner[owner] = false;
        for (uint256 i = 0; i < owners.length - 1; i++) {
            if (owners[i] == owner) {
                owners[i] = owners[owners.length - 1];
                break;
            }
        }
        owners.pop();
        if (required + 1 > owners.length) changeRequirement(owners.length - 1);
        emit OwnerRemoval(owner);
    }

    /**
     * @dev Replaces an owner with a new owner
     * @param owner Address of owner to be replaced
     * @param newOwner Address of new owner
     */
    function replaceOwner(address owner, address newOwner) public onlyWallet {
        if (newOwner == address(0) || isOwner[newOwner]) {
            revert InvalidOwner(newOwner);
        }

        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] == owner) {
                owners[i] = newOwner;
                isOwner[owner] = false;
                isOwner[newOwner] = true;
                emit OwnerRemoval(owner);
                emit OwnerAddition(newOwner);
                return;
            }
        }
        revert NoExistOwner(owner);
    }

    /**
     * @dev Changes the requirement of confirmations
     * @param required_ New number of required confirmations
     */
    function changeRequirement(uint256 required_) public onlyWallet {
        _validRequirement(owners.length, required_);

        required = required_;
        emit RequirementChange(required_);
    }

    /**
     * @dev Submits a new transaction and confirms it
     * @param destination Transaction target address
     * @param value Transaction ETH value
     * @param data Transaction data payload
     * @return transactionId ID of submitted transaction
     */
    function submitTransaction(
        address destination,
        uint256 value,
        bytes calldata data
    ) public returns (uint256 transactionId) {
        if (destination == address(0)) {
            revert InvalidDestination(destination);
        }
        transactionId = _addTransaction(destination, value, data);
        confirmTransaction(transactionId);
    }

    /**
     * @dev Confirms a transaction by an owner
     * @param transactionId ID of transaction to confirm
     */
    function confirmTransaction(uint256 transactionId) public onlyOwner {
        if (transactions.length <= transactionId) {
            revert NoExistTransaction(transactionId);
        }
        if (confirmations[transactionId][msg.sender]) {
            revert ConfirmedTransaction(transactionId);
        }

        confirmations[transactionId][msg.sender] = true;
        emit Confirmation(msg.sender, transactionId);
        executeTransaction(transactionId);
    }

    /**
     * @dev Revokes a confirmation for a transaction
     * @param transactionId ID of transaction to revoke confirmation from
     */
    function revokeConfirmation(uint256 transactionId) public onlyOwner {
        if (!confirmations[transactionId][msg.sender]) {
            revert NotConfirmedTransaction(transactionId);
        }

        if (transactions[transactionId].executed) {
            revert ExecutedTransaction(transactionId);
        }

        confirmations[transactionId][msg.sender] = false;
        emit Revocation(msg.sender, transactionId);
    }

    /**
     * @dev Executes a confirmed transaction
     * @param transactionId ID of transaction to execute
     */
    function executeTransaction(uint256 transactionId) public {
        if (transactions[transactionId].executed) {
            revert ExecutedTransaction(transactionId);
        }

        if (isConfirmed(transactionId)) {
            Transaction storage transaction = transactions[transactionId];
            transaction.executed = true;
            (bool success, ) = transaction.destination.call{
                value: transaction.value
            }(transaction.data);
            if (success) {
                emit Execution(transactionId);
            } else {
                emit ExecutionFailure(transactionId);
            }
        }
    }

    /**
     * @dev Checks if a transaction is confirmed
     * @param transactionId ID of transaction to check
     * @return True if transaction is confirmed
     */
    function isConfirmed(uint256 transactionId) public view returns (bool) {
        uint256 count = 0;
        for (uint256 i = 0; i < owners.length; i++) {
            if (confirmations[transactionId][owners[i]]) count += 1;
            if (count == required) return true;
        }
        return false;
    }

    /**
     * @dev Gets the number of confirmations for a transaction
     * @param transactionId ID of transaction
     * @return count Number of confirmations
     */
    function getConfirmationCount(
        uint256 transactionId
    ) public view returns (uint256 count) {
        for (uint256 i = 0; i < owners.length; i++)
            if (confirmations[transactionId][owners[i]]) count += 1;
    }

    /**
     * @dev Returns list of wallet owners
     * @return Array of owner addresses
     */
    function getOwners() public view returns (address[] memory) {
        return owners;
    }

    /**
     * @dev Returns array of owners who confirmed transaction
     * @param transactionId ID of transaction
     * @return _confirmations Array of owner addresses
     */
    function getConfirmations(
        uint256 transactionId
    ) public view returns (address[] memory _confirmations) {
        address[] memory confirmationsTemp = new address[](owners.length);
        uint256 count = 0;

        for (uint256 i = 0; i < owners.length; i++)
            if (confirmations[transactionId][owners[i]]) {
                confirmationsTemp[count] = owners[i];
                count += 1;
            }
        _confirmations = new address[](count);
        for (uint256 i = 0; i < count; i++)
            _confirmations[i] = confirmationsTemp[i];
    }

    /**
     * @dev Adds a new transaction to the transaction mapping
     * @param destination Transaction target address
     * @param value Transaction ETH value
     * @param data Transaction data payload
     * @return transactionId ID of added transaction
     */
    function _addTransaction(
        address destination,
        uint256 value,
        bytes calldata data
    ) internal returns (uint256 transactionId) {
        transactionId = transactions.length;
        transactions.push(Transaction(destination, value, data, false));
        emit Submission(transactionId, destination, value, data);
    }

    /**
     * @dev Ensures requirement is valid
     * @param ownerCount Number of owners
     * @param required_ Number of required confirmations
     */
    function _validRequirement(
        uint256 ownerCount,
        uint256 required_
    ) internal pure {
        if (
            ownerCount > MAX_OWNER_COUNT ||
            required_ + 1 > ownerCount ||
            required_ < 2
        ) revert InvalidRequirement(ownerCount, required_);
    }
}
