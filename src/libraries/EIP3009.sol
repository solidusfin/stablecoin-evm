// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

import {ERC20PermitUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title EIP-3009
 * @notice Provides internal implementation for gas-abstracted transfers according to EIP-3009 standard
 * @dev Contracts that inherit from this must wrap these functions with publicly
 * accessible methods, optionally adding modifiers where necessary.
 * This implementation allows for meta-transactions where users can sign transfer
 * authorizations off-chain and third parties can execute them on-chain.
 */
abstract contract EIP3009 is ERC20PermitUpgradeable {
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        keccak256(
            "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
        );

    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
        keccak256(
            "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
        );

    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    /**
     * @dev Maps authorizer address to nonce to usage state
     * authorizer address => nonce => bool (true if nonce is used)
     */
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    /**
     * @dev Emitted when an authorization is used
     * @param authorizer The address of the authorizer
     * @param nonce The nonce of the used authorization
     */
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    /**
     * @dev Emitted when an authorization is canceled
     * @param authorizer The address of the authorizer
     * @param nonce The nonce of the canceled authorization
     */
    event AuthorizationCanceled(
        address indexed authorizer,
        bytes32 indexed nonce
    );

    /**
     * @dev Error thrown when the caller is not the specified payee
     * @param caller The address of the caller
     */
    error CallerNotPayee(address caller);

    /**
     * @dev Error thrown when the signature verification fails
     */
    error InvalidSignature();

    /**
     * @dev Error thrown when the authorization is invalid (already used or canceled)
     */
    error AuthorizationInvalid();

    /**
     * @dev Error thrown when the authorization is not yet valid (current time < validAfter)
     * @param start The timestamp after which the authorization becomes valid
     */
    error AuthorizationNotYetValid(uint256 start);

    /**
     * @dev Error thrown when the authorization has expired (current time > validBefore)
     * @param expired The timestamp before which the authorization was valid
     */
    error AuthorizationExpired(uint256 expired);

    /**
     * @notice Returns the state of an authorization
     * @dev Nonces are randomly generated 32-byte data unique to the
     * authorizer's address. Returns true if the nonce has been used or canceled.
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     * @return True if the nonce is used or canceled, false otherwise
     */
    function authorizationState(
        address authorizer,
        bytes32 nonce
    ) public view returns (bool) {
        return _authorizationStates[authorizer][nonce];
    }

    /**
     * @notice Execute a transfer with a signed authorization
     * @dev This function accepts the v, r, s components of the signature separately
     * @param from          Payer's address (Authorizer)
     * @param to            Payee's address
     * @param value         Amount to be transferred
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     * @param nonce         Unique nonce to prevent replay attacks
     * @param v             v of the signature
     * @param r             r of the signature
     * @param s             s of the signature
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual {
        transferWithAuthorization(
            from,
            to,
            value,
            validAfter,
            validBefore,
            nonce,
            abi.encodePacked(r, s, v)
        );
    }

    /**
     * @notice Execute a transfer with a signed authorization
     * @dev This function accepts a packed signature byte array
     * EOA wallet signatures should be packed in the order of r, s, v.
     * @param from          Payer's address (Authorizer)
     * @param to            Payee's address
     * @param value         Amount to be transferred
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     * @param nonce         Unique nonce to prevent replay attacks
     * @param signature     Signature byte array produced by an EOA wallet or a contract wallet
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) public virtual {
        _requireValidAuthorization(from, nonce, validAfter, validBefore);
        _requireValidSignature(
            from,
            keccak256(
                abi.encode(
                    TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
                    from,
                    to,
                    value,
                    validAfter,
                    validBefore,
                    nonce
                )
            ),
            signature
        );

        _markAuthorizationAsUsed(from, nonce);
        _transfer(from, to, value);
    }

    /**
     * @notice Receive a transfer with a signed authorization from the payer
     * @dev This function accepts the v, r, s components of the signature separately
     * This has an additional check to ensure that the payee's address
     * matches the caller of this function to prevent front-running attacks.
     * @param from          Payer's address (Authorizer)
     * @param to            Payee's address
     * @param value         Amount to be transferred
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     * @param nonce         Unique nonce to prevent replay attacks
     * @param v             v of the signature
     * @param r             r of the signature
     * @param s             s of the signature
     */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual {
        receiveWithAuthorization(
            from,
            to,
            value,
            validAfter,
            validBefore,
            nonce,
            abi.encodePacked(r, s, v)
        );
    }

    /**
     * @notice Receive a transfer with a signed authorization from the payer
     * @dev This function accepts a packed signature byte array
     * This has an additional check to ensure that the payee's address
     * matches the caller of this function to prevent front-running attacks.
     * EOA wallet signatures should be packed in the order of r, s, v.
     * @param from          Payer's address (Authorizer)
     * @param to            Payee's address
     * @param value         Amount to be transferred
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     * @param nonce         Unique nonce to prevent replay attacks
     * @param signature     Signature byte array produced by an EOA wallet or a contract wallet
     */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) public virtual {
        if (to != msg.sender) revert CallerNotPayee(msg.sender);

        _requireValidAuthorization(from, nonce, validAfter, validBefore);
        _requireValidSignature(
            from,
            keccak256(
                abi.encode(
                    RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
                    from,
                    to,
                    value,
                    validAfter,
                    validBefore,
                    nonce
                )
            ),
            signature
        );

        _markAuthorizationAsUsed(from, nonce);
        _transfer(from, to, value);
    }

    /**
     * @notice Attempt to cancel an authorization
     * @dev This function accepts the v, r, s components of the signature separately
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization to cancel
     * @param v             v of the signature
     * @param r             r of the signature
     * @param s             s of the signature
     */
    function cancelAuthorization(
        address authorizer,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual {
        cancelAuthorization(authorizer, nonce, abi.encodePacked(r, s, v));
    }

    /**
     * @notice Attempt to cancel an authorization
     * @dev This function accepts a packed signature byte array
     * EOA wallet signatures should be packed in the order of r, s, v.
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization to cancel
     * @param signature     Signature byte array produced by an EOA wallet or a contract wallet
     */
    function cancelAuthorization(
        address authorizer,
        bytes32 nonce,
        bytes memory signature
    ) public virtual {
        _requireUnusedAuthorization(authorizer, nonce);
        _requireValidSignature(
            authorizer,
            keccak256(
                abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce)
            ),
            signature
        );

        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    /**
     * @notice Validates signature against input data struct
     * @dev Uses OpenZeppelin's SignatureChecker to verify the signature,
     * which supports both EOA and EIP-1271 contract signatures
     * @param signer        Signer's address
     * @param dataHash      Hash of encoded data struct
     * @param signature     Signature byte array produced by an EOA wallet or a contract wallet
     */
    function _requireValidSignature(
        address signer,
        bytes32 dataHash,
        bytes memory signature
    ) private view {
        if (
            !SignatureChecker.isValidSignatureNow(
                signer,
                MessageHashUtils.toTypedDataHash(
                    _domainSeparatorV4(),
                    dataHash
                ),
                signature
            )
        ) revert InvalidSignature();
    }

    /**
     * @notice Check that an authorization is unused
     * @dev Reverts if the authorization has already been used or canceled
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     */
    function _requireUnusedAuthorization(
        address authorizer,
        bytes32 nonce
    ) private view {
        if (_authorizationStates[authorizer][nonce]) {
            revert AuthorizationInvalid();
        }
    }

    /**
     * @notice Check that authorization is valid
     * @dev Verifies time-based validity and that the authorization hasn't been used
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     */
    function _requireValidAuthorization(
        address authorizer,
        bytes32 nonce,
        uint256 validAfter,
        uint256 validBefore
    ) private view {
        if (block.timestamp <= validAfter) {
            revert AuthorizationNotYetValid(validAfter);
        }
        if (block.timestamp >= validBefore) {
            revert AuthorizationExpired(validBefore);
        }
        _requireUnusedAuthorization(authorizer, nonce);
    }

    /**
     * @notice Mark an authorization as used
     * @dev Updates the authorization state and emits an event
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     */
    function _markAuthorizationAsUsed(
        address authorizer,
        bytes32 nonce
    ) private {
        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationUsed(authorizer, nonce);
    }
}
