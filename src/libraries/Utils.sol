// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

/**
 * @title Utils
 * @dev Library containing utility functions for the stablecoin contract
 */
library Utils {
    /// @notice Thrown when the passed in signature is not a valid length
    error InvalidSignatureLength();

    /**
     * @dev Mask used to clear the upper bit of the 's' value in EIP-2098 compact signatures
     */
    bytes32 private constant UPPER_BIT_MASK = (
        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    );

    /**
     * @notice Decodes a signature into its r, s, v components
     * @dev Supports both standard 65-byte signatures and EIP-2098 compact 64-byte signatures
     * @param signature The signature bytes to decode
     * @return r The r component of the signature
     * @return s The s component of the signature
     * @return v The recovery id (v) component of the signature
     */
    function decodeRSV(
        bytes calldata signature
    ) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        if (signature.length == 65) {
            // Standard signature format
            (r, s) = abi.decode(signature, (bytes32, bytes32));
            v = uint8(signature[64]);
        } else if (signature.length == 64) {
            // EIP-2098 compact signature format
            bytes32 vs;
            (r, vs) = abi.decode(signature, (bytes32, bytes32));
            s = vs & UPPER_BIT_MASK;
            v = uint8(uint256(vs >> 255)) + 27;
        } else {
            revert InvalidSignatureLength();
        }
    }
}
