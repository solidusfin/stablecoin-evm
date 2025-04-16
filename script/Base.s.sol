// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Script, console} from "forge-std/Script.sol";

abstract contract BaseScript is Script {
    /// @dev Included to enable compilation of the script without a $MNEMONIC environment variable.
    string internal constant TEST_MNEMONIC =
        "test test test test test test test test test test test junk";

    /// @dev The private key of the transaction broadcaster.
    uint256 internal privateKey;

    /// @dev The account of the transaction broadcaster.
    address internal sender;

    /// @dev Initializes the transaction broadcaster like this:
    ///
    /// - If $PRIVATE_KEY is defined, use it.
    /// - Otherwise, derive the broadcaster address from $MNEMONIC.
    /// - If $MNEMONIC is not defined, default to a test mnemonic.
    ///
    /// The use case for $PRIVATE_KEY is to specify the broadcaster key and its address via the command line.
    /// Warning!!!, private keys must start with 0x
    constructor() {
        uint256 key = vm.envOr({name: "PRIVATE_KEY", defaultValue: uint256(0)});
        if (key != 0 && block.chainid != 31337) {
            privateKey = key;
        } else {
            string memory mnemonic = vm.envOr({
                name: "MNEMONIC",
                defaultValue: TEST_MNEMONIC
            });
            (, privateKey) = deriveRememberKey({mnemonic: mnemonic, index: 0});
        }
        sender = vm.addr(privateKey);
    }

    modifier broadcast() {
        console.log("Broadcasting from: %s", sender);
        vm.startBroadcast(privateKey);
        _;
        vm.stopBroadcast();
    }
}
