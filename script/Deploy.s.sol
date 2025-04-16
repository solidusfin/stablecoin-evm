// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Upgrades} from "@openzeppelin/foundry-upgrades/Upgrades.sol";

import {BaseScript} from "./Base.s.sol";
import {StableTokenV1} from "../src/StableTokenV1.sol";

contract DeployScript is BaseScript {
    StableTokenV1 public stableTokenV1;

    function setUp() public {}

    function run() public broadcast {
        address[] memory owners = new address[](1);
        owners[0] = 0x80C5855Eb91287C5F87A322221314A0378DEe303;

        address uupsProxy = Upgrades.deployUUPSProxy(
            "StableTokenV1.sol",
            abi.encodeCall(
                StableTokenV1.initialize,
                (
                    "Stable Token",
                    "SSS",
                    owners[0],
                    owners[0],
                    owners[0],
                    owners[0],
                    owners[0],
                    owners[0]
                )
            )
        );

        stableTokenV1 = StableTokenV1(uupsProxy);
    }
}
