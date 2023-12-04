// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../contracts/AutomataDcapV3Attestation.sol";

contract DeployDCAPScript is Script {
    AutomataDcapV3Attestation attestation;

    function run() public {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        address sigVerifyLib = 0x6999021da59A3C960E1dC98c9C8F558b5b1B98D6;

        // new PEMCertChainLib@0x72d29Aade2F66CF52ADe06eCF27a00c8508eF08e

        attestation = new AutomataDcapV3Attestation(
            sigVerifyLib
        );

        vm.stopBroadcast();
    }
}