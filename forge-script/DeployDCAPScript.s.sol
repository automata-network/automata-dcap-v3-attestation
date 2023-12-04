// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../contracts/AutomataDcapV3Attestation.sol";
import "../contracts/utils/SigVerifyLib.sol";

contract DeployDCAPScript is Script {
    AutomataDcapV3Attestation attestation;
    SigVerifyLib sigVerifyLib;

    function run() public {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        sigVerifyLib = new SigVerifyLib();

        attestation = new AutomataDcapV3Attestation(
            address(sigVerifyLib)
        );

        vm.stopBroadcast();
    }
}