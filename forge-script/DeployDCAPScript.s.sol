// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../contracts/AutomataDcapV3Attestation.sol";
import "../contracts/utils/SigVerifyLib.sol";
import "../contracts/lib/PEMCertChainLib.sol";

contract DeployDCAPScript is Script {
    function deploySigVerifyLib() public {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.broadcast(deployerKey);

        SigVerifyLib sigVerifyLib = new SigVerifyLib();

        console.log("[LOG] SigVerifyLib deployed to %s", address(sigVerifyLib));
    }

    function deployPemCertLib() public {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.broadcast(deployerKey);
        
        PEMCertChainLib pemCertLib = new PEMCertChainLib();

        console.log("[LOG] PEMCertChainLib deployed to %s", address(pemCertLib));
    }

    function deployAttestation() public {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address sigVerifyLib = vm.envAddress("SIGVERIFY_LIB_ADDRESS");
        address pemCertLib = vm.envAddress("PEMCERT_LIB_ADDRESS");
        vm.broadcast(deployerKey);

        AutomataDcapV3Attestation attestation = new AutomataDcapV3Attestation(
            address(sigVerifyLib),
            address(pemCertLib)
        );

        console.log("[LOG] AutomataDcapV3Attestation deployed to %s", address(attestation));
    }
}
