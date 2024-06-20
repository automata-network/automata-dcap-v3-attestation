// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../../contracts/v3/AutomataDcapV3Attestation.sol";

contract DeployDCAPScript is Script {
    uint256 deployerKey = vm.envUint("PRIVATE_KEY");

    function run() public {
        address enclaveIdDaoAddr = vm.envAddress("ENCLAVE_ID_DAO");
        address enclaveIdHelperAddr = vm.envAddress("ENCLAVE_IDENTITY_HELPER");
        address pckHelperAddr = vm.envAddress("X509_HELPER");
        address tcbDaoAddr = vm.envAddress("FMSPC_TCB_DAO");
        address tcbHelperAddr = vm.envAddress("FMSPC_TCB_HELPER");
        address crlHelperAddr = vm.envAddress("X509_CRL_HELPER");
        address pcsDaoAddr = vm.envAddress("PCS_DAO");
        address risc0Verifier = vm.envAddress("RISC0_VERIFIER");
        vm.broadcast(deployerKey);

        bytes32 imageId = vm.envBytes32("DCAP_IMAGE_ID");

        AutomataDcapV3Attestation attestation = new AutomataDcapV3Attestation(
            enclaveIdDaoAddr,
            enclaveIdHelperAddr,
            pckHelperAddr,
            tcbDaoAddr,
            tcbHelperAddr,
            crlHelperAddr,
            pcsDaoAddr,
            risc0Verifier,
            imageId
        );

        console.log("[LOG] AutomataDcapV3Attestation deployed to %s", address(attestation));
    }
}
