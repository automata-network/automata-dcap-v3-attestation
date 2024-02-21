// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../../contracts/v3/AutomataDcapV3Attestation.sol";
import "../../contracts/utils/SigVerifyLib.sol";

contract DeployDCAPScript is Script {
    uint256 deployerKey = vm.envUint("PRIVATE_KEY");

    function deploySigVerifyLib() public {
        vm.broadcast(deployerKey);

        SigVerifyLib sigVerifyLib = new SigVerifyLib();

        console.log("[LOG] SigVerifyLib deployed to %s", address(sigVerifyLib));
    }

    function deployAttestation() public {
        address sigVerifyLibAddr = vm.envAddress("SIGVERIFY_LIB_ADDRESS");
        address enclaveIdDaoAddr = vm.envAddress("ENCLAVE_IDENTITY_DAO_PORTAL");
        address enclaveIdHelperAddr = vm.envAddress("ENCLAVE_IDENTITY_HELPER");
        address pckHelperAddr = vm.envAddress("X509_HELPER");
        address tcbDaoAddr = vm.envAddress("FMSPC_TCB_DAO_PORTAL");
        address tcbHelperAddr = vm.envAddress("FMSPC_TCB_HELPER");
        address crlHelperAddr = vm.envAddress("X509_CRL_HELPER");
        address pcsDaoAddr = vm.envAddress("PCS_DAO_PORTAL");
        vm.broadcast(deployerKey);

        AutomataDcapV3Attestation attestation = new AutomataDcapV3Attestation(
            sigVerifyLibAddr,
            enclaveIdDaoAddr,
            enclaveIdHelperAddr,
            pckHelperAddr,
            tcbDaoAddr,
            tcbHelperAddr,
            crlHelperAddr,
            pcsDaoAddr
        );

        console.log("[LOG] AutomataDcapV3Attestation deployed to %s", address(attestation));
    }
}
