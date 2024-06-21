// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../../contracts/v3/AutomataDcapV3Attestation.sol";

contract ConfigDCAPScript is Script {
    uint256 deployerKey = vm.envUint("PRIVATE_KEY");

    address enclaveIdDaoAddr = vm.envAddress("ENCLAVE_ID_DAO");
    address enclaveIdHelperAddr = vm.envAddress("ENCLAVE_IDENTITY_HELPER");
    address pckHelperAddr = vm.envAddress("X509_HELPER");
    address tcbDaoAddr = vm.envAddress("FMSPC_TCB_DAO");
    address tcbHelperAddr = vm.envAddress("FMSPC_TCB_HELPER");
    address crlHelperAddr = vm.envAddress("X509_CRL_HELPER");
    address pcsDaoAddr = vm.envAddress("PCS_DAO");
    address risc0Verifier = vm.envAddress("RISC0_VERIFIER");

    address dcapAddress = vm.envAddress("DCAP_ADDRESS");

    function updateDcapPccsDao() public {
        AutomataDcapV3Attestation attestation = AutomataDcapV3Attestation(dcapAddress);
        vm.broadcast(deployerKey);
        
        attestation.updateConfig(
            enclaveIdDaoAddr,
            enclaveIdHelperAddr,
            pckHelperAddr,
            tcbDaoAddr,
            tcbHelperAddr,
            crlHelperAddr,
            pcsDaoAddr
        );
    }

    function updateRisc0(address verifier, bytes32 imageId) public {
        AutomataDcapV3Attestation attestation = AutomataDcapV3Attestation(dcapAddress);
        vm.broadcast(deployerKey);

        attestation.updateRisc0Config(verifier, imageId);
    }
}