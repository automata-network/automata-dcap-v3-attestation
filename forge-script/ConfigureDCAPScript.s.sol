// // SPDX-License-Identifier: UNLICENSED
// pragma solidity ^0.8.0;

// import "forge-std/Script.sol";
// import "../contracts/AutomataDcapV3Attestation.sol";
// import "../forge-test/utils/DcapTestUtils.t.sol";
// import "./utils/CRLParser.s.sol";

// contract ConfigureDcapAttestationScript is Script, DcapTestUtils, CRLParser {

//     string internal constant tcbInfoPath = "contracts/assets/0923/tcbInfo.json";
//     string internal constant idPath = "contracts/assets/0923/identity.json";
//     string internal constant fmspc = "00606a000000";
//     AutomataDcapV3Attestation attestation;
//     // address dcapAttestationAddr = 0x5C819CE06daF76Ef5Ae732f3e291047962130ad5; // TBD
//     address dcapAttestationAddr = ;

//      function run() public {
//         uint256 deployerKey = vm.envUint("PRIVATE_KEY");
//         vm.startBroadcast(deployerKey);

//         attestation = AutomataDcapV3Attestation(dcapAttestationAddr);

//         string memory tcbInfoJson = vm.readFile(tcbInfoPath);
//         string memory enclaveIdJson = vm.readFile(idPath);

//         // configure QE
//         // (bool tcbParsedSuccess, TCBInfoStruct.TCBInfo memory parsedTcbInfo) = parseTcbInfoJson(tcbInfoJson);
//         // require(tcbParsedSuccess, "failed to parse tcb");
//         // attestation.configureTcbInfoJson(fmspc, parsedTcbInfo);

//         // // configure TCB
//         // (bool qeIdParsedSuccess, EnclaveIdStruct.EnclaveId memory parsedEnclaveId) =
//         //     parseEnclaveIdentityJson(enclaveIdJson);
//         // require(qeIdParsedSuccess, "failed to parse qeID");
//         // attestation.configureQeIdentityJson(parsedEnclaveId);
        
//         // // configure CRL
//         bytes[] memory crl = decodeCrl(samplePckCrl);
//         attestation.addRevokedCertSerialNum(0, crl);

//         // toggle local enclave report check
//         vm.stopBroadcast();
//     }
// }