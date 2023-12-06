// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../contracts/AutomataDcapV3Attestation.sol";
import "../forge-test/utils/DcapTestUtils.t.sol";
import "./utils/CRLParser.s.sol";

contract ConfigureDcapAttestationScript is Script, DcapTestUtils, CRLParser {

    string internal constant defaultTcbInfoPath = "contracts/assets/0923/tcbInfo.json";
    string internal constant defaultQeIdPath = "contracts/assets/0923/identity.json";
    address dcapAttestationAddr = vm.envAddress("DCAP_ATTESTATION_ADDRESS");
    uint256 deployerKey = vm.envUint("PRIVATE_KEY");

    AutomataDcapV3Attestation attestation = AutomataDcapV3Attestation(dcapAttestationAddr);

    function configureTcb(string calldata tcbInfoPath) public {
        string memory path;
        if (bytes(tcbInfoPath).length == 0) {
            path = defaultTcbInfoPath;
        } else {
            path = tcbInfoPath;
        }
        string memory tcbInfoJson = vm.readFile(path);

        (bool tcbParsedSuccess, TCBInfoStruct.TCBInfo memory parsedTcbInfo) = parseTcbInfoJson(tcbInfoJson);
        require(tcbParsedSuccess, "failed to parse tcb");
        string memory fmspc = parsedTcbInfo.fmspc;
        console.log(fmspc);

        vm.broadcast(deployerKey);
        attestation.configureTcbInfoJson(fmspc, parsedTcbInfo);
    }

    function configureQeIdentity(string calldata qeIdPath) public {
        string memory path;
        if (bytes(qeIdPath).length == 0) {
            path = defaultQeIdPath;
        } else {
            path = qeIdPath;
        }
        string memory enclaveIdJson = vm.readFile(path);

        (bool qeIdParsedSuccess, EnclaveIdStruct.EnclaveId memory parsedEnclaveId) =
            parseEnclaveIdentityJson(enclaveIdJson);
        require(qeIdParsedSuccess, "failed to parse qeID");

        vm.broadcast(deployerKey);
        attestation.configureQeIdentityJson(parsedEnclaveId);
    }

    // CRLs are provided directly in the CRLParser.s.sol script in it's DER encoded form
    function configureCrl() public {
        bytes[] memory crl = decodeCrl(samplePckCrl);

        vm.broadcast(deployerKey);
        attestation.addRevokedCertSerialNum(0, crl);
    }
}
