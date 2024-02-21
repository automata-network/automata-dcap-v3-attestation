// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/StdJson.sol";
import "solady/utils/JSONParserLib.sol";
import "solady/utils/LibString.sol";

import {EnclaveIdentityHelper, EnclaveIdentityJsonObj} from "@automata-network/on-chain-pccs/helper/EnclaveIdentityHelper.sol";
import {EnclaveIdentityDao} from "@automata-network/on-chain-pccs/dao/EnclaveIdentityDao.sol";
import {FmspcTcbHelper, TcbInfoJsonObj} from "@automata-network/on-chain-pccs/helper/FmspcTcbHelper.sol";
import {FmspcTcbDao} from "@automata-network/on-chain-pccs/dao/FmspcTcbDao.sol";
import {PCKHelper} from "@automata-network/on-chain-pccs/helper/PCKHelper.sol";
import {X509CRLHelper} from "@automata-network/on-chain-pccs/helper/X509CRLHelper.sol";
import {PcsDao, CA} from "@automata-network/on-chain-pccs/dao/PcsDao.sol";

abstract contract PCCSSetup is Test {
    using JSONParserLib for JSONParserLib.Item;
    using LibString for string;

    // use a network that where the P256Verifier contract exists
    // ref: https://github.com/daimo-eth/p256-verifier
    string internal rpcUrl = vm.envString("FORK_URL");

    address internal enclaveIdDaoAddr = vm.envAddress("ENCLAVE_IDENTITY_DAO_PORTAL");
    address internal pckHelperAddr = vm.envAddress("X509_HELPER");
    address internal tcbDaoAddr = vm.envAddress("FMSPC_TCB_DAO_PORTAL");
    address internal crlHelperAddr = vm.envAddress("X509_CRL_HELPER");
    address internal pcsDaoAddr = vm.envAddress("PCS_DAO_PORTAL");

    // re-deploy these helpers because they are outdated
    address internal tcbHelperAddr;
    address internal enclaveIdHelperAddr;

    string internal constant tcbInfoPath = "/assets/0224/tcbInfo.json";
    string internal constant idPath = "/assets/0224/identity.json";

    bytes constant tcbDer = hex"3082028b30820232a00302010202147e3882d5fb55294a40498e458403e91491bdf455300a06082a8648ce3d0403023068311a301806035504030c11496e74656c2053475820526f6f74204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553301e170d3138303532313130353031305a170d3235303532313130353031305a306c311e301c06035504030c15496e74656c2053475820544342205369676e696e67311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d0301070342000443451bcc73c9d5917caf766e61af3fe98087dd4f13257b261e851897799dd13d6811fb47713803bb9bae587fccddc2e31be9a28b86962acc6daf96da58eeca96a381b53081b2301f0603551d2304183016801422650cd65a9d3489f383b49552bf501b392706ac30520603551d1f044b30493047a045a043864168747470733a2f2f6365727469666963617465732e7472757374656473657276696365732e696e74656c2e636f6d2f496e74656c534758526f6f7443412e646572301d0603551d0e041604147e3882d5fb55294a40498e458403e91491bdf455300e0603551d0f0101ff0404030206c0300c0603551d130101ff04023000300a06082a8648ce3d040302034700304402201f42f3038037f226c43b46002576e3a29caa36a064e47493272dc81aec1862550220237ed6eb346b0653c607db5d5d46260da0f3eed7d669ff37bc26686e8c1d2807";
    bytes constant rootCaDer = hex"3082028f30820234a003020102021422650cd65a9d3489f383b49552bf501b392706ac300a06082a8648ce3d0403023068311a301806035504030c11496e74656c2053475820526f6f74204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553301e170d3138303532313130343531305a170d3439313233313233353935395a3068311a301806035504030c11496e74656c2053475820526f6f74204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d030107034200040ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394a381bb3081b8301f0603551d2304183016801422650cd65a9d3489f383b49552bf501b392706ac30520603551d1f044b30493047a045a043864168747470733a2f2f6365727469666963617465732e7472757374656473657276696365732e696e74656c2e636f6d2f496e74656c534758526f6f7443412e646572301d0603551d0e0416041422650cd65a9d3489f383b49552bf501b392706ac300e0603551d0f0101ff04040302010630120603551d130101ff040830060101ff020101300a06082a8648ce3d0403020349003046022100e5bfe50911f92f428920dc368a302ee3d12ec5867ff622ec6497f78060c13c20022100e09d25ac7a0cb3e5e8e68fec5fa3bd416c47440bd950639d450edcbea4576aa2";
    bytes internal platformDer = hex"308202963082023da003020102021500956f5dcdbd1be1e94049c9d4f433ce01570bde54300a06082a8648ce3d0403023068311a301806035504030c11496e74656c2053475820526f6f74204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553301e170d3138303532313130353031305a170d3333303532313130353031305a30703122302006035504030c19496e74656c205347582050434b20506c6174666f726d204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d0301070342000435207feeddb595748ed82bb3a71c3be1e241ef61320c6816e6b5c2b71dad5532eaea12a4eb3f948916429ea47ba6c3af82a15e4b19664e52657939a2d96633dea381bb3081b8301f0603551d2304183016801422650cd65a9d3489f383b49552bf501b392706ac30520603551d1f044b30493047a045a043864168747470733a2f2f6365727469666963617465732e7472757374656473657276696365732e696e74656c2e636f6d2f496e74656c534758526f6f7443412e646572301d0603551d0e04160414956f5dcdbd1be1e94049c9d4f433ce01570bde54300e0603551d0f0101ff04040302010630120603551d130101ff040830060101ff020100300a06082a8648ce3d040302034700304402205ec5648b4c3e8ba558196dd417fdb6b9a5ded182438f551e9c0f938c3d5a8b970220261bd520260f9c647d3569be8e14a32892631ac358b994478088f4d2b27cf37e";

    function setUp() public virtual {
        uint256 fork = vm.createFork(rpcUrl);
        vm.selectFork(fork);

        // pinned February 21st, 2024, 0935 UTC
        // comment this line out if you are replacing sampleQuote with your own
        // this line is needed to bypass expiry reverts for stale quotes
        vm.warp(1708508100);

        FmspcTcbHelper fmspcTcbHelper = new FmspcTcbHelper();
        tcbHelperAddr = address(fmspcTcbHelper);
        EnclaveIdentityHelper enclaveIdHelper = new EnclaveIdentityHelper();
        enclaveIdHelperAddr = address(enclaveIdHelper);

        // upsert root ca
        PcsDao pcsDao = PcsDao(pcsDaoAddr);
        pcsDao.upsertPcsCertificates(CA.ROOT, rootCaDer);

        // upsert tcb signing ca
        pcsDao.upsertPcsCertificates(CA.SIGNING, tcbDer);

        // upsert Platform intermediate CA
        pcsDao.upsertPcsCertificates(CA.PLATFORM, platformDer);

        // upsert fmspc tcb
        FmspcTcbDao tcbDao = FmspcTcbDao(tcbDaoAddr);
        TcbInfoJsonObj memory tcbInfoJson = _readTcbInfoJson();
        tcbDao.upsertFmspcTcb(tcbInfoJson);

        // upsert enclave identity
        EnclaveIdentityDao enclaveIdDao = EnclaveIdentityDao(enclaveIdDaoAddr);
        EnclaveIdentityJsonObj memory identityJson = _readIdentityJson();
        enclaveIdDao.upsertEnclaveIdentity(0, 3, identityJson);
    }

    function _readTcbInfoJson() private view returns (TcbInfoJsonObj memory tcbInfoJson) {
        string memory inputFile = string.concat(
            vm.projectRoot(),
            tcbInfoPath
        );
        string memory tcbInfoData = vm.readFile(inputFile);
        
        // use Solady JSONParserLib to get the stringified JSON object
        // since stdJson.readString() method does not accept JSON-objects as a valid string
        JSONParserLib.Item memory root = JSONParserLib.parse(tcbInfoData);
        JSONParserLib.Item[] memory tcbInfoObj = root.children();
        for (uint256 i = 0; i < root.size(); i++) {
            JSONParserLib.Item memory current = tcbInfoObj[i];
            string memory decodedKey = JSONParserLib.decodeString(current.key());
            if (decodedKey.eq("tcbInfo")) {
                tcbInfoJson.tcbInfoStr = current.value();
            }
        }

        // Solady JSONParserLib does not provide a method where I can convert a hexstring to bytes
        // i am sad
        tcbInfoJson.signature = stdJson.readBytes(
            tcbInfoData,
            ".signature"
        );
    }

    function _readIdentityJson() private view returns (EnclaveIdentityJsonObj memory identityJson) {
        string memory inputFile = string.concat(
            vm.projectRoot(),
            idPath
        );
        string memory idData = vm.readFile(inputFile);
        
        // use Solady JSONParserLib to get the stringified JSON object
        // since stdJson.readString() method does not accept JSON-objects as a valid string
        JSONParserLib.Item memory root = JSONParserLib.parse(idData);
        JSONParserLib.Item[] memory idObj = root.children();
        for (uint256 i = 0; i < root.size(); i++) {
            JSONParserLib.Item memory current = idObj[i];
            string memory decodedKey = JSONParserLib.decodeString(current.key());
            if (decodedKey.eq("enclaveIdentity")) {
                identityJson.identityStr = current.value();
            }
        }

        // Solady JSONParserLib does not provide a method where I can convert a hexstring to bytes
        // i am sad
        identityJson.signature = stdJson.readBytes(
            idData,
            ".signature"
        );
    }
}