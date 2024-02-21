//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAttestation} from "../interfaces/IAttestation.sol";
import {EnclaveIdBase, EnclaveIdTcbStatus} from "../base/EnclaveIdBase.sol";
import {PEMCertChainBase, X509CertObj, PCKCertTCB} from "../base/PEMCertChainBase.sol";
import {TCBInfoBase, TcbInfoJsonObj, TCBStatus} from "../base/TCBInfoBase.sol";

// Internal Libraries
import {Base64, LibString} from "solady/Milady.sol";
import {BytesUtils} from "../utils/BytesUtils.sol";
import {V3Struct} from "./QuoteV3Auth/V3Struct.sol";
import {V3Parser} from "./QuoteV3Auth/V3Parser.sol";

// External Libraries
import {ISigVerifyLib} from "../interfaces/ISigVerifyLib.sol";

contract AutomataDcapV3Attestation is IAttestation, EnclaveIdBase, PEMCertChainBase, TCBInfoBase {
    using BytesUtils for bytes;

    ISigVerifyLib public immutable sigVerifyLib;

    // keccak256(hex"0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394")
    // the uncompressed (0x04) prefix is not included in the pubkey pre-image
    bytes32 constant ROOTCA_PUBKEY_HASH = 0x89f72d7c488e5b53a77c23ebcb36970ef7eb5bcf6658e9b8292cfbe4703a8473;

    uint8 constant INVALID_EXIT_CODE = 255;

    bool private checkLocalEnclaveReport;
    mapping(bytes32 enclave => bool trusted) private trustedUserMrEnclave;
    mapping(bytes32 signer => bool trusted) private trustedUserMrSigner;

    address public owner;

    constructor(
        address sigVerifyLibAddr,
        address enclaveIdDaoAddr,
        address enclaveIdHelperAddr,
        address pckHelperAddr,
        address tcbDaoAddr,
        address tcbHelperAddr
    )
        EnclaveIdBase(enclaveIdDaoAddr, enclaveIdHelperAddr)
        PEMCertChainBase(pckHelperAddr)
        TCBInfoBase(tcbDaoAddr, tcbHelperAddr)
    {
        sigVerifyLib = ISigVerifyLib(sigVerifyLibAddr);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "onlyOwner");
        _;
    }

    function setMrSigner(bytes32 _mrSigner, bool _trusted) external onlyOwner {
        trustedUserMrSigner[_mrSigner] = _trusted;
    }

    function setMrEnclave(bytes32 _mrEnclave, bool _trusted) external onlyOwner {
        trustedUserMrEnclave[_mrEnclave] = _trusted;
    }

    function toggleLocalReportCheck() external onlyOwner {
        checkLocalEnclaveReport = !checkLocalEnclaveReport;
    }

    function verifyAttestation(bytes calldata data) external override returns (bool) {
        (bool success,) = _verify(data);
        return success;
    }

    /// --------------- validate parsed quote ---------------
    function verifyParsedQuote(V3Struct.ParsedV3Quote calldata v3quote) external view returns (bool, bytes memory) {
        return _verifyParsedQuote(v3quote, bytes(""));
    }

    /// @dev Provide the raw quote binary as input
    /// @dev The attestation data (or the returned data of this method)
    /// is constructed depending on the validity of the quote verification.
    /// @dev After confirming that a quote has been verified, the attestation's validity then depends on the
    /// status of the associated TCB.
    /// @dev Example scenarios as below:
    /// --------------------------------
    /// @dev Invalid quote verification: returns (false, INVALID_EXIT_CODE)
    ///
    /// @dev For all valid quote verification, the validity of the attestation depends on the status of a
    /// matching TCBInfo and this is defined in the _attestationTcbIsValid() method, which can be overwritten
    /// in derived contracts. (Except for "Revoked" status, which also returns (false, INVALID_EXIT_CODE) value)
    /// @dev For all valid quote verification, returns the following data:
    /// (_attestationTcbIsValid(), abi.encodePacked(sha256(quote), uint8 exitCode))
    /// @dev exitCode is defined in the {{ TCBInfoStruct.TCBStatus }} enum
    function _verify(bytes calldata quote) private view returns (bool, bytes memory) {
        // Step 1: Parse the quote input = 152k gas
        (bool successful, V3Struct.ParsedV3Quote memory parsedV3Quote, bytes memory signedQuoteData) =
            V3Parser.parseInput(quote, address(pemCertLib));
        if (!successful) {
            return (false, abi.encodePacked(INVALID_EXIT_CODE));
        }

        return _verifyParsedQuote(parsedV3Quote, signedQuoteData);
    }

    /// @dev if the qupte is parsed on-chain, you must explicitly pass signedQuoteData here
    /// @dev view modifier omitted, because PCCS cache miss emits an event
    /// @dev view modifier omitted, because a PCCS cache miss emits an event
    /// @dev you can however, make a staticcall to this non-state changing method
    function _verifyParsedQuote(V3Struct.ParsedV3Quote memory v3quote, bytes memory signedQuoteData)
        private
        view
        returns (bool, bytes memory)
    {
        bytes memory retData = abi.encodePacked(INVALID_EXIT_CODE);

        // Step 0: Only validate the parsed quote if provided off-chain (gas-saving)
        if (signedQuoteData.length == 0) {
            signedQuoteData = V3Parser.validateParsedInput(v3quote);
        }

        // Step 2: Verify application enclave report MRENCLAVE and MRSIGNER
        {
            if (checkLocalEnclaveReport) {
                // 4k gas
                bool mrEnclaveIsTrusted = trustedUserMrEnclave[v3quote.localEnclaveReport.mrEnclave];
                bool mrSignerIsTrusted = trustedUserMrSigner[v3quote.localEnclaveReport.mrSigner];

                if (!mrEnclaveIsTrusted || !mrSignerIsTrusted) {
                    return (false, retData);
                }
            }
        }

        // Step 3: Verify enclave identity
        V3Struct.EnclaveReport memory qeEnclaveReport;
        EnclaveIdTcbStatus qeTcbStatus;
        {
            bool verifiedEnclaveIdSuccessfully;
            (verifiedEnclaveIdSuccessfully, qeTcbStatus) = _verifyQEReportWithIdentity(
                qeEnclaveReport.miscSelect,
                qeEnclaveReport.attributes,
                qeEnclaveReport.mrSigner,
                qeEnclaveReport.isvProdId,
                qeEnclaveReport.isvSvn
            );
            if (!verifiedEnclaveIdSuccessfully) {
                return (false, retData);
            }
            if (!verifiedEnclaveIdSuccessfully || qeTcbStatus == EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED) {
                return (false, retData);
            }
        }

        // Step 4: Parse Quote CertChain
        V3Struct.CertificationData memory certification = authDataV3.certification;
        X509CertObj[] memory parsedCerts;
        PCKCertTCB memory pckTcb;
        {
            bool certRetrievedSuccessfully;
            bytes[] memory certs;
            uint256 chainSize = 3;
            // TODO: Support other certification types
            // Ref: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/39989a42bbbb0c968153a47254b6de79a27eb603/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h#L57-L66
            if (certification.certType == 5) {
                // 660k gas
                (certRetrievedSuccessfully, certs) = splitCertificateChain(certification.certData, chainSize);
                if (!certRetrievedSuccessfully) {
                    return (false, retData);
                }
            }

            parsedCerts = new X509CertObj[](chainSize);
            for (uint256 i = 0; i < chainSize; i++) {
                certs[i] = Base64.decode(string(certs[i]));
                parsedCerts[i] = pckHelper.parseX509DER(certs[i]);
                // additional parsing for PCKCert
                if (i == 0) {
                    pckTcb = parsePck(certs[i], parsedCerts[i].extensionPtr);
                }
            }
        }

        // Step 5: basic PCK and TCB check
        TcbInfoJsonObj memory tcbInfoJson;
        {
            bool tcbInfoFound;
            (tcbInfoFound, tcbInfoJson) = _getTcbInfo(string(pckTcb.fmspcBytes));
        }

        // // Step 6: Verify TCB Level
        TCBStatus tcbStatus;
        {
            // 4k gas
            bool tcbVerified;
            (tcbVerified, tcbStatus) = _checkTcbLevels(pckTcb, tcbInfoJson);
            if (!tcbVerified) {
                return (false, retData);
            }
        }

        // // Step 7: Verify cert chain for PCK
        // {
        //     // 660k gas (rootCA pubkey is trusted)
        //     bool pckCertChainVerified = _verifyCertChain(parsedQuoteCerts);
        //     if (!pckCertChainVerified) {
        //         return (false, retData);
        //     }
        // }

        // // Step 8: Verify the local attestation sig and qe report sig = 670k gas
        // {
        //     bool enclaveReportSigsVerified =
        //         _enclaveReportSigVerification(parsedQuoteCerts[0].pubKey, signedQuoteData, authDataV3, qeEnclaveReport);
        //     if (!enclaveReportSigsVerified) {
        //         return (false, retData);
        //     }
        // }

        // retData = abi.encodePacked(sha256(quote), tcbStatus);

        // return (_attestationTcbIsValid(tcbStatus), retData);
    }

    // function _attestationTcbIsValid(TCBInfoStruct.TCBStatus status) internal pure virtual returns (bool valid) {
    //     return status == TCBInfoStruct.TCBStatus.OK || status == TCBInfoStruct.TCBStatus.TCB_SW_HARDENING_NEEDED
    //         || status == TCBInfoStruct.TCBStatus.TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED;
    // }

    // function _checkTcbLevels(PCKCertificateField memory pck, TCBInfoStruct.TCBInfo memory tcb)
    //     private
    //     pure
    //     returns (bool, TCBInfoStruct.TCBStatus status)
    // {
    //     for (uint256 i = 0; i < tcb.tcbLevels.length; i++) {
    //         TCBInfoStruct.TCBLevelObj memory current = tcb.tcbLevels[i];
    //         bool pceSvnIsHigherOrGreater = pck.sgxExtension.pcesvn >= current.pcesvn;
    //         bool cpuSvnsAreHigherOrGreater =
    //             _isCpuSvnHigherOrGreater(pck.sgxExtension.sgxTcbCompSvnArr, current.sgxTcbCompSvnArr);
    //         if (pceSvnIsHigherOrGreater && cpuSvnsAreHigherOrGreater) {
    //             status = current.status;
    //             bool tcbIsRevoked = status == TCBInfoStruct.TCBStatus.TCB_REVOKED;
    //             return (!tcbIsRevoked, status);
    //         }
    //     }
    //     return (true, TCBInfoStruct.TCBStatus.TCB_UNRECOGNIZED);
    // }

    // function _isCpuSvnHigherOrGreater(uint256[] memory pckCpuSvns, uint256[] memory tcbCpuSvns)
    //     private
    //     pure
    //     returns (bool)
    // {
    //     if (pckCpuSvns.length != CPUSVN_LENGTH || tcbCpuSvns.length != CPUSVN_LENGTH) {
    //         return false;
    //     }
    //     for (uint256 i = 0; i < CPUSVN_LENGTH; i++) {
    //         if (pckCpuSvns[i] < tcbCpuSvns[i]) {
    //             return false;
    //         }
    //     }
    //     return true;
    // }

    // function _verifyCertChain(ECSha256Certificate[] memory certs) private view returns (bool) {
    //     uint256 n = certs.length;
    //     bool certRevoked;
    //     bool certNotExpired;
    //     bool verified;
    //     bool certChainCanBeTrusted;
    //     for (uint256 i = 0; i < n; i++) {
    //         ECSha256Certificate memory issuer;
    //         if (i == n - 1) {
    //             // rootCA
    //             issuer = certs[i];
    //         } else {
    //             issuer = certs[i + 1];
    //             if (i == n - 2) {
    //                 // this cert is expected to be signed by the root
    //                 certRevoked = serialNumIsRevoked[uint256(CRL.ROOT)][certs[i].serialNumber];
    //             } else if (certs[i].isPck) {
    //                 certRevoked = serialNumIsRevoked[uint256(CRL.PCK)][certs[i].serialNumber];
    //             }
    //             if (certRevoked) {
    //                 break;
    //             }
    //         }

    //         certNotExpired = block.timestamp > certs[i].notBefore && block.timestamp < certs[i].notAfter;
    //         if (!certNotExpired) {
    //             break;
    //         }

    //         verified = sigVerifyLib.verifyES256Signature(certs[i].tbsCertificate, certs[i].signature, issuer.pubKey);
    //         if (!verified) {
    //             break;
    //         }

    //         bytes32 issuerPubKeyHash = keccak256(issuer.pubKey);

    //         if (issuerPubKeyHash == ROOTCA_PUBKEY_HASH) {
    //             certChainCanBeTrusted = true;
    //             break;
    //         }
    //     }
    //     return !certRevoked && certNotExpired && verified && certChainCanBeTrusted;
    // }

    // function _enclaveReportSigVerification(
    //     bytes memory pckCertPubKey,
    //     bytes memory signedQuoteData,
    //     V3Struct.ECDSAQuoteV3AuthData memory authDataV3,
    //     V3Struct.EnclaveReport memory qeEnclaveReport
    // ) private view returns (bool) {
    //     bytes32 expectedAuthDataHash = bytes32(qeEnclaveReport.reportData.substring(0, 32));
    //     bytes memory concatOfAttestKeyAndQeAuthData =
    //         abi.encodePacked(authDataV3.ecdsaAttestationKey, authDataV3.qeAuthData.data);
    //     bytes32 computedAuthDataHash = sha256(concatOfAttestKeyAndQeAuthData);

    //     bool qeReportDataIsValid = expectedAuthDataHash == computedAuthDataHash;
    //     if (qeReportDataIsValid) {
    //         bool qeSigVerified =
    //             sigVerifyLib.verifyES256Signature(authDataV3.rawQeReport, authDataV3.qeReportSignature, pckCertPubKey);
    //         bool quoteSigVerified = sigVerifyLib.verifyES256Signature(
    //             signedQuoteData, authDataV3.ecdsa256BitSignature, authDataV3.ecdsaAttestationKey
    //         );
    //         return qeSigVerified && quoteSigVerified;
    //     } else {
    //         return false;
    //     }
    // }
}
