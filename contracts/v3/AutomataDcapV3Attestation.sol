//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAttestation} from "../interfaces/IAttestation.sol";
import {EnclaveIdBase, EnclaveIdTcbStatus} from "../base/EnclaveIdBase.sol";
import {PEMCertChainBase, X509CertObj, PCKCertTCB, LibString, BytesUtils} from "../base/PEMCertChainBase.sol";
import {TCBInfoBase, TcbInfoJsonObj, TCBStatus} from "../base/TCBInfoBase.sol";

import {V3Struct} from "./QuoteV3Auth/V3Struct.sol";
import {V3Parser} from "./QuoteV3Auth/V3Parser.sol";

import {P256} from "p256-verifier/P256.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";

contract AutomataDcapV3Attestation is IAttestation, EnclaveIdBase, PEMCertChainBase, TCBInfoBase {
    using BytesUtils for bytes;
    using LibString for bytes;

    /// @notice RISC Zero verifier contract address.
    IRiscZeroVerifier public immutable verifier;

    /// @notice The ImageID of the Risc0 DCAP Guest ELF
    bytes32 public immutable DCAP_RISC0_IMAGE_ID;

    constructor(
        address enclaveIdDaoAddr,
        address enclaveIdHelperAddr,
        address pckHelperAddr,
        address tcbDaoAddr,
        address tcbHelperAddr,
        address crlHelperAddr,
        address pcsDaoAddr,
        address risc0Verifier,
        bytes32 imageId
    )
        EnclaveIdBase(enclaveIdDaoAddr, enclaveIdHelperAddr)
        PEMCertChainBase(pckHelperAddr, crlHelperAddr, pcsDaoAddr)
        TCBInfoBase(tcbDaoAddr, tcbHelperAddr)
    {
        verifier = IRiscZeroVerifier(risc0Verifier);
        DCAP_RISC0_IMAGE_ID = imageId;
    }

    error Failed_To_Verify_Quote();
    error Invalid_Collateral_Hashes();

    function verifyAndAttestOnChain(bytes calldata input) external override returns (bytes memory output) {
        bool verified;
        (verified, output) = _verify(input);
        if (!verified) {
            revert Failed_To_Verify_Quote();
        }
    }

    function verifyAndAttestWithZKProof(bytes calldata journal, bytes32 postStateDigest, bytes calldata seal)
        external
        view
        override
        returns (bytes memory output)
    {
        bool verified = verifier.verify(seal, DCAP_RISC0_IMAGE_ID, postStateDigest, sha256(journal));

        if (!verified) {
            revert Failed_To_Verify_Quote();
        }
        
        (bytes32 tcbSigningCertHash, bytes32 rootCaHash) =
            _getCollateralHashesFromJournal(journal);

        bool verifyHashes = _checkCollateralHashes(tcbSigningCertHash, rootCaHash);
        if (!verifyHashes) {
            revert Invalid_Collateral_Hashes();
        }

        output = journal[0:129];
    }

    /**
     * @dev may parse quotes off-chain, therefore slightly lowering gas cost as compared with { verifyAndAttestOnChain() }
     */
    function verifyParsedQuoteAndAttestOnChain(V3Struct.ParsedV3Quote calldata v3quote)
        external
        returns (bytes memory output)
    {
        bool verified;
        (verified, output) =
            _verifyParsedQuote(v3quote, bytes(""), V3Parser.packQEReport(v3quote.v3AuthData.pckSignedQeReport));
        if (!verified) {
            revert Failed_To_Verify_Quote();
        }
    }

    /// @dev Provide the raw quote binary as input
    /// @dev view modifier omitted, because a PCCS cache miss emits an event
    /// @dev you can however, make a staticcall to this non-state changing method
    /// @return verified output: serialized as bytes of the following values:
    ///     uint8 tcbStatus ++ bytes32 isvMrEnclave ++ bytes32 isvMrSigner ++ bytes64 isvReportData
    function _verify(bytes calldata quote) private returns (bool verified, bytes memory output) {
        // Parse the quote input
        (
            bool successful,
            V3Struct.ParsedV3Quote memory parsedV3Quote,
            bytes memory signedQuoteData,
            bytes memory rawQeReport
        ) = V3Parser.parseInput(quote);
        if (!successful) {
            return (false, output);
        }
        return _verifyParsedQuote(parsedV3Quote, signedQuoteData, rawQeReport);
    }

    /// @dev if the qupte is parsed on-chain, you must explicitly pass signedQuoteData here
    /// @dev view modifier omitted, because a PCCS cache miss emits an event
    /// @dev you can however, make a staticcall to this non-state changing method
    function _verifyParsedQuote(
        V3Struct.ParsedV3Quote memory v3quote,
        bytes memory signedQuoteData,
        bytes memory rawQeReport
    ) private returns (bool verified, bytes memory output) {
        // Step 1: Only validate the parsed quote if provided off-chain (gas-saving)
        if (signedQuoteData.length == 0) {
            signedQuoteData = V3Parser.validateParsedInput(v3quote);
        }

        // Step 2: Verify enclave identity
        V3Struct.EnclaveReport memory qeEnclaveReport;
        EnclaveIdTcbStatus qeTcbStatus;
        {
            qeEnclaveReport = v3quote.v3AuthData.pckSignedQeReport;
            bool verifiedEnclaveIdSuccessfully;
            (verifiedEnclaveIdSuccessfully, qeTcbStatus) = _verifyQEReportWithIdentity(
                qeEnclaveReport.miscSelect,
                qeEnclaveReport.attributes,
                qeEnclaveReport.mrSigner,
                qeEnclaveReport.isvProdId,
                qeEnclaveReport.isvSvn
            );
            if (!verifiedEnclaveIdSuccessfully) {
                return (false, output);
            }
            if (!verifiedEnclaveIdSuccessfully || qeTcbStatus == EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED) {
                return (false, output);
            }
        }

        // Step 3: Parse Quote CertChain
        V3Struct.CertificationData memory certification = v3quote.v3AuthData.certification;
        X509CertObj[] memory parsedCerts;
        PCKCertTCB memory pckTcb;
        {
            bytes[] memory certs = certification.decodedCertDataArray;
            uint256 chainSize = certs.length;
            parsedCerts = new X509CertObj[](chainSize);
            for (uint256 i = 0; i < chainSize; i++) {
                parsedCerts[i] = pckHelper.parseX509DER(certs[i]);
                // additional parsing for PCKCert
                if (i == 0) {
                    pckTcb = parsePck(certs[0], parsedCerts[0].extensionPtr);
                }
            }
        }

        // Step 4: basic PCK and TCB check
        TcbInfoJsonObj memory tcbInfoJson;
        {
            bool tcbInfoFound;
            (tcbInfoFound, tcbInfoJson) = _getTcbInfo(pckTcb.fmspcBytes.toHexStringNoPrefix());
        }

        // Step 5: Verify TCB Level
        TCBStatus tcbStatus;
        {
            // 4k gas
            bool tcbVerified;
            (tcbVerified, tcbStatus) = _checkTcbLevels(qeTcbStatus, pckTcb, tcbInfoJson);
            if (!tcbVerified) {
                return (false, output);
            }
        }

        // Step 6: Verify cert chain only for certType == 5
        // this is because the PCK Certificate Chain is not obtained directly from on-chain PCCS
        // which is untrusted and requires validation
        if (certification.certType == 5) {
            bool pckCertChainVerified = _verifyCertChain(parsedCerts);
            if (!pckCertChainVerified) {
                return (false, output);
            }
        }

        // Step 7: Verify the local attestation sig and qe report sig = 670k gas
        {
            bool enclaveReportSigsVerified = _enclaveReportSigVerification(
                parsedCerts[0].subjectPublicKey, signedQuoteData, v3quote.v3AuthData, rawQeReport
            );
            if (!enclaveReportSigsVerified) {
                return (false, output);
            }
        }

        output = _serializeOutput(
            tcbStatus,
            v3quote.localEnclaveReport.mrEnclave,
            v3quote.localEnclaveReport.mrSigner,
            v3quote.localEnclaveReport.reportData
        );

        return (true, output);
    }

    function _enclaveReportSigVerification(
        bytes memory pckCertPubKey,
        bytes memory signedQuoteData,
        V3Struct.ECDSAQuoteV3AuthData memory authDataV3,
        bytes memory rawQeReport
    ) private view returns (bool) {
        bytes32 expectedAuthDataHash = bytes32(authDataV3.pckSignedQeReport.reportData.substring(0, 32));
        bytes memory concatOfAttestKeyAndQeAuthData =
            abi.encodePacked(authDataV3.ecdsaAttestationKey, authDataV3.qeAuthData.data);
        bytes32 computedAuthDataHash = sha256(concatOfAttestKeyAndQeAuthData);

        bool qeReportDataIsValid = expectedAuthDataHash == computedAuthDataHash;
        if (qeReportDataIsValid) {
            bool qeSigVerified = _ecdsaVerify(sha256(rawQeReport), authDataV3.qeReportSignature, pckCertPubKey);
            bool quoteSigVerified =
                _ecdsaVerify(sha256(signedQuoteData), authDataV3.ecdsa256BitSignature, authDataV3.ecdsaAttestationKey);
            return qeSigVerified && quoteSigVerified;
        } else {
            return false;
        }
    }

    function _ecdsaVerify(bytes32 message, bytes memory signature, bytes memory key)
        private
        view
        returns (bool verified)
    {
        verified = P256.verifySignatureAllowMalleability(
            message,
            uint256(bytes32(signature.substring(0, 32))),
            uint256(bytes32(signature.substring(32, 32))),
            uint256(bytes32(key.substring(0, 32))),
            uint256(bytes32(key.substring(32, 32)))
        );
    }

    function _serializeOutput(
        TCBStatus tcbStatus,
        bytes32 isvMrEnclave,
        bytes32 isvMrSigner,
        bytes memory isvReportData
    ) private pure returns (bytes memory serialized) {
        require(isvReportData.length < 65, "invalid enclave report data length");
        serialized = abi.encodePacked(tcbStatus, isvMrEnclave, isvMrSigner, isvReportData);
    }

    function _getCollateralHashesFromJournal(bytes calldata journal)
        private
        pure
        returns (
            bytes32 tcbSigningCertHash,
            bytes32 rootCaHash
        )
    {
        tcbSigningCertHash = bytes32(journal[199:231]);
        rootCaHash = bytes32(journal[231:263]);
    }

    function _checkCollateralHashes(
        bytes32 tcbSigningCertHash,
        bytes32 rootCaHash
    ) private pure returns (bool success) {
        bool tcbSigningMatched = tcbSigningCertHash == 0xdf3061c165c0191e2658256a2855cac9267f179aafb1990c9e918d6452816adf;
        bool rootCaMatched = rootCaHash == 0x0fa74a3f32c80b978c8ad671395dabf24283eef9091bc3919fd39b9915a87f1a;
        success = tcbSigningMatched && rootCaMatched;
    }
}
