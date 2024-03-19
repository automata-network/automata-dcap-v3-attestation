//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAttestation} from "../interfaces/IAttestation.sol";
import {EnclaveIdBase, EnclaveIdTcbStatus} from "../base/EnclaveIdBase.sol";
import {PEMCertChainBase, X509CertObj, PCKCertTCB, LibString, BytesUtils} from "../base/PEMCertChainBase.sol";
import {TCBInfoBase, TcbInfoJsonObj, TCBStatus} from "../base/TCBInfoBase.sol";

import {V3Struct} from "./QuoteV3Auth/V3Struct.sol";
import {V3Parser} from "./QuoteV3Auth/V3Parser.sol";

import {P256} from "p256-verifier/P256.sol";

contract AutomataDcapV3Attestation is IAttestation, EnclaveIdBase, PEMCertChainBase, TCBInfoBase {
    using BytesUtils for bytes;
    using LibString for bytes;

    // TODO: invalid exit code definitions here...
    uint8 constant INVALID_EXIT_CODE = 255;

    bool private checkLocalEnclaveReport;
    mapping(bytes32 enclave => bool trusted) private trustedUserMrEnclave;
    mapping(bytes32 signer => bool trusted) private trustedUserMrSigner;

    address public owner;

    constructor(
        address enclaveIdDaoAddr,
        address enclaveIdHelperAddr,
        address pckHelperAddr,
        address tcbDaoAddr,
        address tcbHelperAddr,
        address crlHelperAddr,
        address pcsDaoAddr
    )
        EnclaveIdBase(enclaveIdDaoAddr, enclaveIdHelperAddr)
        PEMCertChainBase(pckHelperAddr, crlHelperAddr, pcsDaoAddr)
        TCBInfoBase(tcbDaoAddr, tcbHelperAddr)
    {
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

    function verifyAttestation(bytes calldata data) external override returns (bool, uint256) {
        return _verify(data);
    }

    /// --------------- validate parsed quote ---------------
    function verifyParsedQuote(V3Struct.ParsedV3Quote calldata v3quote) external returns (bool, uint256) {
        return _verifyParsedQuote(v3quote, bytes(""), V3Parser.packQEReport(v3quote.v3AuthData.pckSignedQeReport));
    }

    /// @dev Provide the raw quote binary as input
    /// @dev The return data of this method is constructed depending on the validity of the quote verification.
    /// @dev After confirming that a quote has been verified, the attestation's validity then depends on the
    /// status of the associated TCB.
    /// @dev Example scenarios as below:
    /// --------------------------------
    /// @dev Invalid quote verification: returns (false, INVALID_EXIT_CODE)
    ///
    /// @dev For all valid quote verification, the validity of the attestation depends on the status of a
    /// matching TCBInfo and this is defined in the _attestationTcbIsValid() method, which can be overwritten
    /// in derived contracts. (Except for "Revoked" status, which also returns (false, INVALID_EXIT_CODE) value)
    /// --------------------------------
    /// @dev For all valid quote verification (and valid TCB), returns the following data:
    /// (_attestationTcbIsValid(), 0)
    /// @dev exitCode with varying TCB Statuses is defined in the {{ TCBInfoBase.TCBStatus }} enum
    /// --------------------------------
    /// @dev view modifier omitted, because a PCCS cache miss emits an event
    /// @dev you can however, make a staticcall to this non-state changing method
    function _verify(bytes calldata quote) private returns (bool, uint256) {
        // Parse the quote input
        (
            bool successful,
            V3Struct.ParsedV3Quote memory parsedV3Quote,
            bytes memory signedQuoteData,
            bytes memory rawQeReport
        ) = V3Parser.parseInput(quote);
        if (!successful) {
            return (false, INVALID_EXIT_CODE);
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
    ) private returns (bool, uint256) {
        uint256 exitCode = INVALID_EXIT_CODE;

        // Step 0: Only validate the parsed quote if provided off-chain (gas-saving)
        if (signedQuoteData.length == 0) {
            signedQuoteData = V3Parser.validateParsedInput(v3quote);
        }

        // Step 1: Verify application enclave report MRENCLAVE and MRSIGNER
        {
            if (checkLocalEnclaveReport) {
                // 4k gas
                bool mrEnclaveIsTrusted = trustedUserMrEnclave[v3quote.localEnclaveReport.mrEnclave];
                bool mrSignerIsTrusted = trustedUserMrSigner[v3quote.localEnclaveReport.mrSigner];

                if (!mrEnclaveIsTrusted || !mrSignerIsTrusted) {
                    return (false, exitCode);
                }
            }
        }

        // Step 2: Verify enclave identity
        V3Struct.EnclaveReport memory qeEnclaveReport;
        {
            EnclaveIdTcbStatus qeTcbStatus;
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
                return (false, exitCode);
            }
            if (!verifiedEnclaveIdSuccessfully || qeTcbStatus == EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED) {
                return (false, exitCode);
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
            (tcbVerified, tcbStatus) = _checkTcbLevels(pckTcb, tcbInfoJson);
            if (!tcbVerified) {
                return (false, exitCode);
            }
        }

        // Step 6: Verify cert chain only for certType == 5
        // this is because the PCK Certificate Chain is not obtained directly from on-chain PCCS
        // which is untrusted and requires validation
        if (certification.certType == 5) {
            bool pckCertChainVerified = _verifyCertChain(parsedCerts);
            if (!pckCertChainVerified) {
                return (false, exitCode);
            }
        }

        // Step 7: Verify the local attestation sig and qe report sig = 670k gas
        {
            bool enclaveReportSigsVerified = _enclaveReportSigVerification(
                parsedCerts[0].subjectPublicKey, signedQuoteData, v3quote.v3AuthData, rawQeReport
            );
            if (!enclaveReportSigsVerified) {
                return (false, exitCode);
            }
        }

        exitCode = uint256(tcbStatus);

        return (_attestationTcbIsValid(tcbStatus), exitCode);
    }

    function _attestationTcbIsValid(TCBStatus status) internal pure virtual returns (bool valid) {
        return status == TCBStatus.OK || status == TCBStatus.TCB_SW_HARDENING_NEEDED
            || status == TCBStatus.TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED;
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
}
