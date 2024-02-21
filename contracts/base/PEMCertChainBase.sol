// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Base64, LibString} from "solady/Milady.sol";
import {PCKHelper, X509CertObj} from "@automata-network/on-chain-pccs/helper/PCKHelper.sol";
import {X509CRLHelper} from "@automata-network/on-chain-pccs/helper/X509CRLHelper.sol";
import {PcsDao, CA} from "@automata-network/on-chain-pccs/dao/PcsDao.sol";

// External Libraries
import {ISigVerifyLib} from "../interfaces/ISigVerifyLib.sol";

struct PCKCertTCB {
    uint16 pcesvn;
    uint8[] cpusvns;
    bytes fmspcBytes;
    bytes pceidBytes;
}

abstract contract PEMCertChainBase {
    ISigVerifyLib public immutable sigVerifyLib;
    PCKHelper public immutable pckHelper;
    X509CRLHelper public immutable crlHelper;
    PcsDao public immutable pcsDao;

    string constant HEADER = "-----BEGIN CERTIFICATE-----";
    string constant FOOTER = "-----END CERTIFICATE-----";
    uint256 internal constant HEADER_LENGTH = 27;
    uint256 internal constant FOOTER_LENGTH = 25;

    // keccak256(hex"0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394")
    // the uncompressed (0x04) prefix is not included in the pubkey pre-image
    bytes32 constant ROOTCA_PUBKEY_HASH = 0x89f72d7c488e5b53a77c23ebcb36970ef7eb5bcf6658e9b8292cfbe4703a8473;

    constructor(address _sigVerifyLib, address _pckHelper, address _crlHelper, address _pcsDao) {
        sigVerifyLib = ISigVerifyLib(_sigVerifyLib);
        pckHelper = PCKHelper(_pckHelper);
        crlHelper = X509CRLHelper(_crlHelper);
        pcsDao = PcsDao(_pcsDao);
    }

    function splitCertificateChain(bytes memory pemChain, uint256 size)
        internal
        pure
        returns (bool success, bytes[] memory certs)
    {
        certs = new bytes[](size);
        string memory pemChainStr = string(pemChain);

        uint256 index = 0;
        uint256 len = pemChain.length;

        for (uint256 i = 0; i < size; i++) {
            string memory input;
            if (i > 0) {
                input = LibString.slice(pemChainStr, index, index + len);
            } else {
                input = pemChainStr;
            }
            uint256 increment;
            (success, certs[i], increment) = _removeHeadersAndFooters(input);

            if (!success) {
                return (false, certs);
            }

            index += increment;
        }

        success = true;
    }

    function parsePck(bytes memory der, uint256 extensionPtr) internal view returns (PCKCertTCB memory pckTCB) {
        (pckTCB.pcesvn, pckTCB.cpusvns, pckTCB.fmspcBytes, pckTCB.pceidBytes) =
            pckHelper.parsePckExtension(der, extensionPtr);
    }

    function _removeHeadersAndFooters(string memory pemData)
        private
        pure
        returns (bool success, bytes memory extracted, uint256 endIndex)
    {
        // Check if the input contains the "BEGIN" and "END" headers
        uint256 beginPos = LibString.indexOf(pemData, HEADER);
        uint256 endPos = LibString.indexOf(pemData, FOOTER);

        bool headerFound = beginPos != LibString.NOT_FOUND;
        bool footerFound = endPos != LibString.NOT_FOUND;

        if (!headerFound || !footerFound) {
            return (false, extracted, endIndex);
        }

        // Extract the content between the headers
        uint256 contentStart = beginPos + HEADER_LENGTH;

        // Extract and return the content
        bytes memory contentBytes;

        // do not include newline
        bytes memory delimiter = hex"0a";
        string memory contentSlice = LibString.slice(pemData, contentStart, endPos);
        string[] memory split = LibString.split(contentSlice, string(delimiter));
        string memory contentStr;

        for (uint256 i = 0; i < split.length; i++) {
            contentStr = LibString.concat(contentStr, split[i]);
        }

        contentBytes = bytes(contentStr);
        return (true, contentBytes, endPos + FOOTER_LENGTH);
    }

    function _verifyCertChain(X509CertObj[] memory certs) internal view returns (bool) {
        uint256 n = certs.length;
        bool certRevoked;
        bool certNotExpired;
        bool verified;
        bool certChainCanBeTrusted;
        for (uint256 i = 0; i < n; i++) {
            X509CertObj memory issuer;
            if (i == n - 1) {
                // rootCA
                issuer = certs[i];
            } else {
                issuer = certs[i + 1];
                if (i == n - 2) {
                    (, bytes memory rootCrl) = pcsDao.getCertificateById(CA.ROOT);
                    certRevoked = crlHelper.serialNumberIsRevoked(certs[i].serialNumber, rootCrl);
                } else if (i == 0) {
                    (, bytes memory pckCrl) = pcsDao.getCertificateById(CA.PLATFORM);
                    certRevoked = crlHelper.serialNumberIsRevoked(certs[i].serialNumber, pckCrl);
                }
                if (certRevoked) {
                    break;
                }
            }

            certNotExpired = block.timestamp > certs[i].validityNotBefore && block.timestamp < certs[i].validityNotAfter;
            if (!certNotExpired) {
                break;
            }

            verified = sigVerifyLib.verifyES256Signature(certs[i].tbs, certs[i].signature, issuer.subjectPublicKey);
            if (!verified) {
                break;
            }

            bytes32 issuerPubKeyHash = keccak256(issuer.subjectPublicKey);

            if (issuerPubKeyHash == ROOTCA_PUBKEY_HASH) {
                certChainCanBeTrusted = true;
                break;
            }
        }
        return !certRevoked && certNotExpired && verified && certChainCanBeTrusted;
    }
}
