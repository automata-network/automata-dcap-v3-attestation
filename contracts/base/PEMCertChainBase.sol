// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Base64, LibString} from "solady/Milady.sol";
import {PCKHelper, X509CertObj} from "@automata-network/on-chain-pccs/helper/PCKHelper.sol";

struct PCKCertTCB {
    uint16 pcesvn;
    uint8[] cpusvns;
    bytes fmspcBytes;
    bytes pceidBytes;
}

abstract contract PEMCertChainBase {
    PCKHelper public immutable pckHelper;

    string constant HEADER = "-----BEGIN CERTIFICATE-----";
    string constant FOOTER = "-----END CERTIFICATE-----";
    uint256 internal constant HEADER_LENGTH = 27;
    uint256 internal constant FOOTER_LENGTH = 25;

    constructor(address _pckHelper) {
        pckHelper = PCKHelper(_pckHelper);
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

    function parsePck(bytes memory der, uint256 extensionPtr) internal pure returns (PCKCertTCB memory pckTCB) {
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
}
