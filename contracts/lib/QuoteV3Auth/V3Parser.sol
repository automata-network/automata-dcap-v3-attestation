//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BytesUtils} from "../../utils/BytesUtils.sol";
import {Base64} from "solady/src/Milady.sol";
import {V3Struct} from "./V3Struct.sol";
import {IPEMCertChainLib, PEMCertChainLib} from "../../lib/PEMCertChainLib.sol";

library V3Parser {
    using BytesUtils for bytes;

    uint256 constant MINIMUM_QUOTE_LENGTH = 1020;
    bytes2 constant SUPPORTED_QUOTE_VERSION = 0x0300;
    bytes2 constant SUPPORTED_ATTESTATION_KEY_TYPE = 0x0200;
    // SGX only
    bytes4 constant SUPPORTED_TEE_TYPE = 0;
    bytes16 constant VALID_QE_VENDOR_ID = 0x939a7233f79c4ca9940a0db3957f0607;

    function parseInput(
        bytes memory quote,
        address pemCertLibAddr
    )
        internal
        pure
        returns (
            bool success,
            V3Struct.ParsedV3QuoteStruct memory v3ParsedQuote
        )
    {
        if (quote.length <= MINIMUM_QUOTE_LENGTH) {
            return (
                false,
                v3ParsedQuote
            );
        }

        uint256 localAuthDataSize = littleEndianDecode(quote.substring(432, 4));
        if (quote.length - 436 != localAuthDataSize) {
            return (
                false,
                v3ParsedQuote
            );
        }

        bytes memory rawHeader = quote.substring(0, 48);
        (bool headerVerifiedSuccessfully, V3Struct.Header memory header) = parseAndVerifyHeader(rawHeader);
        if (!headerVerifiedSuccessfully) {
            return (
                false,
                v3ParsedQuote
            );
        }

        (
            bool authDataVerifiedSuccessfully,
            V3Struct.ECDSAQuoteV3AuthData memory authDataV3
        ) = parseAuthDataAndVerifyCertType(
            quote.substring(436, localAuthDataSize),
            pemCertLibAddr
        );
        if (!authDataVerifiedSuccessfully) {
            return (
                false,
                v3ParsedQuote
            );
        }

        bytes memory rawLocalEnclaveReport = quote.substring(48, 384);
        V3Struct.EnclaveReport memory localEnclaveReport = parseEnclaveReport(rawLocalEnclaveReport);

        v3ParsedQuote = V3Struct.ParsedV3QuoteStruct({
            header: header,
            localEnclaveReport: localEnclaveReport,
            v3AuthData: authDataV3
        });

        success = true;
    }

    function parseEnclaveReport(
        bytes memory rawEnclaveReport
    ) internal pure returns (V3Struct.EnclaveReport memory enclaveReport) {
        enclaveReport.cpuSvn = bytes16(rawEnclaveReport.substring(0, 16));
        enclaveReport.miscSelect = bytes4(rawEnclaveReport.substring(16, 4));
        enclaveReport.reserved1 = bytes28(rawEnclaveReport.substring(20, 28));
        enclaveReport.attributes = bytes16(rawEnclaveReport.substring(48, 16));
        enclaveReport.mrEnclave = bytes32(rawEnclaveReport.substring(64, 32));
        enclaveReport.reserved2 = bytes32(rawEnclaveReport.substring(96, 32));
        enclaveReport.mrSigner = bytes32(rawEnclaveReport.substring(128, 32));
        enclaveReport.reserved3 = rawEnclaveReport.substring(160, 96);
        enclaveReport.isvProdId = uint16(
            littleEndianDecode(rawEnclaveReport.substring(256, 2))
        );
        enclaveReport.isvSvn = uint16(
            littleEndianDecode(rawEnclaveReport.substring(258, 2))
        );
        enclaveReport.reserved4 = rawEnclaveReport.substring(260, 60);
        enclaveReport.reportData = rawEnclaveReport.substring(320, 64);
    }

    function littleEndianDecode(
        bytes memory encoded
    ) private pure returns (uint256 decoded) {
        for (uint256 i = 0; i < encoded.length; i++) {
            uint256 digits = uint256(uint8(bytes1(encoded[i])));
            uint256 upperDigit = digits / 16;
            uint256 lowerDigit = digits % 16;

            uint256 acc = lowerDigit * (16 ** (2 * i));
            acc += upperDigit * (16 ** ((2 * i) + 1));

            decoded += acc;
        }
    }

    function parseAndVerifyHeader(
        bytes memory rawHeader
    ) private pure returns (bool success, V3Struct.Header memory header) {
        bytes2 version = bytes2(rawHeader.substring(0, 2));
        if (version != SUPPORTED_QUOTE_VERSION) {
            return (false, header);
        }

        bytes2 attestationKeyType = bytes2(rawHeader.substring(2, 2));
        if (attestationKeyType != SUPPORTED_ATTESTATION_KEY_TYPE) {
            return (false, header);
        }

        bytes4 teeType = bytes4(rawHeader.substring(4, 4));
        if (teeType != SUPPORTED_TEE_TYPE) {
            return (false, header);
        }

        bytes16 qeVendorId = bytes16(rawHeader.substring(12, 16));
        if (qeVendorId != VALID_QE_VENDOR_ID) {
            return (false, header);
        }

        header = V3Struct.Header({
            version: version,
            attestationKeyType: attestationKeyType,
            teeType: teeType,
            qeSvn: bytes2(rawHeader.substring(8, 2)),
            pceSvn: bytes2(rawHeader.substring(10, 2)),
            qeVendorId: qeVendorId,
            userData: bytes20(rawHeader.substring(28, 20))
        });

        success = true;
    }

    function parseAuthDataAndVerifyCertType(
        bytes memory rawAuthData,
        address pemCertLibAddr
    )
        private
        pure
        returns (bool success, V3Struct.ECDSAQuoteV3AuthData memory authDataV3)
    {
        V3Struct.QEAuthData memory qeAuthData;
        qeAuthData.parsedDataSize = uint16(
            littleEndianDecode(rawAuthData.substring(576, 2))
        );
        qeAuthData.data = rawAuthData.substring(578, qeAuthData.parsedDataSize);

        uint256 offset = 578 + qeAuthData.parsedDataSize;
        V3Struct.CertificationData memory cert;
        cert.certType = uint16(
            littleEndianDecode(rawAuthData.substring(offset, 2))
        );
        if (cert.certType < 1 || cert.certType > 5) {
            return (false, authDataV3);
        }
        offset += 2;
        cert.certDataSize = uint32(
            littleEndianDecode(rawAuthData.substring(offset, 4))
        );
        offset += 4;
        bytes memory certData = rawAuthData.substring(
            offset,
            cert.certDataSize
        );
        cert.decodedCertDataArray = parseCerificationChainBytes(
            certData,
            pemCertLibAddr
        );

        authDataV3.ecdsa256BitSignature = rawAuthData.substring(0, 64);
        authDataV3.ecdsaAttestationKey = rawAuthData.substring(64, 64);
        bytes memory rawQeReport = rawAuthData.substring(128, 384);
        authDataV3.pckSignedQeReport = parseEnclaveReport(rawQeReport);
        authDataV3.qeReportSignature = rawAuthData.substring(512, 64);
        authDataV3.qeAuthData = qeAuthData;
        authDataV3.certification = cert;

        success = true;
    }

    /// for structured quote parse
    function validateParsedInput(
        V3Struct.ParsedV3QuoteStruct memory v3Quote
    )
        internal
        pure
        returns (
            bool success,
            V3Struct.Header memory header,
            V3Struct.EnclaveReport memory localEnclaveReport,
            bytes memory signedQuoteData, // concatenation of header and local enclave report bytes
            V3Struct.ECDSAQuoteV3AuthData memory authDataV3
        )
    {
        success = true;
        localEnclaveReport = v3Quote.localEnclaveReport;
        V3Struct.EnclaveReport memory pckSignedQeReport = v3Quote
            .v3AuthData
            .pckSignedQeReport;

        require(
            localEnclaveReport.reserved3.length == 96 &&
                localEnclaveReport.reserved4.length == 60 &&
                localEnclaveReport.reportData.length == 64,
            "local QE report has wrong length"
        );
        require(
            pckSignedQeReport.reserved3.length == 96 &&
                pckSignedQeReport.reserved4.length == 60 &&
                pckSignedQeReport.reportData.length == 64,
            "QE report has wrong length"
        );
        require(
            v3Quote.v3AuthData.certification.certType == 5,
            "certType must be 5: Concatenated PCK Cert Chain (PEM formatted)"
        );
        require(
            v3Quote.v3AuthData.certification.decodedCertDataArray.length == 3,
            "3 certs in chain"
        );
        require(
            v3Quote.v3AuthData.ecdsa256BitSignature.length == 64 &&
                v3Quote.v3AuthData.ecdsaAttestationKey.length == 64 &&
                v3Quote.v3AuthData.qeReportSignature.length == 64,
            "Invalid ECDSA signature format"
        );
        require(
            v3Quote.v3AuthData.qeAuthData.parsedDataSize ==
                v3Quote.v3AuthData.qeAuthData.data.length,
            "Invalid QEAuthData size"
        );

        // // todo!
        // // v3Quote.v3AuthData.certification.certDataSize ==
        // //      len(join((BEGIN_CERT, base64.encode(certArray[i]), END_CERT) for i in 0..3))
        // // This check need b64 encoding, skip it now.
        // require(
        //     base64.encode(v3Quote.v3AuthData.certification.decodedCertDataArray[0]).length +
        //          base64.encode(v3Quote
        //             .v3AuthData
        //             .certification
        //             .decodedCertDataArray[1])
        //             .length +
        //          base64.encode(v3Quote
        //             .v3AuthData
        //             .certification
        //             .decodedCertDataArray[2])
        //             .length +
        //         3 *
        //         (HEADER_LENGTH + FOOTER_LENGTH) ==
        //         v3Quote.v3AuthData.certification.certDataSize,
        //     "Invalid certData size"
        // );

        uint32 totalQuoteSize = 48 + // header
            384 + // local QE report
            64 + // ecdsa256BitSignature
            64 + // ecdsaAttestationKey
            384 + // QE report
            64 + // qeReportSignature
            2 + // sizeof(v3Quote.v3AuthData.qeAuthData.parsedDataSize)
            v3Quote.v3AuthData.qeAuthData.parsedDataSize +
            2 + // sizeof(v3Quote.v3AuthData.certification.certType)
            4 + // sizeof(v3Quote.v3AuthData.certification.certDataSize)
            v3Quote.v3AuthData.certification.certDataSize;
        require(totalQuoteSize >= MINIMUM_QUOTE_LENGTH, "Invalid quote size");

        header = v3Quote.header;
        bytes memory headerBytes = abi.encodePacked(
            header.version,
            header.attestationKeyType,
            header.teeType,
            header.qeSvn,
            header.pceSvn,
            header.qeVendorId,
            header.userData
        );

        signedQuoteData = abi.encodePacked(
            headerBytes,
            V3Parser.packQEReport(localEnclaveReport)
        );
        authDataV3 = v3Quote.v3AuthData;
    }

    /// enclaveReport to bytes for hash calculation.
    /// the only difference between enclaveReport and packedQEReport is the
    /// order of isvProdId and isvSvn. enclaveReport is in little endian, while
    /// in bytes should be in big endian according to Intel spec.
    /// @param enclaveReport enclave report
    /// @return packedQEReport enclave report in bytes
    function packQEReport(
        V3Struct.EnclaveReport memory enclaveReport
    ) internal pure returns (bytes memory packedQEReport) {
        uint16 isvProdIdPackBE = (enclaveReport.isvProdId >> 8) |
            (enclaveReport.isvProdId << 8);
        uint16 isvSvnPackBE = (enclaveReport.isvSvn >> 8) |
            (enclaveReport.isvSvn << 8);
        packedQEReport = abi.encodePacked(
            enclaveReport.cpuSvn,
            enclaveReport.miscSelect,
            enclaveReport.reserved1,
            enclaveReport.attributes,
            enclaveReport.mrEnclave,
            enclaveReport.reserved2,
            enclaveReport.mrSigner,
            enclaveReport.reserved3,
            isvProdIdPackBE,
            isvSvnPackBE,
            enclaveReport.reserved4,
            enclaveReport.reportData
        );
    }

    function parseCerificationChainBytes(
        bytes memory certBytes,
        address pemCertLibAddr
    ) internal pure returns (bytes[3] memory certChainData) {
        IPEMCertChainLib pemCertLib = PEMCertChainLib(pemCertLibAddr);
        IPEMCertChainLib.ECSha256Certificate[] memory parsedQuoteCerts;
        (bool certParsedSuccessfully, bytes[] memory quoteCerts) = pemCertLib
            .splitCertificateChain(certBytes, 3);
        require(certParsedSuccessfully, "splitCertificateChain failed");
        parsedQuoteCerts = new IPEMCertChainLib.ECSha256Certificate[](3);
        for (uint256 i = 0; i < 3; i++) {
            quoteCerts[i] = Base64.decode(string(quoteCerts[i]));
        }

        certChainData = [quoteCerts[0], quoteCerts[1], quoteCerts[2]];
    }
}
