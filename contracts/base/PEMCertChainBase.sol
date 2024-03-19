// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BytesUtils} from "../utils/BytesUtils.sol";

import {LibString} from "solady/utils/LibString.sol";
import {PCKHelper, X509CertObj} from "@automata-network/on-chain-pccs/helper/PCKHelper.sol";
import {X509CRLHelper} from "@automata-network/on-chain-pccs/helper/X509CRLHelper.sol";
import {PcsDao, CA} from "@automata-network/on-chain-pccs/dao/PcsDao.sol";
import {P256} from "p256-verifier/P256.sol";

struct PCKCertTCB {
    uint16 pcesvn;
    uint8[] cpusvns;
    bytes fmspcBytes;
    bytes pceidBytes;
}

abstract contract PEMCertChainBase {
    using BytesUtils for bytes;

    PCKHelper public immutable pckHelper;
    X509CRLHelper public immutable crlHelper;
    PcsDao public immutable pcsDao;

    string constant PLATFORM_ISSUER_NAME = "Intel SGX PCK Platform CA";
    string constant PROCESSOR_ISSUER_NAME = "Intel SGX PCK Processor CA";

    // keccak256(hex"0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394")
    // the uncompressed (0x04) prefix is not included in the pubkey pre-image
    bytes32 constant ROOTCA_PUBKEY_HASH = 0x89f72d7c488e5b53a77c23ebcb36970ef7eb5bcf6658e9b8292cfbe4703a8473;

    constructor(address _pckHelper, address _crlHelper, address _pcsDao) {
        pckHelper = PCKHelper(_pckHelper);
        crlHelper = X509CRLHelper(_crlHelper);
        pcsDao = PcsDao(_pcsDao);
    }

    function parsePck(bytes memory der, uint256 extensionPtr) internal view returns (PCKCertTCB memory pckTCB) {
        (pckTCB.pcesvn, pckTCB.cpusvns, pckTCB.fmspcBytes, pckTCB.pceidBytes) =
            pckHelper.parsePckExtension(der, extensionPtr);
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
                bytes memory crl;
                if (i == n - 2) {
                    (, crl) = pcsDao.getCertificateById(CA.ROOT);
                } else if (i == 0) {
                    string memory issuerName = certs[i].issuerCommonName;
                    if (LibString.eq(issuerName, PLATFORM_ISSUER_NAME)) {
                        (, crl) = pcsDao.getCertificateById(CA.PLATFORM);
                    } else if (LibString.eq(issuerName, PROCESSOR_ISSUER_NAME)) {
                        (, crl) = pcsDao.getCertificateById(CA.PROCESSOR);
                    } else {
                        return false;
                    }
                }
                if (crl.length > 0) {
                    certRevoked = crlHelper.serialNumberIsRevoked(certs[i].serialNumber, crl);
                }
                if (certRevoked) {
                    break;
                }
            }

            certNotExpired = block.timestamp > certs[i].validityNotBefore && block.timestamp < certs[i].validityNotAfter;
            if (!certNotExpired) {
                break;
            }

            {
                verified = P256.verifySignatureAllowMalleability(
                    sha256(certs[i].tbs),
                    uint256(bytes32(certs[i].signature.substring(0, 32))),
                    uint256(bytes32(certs[i].signature.substring(32, 32))),
                    uint256(bytes32(issuer.subjectPublicKey.substring(0, 32))),
                    uint256(bytes32(issuer.subjectPublicKey.substring(32, 32)))
                );
                if (!verified) {
                    break;
                }
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
