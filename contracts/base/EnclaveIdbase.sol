//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {
    EnclaveIdentityHelper,
    EnclaveIdentityJsonObj,
    IdentityObj,
    EnclaveId,
    Tcb,
    EnclaveIdTcbStatus
} from "@automata-network/on-chain-pccs/helper/EnclaveIdentityHelper.sol";
import {EnclaveIdentityDao} from "@automata-network/on-chain-pccs/dao/EnclaveIdentityDao.sol";

abstract contract EnclaveIdBase {
    EnclaveIdentityDao public immutable enclaveIdDao;
    EnclaveIdentityHelper public immutable enclaveIdHelper;

    constructor(address _enclaveIdDao, address _enclaveIdHelper) {
        enclaveIdDao = EnclaveIdentityDao(_enclaveIdDao);
        enclaveIdHelper = EnclaveIdentityHelper(_enclaveIdHelper);
    }

    /// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/Verifiers/EnclaveReportVerifier.cpp#L47-L113
    function _verifyQEReportWithIdentity(
        bytes4 enclaveReportMiscselect,
        bytes16 enclaveReportAttributes,
        bytes32 enclaveReportMrsigner,
        uint16 enclaveReportIsvprodid,
        uint16 enclaveReportIsvSvn
    ) internal returns (bool, EnclaveIdTcbStatus status) {
        EnclaveIdentityJsonObj memory idJsonObj = enclaveIdDao.getEnclaveIdentity(0, 3);
        IdentityObj memory identity = enclaveIdHelper.parseIdentityString(idJsonObj.identityStr);
        Tcb[] memory identityTcbs = enclaveIdHelper.parseTcb(identity.rawTcbLevelsObjStr);

        bool miscselectMatched = enclaveReportMiscselect & identity.miscselectMask == identity.miscselect;
        bool attributesMatched = enclaveReportAttributes & identity.attributesMask == identity.attributes;
        bool mrsignerMatched = enclaveReportMrsigner == identity.mrsigner;
        bool isvprodidMatched = enclaveReportIsvprodid == identity.isvprodid;

        bool tcbFound;
        for (uint256 i = 0; i < identityTcbs.length; i++) {
            if (identityTcbs[i].isvsvn <= enclaveReportIsvSvn) {
                tcbFound = true;
                status = identityTcbs[i].status;
                break;
            }
        }
        return (miscselectMatched && attributesMatched && mrsignerMatched && isvprodidMatched && tcbFound, status);
    }
}
