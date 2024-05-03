//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {
    FmspcTcbHelper,
    TcbInfoJsonObj,
    TCBLevelsObj,
    TCBStatus
} from "@automata-network/on-chain-pccs/helper/FmspcTcbHelper.sol";
import {EnclaveIdTcbStatus} from "@automata-network/on-chain-pccs/helper/EnclaveIdentityHelper.sol";
import {FmspcTcbDao} from "@automata-network/on-chain-pccs/dao/FmspcTcbDao.sol";

import {PCKCertTCB} from "./PEMCertChainBase.sol";

abstract contract TCBInfoBase {
    FmspcTcbDao public immutable tcbDao;
    FmspcTcbHelper public immutable tcbHelper;

    // https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/e7604e02331b3377f3766ed3653250e03af72d45/QuoteVerification/QVL/Src/AttestationLibrary/src/CertVerification/X509Constants.h#L64
    uint256 constant CPUSVN_LENGTH = 16;

    constructor(address _tcbDao, address _tcbHelper) {
        tcbDao = FmspcTcbDao(_tcbDao);
        tcbHelper = FmspcTcbHelper(_tcbHelper);
    }

    function _getTcbInfo(string memory fmspc) internal returns (bool success, TcbInfoJsonObj memory tcbObj) {
        // v3 SGX Quote uses V2 TCBInfo
        tcbObj = tcbDao.getTcbInfo(0, fmspc, 2);
        success = bytes(tcbObj.tcbInfoStr).length > 0 && tcbObj.signature.length > 0;
    }

    function _checkTcbLevels(EnclaveIdTcbStatus qeTcbStatus, PCKCertTCB memory pckTcb, TcbInfoJsonObj memory tcbJson)
        internal
        view
        returns (bool, TCBStatus status)
    {
        // TODO: it is prohibitively expensive to *repeateddly* parse collaterals on every call
        // TODO: we might have to separately store these parsed collaterals on chain as well
        (, TCBLevelsObj[] memory tcbLevels) = tcbHelper.parseTcbLevels(tcbJson.tcbInfoStr);

        for (uint256 i = 0; i < tcbLevels.length; i++) {
            TCBLevelsObj memory current = tcbLevels[i];
            bool pceSvnIsHigherOrGreater = pckTcb.pcesvn >= current.pcesvn;
            bool cpuSvnsAreHigherOrGreater = _isCpuSvnHigherOrGreater(pckTcb.cpusvns, current.cpusvnsArr);
            if (pceSvnIsHigherOrGreater && cpuSvnsAreHigherOrGreater) {
                bool tcbIsRevoked = status == TCBStatus.TCB_REVOKED
                    || qeTcbStatus == EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED;
                // https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L271-L312
                if (qeTcbStatus == EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE) {
                    if (current.status == TCBStatus.OK || current.status == TCBStatus.TCB_SW_HARDENING_NEEDED) {
                        status = TCBStatus.TCB_OUT_OF_DATE;
                    }
                    if (
                        current.status == TCBStatus.TCB_CONFIGURATION_NEEDED
                            || current.status == TCBStatus.TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED
                    ) {
                        status = TCBStatus.TCB_OUT_OF_DATE_CONFIGURATION_NEEDED;
                    }
                } else {
                    status = current.status;
                }
                return (!tcbIsRevoked, status);
            }
        }
        return (true, TCBStatus.TCB_UNRECOGNIZED);
    }

    function _isCpuSvnHigherOrGreater(uint8[] memory pckCpuSvns, uint256[] memory tcbCpuSvns)
        private
        pure
        returns (bool)
    {
        if (pckCpuSvns.length != CPUSVN_LENGTH || tcbCpuSvns.length != CPUSVN_LENGTH) {
            return false;
        }
        for (uint256 i = 0; i < CPUSVN_LENGTH; i++) {
            if (uint256(pckCpuSvns[i]) < tcbCpuSvns[i]) {
                return false;
            }
        }
        return true;
    }
}
