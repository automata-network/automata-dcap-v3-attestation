//SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

interface IAttestation {
    function verifyAttestation(bytes calldata data) view external returns (bool);
}