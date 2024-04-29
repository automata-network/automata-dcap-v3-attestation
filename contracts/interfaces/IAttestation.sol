//SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/**
 * @title Interface standard that implement attestation contracts whose verification logic can be implemented
 * both on-chain and with Risc0 ZK proofs
 * @notice The interface simply provides two verification methods for a given attestation input.
 * The user can either pay a possibly hefty gas cost to fully verify an attestation fully on-chain
 * OR
 * Provides ZK proofs from executing an off-chain program where the verification of such attestation is conducted.
 * @dev should also implement Risc0 Guest Program to use this interface.
 * See https://dev.risczero.com/api/blockchain-integration/bonsai-on-eth to learn more
 */
interface IAttestation {
    /**
     * @notice full on-chain verification for an attestation
     * @dev must further specify the structure of inputs/outputs, to be serialized and passed to this method
     * @param input - serialized raw input as defined by the project
     * @return output - the output upon completion of verification. The output data may require post-processing by the consumer
     */
    function verifyAndAttestOnChain(bytes calldata input) external returns (bytes memory output);

    /**
     * @notice inputs/outputs of this method is identical as { verifyAttestationOnChain }
     * @param postStateDigest - A hash of the final memory state. Required to run the verifier, but
     *     otherwise can be left unconstrained for most use cases.
     * @param seal - The encoded cryptographic proof (i.e. SNARK).
     */
    function verifyAndAttestWithZKProof(bytes calldata input, bytes32 postStateDigest, bytes calldata seal)
        external
        returns (bytes memory output);
}
