#!/bin/bash

source .env

DEPLOY_SCRIPT="DeployDCAPScript"
FORGE_COMMAND_SUFFIX="--broadcast --rpc-url $RPC_URL"

echo "[LOG] Deploying AutomataDcapV3Attestation..."
DCAP_ATTESTATION_OUTPUT=$(forge script $DEPLOY_SCRIPT --sig "deployAttestation()" $FORGE_COMMAND_SUFFIX | grep LOG)
export DCAP_ATTESTATION_ADDRESS=$(echo $DCAP_ATTESTATION_OUTPUT | grep -oE '0x[0-9A-Fa-f]+')
# echo "DCAP_ATTESTATION_ADDRESS=$DCAP_ATTESTATION_ADDRESS" >> .env
echo $DCAP_ATTESTATION_OUTPUT