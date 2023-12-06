#!/bin/bash

source .env

DEPLOY_SCRIPT="DeployDCAPScript"
CONFIGURE_SCRIPT="ConfigureDcapAttestationScript"
FORGE_COMMAND_SUFFIX="--broadcast --rpc-url $RPC_URL"

# STARTING_LINE=6

echo "[LOG] Deploying SigVerifyLib..."
SIGVERIFY_LIB_OUTPUT=$(forge script $DEPLOY_SCRIPT --sig "deploySigVerifyLib()" $FORGE_COMMAND_SUFFIX | grep LOG)
export SIGVERIFY_LIB_ADDRESS=$(echo $SIGVERIFY_LIB_OUTPUT | grep -oE '0x[0-9A-Fa-f]+')
# echo "SIGVERIFY_LIB_ADDRESS=$SIGVERIFY_LIB_ADDRESS" >> .env
# sed -i "" "${STARTING_LINE}i\\$SIGVERIFY_LIB_ADDRESS" .env
echo $SIGVERIFY_LIB_OUTPUT

echo "[LOG] Deploying PEMCertChainLib..."
PEMCERT_LIB_OUTPUT=$(forge script $DEPLOY_SCRIPT --sig "deployPemCertLib()" $FORGE_COMMAND_SUFFIX | grep LOG)
export PEMCERT_LIB_ADDRESS=$(echo $PEMCERT_LIB_OUTPUT | grep -oE '0x[0-9A-Fa-f]+')
# echo "PEMCERT_LIB_ADDRESS=$PEMCERT_LIB_ADDRESS" >> .env
echo $PEMCERT_LIB_OUTPUT

echo "[LOG] Deploying AutomataDcapV3Attestation..."
DCAP_ATTESTATION_OUTPUT=$(forge script $DEPLOY_SCRIPT --sig "deployAttestation()" $FORGE_COMMAND_SUFFIX | grep LOG)
export DCAP_ATTESTATION_ADDRESS=$(echo $DCAP_ATTESTATION_OUTPUT | grep -oE '0x[0-9A-Fa-f]+')
# echo "DCAP_ATTESTATION_ADDRESS=$DCAP_ATTESTATION_ADDRESS" >> .env
echo $DCAP_ATTESTATION_OUTPUT

echo "[LOG] Contract Deployment is complete. Setting up the attestation contract..."

echo "[LOG] Configuring TCBInfo..."
TCB_INFO_OUTPUT=$(forge script $CONFIGURE_SCRIPT --sig "configureTcb(string)" "" $FORGE_COMMAND_SUFFIX | grep Hash)
echo $TCB_INFO_OUTPUT

echo "[LOG] Configuring QeIdentity..."
QE_ID_OUTPUT=$(forge script $CONFIGURE_SCRIPT --sig "configureQeIdentity(string)" "" $FORGE_COMMAND_SUFFIX | grep Hash)
echo $QE_ID_OUTPUT

echo "[LOG] Adding revoked serial numbers from the provided CRL..."
CRL_OUTPUT=$(forge script $CONFIGURE_SCRIPT --sig "configureCrl()" "" $FORGE_COMMAND_SUFFIX | grep Hash)
echo $CRL_OUTPUT