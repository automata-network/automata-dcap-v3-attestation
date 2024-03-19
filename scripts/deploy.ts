import * as dotenv from 'dotenv';
import { ethers } from "hardhat";

dotenv.config();

const {
  ENCLAVE_IDENTITY_DAO_PORTAL,
  ENCLAVE_IDENTITY_HELPER,
  X509_HELPER,
  FMSPC_TCB_DAO_PORTAL,
  FMSPC_TCB_HELPER,
  X509_CRL_HELPER,
  PCS_DAO_PORTAL
} = process.env;

async function main() {
  const attestation = await ethers.deployContract("AutomataDcapV3Attestation", [
    ENCLAVE_IDENTITY_DAO_PORTAL,
    ENCLAVE_IDENTITY_HELPER,
    X509_HELPER,
    FMSPC_TCB_DAO_PORTAL,
    FMSPC_TCB_HELPER,
    X509_CRL_HELPER,
    PCS_DAO_PORTAL
  ], {});
  await attestation.waitForDeployment();
  const attestationAddr = await attestation.getAddress();
  console.log("attestation address:", attestationAddr);
}


// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
