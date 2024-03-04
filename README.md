# AutomataDcapV3Attestation

## Getting Started

Clone this repo, by running the following command:

```bash
git clone git@github.com:automata-network/automata-dcap-v3-attestation.git --recurse-submodules
```

This repo includes both Hardhat and Foundry frameworks. Therefore, you can absolutely provide additional scripts and test cases written in both Solidity and TypeScript.

If you are building with Hardhat, make sure to run the command below to install the necessary NPM packages.

```bash
npm install
```

Before you begin, make sure to create a copy of the `.env` file with the example provided. Then, please provide any remaining variables that are missing.

```bash
cp .env.example .env
```
---

## Building With Foundry

Compile the contract:

```bash
forge install
forge build
```

Testing the contract:

```bash
forge test
```

To provide additional test cases, please include those in the `/forge-test` directory.

To provide additional scripts, please include those in the `/forge-script` directory.

### Deployment Scripts

If you would like to test run the provided scripts locally, we recommend setting up Anvil that forks the Sepolia testnet (or any other network with the [P256Verifier library](https://p256.eth.limo/) deployed).

```bash
anvil --fork-url <SEPOLIA-RPC-URL>
```

We have included the `forge-script/setup.sh` script to help you quickly set up with the contracts deployment and configuration. Use this script, if you simply wish to see the full setup process or after you have modified the Solidity script to cater to your specific setup.

```bash
./forge-script/setup.sh
```

The setup consists of several tasks that can be broken down into the following steps:

- `SigVerifyLib` deployment

```bash
forge script DeployDCAPScript --sig "deploySigVerifyLib()" --broadcast --rpc-url $RPC_URL
```

- `PEMCertChainLib` deployment

```bash
forge script DeployDCAPScript --sig "deployPemCertLib()" --broadcast --rpc-url $RPC_URL
```

- `AutomataDcapV3Attestation` deployment

```bash
forge script DeployDCAPScript --sig "deployAttestation()" --broadcast --rpc-url $RPC_URL
```

- TCBInfo Configuration

If you do not provide a path to your TCBInfo JSON, you must pass an empty `""`, the [default](./forge-script/ConfigureDCAPScript.s.sol) TCBInfo JSON will then be passed as the argument. 

```bash
forge script ConfigureDcapAttestationScript --sig "configureTcb(string)" "<path-to-TCBInfoJSON>" --broadcast --rpc-url $RPC_URL
```

- QEIdentity Configuration

If you do not provide a path to your QEIdentity JSON, you must pass an empty `""`, the [default](./forge-script/ConfigureDCAPScript.s.sol) QEIdentity JSON will then be passed as the argument. 

```bash
forge script ConfigureDcapAttestationScript --sig "configureQeIdentity(string)" "<path-to-TCBInfoJSON>" --broadcast --rpc-url $RPC_URL
```

- CRL Configuration

CRLs are configured [here](./forge-script/utils/CRLParser.s.sol) by assigning it's DER encoded form.

Index numbers grouping for CRLs:

- 0: A list of revoked PCK serial numbers extracted from PCK Platform CA or PCK Processor CA CRLs
- 1: A list of revoked intermediate certificate serial numbers from the Root CA CRL

```bash
forge script ConfigureDcapAttestationScript --sig "configureCrl(uint256)" <index> --broadcast --rpc-url $RPC_URL
```

---

## Building With Hardhat

Compile the contract:

```bash
npx hardhat compile
```

Local deployment and testing:

```bash
npx hardhat run scripts/deploy.ts
```

To deploy the contract on a live network, please configure `hardhat.config.ts`, then pass the `--network` flag to the command.

To provide additional test cases, please include those in the `/test` directory.

To provide additional scripts, please include those in the `/scripts` directory.