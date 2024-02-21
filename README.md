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
forge build
```

Testing the contract:

```bash
forge test
```

To provide additional test cases, please include those in the `/forge-test` directory.

To provide additional scripts, please include those in the `/forge-script` directory.

### Deployment Scripts

If you would like to test run the provided scripts locally, we recommend setting up Anvil that forks the Linea Gorli testnet (or any other network with the [P256Verifier library](https://p256.eth.limo/) deployed).

```bash
anvil --fork-url <LINEA-GORLI-RPC-URL>
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

- `AutomataDcapV3Attestation` deployment

```bash
forge script DeployDCAPScript --sig "deployAttestation()" --broadcast --rpc-url $RPC_URL
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