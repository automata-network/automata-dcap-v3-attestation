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

## Building With Hardhat

Compile the contract:

```bash
npx hardhat compile
```

Local deployment and testing:

```bash
npx hardhat run scripts/deploy.ts
```

To deploy the contract on a live network, please configure `hardhat.config.ts` and pass the `--network` flag to the command.

To provide additional test cases, please include those in the `/test` directory.

To provide additional scripts, please include those in the `/scripts` directory.