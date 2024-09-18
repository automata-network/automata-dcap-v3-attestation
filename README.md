<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# AutomataDcapV3Attestation
[![Automata DCAP V3](https://img.shields.io/badge/Power%20By-Automata-orange.svg)](https://github.com/automata-network)

## Archived Notification

We released the [Automata DCAP Attestation](https://github.com/automata-network/automata-dcap-attestation) to support Intel SGX/TDX DCAP attestation together with the [Automata On Chain PCCS](https://github.com/automata-network/automata-on-chain-pccs), please check the latest repositories to start your DCAP journey.

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

- `AutomataDcapV3Attestation` deployment

```bash
forge script DeployDCAPScript --broadcast --rpc-url $RPC_URL
```

---

<!-- ## Building With Hardhat

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

To provide additional scripts, please include those in the `/scripts` directory. -->


## Projects using AutomataDcapV3Attestation

* [Flashbots](https://writings.flashbots.net/suave-tee-coprocessor)
* [Taiko](
https://github.com/taikoxyz/taiko-mono/tree/main/packages/protocol/contracts/automata-attestation)
