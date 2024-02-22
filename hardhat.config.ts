import * as dotenv from 'dotenv';
import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-foundry";

dotenv.config();

const { FORK_URL, PRIVATE_KEY } = process.env;

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.21",
    settings: {
      optimizer: {
        enabled: true,
        runs: Math.pow(2, 32) - 1
      },
      viaIR: true
    }
  },
  networks: {
    hardhat: {
      forking: {
        // provide a network url where the P256Verifier library exists
        // ref: https://github.com/daimo-eth/p256-verifier
        url: FORK_URL!,
        blockNumber: 3881764 // pinned Feb 22nd, 2024, 1339h UTC+8
      },
      accounts: [{
        privateKey: PRIVATE_KEY!,
        balance: "10000000000000000000000" // 10000 ETH
      }]
    }
  }
};

export default config;
