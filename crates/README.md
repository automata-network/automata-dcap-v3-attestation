# AutomataDcapV3Attestation Cli

Verify multiple certs in one circuit.

```
N: number of signatures to verify

N=1: evm_code_size: 14810, gas: 384620
N=2: evm_code_size: 21135, gas: 507341
N=3: evm_code_size: 28040, gas: 642653
N=4: evm_code_size: 33875, gas: 749759
N=5: evm_code_size: 41251, gas: 886244
N=6: evm_code_size: 48255, gas: 1004665
```

## Generate Verifier

```
> cargo run --release generate-verifier verifier.bin
```

## Verify Quote Certificates

1. Extract the certs in DCAP Quote
2. Generate the proof to verify

```
> cargo run --release verify-quote-certs --quote crates/dcap-quote/test_quote.hex --verifier verifier.bin
```

