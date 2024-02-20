use dcap_quote::parse_quote;
use halo2_secp256r1_circuit::{Secp256r1Instance, Secp256r1Verifier, SerdeFormat};
use structopt::StructOpt;

use crate::utils::{debug, read_file, read_file_or_hex};

#[derive(StructOpt, Debug)]
pub struct VerifyQuoteCerts {
    #[structopt(long)]
    quote: String,
    #[structopt(long)]
    verifier: String,
}

impl VerifyQuoteCerts {
    pub fn run(&self) -> Result<(), String> {
        const N: usize = 2;
        let quote = read_file_or_hex(&self.quote)?;
        let verifier = read_file(&self.verifier)?;

        let verifier =
            <Secp256r1Verifier<N>>::from_bytes(&verifier, SerdeFormat::RawBytes).unwrap();
        let quote = parse_quote(&quote).map_err(debug)?;

        let mut instances = vec![];
        for (idx, cert) in quote.certs.iter().enumerate() {
            let issuer = if idx == quote.certs.len() - 1 {
                cert
            } else {
                &quote.certs[idx + 1]
            };

            instances.push(Secp256r1Instance {
                pubkey: &issuer.pub_key,
                sig: &cert.signature,
                msg: &cert.tbs_certificate,
            });
        }
        for chunk in instances.chunks(N) {
            if chunk.len() != N {
                break;
            }
            let instances = Secp256r1Instance::build_instances(&chunk);
            let proof = verifier.generate_proof(verifier.keygen_circuit.clone(), instances.clone());

            let result = verifier.evm_verify(instances, &proof);
            println!("proof: 0x{}", hex::encode(proof));
            println!("result: {:?}", result);
        }

        Ok(())
    }
}
