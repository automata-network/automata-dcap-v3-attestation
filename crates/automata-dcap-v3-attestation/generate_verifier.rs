use std::fs;

use halo2_secp256r1_circuit::{Secp256r1Verifier, SerdeFormat};
use structopt::StructOpt;

use crate::utils::debug;

#[derive(Debug, StructOpt)]
pub struct GenerateVerifier {
    out_path: String,
}

impl GenerateVerifier {
    pub fn run(&self) -> Result<(), String> {
        let k: u32 = halo2_secp256r1_circuit::K;
        let verifier = Secp256r1Verifier::<2>::new(k).unwrap();
        fs::write(&self.out_path, verifier.to_bytes(SerdeFormat::RawBytes)).map_err(debug)?;
        Ok(())
    }
}
