use crate::utils::*;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct ExtractCerts {
    quote: String,
}

impl ExtractCerts {
    pub fn run(&self) -> Result<(), String> {
        let quote_bytes = read_file_or_hex(&self.quote)?;
        let quote = dcap_quote::parse_quote(&quote_bytes).unwrap();
        for (idx, cert) in quote.certs.iter().enumerate() {
            let issuer = if idx == quote.certs.len() - 1 {
                cert
            } else {
                &quote.certs[idx + 1]
            };

            let issue_pubkey_hash = keccak_hash::keccak(&issuer.pub_key);

            println!("{}", "=".repeat(80));
            if let Some(pck) = &cert.pck {
                println!("pck: \n{:?}\n", pck);
            }
            println!("serial_number: \n0x{}\n", hex::encode(&cert.serial_number));
            println!("tbs_certificate: \n0x{}\n", hex::encode(&cert.tbs_certificate));
            println!("signature: \n0x{}\n", hex::encode(&cert.signature));
            println!("issuer_pubkey_hash: \n{:?}\n", issue_pubkey_hash);
        }
        Ok(())
    }
}
