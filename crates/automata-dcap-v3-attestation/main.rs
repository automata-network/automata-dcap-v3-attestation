mod extract_certs;
mod generate_verifier;
mod utils;
mod verify_quote_certs;

use extract_certs::ExtractCerts;
use generate_verifier::GenerateVerifier;
use structopt::StructOpt;
use verify_quote_certs::VerifyQuoteCerts;

#[derive(Debug, StructOpt)]
pub enum AutomataDcapV3Attestation {
    ExtractCerts(ExtractCerts),
    GenerateVerifier(GenerateVerifier),
    VerifyQuoteCerts(VerifyQuoteCerts),
}

fn main() {
    match AutomataDcapV3Attestation::from_args() {
        AutomataDcapV3Attestation::ExtractCerts(args) => args.run(),
        AutomataDcapV3Attestation::GenerateVerifier(args) => args.run(),
        AutomataDcapV3Attestation::VerifyQuoteCerts(args) => args.run(),
    }
    .unwrap();
}
