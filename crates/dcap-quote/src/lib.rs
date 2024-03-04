mod asn1;

use std::{borrow::Cow, io::Read};

use base64::prelude::*;
use asn1::{Asn1, NodePtr};
use ethereum_types::H256;

pub const MINIMUM_QUOTE_LENGTH: usize = 1020;
pub const SGX_TCB_CPUSVN_SIZE: usize = 16;

pub const SGX_EXTENSION_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01];
pub const TCB_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x02];
pub const PCESVN_OID: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x02, 0x11,
];
pub const PCEID_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x03];
pub const FMSPC_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x04];
lazy_static::lazy_static! {
    pub static ref ROOTCA_PUBKEY_HASH: H256 = "0x89f72d7c488e5b53a77c23ebcb36970ef7eb5bcf6658e9b8292cfbe4703a8473".parse().unwrap();
}

#[derive(Debug)]
pub enum Error {
    InvalidPckIssuerName,
    InvalidPckCommonName,
    InvalidLength,
    CertInvalidExtTag,
    InvalidCertType,
    InvalidCertTag,
    InvalidCertData,
    InvalidCertValidation,
    PckInvalidExtType,
    CertSgxExtFmspcNotFound,
    CertSgxExtPceidNotFound,
    CertSgxExtNotFound,
}

#[derive(Debug)]
pub struct SgxQuote {
    pub auth_type: ECDSAQuoteV3AuthData,
    pub certs: Vec<ECSha256Certificate>,
}

impl SgxQuote {
    pub fn verify_cert(&self, root_hash: H256) -> Result<bool, Error> {
        // ROOTCA_PUBKEY_HASH: 0x89f72d7c488e5b53a77c23ebcb36970ef7eb5bcf6658e9b8292cfbe4703a8473
        let mut root_verified = false;
        for (idx, cert) in self.certs.iter().enumerate() {
            let issuer = if idx == self.certs.len() - 1 {
                cert
            } else {
                &self.certs[idx + 1]
            };

            secp256r1_verify(&cert.tbs_certificate, &cert.signature, &issuer.pub_key)?;
            let issue_pubkey_hash = keccak_hash::keccak(&issuer.pub_key);
            if issue_pubkey_hash == root_hash {
                root_verified = true;
                break;
            }
        }

        let pck_cert_pubkey = &self.certs[0].pub_key;
        secp256r1_verify(
            &self.auth_type.raw_qe_report,
            &self.auth_type.qe_report_signature,
            &pck_cert_pubkey,
        )?;
        Ok(root_verified)
    }
}

#[derive(Debug, Default)]
pub struct ECSha256Certificate {
    pub not_before: usize,
    pub not_after: usize,
    pub serial_number: Vec<u8>,
    pub tbs_certificate: Vec<u8>,
    pub pub_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub pck: Option<PCKCertificateField>,
}

#[derive(Debug, Default)]
pub struct PCKCertificateField {
    pub common_name: String,
    pub issuer_name: String,
    pub sgx_extension: PckTcbInfo,
}

#[derive(Debug)]
pub struct ECDSAQuoteV3AuthData {
    pub ecdsa256_bit_signature: [u8; 64],
    pub ecdsa_attestation_key: [u8; 64],
    pub raw_qe_report: [u8; 384],
    pub qe_report_signature: [u8; 64],
    pub qe_auth_data: QEAuthData,
    pub certification: CertificationData,
}

trait ReadOn: Read {
    fn read_on<T: AsMut<[u8]>>(&mut self, mut val: T) -> T {
        self.read_exact(val.as_mut()).unwrap();
        val
    }
}

#[derive(Debug, Default)]
pub struct TcbInfo {
    pub pcesvn: u32,
    pub cpusvns: Vec<u16>,
}

impl<T: Read> ReadOn for T {}

impl ECDSAQuoteV3AuthData {
    pub fn parse(mut raw: &[u8]) -> Result<Self, Error> {
        let buf = &mut raw;

        let ecdsa256_bit_signature = buf.read_on([0_u8; 64]);
        let ecdsa_attestation_key = buf.read_on([0_u8; 64]);
        let raw_qe_report = buf.read_on([0_u8; 384]);
        let qe_report_signature = buf.read_on([0_u8; 64]);

        let qe_auth_data = {
            let parsed_data_size = u16::from_le_bytes(buf.read_on([0_u8; 2]));
            let data = buf.read_on(vec![0_u8; parsed_data_size as usize]);
            QEAuthData {
                parsed_data_size,
                data,
            }
        };

        let certification = {
            let cert_type = u16::from_le_bytes(buf.read_on([0_u8; 2]));
            if cert_type < 1 || cert_type > 5 {
                return Err(Error::InvalidCertType);
            }
            let cert_data_size = u32::from_le_bytes(buf.read_on([0_u8; 4]));
            let cert_data = buf.read_on(vec![0_u8; cert_data_size as usize]);
            let cert_data = String::from_utf8(cert_data).map_err(|_| Error::InvalidCertData)?;
            CertificationData {
                cert_type,
                cert_data_size,
                cert_data,
            }
        };

        Ok(ECDSAQuoteV3AuthData {
            ecdsa256_bit_signature,
            ecdsa_attestation_key,
            raw_qe_report,
            qe_report_signature,
            qe_auth_data,
            certification,
        })
    }
}

#[derive(Debug, Default)]
pub struct CertificationData {
    pub cert_type: u16,
    pub cert_data_size: u32,
    pub cert_data: String,
}

#[derive(Debug, Default)]
pub struct PckTcbInfo {
    pub pcesvn: u32,
    pub cpusvns: Vec<u16>,
    pub fmspc_bytes: Vec<u8>,
    pub pceid_bytes: Vec<u8>,
}

impl CertificationData {
    pub fn split_certs(&self) -> Result<Vec<ECSha256Certificate>, Error> {
        const HEADER: &str = "-----BEGIN CERTIFICATE-----\n";
        const FOOTER: &str = "\n-----END CERTIFICATE-----\n";
        let raw_certs = self.cert_data.trim_end_matches("\0").split(HEADER);
        let mut cert_idx = 0;
        let mut certs = Vec::new();
        for raw_cert in raw_certs {
            if raw_cert == "" {
                continue;
            }
            let data: Vec<_> = raw_cert.trim_end_matches(FOOTER).split("\n").collect();
            let data = data.join("");
            let data = BASE64_STANDARD.decode(data).unwrap();
            let is_pck_cert = cert_idx == 0;
            cert_idx += 1;
            let cert = self.decode_cert(&data, is_pck_cert)?;
            certs.push(cert);
        }
        Ok(certs)
    }

    fn decode_cert(&self, msg: &[u8], is_pck_cert: bool) -> Result<ECSha256Certificate, Error> {
        let mut cert = ECSha256Certificate::default();
        let mut pck = PCKCertificateField::default();

        let der = Asn1::new(msg);
        let root = der.root();
        let tbs_parent_ptr = der.first_child_of(&root);

        // Begin iterating through the descendants of tbsCertificate
        let tbs_ptr = der.first_child_of(&tbs_parent_ptr);

        let tbs_ptr = der.next_sibling_of(&tbs_ptr);
        cert.serial_number = der.bytes_at(&tbs_ptr).into();

        let tbs_ptr = der.next_sibling_of(&tbs_ptr);
        let tbs_ptr = der.next_sibling_of(&tbs_ptr);

        if is_pck_cert {
            let mut issuer_ptr = der.first_child_of(&tbs_ptr);
            issuer_ptr = der.first_child_of(&issuer_ptr);
            issuer_ptr = der.first_child_of(&issuer_ptr);
            issuer_ptr = der.next_sibling_of(&issuer_ptr);
            let pck_issuer_name = der.bytes_at(&issuer_ptr);
            pck.issuer_name = String::from_utf8(pck_issuer_name.into())
                .map_err(|_| Error::InvalidPckIssuerName)?;
            // bool issuerNameIsValid = LibString.eq(cert.pck.issuerName, PLATFORM_ISSUER_NAME)
            //     || LibString.eq(cert.pck.issuerName, PROCESSOR_ISSUER_NAME);
            // if !issuerNameIsValid {
            //     return (false, cert);
            // }
        }

        let tbs_ptr = der.next_sibling_of(&tbs_ptr);

        {
            let not_before_ptr = der.first_child_of(&tbs_ptr);
            let not_after_ptr = der.next_sibling_of(&not_before_ptr);
            let not_before_tag = der.byte_at(&not_before_ptr);
            let not_after_tag = der.byte_at(&not_after_ptr);
            if (not_before_tag != 0x17 && not_before_tag == 0x8)
                || (not_after_tag != 0x17 && not_after_tag != 0x18)
            {
                return Err(Error::InvalidCertTag);
            }
            // let not_before = X509DateUtils.toTimestamp(der.bytes_at(&not_before_ptr));
            // let not_after = X509DateUtils.toTimestamp(der.bytes_at(&not_after_ptr));
        }

        let tbs_ptr = der.next_sibling_of(&tbs_ptr);

        if is_pck_cert {
            let mut subject_ptr = der.first_child_of(&tbs_ptr);
            subject_ptr = der.first_child_of(&subject_ptr);
            subject_ptr = der.first_child_of(&subject_ptr);
            subject_ptr = der.next_sibling_of(&subject_ptr);
            let common_name = der.bytes_at(&subject_ptr);

            pck.common_name =
                String::from_utf8(common_name.into()).map_err(|_| Error::InvalidPckIssuerName)?;
        }

        let tbs_ptr = der.next_sibling_of(&tbs_ptr);

        {
            // Entering subjectPublicKeyInfo sequence
            let subject_public_key_info_ptr = der.first_child_of(&tbs_ptr);
            let subject_public_key_info_ptr = der.next_sibling_of(&subject_public_key_info_ptr);

            // The Signature sequence is located two sibling elements below the tbsCertificate element
            let mut sig_ptr = der.next_sibling_of(&tbs_parent_ptr);
            sig_ptr = der.next_sibling_of(&sig_ptr);

            // Skip three bytes to the right, TODO: why is it tagged with 0x03?
            // the three bytes in question: 0x034700 or 0x034800 or 0x034900
            sig_ptr = sig_ptr.forward(3);

            sig_ptr = der.first_child_of(&sig_ptr);
            let sig_x = der.bytes_at_limit(&sig_ptr, 32);

            sig_ptr = der.next_sibling_of(&sig_ptr);
            let sig_y = der.bytes_at_limit(&sig_ptr, 32);

            cert.tbs_certificate = der.all_bytes_at(&tbs_parent_ptr).into();
            cert.pub_key = der.bytes_at_limit(&subject_public_key_info_ptr, 64).into();
            cert.signature = [sig_x, sig_y].concat().into();
        }

        if is_pck_cert {
            // entering Extension sequence
            let mut tbs_ptr = der.next_sibling_of(&tbs_ptr);

            // check for the extension tag
            if der.byte_at(&tbs_ptr) != 0xA3 {
                return Err(Error::CertInvalidExtTag);
            }

            tbs_ptr = der.first_child_of(&tbs_ptr);
            tbs_ptr = der.first_child_of(&tbs_ptr);

            pck.sgx_extension = self.find_pck_tcb_info(&der, &tbs_ptr, &tbs_parent_ptr)?;
            cert.pck = Some(pck);
            // cert.pck.sgxExtension.pceid = LibString.toHexStringNoPrefix(pceid_bytes);
            // cert.pck.sgxExtension.fmspc = LibString.toHexStringNoPrefix(fmspc_bytes);
        }
        Ok(cert)
    }

    fn find_tcb<'a>(&self, der: &Asn1<'a>, oid_ptr: &NodePtr) -> TcbInfo {
        // sibiling of tcbOid
        let tcb_ptr = der.next_sibling_of(&oid_ptr);
        // get the first svn object in the sequence
        let mut svn_parent_ptr = der.first_child_of(&tcb_ptr);
        let mut tcb_info = TcbInfo::default();
        tcb_info.cpusvns = Vec::with_capacity(SGX_TCB_CPUSVN_SIZE);
        for _ in 0..SGX_TCB_CPUSVN_SIZE {
            let svn_ptr = der.first_child_of(&svn_parent_ptr); // OID
            let svn_value_ptr = der.next_sibling_of(&svn_ptr); // value
            let svn_value_bytes = der.bytes_at(&svn_value_ptr);
            let svn_value = if svn_value_bytes.len() < 2 {
                svn_value_bytes[0] as u16
            } else {
                let mut tmp2b = [0_u8; 2];
                tmp2b.copy_from_slice(svn_value_bytes);
                u16::from_be_bytes(tmp2b)
            };
            if der.bytes_at(&svn_ptr) == PCESVN_OID {
                // pcesvn is 4 bytes in size
                tcb_info.pcesvn = svn_value as u32;
            } else {
                // each cpusvn is at maximum two bytes in size
                tcb_info.cpusvns.push(svn_value);
            }

            // iterate to the next svn object in the sequence
            svn_parent_ptr = der.next_sibling_of(&svn_parent_ptr);
        }
        tcb_info
    }

    fn find_pck_tcb_info<'a>(
        &self,
        der: &Asn1<'a>,
        tbs_ptr: &NodePtr,
        tbs_parent_ptr: &NodePtr,
    ) -> Result<PckTcbInfo, Error> {
        // iterate through the elements in the Extension sequence
        // until we locate the SGX Extension OID

        let mut tbs_ptr = Cow::Borrowed(tbs_ptr);
        let mut info = PckTcbInfo::default();
        loop {
            let mut internal_ptr = der.first_child_of(&tbs_ptr);
            if der.byte_at(&internal_ptr) != 0x06 {
                return Err(Error::PckInvalidExtType);
            }

            if der.bytes_at(&internal_ptr) == SGX_EXTENSION_OID {
                // 1.2.840.113741.1.13.1
                internal_ptr = der.next_sibling_of(&internal_ptr);
                let extn_value_parent_ptr = der.root_of_octet_string_at(&internal_ptr);
                let mut extn_value_ptr = der.first_child_of(&extn_value_parent_ptr);

                let mut fmspc_found = false;
                let mut pceid_found = false;
                let mut tcb_found = false;

                while !(fmspc_found && pceid_found && tcb_found) {
                    let extn_value_oid_ptr = der.first_child_of(&extn_value_ptr);
                    if der.byte_at(&extn_value_oid_ptr) != 0x06 {
                        return Err(Error::PckInvalidExtType);
                    }
                    if der.bytes_at(&extn_value_oid_ptr) == TCB_OID {
                        // 1.2.840.113741.1.13.1.2
                        tcb_found = true;
                        let tcb_info = self.find_tcb(der, &extn_value_oid_ptr);
                        info.cpusvns = tcb_info.cpusvns;
                        info.pcesvn = tcb_info.pcesvn;
                    }
                    if der.bytes_at(&extn_value_oid_ptr) == PCEID_OID {
                        // 1.2.840.113741.1.13.1.3
                        let pceid_ptr = der.next_sibling_of(&extn_value_oid_ptr);
                        info.pceid_bytes = der.bytes_at(&pceid_ptr).into();
                        pceid_found = true;
                    }
                    if der.bytes_at(&extn_value_oid_ptr) == FMSPC_OID {
                        // 1.2.840.113741.1.13.1.4
                        let fmspc_ptr = der.next_sibling_of(&extn_value_oid_ptr);
                        info.fmspc_bytes = der.bytes_at(&fmspc_ptr).into();
                        fmspc_found = true;
                    }

                    if extn_value_ptr.ixl < extn_value_parent_ptr.ixl {
                        extn_value_ptr = der.next_sibling_of(&extn_value_ptr);
                    } else {
                        break;
                    }
                }
                if !fmspc_found {
                    return Err(Error::CertSgxExtFmspcNotFound);
                }
                if !pceid_found {
                    return Err(Error::CertSgxExtPceidNotFound);
                }
                if !tcb_found {
                    return Err(Error::CertSgxExtNotFound);
                }
                break;
            }

            if tbs_ptr.ixl < tbs_parent_ptr.ixl {
                tbs_ptr = Cow::Owned(der.next_sibling_of(&tbs_ptr));
            } else {
                break;
            }
        }
        Ok(info)
    }
}

#[derive(Debug, Default)]
pub struct QEAuthData {
    pub parsed_data_size: u16,
    pub data: Vec<u8>,
}

pub fn secp256r1_verify(msg: &[u8], sig: &[u8], pubkey: &[u8]) -> Result<(), Error> {
    use ring::signature::{VerificationAlgorithm, ECDSA_P256_SHA256_FIXED};
    let mut uncompress_key = vec![4];
    uncompress_key.extend(pubkey);
    ECDSA_P256_SHA256_FIXED
        .verify(uncompress_key.as_slice().into(), msg.into(), sig.into())
        .map_err(|_| Error::InvalidCertValidation)
}

pub fn parse_quote(quote: &[u8]) -> Result<SgxQuote, Error> {
    if quote.len() < MINIMUM_QUOTE_LENGTH {
        return Err(Error::InvalidLength);
    }
    let mut tmp4b = [0_u8; 4];
    tmp4b.copy_from_slice(&quote[432..436]);
    let local_auth_data_size = u32::from_le_bytes(tmp4b) as usize;
    if quote.len() - 436 != local_auth_data_size {
        return Err(Error::InvalidLength);
    }

    let auth_type = ECDSAQuoteV3AuthData::parse(&quote[436..436 + local_auth_data_size])?;
    let certs = auth_type.certification.split_certs()?;
    let quote = SgxQuote { auth_type, certs };
    quote.verify_cert(Default::default())?;

    Ok(quote)
}
