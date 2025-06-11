use anyhow::Result;
use std::io::Read;
use ureq::get;
use x509_parser::oid_registry::asn1_rs::{FromDer, Oid, Sequence, oid};
use x509_parser::prelude::{Pem, X509Certificate};

fn fetch_certificate(url_str: &str) -> Result<Vec<u8>> {
    let rsp = get(url_str).call()?;
    let mut bytes: Vec<u8> = Vec::with_capacity(8192);
    rsp.into_reader().take(8192).read_to_end(&mut bytes)?;
    Ok(bytes)
}

// PEM chain to DER-encoded bytes conversion
// Provide PEM data directly to this function call
pub fn pem_to_der(pem_chain: &[u8]) -> Vec<Vec<u8>> {
    let mut der_chain: Vec<Vec<u8>> = Vec::new();

    for pem in Pem::iter_from_buffer(pem_chain) {
        let current_pem_content = pem.unwrap().contents;
        der_chain.push(current_pem_content);
    }

    der_chain
}

pub fn get_tpm_cert_der_chain(leaf_der: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut ret = vec![];

    let (_, leaf_cert) = X509Certificate::from_der(leaf_der)?;
    let mut issuer_data = parse_cert_and_get_issuer_data(&leaf_cert);
    while issuer_data.as_ref().is_some() {
        let issuer = issuer_data.unwrap();
        ret.push(issuer.clone());
        let (_, issuer_cert) = X509Certificate::from_der(&issuer).unwrap();
        issuer_data = parse_cert_and_get_issuer_data(&issuer_cert);
    }

    Ok(ret)
}

fn parse_cert_and_get_issuer_data(cert: &X509Certificate<'_>) -> Option<Vec<u8>> {
    let ext = cert.get_extension_unique(&oid!(1.3.6.1.5.5.7.1.1)).unwrap();
    match ext {
        Some(ext) => {
            let authority_info_access_bytes = ext.value;
            let (_, aia_sequence) = Sequence::from_der(authority_info_access_bytes).unwrap();
            let i = aia_sequence.content.as_ref();
            if i.len() > 0 {
                let (_, current_sequence) = Sequence::from_der(i).unwrap();
                let (j, current_oid) = Oid::from_der(current_sequence.content.as_ref()).unwrap();
                match current_oid.to_id_string().as_str() {
                    _CA_ISSUERS_OID => {
                        let url_utf8_vec = j.to_vec();
                        let url_str = std::str::from_utf8(&url_utf8_vec[2..]).unwrap();
                        let issuer = fetch_certificate(url_str).unwrap();
                        return Some(issuer);
                    }
                    // TODO: handle OCSP access method
                    // See Section 3.2.13 of https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_Credential_Profile_EK_V2.1_R13.pdf
                    _ => {
                        panic!("Unknown authority info access method");
                    }
                }
            } else {
                panic!("AIA extension empty");
            }
        }
        _ => {
            // Return self if root
            // empty otherwise
            None
        }
    }
}
