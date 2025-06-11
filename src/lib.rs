pub mod certs;
pub mod constants;
pub mod tpm;

use anyhow::Result;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use rsa::{Pkcs1v15Sign, RsaPublicKey, pkcs1::DecodeRsaPublicKey};
use sha2::{Digest, Sha256};
use tpm::{FromBytes, HashAlg, TPMSAttest, TPMSSignature, TPMTSignature};

pub fn verify_tpm_quote_extra_data(tpm_quote: &[u8], ref_extra_data: &[u8]) -> Result<()> {
    let quote = TPMSAttest::from_bytes(tpm_quote);
    if quote.extra_data.as_slice() != ref_extra_data {
        return Err(anyhow::anyhow!(
            "TPM quote extra data does not match reference value!"
        ));
    }
    Ok(())
}

pub fn verify_tpm_quote_signature(
    tpm_quote: &[u8],
    tpm_raw_signature: &[u8],
    signer_key: &[u8],
) -> Result<()> {
    let tpmt_sig = TPMTSignature::from_bytes(tpm_raw_signature);
    match tpmt_sig.signature {
        TPMSSignature::TPMSEcdsaSignature(sig) => {
            match tpmt_sig.hash_alg {
                HashAlg::SHA256 => {
                    // For now, we only  assume support for P-256 curve.
                    let signature = Signature::from_bytes(sig.as_slice().try_into()?)?;
                    let verifying_key = VerifyingKey::from_sec1_bytes(signer_key)?;
                    verifying_key.verify(tpm_quote, &signature)?;
                    Ok(())
                }
                _ => {
                    panic!("Unsupported TPM hash algorithm")
                }
            }
        }
        TPMSSignature::TPMSRsaSignature(sig) => {
            let verifying_key = RsaPublicKey::from_pkcs1_der(signer_key)?;
            match tpmt_sig.hash_alg {
                HashAlg::SHA256 => {
                    let mut hasher = Sha256::new();
                    hasher.update(&tpm_quote);
                    let hashed_message = hasher.finalize();

                    verifying_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_message, &sig)?;
                    Ok(())
                }
                _ => {
                    panic!("Unsupported TPM hash algorithm")
                }
            }
        }
    }
}
