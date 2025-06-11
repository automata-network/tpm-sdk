// Reference manual: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
use crate::constants::{TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE};

const CLOCK_LEN: usize = 17;

pub trait FromBytes {
    fn from_bytes(raw: &[u8]) -> Self;
}

#[derive(Debug)]
pub struct TPMTSignature {
    pub sig_alg: SigAlg,
    pub hash_alg: HashAlg,
    pub signature: TPMSSignature,
}

#[derive(Debug)]
pub enum TPMSSignature {
    TPMSEcdsaSignature(Vec<u8>),
    TPMSRsaSignature(Vec<u8>),
}

#[derive(Debug)]
pub enum SigAlg {
    RSA,
    ECDSA,
}

impl SigAlg {
    pub fn from_u16(sig_alg: u16) -> Self {
        match sig_alg {
            0x0014 => SigAlg::RSA,
            0x0018 => SigAlg::ECDSA,
            _ => panic!("Unsupported signature algorithm"),
        }
    }
}

#[derive(Debug)]
pub enum HashAlg {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}

impl HashAlg {
    pub fn from_u16(hash_alg: u16) -> Self {
        match hash_alg {
            0x0004 => HashAlg::SHA1,
            0x000B => HashAlg::SHA256,
            0x000C => HashAlg::SHA384,
            0x000D => HashAlg::SHA512,
            _ => panic!("Unsupported hash algorithm"),
        }
    }
}

impl FromBytes for TPMTSignature {
    fn from_bytes(raw_sig: &[u8]) -> Self {
        let sig_alg = u16::from_be_bytes([raw_sig[0], raw_sig[1]]);
        let hash_alg = u16::from_be_bytes([raw_sig[2], raw_sig[3]]);
        let sig_size = u16::from_be_bytes([raw_sig[4], raw_sig[5]]) as usize;

        let signature = match sig_alg {
            // RSA
            0x0014 => {
                let mut ret: Vec<u8> = Vec::with_capacity(sig_size);
                ret.extend_from_slice(&raw_sig[6..6 + sig_size]);
                TPMSSignature::TPMSRsaSignature(ret)
            }
            // ECDSA
            0x0018 => {
                let mut ret: Vec<u8> = Vec::with_capacity(sig_size * 2);
                let r_size = sig_size;
                ret.extend_from_slice(&raw_sig[6..6 + r_size]);
                let offset = 6 + sig_size;
                let s_size = u16::from_be_bytes([raw_sig[offset], raw_sig[offset + 1]]) as usize;
                ret.extend_from_slice(&raw_sig[offset + 2..offset + 2 + s_size]);
                TPMSSignature::TPMSEcdsaSignature(ret)
            }
            _ => panic!("Unsupported signature algorithm"),
        };

        TPMTSignature {
            sig_alg: SigAlg::from_u16(sig_alg),
            hash_alg: HashAlg::from_u16(hash_alg),
            signature,
        }
    }
}

// Table 122
#[derive(Debug)]
pub struct TPMSAttest {
    pub magic: u32,
    pub att_type: u16,
    pub qualified_signer: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub tpms_clock_info: ClockInfo,
    pub firmware_version: u64,
    pub attested: TPMUAttest,
}
impl FromBytes for TPMSAttest {
    fn from_bytes(raw_attest: &[u8]) -> Self {
        let magic =
            u32::from_be_bytes([raw_attest[0], raw_attest[1], raw_attest[2], raw_attest[3]]);

        assert!(magic == TPM_GENERATED_VALUE, "Invalid magic value");

        let att_type = u16::from_be_bytes([raw_attest[4], raw_attest[5]]);

        let qualified_signer_len = u16::from_be_bytes([raw_attest[6], raw_attest[7]]) as usize;
        let mut offset = 8usize;
        let mut qualified_signer: Vec<u8> = Vec::with_capacity(qualified_signer_len);
        qualified_signer.extend_from_slice(&raw_attest[offset..offset + qualified_signer_len]);
        offset += qualified_signer_len;

        let extra_data_len =
            u16::from_be_bytes([raw_attest[offset], raw_attest[offset + 1]]) as usize;
        offset += 2;
        let mut extra_data: Vec<u8> = Vec::with_capacity(extra_data_len);
        extra_data.extend_from_slice(&raw_attest[offset..offset + extra_data_len]);
        offset += extra_data_len;

        let clock_info_slice = &raw_attest[offset..offset + CLOCK_LEN];
        let tpms_clock_info = ClockInfo::from_bytes(clock_info_slice);
        offset += CLOCK_LEN;

        let firmware_version = u64::from_be_bytes([
            raw_attest[offset],
            raw_attest[offset + 1],
            raw_attest[offset + 2],
            raw_attest[offset + 3],
            raw_attest[offset + 4],
            raw_attest[offset + 5],
            raw_attest[offset + 6],
            raw_attest[offset + 7],
        ]);
        offset += 8;

        let attested = match att_type {
            TPM_ST_ATTEST_QUOTE => {
                let tpms_quote_info = TPMSQuoteInfo::from_bytes(&raw_attest[offset..]);
                TPMUAttest::Quote(tpms_quote_info)
            }
            _ => panic!("Unsupported attested type"),
        };

        TPMSAttest {
            magic,
            att_type,
            qualified_signer,
            extra_data,
            tpms_clock_info,
            firmware_version,
            attested,
        }
    }
}

// 10.11.1
#[derive(Debug)]
pub struct ClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
}
impl FromBytes for ClockInfo {
    fn from_bytes(raw_clock_info: &[u8]) -> Self {
        assert!(
            raw_clock_info.len() == CLOCK_LEN,
            "Incorrect TPMS_CLOCK_INFO length"
        );
        let clock = u64::from_be_bytes([
            raw_clock_info[0],
            raw_clock_info[1],
            raw_clock_info[2],
            raw_clock_info[3],
            raw_clock_info[4],
            raw_clock_info[5],
            raw_clock_info[6],
            raw_clock_info[7],
        ]);
        let reset_count = u32::from_be_bytes([
            raw_clock_info[8],
            raw_clock_info[9],
            raw_clock_info[10],
            raw_clock_info[11],
        ]);
        let restart_count = u32::from_be_bytes([
            raw_clock_info[12],
            raw_clock_info[13],
            raw_clock_info[14],
            raw_clock_info[15],
        ]);
        let safe = match raw_clock_info[16] {
            0 => false,
            1 => true,
            _ => panic!("Invalid bool value"),
        };

        ClockInfo {
            clock,
            reset_count,
            restart_count,
            safe,
        }
    }
}

// 10.12.7
#[derive(Debug)]
pub enum TPMUAttest {
    Quote(TPMSQuoteInfo),
}

// 10.12.1
#[derive(Debug)]
pub struct TPMSQuoteInfo {
    // TPML_PCR_SELECTION is defined here rather than its own struct
    pub count: u32,
    pub pcr_selections: Vec<TPMSPCRSelection>,
    pub pcr_digest: Vec<u8>,
}
impl FromBytes for TPMSQuoteInfo {
    fn from_bytes(raw_tpms_quote_info: &[u8]) -> Self {
        let count = u32::from_be_bytes([
            raw_tpms_quote_info[0],
            raw_tpms_quote_info[1],
            raw_tpms_quote_info[2],
            raw_tpms_quote_info[3],
        ]);

        // TODO: support multiple PCRSelections
        assert!(
            count == 1,
            "Currently does not support more than one PCRSelections"
        );
        let mut pcr_selections: Vec<TPMSPCRSelection> = Vec::with_capacity(count as usize);
        let pcr_selection = TPMSPCRSelection::from_bytes(&raw_tpms_quote_info[4..]);
        let offset = 4usize + pcr_selection.size();
        pcr_selections.push(pcr_selection);

        let pcr_digest_slice = &raw_tpms_quote_info[offset..];
        let pcr_digest_size =
            u16::from_be_bytes([pcr_digest_slice[0], pcr_digest_slice[1]]) as usize;
        let mut pcr_digest: Vec<u8> = Vec::with_capacity(pcr_digest_size as usize);
        pcr_digest.extend_from_slice(&pcr_digest_slice[2..2 + pcr_digest_size]);

        TPMSQuoteInfo {
            count,
            pcr_selections,
            pcr_digest,
        }
    }
}

// 10.6.2
#[derive(Debug)]
pub struct TPMSPCRSelection {
    pub hash: u16,
    pub size_of_select: u8,
    pub pcr_select: Vec<u8>,
}
impl FromBytes for TPMSPCRSelection {
    fn from_bytes(raw_tpms_pcr_selection: &[u8]) -> Self {
        let hash = u16::from_be_bytes([raw_tpms_pcr_selection[0], raw_tpms_pcr_selection[1]]);

        let size_of_select = raw_tpms_pcr_selection[2];

        let mut pcr_select: Vec<u8> = Vec::with_capacity(size_of_select as usize);
        pcr_select.extend_from_slice(&raw_tpms_pcr_selection[3..3 + size_of_select as usize]);

        TPMSPCRSelection {
            hash,
            size_of_select,
            pcr_select,
        }
    }
}
impl TPMSPCRSelection {
    pub fn size(&self) -> usize {
        (3 + self.size_of_select) as usize
    }

    pub fn parse_pcr_selection(&self) -> Vec<usize> {
        let mut registers = Vec::new();
        for (i, &byte) in self.pcr_select.iter().enumerate() {
            for bit in 0..8 {
                if (byte & (1 << bit)) != 0 {
                    registers.push(i * 8 + bit);
                }
            }
        }
        registers
    }

    // TODO: Figure out exactly how does TPM2 encode multiple PCRSelections
    // pub fn get_pcr_selections_arr(raw_tpms_pcr_selection_arr: &[u8]) -> Vec<Self> {
    //     let mut offset = 0usize;
    //     let mut ret: Vec<Self> = vec![];
    //     while offset < raw_tpms_pcr_selection_arr.len() {
    //         let current_selection = TPMSPCRSelection::from_bytes(&raw_tpms_pcr_selection_arr[offset..]);
    //         offset += current_selection.size();
    //         ret.push(current_selection);
    //     }
    //     ret
    // }

    // pub fn get_pcr_selection_arr_bytes_len(tpms_pcr_selections_arr: &[Self]) -> usize {
    //     let mut size = 0usize;
    //     for selection in tpms_pcr_selections_arr.iter() {
    //         size += selection.size()
    //     }
    //     size
    // }
}

#[test]
fn test_parse_quote() {
    let raw = [
        255, 84, 67, 71, 128, 24, 0, 34, 0, 11, 43, 88, 231, 245, 1, 155, 168, 94, 10, 11, 88, 59,
        85, 78, 65, 36, 204, 208, 86, 215, 35, 98, 220, 62, 180, 120, 103, 28, 101, 190, 204, 210,
        0, 0, 0, 0, 0, 0, 51, 198, 131, 133, 0, 0, 0, 45, 0, 0, 0, 0, 1, 32, 32, 3, 18, 0, 18, 0,
        3, 0, 0, 0, 1, 0, 11, 3, 32, 8, 128, 0, 32, 167, 217, 4, 32, 127, 222, 144, 149, 185, 112,
        226, 210, 86, 12, 20, 144, 210, 235, 213, 6, 135, 204, 241, 12, 185, 175, 101, 156, 120,
        199, 222, 225,
    ];
    let _tpm_quote = TPMSAttest::from_bytes(&raw);
    assert!(true);
}

#[test]
fn test_convert_tpmt_to_rsa_signature() {
    let raw = [
        0, 20, 0, 11, 1, 0, 75, 88, 29, 168, 197, 79, 192, 33, 72, 43, 104, 79, 127, 27, 75, 92,
        169, 142, 219, 11, 207, 178, 245, 127, 81, 67, 53, 242, 235, 56, 242, 164, 104, 94, 79,
        169, 39, 203, 156, 145, 132, 7, 43, 210, 148, 55, 132, 242, 154, 173, 47, 198, 201, 159,
        129, 115, 186, 183, 45, 53, 251, 225, 15, 87, 216, 102, 242, 66, 142, 229, 104, 14, 204,
        88, 72, 254, 22, 88, 203, 133, 255, 74, 207, 73, 136, 174, 8, 188, 153, 91, 138, 9, 1, 74,
        188, 112, 222, 162, 55, 75, 139, 162, 190, 153, 218, 193, 118, 71, 108, 190, 16, 245, 50,
        105, 174, 75, 118, 18, 181, 182, 4, 56, 171, 226, 194, 5, 176, 58, 91, 252, 12, 185, 197,
        35, 206, 198, 64, 69, 99, 85, 93, 57, 234, 18, 219, 211, 165, 139, 25, 66, 84, 120, 235,
        151, 189, 175, 127, 16, 243, 113, 253, 252, 19, 125, 96, 198, 72, 103, 92, 199, 8, 54, 39,
        27, 214, 82, 29, 116, 250, 151, 62, 60, 168, 56, 200, 182, 20, 216, 177, 188, 95, 185, 251,
        54, 192, 212, 7, 29, 57, 127, 253, 120, 32, 162, 137, 239, 85, 103, 120, 18, 30, 192, 237,
        0, 165, 145, 36, 49, 234, 134, 117, 115, 127, 206, 54, 99, 246, 59, 177, 245, 243, 105,
        115, 251, 208, 119, 74, 102, 3, 252, 77, 117, 191, 83, 31, 55, 239, 145, 27, 172, 117, 19,
        205, 255, 89, 33,
    ];
    let _sig = TPMTSignature::from_bytes(&raw);
    assert!(true);
}

#[test]
fn test_convert_tpmt_to_ecdsa_signature() {
    let raw = [
        0, 24, 0, 11, 0, 32, 94, 51, 186, 186, 233, 90, 63, 0, 23, 78, 158, 118, 71, 102, 46, 85,
        55, 228, 186, 219, 8, 209, 51, 97, 92, 212, 132, 36, 217, 10, 237, 224, 0, 32, 81, 87, 173,
        156, 216, 166, 135, 61, 192, 136, 168, 25, 216, 206, 89, 207, 58, 13, 218, 252, 248, 75,
        12, 204, 106, 96, 232, 157, 113, 215, 162, 59,
    ];
    let _sig = TPMTSignature::from_bytes(&raw);
    assert!(true);
}
