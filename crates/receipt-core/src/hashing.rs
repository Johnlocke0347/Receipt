//! Commitment and identifier derivations (all SHA-256, domain separated).

use sha2::{Digest, Sha256};

use crate::receipt::WorkOutcome;

/// Domain tag for the confidential settlement commitment.
pub const CONFIDENTIAL_DOMAIN: &[u8] = b"RECEIPT_CONFIDENTIAL_V1";
/// Domain tag for the outcome-committed enclave output hash.
pub const ENCLAVE_OUTPUT_DOMAIN: &[u8] = b"RECEIPT_OUTCOME_OUTPUT_V1";
/// Domain tag for the evidence commitment.
pub const EVIDENCE_DOMAIN: &[u8] = b"RECEIPT_EVIDENCE_V1";
/// Domain tag for the receipt id.
pub const RECEIPT_ID_DOMAIN: &[u8] = b"RECEIPT_ID_V1";

/// SHA-256 over the concatenation of `parts`.
#[must_use]
pub fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `SHA256("RECEIPT_CONFIDENTIAL_V1" || intent_id || amount_le16 || currency_hash || buyer_salt)`.
///
/// `intent_id` is the 32-byte intent hash; `amount` is encoded as 16 little-endian bytes.
#[must_use]
pub fn confidential_settlement_commitment(
    intent_id: &[u8; 32],
    amount: u128,
    currency_hash: &[u8; 32],
    buyer_salt: &[u8; 32],
) -> [u8; 32] {
    sha256_concat(&[
        CONFIDENTIAL_DOMAIN,
        intent_id,
        &amount.to_le_bytes(),
        currency_hash,
        buyer_salt,
    ])
}

/// `SHA256("RECEIPT_OUTCOME_OUTPUT_V1" || [outcome as u8] || raw_enclave_output_hash)`.
#[must_use]
pub fn enclave_output_hash(outcome: WorkOutcome, raw_enclave_output_hash: &[u8; 32]) -> [u8; 32] {
    sha256_concat(&[
        ENCLAVE_OUTPUT_DOMAIN,
        &[outcome as u8],
        raw_enclave_output_hash,
    ])
}

/// `SHA256("RECEIPT_EVIDENCE_V1" || wasm_hash || input_hash || output_hash || settlement)`.
#[must_use]
pub fn evidence_commitment(
    wasm_hash: &[u8; 32],
    input_hash: &[u8; 32],
    output_hash: &[u8; 32],
    confidential_settlement_commitment: &[u8; 32],
) -> [u8; 32] {
    sha256_concat(&[
        EVIDENCE_DOMAIN,
        wasm_hash,
        input_hash,
        output_hash,
        confidential_settlement_commitment,
    ])
}

/// `SHA256("RECEIPT_ID_V1" || provider_id || nonce_le8 || evidence_commitment)`.
#[must_use]
pub fn receipt_id(provider_identity: &str, nonce: u64, evidence_commitment: &[u8; 32]) -> [u8; 32] {
    sha256_concat(&[
        RECEIPT_ID_DOMAIN,
        provider_identity.as_bytes(),
        &nonce.to_le_bytes(),
        evidence_commitment,
    ])
}

/// `SHA256(mrtd || rtmr0 || rtmr1 || rtmr2 || rtmr3)`.
#[must_use]
pub fn verifier_measurement(mrtd: &[u8; 48], rtmrs: &[[u8; 48]; 4]) -> [u8; 32] {
    sha256_concat(&[mrtd, &rtmrs[0], &rtmrs[1], &rtmrs[2], &rtmrs[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitments_are_domain_separated() {
        let z = [0u8; 32];
        assert_ne!(
            evidence_commitment(&z, &z, &z, &z),
            confidential_settlement_commitment(&z, 0, &z, &z)
        );
    }

    #[test]
    fn amount_changes_commitment() {
        let z = [1u8; 32];
        assert_ne!(
            confidential_settlement_commitment(&z, 1, &z, &z),
            confidential_settlement_commitment(&z, 2, &z, &z)
        );
    }

    #[test]
    fn outcome_changes_enclave_output_hash() {
        let raw = [0xaa; 32];
        assert_ne!(
            enclave_output_hash(WorkOutcome::Pass, &raw),
            enclave_output_hash(WorkOutcome::Fail, &raw)
        );
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            hex::encode(sha256_concat(&[b"a", b"bc"])),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
