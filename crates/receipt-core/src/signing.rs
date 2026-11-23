//! Domain-separated Ed25519 co-signatures and replay-nonce validation.
//!
//! Digest = `SHA256(domain || len(chain_id)_le4 || chain_id || len(registry_id)_le4 ||
//! registry_id || borsh(ReceiptSigningPayloadV1))`.
//!
//! NOTE: PLAN.md specifies plain concatenation; we additionally length-prefix the two
//! variable-length strings so `(chain_id, registry_id)` boundaries are unambiguous. The NEAR
//! contract (Phase 2) must use this exact function.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::error::ReceiptError;
use crate::hashing;
use crate::receipt::{
    ConsequenceState, ReceiptSigningPayloadV1, ReceiptV1, WorkOutcome, SCHEMA_VERSION,
};

/// Buyer signature domain.
pub const BUYER_DOMAIN: &[u8] = b"NEAR_RECEIPT_BUYER_SIG_V1";
/// Provider signature domain.
pub const PROVIDER_DOMAIN: &[u8] = b"NEAR_RECEIPT_PROVIDER_SIG_V1";

/// Which party is signing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Party {
    /// The buyer.
    Buyer,
    /// The provider.
    Provider,
}

impl Party {
    fn domain(self) -> &'static [u8] {
        match self {
            Party::Buyer => BUYER_DOMAIN,
            Party::Provider => PROVIDER_DOMAIN,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Party::Buyer => "buyer",
            Party::Provider => "provider",
        }
    }
}

/// Compute the 32-byte message digest a party signs.
///
/// # Errors
/// Fails if the payload cannot be Borsh-serialized or an id exceeds `u32::MAX` bytes.
pub fn signing_digest(
    party: Party,
    chain_id: &str,
    registry_id: &str,
    payload: &ReceiptSigningPayloadV1,
) -> Result<[u8; 32], ReceiptError> {
    let body = borsh::to_vec(payload).map_err(|e| ReceiptError::Serialization(e.to_string()))?;
    let len = |s: &str| -> Result<[u8; 4], ReceiptError> {
        u32::try_from(s.len())
            .map(u32::to_le_bytes)
            .map_err(|_| ReceiptError::InvalidInput("identifier too long".into()))
    };
    Ok(hashing::sha256_concat(&[
        party.domain(),
        &len(chain_id)?,
        chain_id.as_bytes(),
        &len(registry_id)?,
        registry_id.as_bytes(),
        &body,
    ]))
}

/// Sign the receipt payload as `party`.
///
/// # Errors
/// Fails if the digest cannot be computed.
pub fn sign_payload(
    party: Party,
    key: &SigningKey,
    chain_id: &str,
    registry_id: &str,
    payload: &ReceiptSigningPayloadV1,
) -> Result<[u8; 64], ReceiptError> {
    let digest = signing_digest(party, chain_id, registry_id, payload)?;
    Ok(key.sign(&digest).to_bytes())
}

fn verify_party(
    party: Party,
    pubkey: &[u8; 32],
    signature: &[u8; 64],
    chain_id: &str,
    registry_id: &str,
    payload: &ReceiptSigningPayloadV1,
) -> Result<(), ReceiptError> {
    let vk =
        VerifyingKey::from_bytes(pubkey).map_err(|_| ReceiptError::BadPublicKey(party.label()))?;
    let digest = signing_digest(party, chain_id, registry_id, payload)?;
    vk.verify(&digest, &Signature::from_bytes(signature))
        .map_err(|_| ReceiptError::BadSignature(party.label()))
}

/// Verify both co-signatures on a receipt.
///
/// # Errors
/// [`ReceiptError::BadSignature`] / [`ReceiptError::BadPublicKey`] on failure.
pub fn verify_receipt_signatures(
    receipt: &ReceiptV1,
    chain_id: &str,
    registry_id: &str,
) -> Result<(), ReceiptError> {
    let payload = receipt.signing_payload();
    verify_party(
        Party::Buyer,
        &receipt.buyer_pubkey,
        &receipt.buyer_signature,
        chain_id,
        registry_id,
        &payload,
    )?;
    verify_party(
        Party::Provider,
        &receipt.provider_pubkey,
        &receipt.provider_signature,
        chain_id,
        registry_id,
        &payload,
    )
}

/// Tracks `(provider_pubkey, nonce)` pairs to reject replays.
#[derive(Default, Debug)]
pub struct NonceTracker {
    seen: HashSet<([u8; 32], u64)>,
}

impl NonceTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the nonce, failing if it was already used by this provider.
    ///
    /// # Errors
    /// [`ReceiptError::NonceReplay`] if already seen.
    pub fn check_and_record(
        &mut self,
        provider_pubkey: &[u8; 32],
        nonce: u64,
    ) -> Result<(), ReceiptError> {
        if self.seen.insert((*provider_pubkey, nonce)) {
            Ok(())
        } else {
            Err(ReceiptError::NonceReplay { nonce })
        }
    }
}

/// Full off-chain admission check mirrored by the NEAR contract: structure, expected WASM hash,
/// signatures, and nonce replay. Does not check TDX evidence (see [`crate::tdx`]).
///
/// # Errors
/// Returns the first violated invariant.
pub fn validate_receipt(
    receipt: &ReceiptV1,
    expected_wasm_hash: &[u8; 32],
    chain_id: &str,
    registry_id: &str,
    nonces: &mut NonceTracker,
) -> Result<(), ReceiptError> {
    receipt.validate_structure()?;
    if &receipt.wasm_hash != expected_wasm_hash {
        return Err(ReceiptError::WasmHashMismatch);
    }
    verify_receipt_signatures(receipt, chain_id, registry_id)?;
    nonces.check_and_record(&receipt.provider_pubkey, receipt.nonce)
}

/// Inputs for [`build_signed_receipt`].
#[derive(Clone, Debug)]
pub struct ReceiptParams {
    /// Provider identity string.
    pub provider_identity: String,
    /// Work category.
    pub work_category: String,
    /// Acceptance outcome.
    pub outcome: WorkOutcome,
    /// TDX measurement digest.
    pub verifier_measurement: [u8; 32],
    /// WASM hash.
    pub wasm_hash: [u8; 32],
    /// Input hash.
    pub input_hash: [u8; 32],
    /// Output hash.
    pub output_hash: [u8; 32],
    /// Settlement commitment.
    pub confidential_settlement_commitment: [u8; 32],
    /// Authorized borrower EVM address on the destination chain (`20` bytes).
    pub borrower_evm_address: [u8; 20],
    /// Maximum credit principal (in minimal credit token units) authorized by this receipt.
    pub max_credit_principal: u128,
    /// Attested net revenue from this settled work receipt (minimal credit token units, 6 decimals).
    pub attested_revenue: u128,
    /// Replay nonce.
    pub nonce: u64,
    /// Creation time (UNIX seconds).
    pub created_at: u64,
}

/// Derive ids, then produce a fully co-signed receipt.
///
/// # Errors
/// Fails if the digest cannot be computed.
pub fn build_signed_receipt(
    params: &ReceiptParams,
    buyer: &SigningKey,
    provider: &SigningKey,
    chain_id: &str,
    registry_id: &str,
) -> Result<ReceiptV1, ReceiptError> {
    let evidence = hashing::evidence_commitment(
        &params.wasm_hash,
        &params.input_hash,
        &params.output_hash,
        &params.confidential_settlement_commitment,
    );
    let mut receipt = ReceiptV1 {
        receipt_id: hashing::receipt_id(&params.provider_identity, params.nonce, &evidence),
        schema_version: SCHEMA_VERSION,
        provider_identity: params.provider_identity.clone(),
        work_category: params.work_category.clone(),
        outcome: params.outcome,
        verifier_measurement: params.verifier_measurement,
        wasm_hash: params.wasm_hash,
        input_hash: params.input_hash,
        output_hash: params.output_hash,
        evidence_commitment: evidence,
        buyer_pubkey: buyer.verifying_key().to_bytes(),
        provider_pubkey: provider.verifying_key().to_bytes(),
        buyer_signature: [0; 64],
        provider_signature: [0; 64],
        nonce: params.nonce,
        created_at: params.created_at,
        confidential_settlement_commitment: params.confidential_settlement_commitment,
        borrower_evm_address: params.borrower_evm_address,
        max_credit_principal: params.max_credit_principal,
        attested_revenue: params.attested_revenue,
        consequence_state: ConsequenceState::RegisteredVerified,
        foreign_chain_id: None,
        foreign_tx_hash: None,
        lender_id: None,
        verified_finality_evidence: None,
    };
    let payload = receipt.signing_payload();
    receipt.buyer_signature = sign_payload(Party::Buyer, buyer, chain_id, registry_id, &payload)?;
    receipt.provider_signature =
        sign_payload(Party::Provider, provider, chain_id, registry_id, &payload)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN: &str = "testnet";
    const REG: &str = "receipt-registry.testnet";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn params() -> ReceiptParams {
        ReceiptParams {
            provider_identity: "provider.testnet".into(),
            work_category: "rust_smart_contract_audit".into(),
            outcome: WorkOutcome::Pass,
            verifier_measurement: [7; 32],
            wasm_hash: [1; 32],
            input_hash: [2; 32],
            output_hash: [3; 32],
            confidential_settlement_commitment: [4; 32],
            borrower_evm_address: [0x22; 20],
            max_credit_principal: 250_000_000,
            attested_revenue: 250_000_000,
            nonce: 1,
            created_at: 1_700_000_000,
        }
    }

    fn signed() -> ReceiptV1 {
        build_signed_receipt(&params(), &key(1), &key(2), CHAIN, REG).unwrap()
    }

    #[test]
    fn valid_receipt_passes() {
        let r = signed();
        let mut n = NonceTracker::new();
        validate_receipt(&r, &[1; 32], CHAIN, REG, &mut n).unwrap();
    }

    #[test]
    fn replayed_nonce_rejected() {
        let r = signed();
        let mut n = NonceTracker::new();
        validate_receipt(&r, &[1; 32], CHAIN, REG, &mut n).unwrap();
        assert_eq!(
            validate_receipt(&r, &[1; 32], CHAIN, REG, &mut n),
            Err(ReceiptError::NonceReplay { nonce: 1 })
        );
    }

    #[test]
    fn fail_outcome_rejected() {
        let mut p = params();
        p.outcome = WorkOutcome::Fail;
        let r = build_signed_receipt(&p, &key(1), &key(2), CHAIN, REG).unwrap();
        let mut n = NonceTracker::new();
        assert_eq!(
            validate_receipt(&r, &[1; 32], CHAIN, REG, &mut n),
            Err(ReceiptError::OutcomeNotPass)
        );
    }

    #[test]
    fn wrong_wasm_hash_rejected() {
        let mut n = NonceTracker::new();
        assert_eq!(
            validate_receipt(&signed(), &[9; 32], CHAIN, REG, &mut n),
            Err(ReceiptError::WasmHashMismatch)
        );
    }

    #[test]
    fn tampered_output_hash_rejected() {
        let mut r = signed();
        r.output_hash = [0xff; 32];
        assert_eq!(r.validate_structure(), Err(ReceiptError::EvidenceMismatch));
    }

    #[test]
    fn tampered_field_with_rederived_commitments_fails_signature() {
        let mut r = signed();
        r.work_category = "other".into();
        assert_eq!(
            verify_receipt_signatures(&r, CHAIN, REG),
            Err(ReceiptError::BadSignature("buyer"))
        );
    }

    #[test]
    fn swapped_signatures_rejected_by_domain_separation() {
        let mut r = signed();
        std::mem::swap(&mut r.buyer_signature, &mut r.provider_signature);
        assert!(verify_receipt_signatures(&r, CHAIN, REG).is_err());
    }

    #[test]
    fn wrong_registry_or_chain_rejected() {
        let r = signed();
        assert!(verify_receipt_signatures(&r, CHAIN, "other.testnet").is_err());
        assert!(verify_receipt_signatures(&r, "mainnet", REG).is_err());
    }

    #[test]
    fn length_prefix_prevents_boundary_shift() {
        let r = signed();
        let p = r.signing_payload();
        let a = signing_digest(Party::Buyer, "ab", "c", &p).unwrap();
        let b = signing_digest(Party::Buyer, "a", "bc", &p).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn bad_provider_signature_rejected() {
        let mut r = signed();
        r.provider_signature[0] ^= 1;
        assert_eq!(
            verify_receipt_signatures(&r, CHAIN, REG),
            Err(ReceiptError::BadSignature("provider"))
        );
    }

    #[test]
    fn tampered_borrower_or_credit_limit_rejected_by_signature() {
        let mut r_borrower = signed();
        r_borrower.borrower_evm_address[0] ^= 0xff;
        assert_eq!(
            verify_receipt_signatures(&r_borrower, CHAIN, REG),
            Err(ReceiptError::BadSignature("buyer"))
        );

        let mut r_limit = signed();
        r_limit.max_credit_principal += 1;
        assert_eq!(
            verify_receipt_signatures(&r_limit, CHAIN, REG),
            Err(ReceiptError::BadSignature("buyer"))
        );
    }

    #[test]
    fn json_and_borsh_roundtrip() {
        let r = signed();
        assert_eq!(
            ReceiptV1::from_json(&r.to_canonical_json().unwrap()).unwrap(),
            r
        );
        assert_eq!(
            borsh::from_slice::<ReceiptV1>(&r.to_borsh().unwrap()).unwrap(),
            r
        );
    }
}
