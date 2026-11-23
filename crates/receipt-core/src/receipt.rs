//! Canonical `ReceiptV1` data model.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::error::ReceiptError;
use crate::hashing;
use crate::hexser;

/// Only schema version supported by the MVP.
pub const SCHEMA_VERSION: u16 = 1;

/// Deterministic acceptance result.
#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum WorkOutcome {
    /// Acceptance test failed.
    Fail = 0,
    /// Acceptance test passed.
    Pass = 1,
}

/// Lifecycle and cross-chain consequence state.
#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
pub enum ConsequenceState {
    /// Signatures, nonce, PASS and TDX quote validated.
    RegisteredVerified,
    /// A Base Sepolia loan authorization has been signed via Chain Signatures.
    LoanAuthorized,
    /// `verify_foreign_transaction` is in flight for draw confirmation.
    VerificationPending,
    /// MPC-verified loan disbursement consequence recorded (loan active/encumbered).
    ConsumedVerified,
    /// `verify_foreign_transaction` is in flight for repayment confirmation.
    RepaymentVerificationPending,
    /// MPC-verified full loan repayment recorded (encumbrance cleared).
    RepaidVerified,
    /// `verify_foreign_transaction` is in flight for default confirmation.
    DefaultVerificationPending,
    /// MPC-verified loan default recorded (provider credit frozen).
    DefaultedVerified,
    /// Terminal failure state.
    RejectedOrFailed,
}

/// MPC attestation of the foreign-chain consequence.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFinalityEvidence {
    /// `SHA256(Borsh(ForeignTxSignPayload::V1))` that the MPC network signed.
    #[serde(with = "hexser")]
    pub payload_hash: [u8; 32],
    /// Compressed/affine secp256k1 `r` component.
    #[serde(with = "hexser")]
    pub signature_r: [u8; 32],
    /// secp256k1 `s` component.
    #[serde(with = "hexser")]
    pub signature_s: [u8; 32],
    /// Recovery id.
    pub signature_v: u8,
}

/// Fields covered by both co-signatures (everything immutable at signing time).
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReceiptSigningPayloadV1 {
    /// See [`ReceiptV1::receipt_id`].
    #[serde(with = "hexser")]
    pub receipt_id: [u8; 32],
    /// Schema version.
    pub schema_version: u16,
    /// Provider identity.
    pub provider_identity: String,
    /// Work category.
    pub work_category: String,
    /// Outcome.
    pub outcome: WorkOutcome,
    /// TDX measurement digest.
    #[serde(with = "hexser")]
    pub verifier_measurement: [u8; 32],
    /// WASM hash.
    #[serde(with = "hexser")]
    pub wasm_hash: [u8; 32],
    /// Input hash.
    #[serde(with = "hexser")]
    pub input_hash: [u8; 32],
    /// Output hash.
    #[serde(with = "hexser")]
    pub output_hash: [u8; 32],
    /// Evidence commitment.
    #[serde(with = "hexser")]
    pub evidence_commitment: [u8; 32],
    /// Buyer pubkey.
    #[serde(with = "hexser")]
    pub buyer_pubkey: [u8; 32],
    /// Provider pubkey.
    #[serde(with = "hexser")]
    pub provider_pubkey: [u8; 32],
    /// Replay nonce.
    pub nonce: u64,
    /// Creation time (UNIX seconds).
    pub created_at: u64,
    /// Settlement commitment.
    #[serde(with = "hexser")]
    pub confidential_settlement_commitment: [u8; 32],
    /// Authorized borrower EVM address on the destination chain (`20` bytes).
    #[serde(with = "hexser")]
    pub borrower_evm_address: [u8; 20],
    /// Maximum credit principal (in minimal credit token units) authorized by this receipt.
    pub max_credit_principal: u128,
    /// Attested net revenue from this settled work receipt (minimal credit token units, 6 decimals).
    pub attested_revenue: u128,
}

/// The canonical receipt registered on the NEAR `ReceiptRegistry`.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReceiptV1 {
    /// `SHA256("RECEIPT_ID_V1" || provider_id || nonce_le8 || evidence_commitment)`.
    #[serde(with = "hexser")]
    pub receipt_id: [u8; 32],
    /// Strictly 1 for the MVP.
    pub schema_version: u16,
    /// Provider NEAR account or pseudonymous identifier.
    pub provider_identity: String,
    /// Categorical work classification.
    pub work_category: String,
    /// Acceptance result.
    pub outcome: WorkOutcome,
    /// `SHA256(mrtd || rtmr0 || rtmr1 || rtmr2 || rtmr3)`.
    #[serde(with = "hexser")]
    pub verifier_measurement: [u8; 32],
    /// SHA-256 of the executed acceptance WASM binary.
    #[serde(with = "hexser")]
    pub wasm_hash: [u8; 32],
    /// SHA-256 of the canonical acceptance input.
    #[serde(with = "hexser")]
    pub input_hash: [u8; 32],
    /// SHA-256 of the canonical acceptance stdout.
    #[serde(with = "hexser")]
    pub output_hash: [u8; 32],
    /// Binding over wasm, input, output and settlement.
    #[serde(with = "hexser")]
    pub evidence_commitment: [u8; 32],
    /// Buyer's pseudonymous Ed25519 key.
    #[serde(with = "hexser")]
    pub buyer_pubkey: [u8; 32],
    /// Provider's Ed25519 key.
    #[serde(with = "hexser")]
    pub provider_pubkey: [u8; 32],
    /// Buyer co-signature.
    #[serde(with = "hexser")]
    pub buyer_signature: [u8; 64],
    /// Provider co-signature.
    #[serde(with = "hexser")]
    pub provider_signature: [u8; 64],
    /// Per-provider replay nonce.
    pub nonce: u64,
    /// Creation time (UNIX seconds).
    pub created_at: u64,
    /// Commitment to the Confidential Intents settlement.
    #[serde(with = "hexser")]
    pub confidential_settlement_commitment: [u8; 32],
    /// Authorized borrower EVM address on the destination chain (`20` bytes).
    #[serde(with = "hexser")]
    pub borrower_evm_address: [u8; 20],
    /// Maximum credit principal (in minimal credit token units) authorized by this receipt.
    pub max_credit_principal: u128,
    /// Attested net revenue from this settled work receipt (minimal credit token units, 6 decimals).
    pub attested_revenue: u128,
    /// Lifecycle state.
    pub consequence_state: ConsequenceState,
    /// Foreign chain identifier (e.g. `eip155:84532`).
    pub foreign_chain_id: Option<String>,
    /// Foreign tx hash (set after verification).
    #[serde(with = "hexser::option")]
    pub foreign_tx_hash: Option<[u8; 32]>,
    /// Lender id on the foreign chain.
    pub lender_id: Option<String>,
    /// MPC finality evidence.
    pub verified_finality_evidence: Option<VerifiedFinalityEvidence>,
}

impl ReceiptV1 {
    /// Extract the immutable payload that both parties sign.
    #[must_use]
    pub fn signing_payload(&self) -> ReceiptSigningPayloadV1 {
        ReceiptSigningPayloadV1 {
            receipt_id: self.receipt_id,
            schema_version: self.schema_version,
            provider_identity: self.provider_identity.clone(),
            work_category: self.work_category.clone(),
            outcome: self.outcome,
            verifier_measurement: self.verifier_measurement,
            wasm_hash: self.wasm_hash,
            input_hash: self.input_hash,
            output_hash: self.output_hash,
            evidence_commitment: self.evidence_commitment,
            buyer_pubkey: self.buyer_pubkey,
            provider_pubkey: self.provider_pubkey,
            nonce: self.nonce,
            created_at: self.created_at,
            confidential_settlement_commitment: self.confidential_settlement_commitment,
            borrower_evm_address: self.borrower_evm_address,
            max_credit_principal: self.max_credit_principal,
            attested_revenue: self.attested_revenue,
        }
    }

    /// Check schema version, PASS outcome, non-zero credit terms, and derived `evidence_commitment` / `receipt_id`.
    ///
    /// # Errors
    /// Returns the first violated invariant.
    pub fn validate_structure(&self) -> Result<(), ReceiptError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ReceiptError::UnsupportedSchema(self.schema_version));
        }
        if self.outcome != WorkOutcome::Pass {
            return Err(ReceiptError::OutcomeNotPass);
        }
        if self.borrower_evm_address == [0u8; 20]
            || self.max_credit_principal == 0
            || self.attested_revenue == 0
        {
            return Err(ReceiptError::InvalidInput(
                "borrower_evm_address, max_credit_principal, and attested_revenue must be non-zero"
                    .into(),
            ));
        }
        let evidence = hashing::evidence_commitment(
            &self.wasm_hash,
            &self.input_hash,
            &self.output_hash,
            &self.confidential_settlement_commitment,
        );
        if evidence != self.evidence_commitment {
            return Err(ReceiptError::EvidenceMismatch);
        }
        if hashing::receipt_id(&self.provider_identity, self.nonce, &evidence) != self.receipt_id {
            return Err(ReceiptError::ReceiptIdMismatch);
        }
        Ok(())
    }

    /// Canonical Borsh bytes.
    ///
    /// # Errors
    /// Fails if serialization fails.
    pub fn to_borsh(&self) -> Result<Vec<u8>, ReceiptError> {
        borsh::to_vec(self).map_err(|e| ReceiptError::Serialization(e.to_string()))
    }

    /// Canonical JSON (struct field order, hex-encoded byte arrays, no whitespace).
    ///
    /// # Errors
    /// Fails if serialization fails.
    pub fn to_canonical_json(&self) -> Result<String, ReceiptError> {
        serde_json::to_string(self).map_err(|e| ReceiptError::Serialization(e.to_string()))
    }

    /// Parse from canonical JSON.
    ///
    /// # Errors
    /// Fails on malformed JSON or field shapes.
    pub fn from_json(json: &str) -> Result<Self, ReceiptError> {
        serde_json::from_str(json).map_err(|e| ReceiptError::Serialization(e.to_string()))
    }
}
