//! Error type shared by every `receipt-core` module.

use thiserror::Error;

/// All failure modes of receipt validation, signing, and attestation parsing.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReceiptError {
    /// The receipt outcome is not `Pass`.
    #[error("receipt outcome is not PASS")]
    OutcomeNotPass,
    /// Schema version is unsupported.
    #[error("unsupported schema version {0}")]
    UnsupportedSchema(u16),
    /// `receipt_id` does not match its derivation.
    #[error("receipt_id does not match SHA256(RECEIPT_ID_V1 || provider || nonce || evidence)")]
    ReceiptIdMismatch,
    /// `evidence_commitment` does not match wasm/input/output/settlement hashes.
    #[error("evidence_commitment does not match its components")]
    EvidenceMismatch,
    /// `verifier_measurement` does not match the TDX measurements.
    #[error("verifier_measurement does not match TDX measurements")]
    MeasurementMismatch,
    /// A signature failed verification.
    #[error("invalid {0} signature")]
    BadSignature(&'static str),
    /// A public key is not a valid Ed25519 point.
    #[error("invalid {0} public key")]
    BadPublicKey(&'static str),
    /// The (provider, nonce) pair was already used.
    #[error("nonce {nonce} already used by provider")]
    NonceReplay {
        /// The replayed nonce.
        nonce: u64,
    },
    /// The WASM hash is not the one both parties agreed on.
    #[error("wasm_hash does not match the expected verifier")]
    WasmHashMismatch,
    /// Malformed TDX quote.
    #[error("malformed TDX quote: {0}")]
    Quote(String),
    /// TDX `report_data` does not bind the expected task hash.
    #[error("report_data[0..32] does not match task_hash")]
    ReportDataMismatch,
    /// TDX measurements are not in the approved allowlist.
    #[error("TDX measurements are not approved")]
    MeasurementNotApproved,
    /// TDX quote ECDSA signature failed.
    #[error("TDX quote signature verification failed: {0}")]
    QuoteSignature(String),
    /// Full Intel DCAP verification (PCK chain, Intel root, CRLs, TCB collateral, QE identity) failed.
    #[error("Intel DCAP verification failed: {0}")]
    DcapVerification(String),
    /// Serialization failure.
    #[error("serialization error: {0}")]
    Serialization(String),
    /// Invalid caller input (lengths, hex, ranges).
    #[error("invalid input: {0}")]
    InvalidInput(String),
}
