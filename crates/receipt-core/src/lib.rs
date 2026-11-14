//! Shared cryptography and data model for RECEIPT.
//!
//! * [`receipt`]: canonical `ReceiptV1` schema, Borsh + canonical-JSON serialization.
//! * [`signing`]: domain-separated Ed25519 co-signatures and replay-nonce validation.
//! * [`hashing`]: commitments (`evidence`, `confidential settlement`, `receipt id`).
//! * [`confidential`]: Confidential Intents adapter and the labeled testnet bridge.
//! * [`tdx`]: Intel TDX DCAP quote v4 parser and OutLayer `task_hash` verifier.
//! * [`mpc_foreign_tx`]: Borsh replicas of the NEAR MPC foreign-chain payload types.
//! * [`eip712`]: EIP-712 Loan Authorization digest, `ecrecover`, and `LoanDrawn` log validation.
//! * [`mpc_sign`]: NEAR Chain Signatures KDF and `v1.signer-prod.testnet` wire DTOs.

pub mod confidential;
pub mod eip712;
pub mod error;
pub mod hashing;
pub mod hexser;
pub mod mpc_foreign_tx;
pub mod mpc_sign;
pub mod receipt;
pub mod signing;
pub mod tdx;

pub use error::ReceiptError;
