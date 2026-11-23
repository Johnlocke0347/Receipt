//! `near-receipt-registry`: On-chain NEAR Receipt Registry & Consequence Graph (`near-sdk` v5).
//!
//! Responsibilities:
//! 1. Maintain approved Intel TDX measurement sets synced from `worker.outlayer.testnet`.
//! 2. Verify and register `ReceiptV1` artifacts (`PASS` outcome, `(provider_pubkey, nonce)` replay
//!    guard, Buyer & Provider domain-separated Ed25519 co-signatures, and Intel TDX DCAP Quote v4
//!    binary verification + `report_data[0..32] == task_hash`).
//! 3. Authorize Base Sepolia credit draws (`authorize_loan`) by computing an EIP-712 Loan
//!    Authorization digest and requesting a threshold secp256k1 signature from
//!    `v1.signer-prod.testnet::sign` (`domain_id: 0`, path `"receipt-credit-vault-v1"`).
//! 4. Verify Base Sepolia loan draw consequences (`verify_loan_consequence`) by validating the
//!    extracted `LoanDrawn` `EvmLog`, computing `SHA256(Borsh(ForeignTxSignPayload::V1))`, and
//!    calling `v1.signer-prod.testnet::verify_foreign_transaction` (`domain_id: 3`).

#![allow(missing_docs, clippy::missing_panics_doc)]
#![cfg_attr(target_arch = "wasm32", allow(clippy::too_many_arguments))]

use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(target_arch = "wasm32")]
use near_sdk::json_types::U128;
#[cfg(target_arch = "wasm32")]
use near_sdk::{
    ext_contract, near, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseError,
};
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
pub use host_types::{AccountId, Gas, NearToken, PromiseError, U128};
#[cfg(not(target_arch = "wasm32"))]
pub use rt::{set_test_context, set_test_timestamp};

#[cfg(not(target_arch = "wasm32"))]
mod host_types {
    use std::fmt;
    use std::str::FromStr;

    use borsh::{BorshDeserialize, BorshSerialize};
    use serde::{Deserialize, Serialize};

    /// Pure-Rust NEAR `AccountId` wrapper used in non-WASM unit tests.
    #[derive(
        BorshSerialize,
        BorshDeserialize,
        Serialize,
        Deserialize,
        Clone,
        Debug,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
    )]
    #[serde(transparent)]
    pub struct AccountId(String);

    impl AccountId {
        /// Return the underlying string slice.
        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    impl FromStr for AccountId {
        type Err = &'static str;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            if s.len() < 2 || s.len() > 64 {
                return Err("invalid NEAR AccountId length");
            }
            Ok(Self(s.to_string()))
        }
    }

    impl fmt::Display for AccountId {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    /// Pure-Rust `Gas` wrapper used in non-WASM unit tests.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Gas(u64);

    impl Gas {
        /// Construct `Gas` from TeraGas (`10^12` gas units).
        #[must_use]
        pub const fn from_tgas(tgas: u64) -> Self {
            Self(tgas * 1_000_000_000_000)
        }

        /// Return raw gas units.
        #[must_use]
        pub const fn as_gas(self) -> u64 {
            self.0
        }
    }

    /// Pure-Rust `NearToken` wrapper used in non-WASM unit tests.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct NearToken(u128);

    impl NearToken {
        /// Construct `NearToken` from yoctoNEAR (`10^-24` NEAR).
        #[must_use]
        pub const fn from_yoctonear(yocto: u128) -> Self {
            Self(yocto)
        }

        /// Return raw yoctoNEAR amount.
        #[must_use]
        pub const fn as_yoctonear(self) -> u128 {
            self.0
        }
    }

    /// Pure-Rust `U128` JSON string-wrapped integer used in non-WASM unit tests.
    #[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
    pub struct U128(pub u128);

    impl Serialize for U128 {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&self.0.to_string())
        }
    }

    impl<'de> Deserialize<'de> for U128 {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let s = <String as Deserialize>::deserialize(deserializer)?;
            s.parse::<u128>()
                .map(U128)
                .map_err(serde::de::Error::custom)
        }
    }

    /// Pure-Rust `PromiseError` used in non-WASM unit tests.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum PromiseError {
        /// Cross-contract promise failed.
        Failed,
    }
}

use receipt_core::eip712::{
    eip712_loan_authorization_digest, pubkey64_to_evm_address, verify_loan_defaulted_log,
    verify_loan_drawn_log, verify_loan_repaid_log, LoanAuthorizationPacket, BASE_SEPOLIA_CAIP2,
    BASE_SEPOLIA_CHAIN_ID,
};
use receipt_core::hexser;
use receipt_core::mpc_foreign_tx::{
    base_block_and_log_payload, verify_foreign_transaction_args, EvmFinality, EvmLog,
    FOREIGN_TX_DOMAIN_ID,
};
use receipt_core::mpc_sign::{
    derive_mpc_secp256k1_pubkey, parse_near_secp256k1_pubkey, sign_request_args,
    MpcSecp256k1Signature, VerifyForeignTransactionResponseDto, DEFAULT_DERIVATION_PATH,
    MPC_SIGNER_TESTNET_ACCOUNT, SIGN_DOMAIN_ID, TESTNET_FOREIGN_TX_DOMAIN_3_PUBLIC_KEY,
    TESTNET_SIGN_DOMAIN_0_PUBLIC_KEY,
};
use receipt_core::receipt::{ConsequenceState, ReceiptV1, VerifiedFinalityEvidence, WorkOutcome};
use receipt_core::signing::verify_receipt_signatures;
use receipt_core::tdx::{
    compute_task_hash, verify_quote_signature, verify_report_data, HexMeasurements, Measurements,
    TaskHashInputs, TdxQuote,
};

/// Default OutLayer worker measurement registry on NEAR Testnet.
pub const OUTLAYER_WORKER_TESTNET_ACCOUNT: &str = "worker.outlayer.testnet";
/// Trailing revenue window for underwriting (`14` days = `1,209,600` seconds).
pub const TRAILING_REVENUE_WINDOW_SECS: u64 = 1_209_600;
/// Default fixed hard advance cap (`250 USDC` in 6-decimal minimal units; overrideable on deployment).
pub const DEFAULT_FIXED_ADVANCE_CAP: u128 = 250_000_000;
/// Default minimum number of distinct independent payers required to unlock revenue advances.
pub const DEFAULT_MIN_DISTINCT_PAYERS: u32 = 2;
/// Gas attached to outbound MPC `sign` and `verify_foreign_transaction` calls (`35 TGas`).
const MPC_CALL_GAS: Gas = Gas::from_tgas(35);
/// Gas attached to local callback handlers (`15 TGas`).
#[cfg(target_arch = "wasm32")]
const CALLBACK_GAS: Gas = Gas::from_tgas(15);
/// Gas attached to `worker.outlayer.testnet::get_approved_measurements` (`15 TGas`).
const OUTLAYER_SYNC_GAS: Gas = Gas::from_tgas(15);

/// Outbound cross-contract promise type (`near_sdk::Promise` in production WASM builds;
/// inspectable descriptor in native unit tests).
#[cfg(target_arch = "wasm32")]
pub type OutboundPromise = Promise;

/// Inspectable outbound cross-contract promise descriptor used in native unit tests.
#[cfg(not(target_arch = "wasm32"))]
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OutboundPromise {
    /// Target contract account ID.
    pub receiver_id: AccountId,
    /// Target method name.
    pub method_name: String,
    /// JSON-encoded call arguments.
    pub args: Vec<u8>,
    /// Attached deposit in yoctoNEAR.
    pub deposit_yocto: u128,
    /// Attached gas in gas units.
    pub gas: u64,
    /// Callback method scheduled on `self`.
    pub callback_method: String,
}

mod rt {
    use super::{AccountId, NearToken};

    #[cfg(target_arch = "wasm32")]
    pub fn current_account_id() -> AccountId {
        near_sdk::env::current_account_id()
    }

    #[cfg(target_arch = "wasm32")]
    pub fn predecessor_account_id() -> AccountId {
        near_sdk::env::predecessor_account_id()
    }

    #[cfg(target_arch = "wasm32")]
    pub fn attached_deposit() -> NearToken {
        near_sdk::env::attached_deposit()
    }

    #[cfg(target_arch = "wasm32")]
    pub fn block_timestamp_secs() -> u64 {
        near_sdk::env::block_timestamp() / 1_000_000_000
    }

    #[cfg(target_arch = "wasm32")]
    pub fn panic_str(msg: &str) -> ! {
        near_sdk::env::panic_str(msg)
    }

    #[cfg(not(target_arch = "wasm32"))]
    use std::cell::RefCell;

    #[cfg(not(target_arch = "wasm32"))]
    struct TestCtx {
        current_account_id: AccountId,
        predecessor_account_id: AccountId,
        attached_deposit: NearToken,
        block_timestamp_secs: u64,
    }

    #[cfg(not(target_arch = "wasm32"))]
    thread_local! {
        static CTX: RefCell<TestCtx> = RefCell::new(TestCtx {
            current_account_id: "receipt-registry.testnet".parse().unwrap(),
            predecessor_account_id: "owner.testnet".parse().unwrap(),
            attached_deposit: NearToken::from_yoctonear(0),
            block_timestamp_secs: 1_771_590_000,
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn set_test_context(current: &str, predecessor: &str, deposit_yocto: u128) {
        CTX.with(|c| {
            let mut borrow = c.borrow_mut();
            borrow.current_account_id = current.parse().unwrap();
            borrow.predecessor_account_id = predecessor.parse().unwrap();
            borrow.attached_deposit = NearToken::from_yoctonear(deposit_yocto);
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn set_test_timestamp(ts_secs: u64) {
        CTX.with(|c| {
            c.borrow_mut().block_timestamp_secs = ts_secs;
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn current_account_id() -> AccountId {
        CTX.with(|c| c.borrow().current_account_id.clone())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn predecessor_account_id() -> AccountId {
        CTX.with(|c| c.borrow().predecessor_account_id.clone())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn attached_deposit() -> NearToken {
        CTX.with(|c| c.borrow().attached_deposit)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn block_timestamp_secs() -> u64 {
        CTX.with(|c| c.borrow().block_timestamp_secs)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn panic_str(msg: &str) -> ! {
        panic!("{msg}")
    }
}

/// Self-callbacks invoked after cross-contract promises resolve.
#[cfg(target_arch = "wasm32")]
#[ext_contract(ext_self)]
pub trait ReceiptRegistryCallbacks {
    /// Callback after `worker.outlayer.testnet::get_approved_measurements`.
    fn on_measurements_synced(
        &mut self,
        #[callback_result] call_result: Result<Vec<HexMeasurements>, PromiseError>,
    ) -> u32;

    /// Callback after `v1.signer-prod.testnet::sign`.
    fn on_loan_authorization_signed(
        &mut self,
        receipt_id: [u8; 32],
        #[callback_result] call_result: Result<MpcSecp256k1Signature, PromiseError>,
    ) -> Option<LoanAuthorizationPacket>;

    /// Callback after `v1.signer-prod.testnet::verify_foreign_transaction` for disbursement.
    fn on_foreign_tx_verified(
        &mut self,
        receipt_id: [u8; 32],
        #[callback_result] call_result: Result<VerifyForeignTransactionResponseDto, PromiseError>,
    ) -> bool;

    /// Callback after `v1.signer-prod.testnet::verify_foreign_transaction` for repayment.
    fn on_repayment_tx_verified(
        &mut self,
        receipt_id: [u8; 32],
        #[callback_result] call_result: Result<VerifyForeignTransactionResponseDto, PromiseError>,
    ) -> bool;

    /// Callback after `v1.signer-prod.testnet::verify_foreign_transaction` for default.
    fn on_default_tx_verified(
        &mut self,
        receipt_id: [u8; 32],
        #[callback_result] call_result: Result<VerifyForeignTransactionResponseDto, PromiseError>,
    ) -> bool;
}

/// In-flight loan authorization parameters saved between `authorize_loan` and
/// `on_loan_authorization_signed`.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PendingLoanAuthorization {
    /// Receipt identifier (`bytes32`).
    #[serde(with = "hexser")]
    pub receipt_id: [u8; 32],
    /// Borrower EVM address (`20` bytes).
    #[serde(with = "hexser")]
    pub borrower_evm_address: [u8; 20],
    /// Principal amount in minimal credit token units.
    pub principal_amount: u128,
    /// Fixed financing fee in minimal credit token units.
    pub fee_amount: u128,
    /// Loan maturity timestamp (UNIX seconds).
    pub maturity_at: u64,
    /// Evidence commitment from the registered receipt.
    #[serde(with = "hexser")]
    pub evidence_commitment: [u8; 32],
    /// Target `ReceiptCreditVault` contract address on Base Sepolia.
    #[serde(with = "hexser")]
    pub base_vault_address: [u8; 20],
    /// Target EVM chain ID (`84532`).
    pub chain_id: u64,
    /// Expiry timestamp (UNIX seconds).
    pub deadline: u64,
    /// Precomputed 32-byte EIP-712 signing digest.
    #[serde(with = "hexser")]
    pub eip712_digest: [u8; 32],
}

/// In-flight foreign transaction verification parameters saved between
/// `verify_loan_consequence` and `on_foreign_tx_verified`.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PendingConsequenceVerification {
    /// Receipt identifier (`bytes32`).
    #[serde(with = "hexser")]
    pub receipt_id: [u8; 32],
    /// Base Sepolia transaction hash (`bytes32`).
    #[serde(with = "hexser")]
    pub base_tx_hash: [u8; 32],
    /// Base Sepolia block hash (`bytes32`).
    #[serde(with = "hexser")]
    pub base_block_hash: [u8; 32],
    /// 32-byte `lenderId` extracted from `LoanDrawn` `topics[3]`.
    #[serde(with = "hexser")]
    pub lender_id: [u8; 32],
    /// Expected `SHA256(Borsh(ForeignTxSignPayload::V1))`.
    #[serde(with = "hexser")]
    pub expected_payload_hash: [u8; 32],
}

/// In-flight repayment verification parameters saved between
/// `verify_loan_repayment` and `on_repayment_tx_verified`.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PendingRepaymentVerification {
    /// Receipt identifier (`bytes32`).
    #[serde(with = "hexser")]
    pub receipt_id: [u8; 32],
    /// Base Sepolia transaction hash (`bytes32`).
    #[serde(with = "hexser")]
    pub base_tx_hash: [u8; 32],
    /// Base Sepolia block hash (`bytes32`).
    #[serde(with = "hexser")]
    pub base_block_hash: [u8; 32],
    /// 32-byte `lenderId` extracted from `LoanRepaid` `topics[3]`.
    #[serde(with = "hexser")]
    pub lender_id: [u8; 32],
    /// Repaid token units extracted from `LoanRepaid`.
    pub amount_paid: u128,
    /// Remaining balance after payment (`0` means fully repaid).
    pub remaining_balance: u128,
    /// Expected `SHA256(Borsh(ForeignTxSignPayload::V1))`.
    #[serde(with = "hexser")]
    pub expected_payload_hash: [u8; 32],
}

/// In-flight default verification parameters saved between
/// `verify_loan_default` and `on_default_tx_verified`.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PendingDefaultVerification {
    /// Receipt identifier (`bytes32`).
    #[serde(with = "hexser")]
    pub receipt_id: [u8; 32],
    /// Base Sepolia transaction hash (`bytes32`).
    #[serde(with = "hexser")]
    pub base_tx_hash: [u8; 32],
    /// Base Sepolia block hash (`bytes32`).
    #[serde(with = "hexser")]
    pub base_block_hash: [u8; 32],
    /// 32-byte `lenderId` extracted from `LoanDefaulted` `topics[3]`.
    #[serde(with = "hexser")]
    pub lender_id: [u8; 32],
    /// Unpaid principal slashed in the Base default event.
    pub unpaid_principal: u128,
    /// First-loss reserves absorbed in the Base default event.
    pub first_loss_absorbed: u128,
    /// Expected `SHA256(Borsh(ForeignTxSignPayload::V1))`.
    #[serde(with = "hexser")]
    pub expected_payload_hash: [u8; 32],
}

/// Provider repayment and default profile tracked by the registry.
#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq,
)]
pub struct ProviderCreditProfile {
    /// Total loans verified as drawn (`ConsumedVerified`).
    pub total_loans_drawn: u32,
    /// Total loans verified as fully repaid (`RepaidVerified`).
    pub total_loans_repaid: u32,
    /// Total verified defaults (`DefaultedVerified`).
    pub defaults_count: u32,
    /// Cumulative principal repaid cleanly across all loans.
    pub cumulative_repaid_principal: u128,
    /// Whether this provider is frozen from new advances due to a verified default.
    pub credit_frozen: bool,
}

/// Trailing 14-day attested revenue summary and resulting advance cap for a provider.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TrailingRevenueView {
    /// Provider identity queried.
    pub provider_identity: String,
    /// UNIX timestamp at which the trailing window ends.
    pub as_of_timestamp: u64,
    /// Trailing window length in seconds (`1,209,600` = 14 days).
    pub window_secs: u64,
    /// Number of PASS non-defaulted receipts in the trailing window.
    pub eligible_receipts: u32,
    /// Number of distinct independent `buyer_pubkey`s across those receipts.
    pub distinct_payers: u32,
    /// Total `attested_revenue` summed over eligible receipts.
    pub total_revenue: U128,
    /// Configured hard advance cap (`fixed_advance_cap`).
    pub fixed_advance_cap: U128,
    /// Required minimum distinct payers (`min_distinct_payers`).
    pub min_distinct_payers: u32,
    /// Effective advance cap: `0` if `distinct_payers < min_distinct_payers`, else `min(fixed_advance_cap, 1.5 * total_revenue)`.
    pub advance_cap: U128,
}

/// ERC-8004-compatible reputation summary derived from verified loans.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Erc8004ReputationSummaryView {
    /// Total verified terminal loan outcomes (repaid + defaulted).
    pub count: u64,
    /// Net reputation score (`+100` per repaid loan, `-100` per default).
    pub value: i128,
    /// Decimal scaling (`0`).
    pub value_decimals: u8,
}

/// Append-only node in a provider's verified Consequence Graph.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ConsequenceNode {
    /// Receipt ID (`bytes32`).
    #[serde(with = "hexser")]
    pub receipt_id: [u8; 32],
    /// Provider identity.
    pub provider_identity: String,
    /// Work category.
    pub work_category: String,
    /// Evidence commitment bound into both the receipt and the Base Sepolia `LoanDrawn` event.
    #[serde(with = "hexser")]
    pub evidence_commitment: [u8; 32],
    /// Confidential Intents settlement commitment.
    #[serde(with = "hexser")]
    pub confidential_settlement_commitment: [u8; 32],
    /// Borrower EVM address on Base Sepolia.
    #[serde(with = "hexser")]
    pub borrower_evm_address: [u8; 20],
    /// Disbursed loan principal in minimal credit token units.
    pub principal_amount: u128,
    /// Base Sepolia `ReceiptCreditVault` contract address.
    #[serde(with = "hexser")]
    pub base_vault_address: [u8; 20],
    /// CAIP-2 foreign chain identifier (`"eip155:84532"`).
    pub foreign_chain_id: String,
    /// Verified Base Sepolia transaction hash (`bytes32`).
    #[serde(with = "hexser")]
    pub foreign_tx_hash: [u8; 32],
    /// Verified Base Sepolia block hash (`bytes32`).
    #[serde(with = "hexser")]
    pub foreign_block_hash: [u8; 32],
    /// Verified 32-byte `lenderId` from `LoanDrawn`.
    #[serde(with = "hexser")]
    pub lender_id: [u8; 32],
    /// MPC finality evidence over `ForeignTxSignPayload::V1`.
    pub verified_finality_evidence: VerifiedFinalityEvidence,
}

/// Self-contained cryptographic proof bundle returned by [`ReceiptRegistry::verify_consequence_proof`].
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ConsequenceProofView {
    /// Registered receipt record.
    pub receipt: ReceiptV1,
    /// Signed EIP-712 loan authorization packet if authorized.
    pub loan_authorization: Option<LoanAuthorizationPacket>,
    /// Whether the receipt has reached `ConsumedVerified` AND its stored MPC `ForeignTx` signature
    /// cryptographically verifies against the configured `domain_id: 3` root public key.
    pub is_mpc_consequence_verified: bool,
}

/// On-chain Receipt Registry & Cross-Chain Consequence Graph contract.
#[cfg_attr(target_arch = "wasm32", near(contract_state))]
#[cfg_attr(target_arch = "wasm32", derive(PanicOnDefault))]
pub struct ReceiptRegistry {
    /// Contract owner account.
    pub owner: AccountId,
    /// NEAR chain ID used in receipt signature domain separation (`"testnet"`).
    pub near_chain_id: String,
    /// NEAR Chain Signatures & Foreign-Tx MPC contract (`v1.signer-prod.testnet`).
    pub mpc_signer_account: AccountId,
    /// OutLayer worker measurement contract (`worker.outlayer.testnet`).
    pub outlayer_worker_account: AccountId,
    /// MPC domain ID for `sign` (`0`).
    pub sign_domain_id: u64,
    /// MPC domain ID for `verify_foreign_transaction` (`3`).
    pub foreign_tx_domain_id: u64,
    /// Root secp256k1 uncompressed 64-byte public key for `sign_domain_id`.
    pub sign_domain_root_pubkey: [u8; 64],
    /// Root secp256k1 uncompressed 64-byte public key for `foreign_tx_domain_id`.
    pub foreign_tx_domain_root_pubkey: [u8; 64],
    /// Derivation path used for `sign` (`"receipt-credit-vault-v1"`).
    pub derivation_path: String,
    /// Target Base Sepolia chain ID (`84532`).
    pub base_chain_id: u64,
    /// Optional pinned Base Sepolia `ReceiptCreditVault` address (`20` bytes).
    pub configured_base_vault: Option<[u8; 20]>,
    /// Optional allowlist of expected acceptance-verifier WASM hashes (`SHA-256`).
    pub expected_wasm_hashes: BTreeSet<[u8; 32]>,
    /// Approved 5-measurement sets keyed by `Measurements::digest()`.
    pub approved_measurements: BTreeMap<[u8; 32], Measurements>,
    /// Replay protection set over `(provider_pubkey, nonce)`.
    pub used_nonces: BTreeSet<([u8; 32], u64)>,
    /// Replay protection set over consumed OutLayer TDX attestation `task_id`s.
    pub consumed_task_ids: BTreeSet<u64>,
    /// Registered receipts keyed by `receipt_id`.
    pub receipts: BTreeMap<[u8; 32], ReceiptV1>,
    /// In-flight loan authorization requests awaiting `v1.signer-prod.testnet::sign`.
    pub pending_loan_requests: BTreeMap<[u8; 32], PendingLoanAuthorization>,
    /// Completed EIP-712 loan authorization packets keyed by `receipt_id`.
    pub loan_authorizations: BTreeMap<[u8; 32], LoanAuthorizationPacket>,
    /// In-flight consequence verification requests awaiting `verify_foreign_transaction`.
    pub pending_consequence_requests: BTreeMap<[u8; 32], PendingConsequenceVerification>,
    /// In-flight repayment verification requests awaiting `verify_foreign_transaction`.
    pub pending_repayment_requests: BTreeMap<[u8; 32], PendingRepaymentVerification>,
    /// In-flight default verification requests awaiting `verify_foreign_transaction`.
    pub pending_default_requests: BTreeMap<[u8; 32], PendingDefaultVerification>,
    /// Verified cross-chain consequence graph indexed by `provider_identity`.
    pub provider_credit_graph: BTreeMap<String, Vec<ConsequenceNode>>,
    /// Owner emergency pause switch blocking new `authorize_loan` requests.
    pub paused: bool,
    /// Fixed hard advance ceiling (6-decimal token units, e.g. `5_000_000` for `$5`).
    pub fixed_advance_cap: u128,
    /// Minimum distinct independent payers required in trailing 14d revenue window.
    pub min_distinct_payers: u32,
    /// Active encumbered receipt keyed by `provider_identity` (blocks second advance until repaid).
    pub active_encumbered_receipt: BTreeMap<String, [u8; 32]>,
    /// Active encumbered receipt keyed by `borrower_evm_address`.
    pub active_encumbered_borrower: BTreeMap<[u8; 20], [u8; 32]>,
    /// Provider repayment and default profiles keyed by `provider_identity`.
    pub provider_profiles: BTreeMap<String, ProviderCreditProfile>,
}

#[cfg_attr(target_arch = "wasm32", near)]
impl ReceiptRegistry {
    /// Add a single approved OutLayer TDX 5-measurement set (`mrtd`, `rtmr0..3`).
    /// Returns the 64-character hex `Measurements::digest()`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn add_approved_measurement(&mut self, measurement: HexMeasurements) -> String {
        self.assert_owner();
        let parsed = Measurements::try_from(&measurement)
            .unwrap_or_else(|e| rt::panic_str(&format!("invalid measurement: {e}")));
        let digest = parsed.digest();
        self.approved_measurements.insert(digest, parsed);
        hex::encode(digest)
    }

    /// Add a batch of approved OutLayer TDX 5-measurement sets.
    /// Returns the total number of approved measurement sets after insertion.
    #[allow(clippy::needless_pass_by_value)]
    pub fn add_approved_measurements_batch(&mut self, measurements: Vec<HexMeasurements>) -> u32 {
        self.assert_owner();
        for m in &measurements {
            let parsed = Measurements::try_from(m)
                .unwrap_or_else(|e| rt::panic_str(&format!("invalid measurement: {e}")));
            self.approved_measurements.insert(parsed.digest(), parsed);
        }
        u32::try_from(self.approved_measurements.len()).unwrap_or(u32::MAX)
    }

    /// Synchronize approved worker TDX measurements directly from
    /// `worker.outlayer.testnet::get_approved_measurements`.
    pub fn sync_approved_measurements(&mut self) -> OutboundPromise {
        self.assert_owner();
        #[cfg(target_arch = "wasm32")]
        {
            Promise::new(self.outlayer_worker_account.clone())
                .function_call(
                    "get_approved_measurements".to_string(),
                    b"{}".to_vec(),
                    NearToken::from_yoctonear(0),
                    OUTLAYER_SYNC_GAS,
                )
                .then(
                    ext_self::ext(rt::current_account_id())
                        .with_static_gas(CALLBACK_GAS)
                        .on_measurements_synced(),
                )
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            OutboundPromise {
                receiver_id: self.outlayer_worker_account.clone(),
                method_name: "get_approved_measurements".to_string(),
                args: b"{}".to_vec(),
                deposit_yocto: 0,
                gas: OUTLAYER_SYNC_GAS.as_gas(),
                callback_method: "on_measurements_synced".to_string(),
            }
        }
    }

    /// Pin an expected acceptance-verifier WASM SHA-256 hash (`64` hex chars).
    #[allow(clippy::needless_pass_by_value)]
    pub fn add_expected_wasm_hash(&mut self, wasm_hash_hex: String) {
        self.assert_owner();
        let hash = decode_hex_array::<32>(&wasm_hash_hex, "wasm_hash_hex");
        self.expected_wasm_hashes.insert(hash);
    }

    /// Configure or update the pinned Base Sepolia `ReceiptCreditVault` address (`20` bytes hex).
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_configured_base_vault(&mut self, vault_address_hex: String) {
        self.assert_owner();
        let addr = decode_hex_array::<20>(&vault_address_hex, "vault_address_hex");
        if addr == [0u8; 20] {
            rt::panic_str("vault_address_hex cannot be zero");
        }
        self.configured_base_vault = Some(addr);
    }

    /// Configure the root secp256k1 public keys for `sign_domain_id` (`domain_id: 0`) and
    /// `foreign_tx_domain_id` (`domain_id: 3`). Defaults to the live `v1.signer-prod.testnet` keys.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_domain_root_pubkeys(&mut self, sign_root_pk: String, foreign_tx_root_pk: String) {
        self.assert_owner();
        self.sign_domain_root_pubkey = parse_near_secp256k1_pubkey(&sign_root_pk)
            .unwrap_or_else(|e| rt::panic_str(&format!("invalid sign_root_pk: {e}")));
        self.foreign_tx_domain_root_pubkey = parse_near_secp256k1_pubkey(&foreign_tx_root_pk)
            .unwrap_or_else(|e| rt::panic_str(&format!("invalid foreign_tx_root_pk: {e}")));
    }

    /// Owner emergency pause switch for `authorize_loan`.
    pub fn set_paused(&mut self, paused: bool) {
        self.assert_owner();
        self.paused = paused;
    }

    /// Configure `fixed_advance_cap` and `min_distinct_payers` underwriting thresholds.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_underwriting_policy(&mut self, fixed_advance_cap: U128, min_distinct_payers: u32) {
        self.assert_owner();
        if fixed_advance_cap.0 == 0 || min_distinct_payers == 0 {
            rt::panic_str("fixed_advance_cap and min_distinct_payers must be positive");
        }
        self.fixed_advance_cap = fixed_advance_cap.0;
        self.min_distinct_payers = min_distinct_payers;
    }

    /// Register a verified `ReceiptV1` after enforcing:
    /// 1. `outcome == PASS` and canonical `evidence_commitment` + `receipt_id` derivation.
    /// 2. Expected acceptance-verifier WASM hash allowlist (if configured).
    /// 3. `(provider_pubkey, nonce)` replay protection.
    /// 4. Buyer and Provider domain-separated Ed25519 co-signatures.
    /// 5. OutLayer task metadata hash bindings (`wasm_hash`, `input_hash`, `output_hash`).
    /// 6. Intel TDX Quote v4 binary parsing, approved worker measurement membership, ECDSA P-256
    ///    attestation signature + QE report binding, and `report_data[0..32] == task_hash`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn register_receipt(
        &mut self,
        receipt: ReceiptV1,
        tdx_quote_bytes: Vec<u8>,
        outlayer_task_meta: TaskHashInputs,
    ) -> String {
        let mut receipt = receipt;
        receipt
            .validate_structure()
            .unwrap_or_else(|e| rt::panic_str(&format!("receipt structure invalid: {e}")));

        if !self.expected_wasm_hashes.is_empty()
            && !self.expected_wasm_hashes.contains(&receipt.wasm_hash)
        {
            rt::panic_str("wasm_hash is not in expected_wasm_hashes allowlist");
        }

        let nonce_key = (receipt.provider_pubkey, receipt.nonce);
        if self.used_nonces.contains(&nonce_key) {
            rt::panic_str(&format!("nonce {} already used by provider", receipt.nonce));
        }
        if self.receipts.contains_key(&receipt.receipt_id) {
            rt::panic_str("receipt_id already registered");
        }
        if self.consumed_task_ids.contains(&outlayer_task_meta.task_id) {
            rt::panic_str(&format!(
                "outlayer task_id {} already consumed by a registered receipt",
                outlayer_task_meta.task_id
            ));
        }

        let registry_account = rt::current_account_id();
        verify_receipt_signatures(&receipt, &self.near_chain_id, registry_account.as_str())
            .unwrap_or_else(|e| {
                rt::panic_str(&format!("receipt signature verification failed: {e}"))
            });

        if outlayer_task_meta.wasm_hash != Some(receipt.wasm_hash) {
            rt::panic_str("outlayer_task_meta.wasm_hash does not match receipt.wasm_hash");
        }
        if outlayer_task_meta.input_hash != Some(receipt.input_hash) {
            rt::panic_str("outlayer_task_meta.input_hash does not match receipt.input_hash");
        }
        let expected_output_hash = receipt_core::hashing::enclave_output_hash(
            receipt.outcome,
            &outlayer_task_meta.output_hash,
        );
        if receipt.output_hash != expected_output_hash {
            rt::panic_str(
                "receipt.output_hash does not commit receipt.outcome into outlayer_task_meta.output_hash",
            );
        }

        let quote = TdxQuote::parse(&tdx_quote_bytes)
            .unwrap_or_else(|e| rt::panic_str(&format!("invalid TDX v4 quote: {e}")));
        let quote_measurement_digest = quote.measurements.digest();
        if quote_measurement_digest != receipt.verifier_measurement {
            rt::panic_str("receipt.verifier_measurement does not match TDX quote measurements");
        }

        let Some(approved) = self.approved_measurements.get(&quote_measurement_digest) else {
            rt::panic_str("TDX quote measurements are not in approved_measurements");
        };
        if approved != &quote.measurements {
            rt::panic_str("TDX quote 5-measurement tuple mismatch");
        }

        verify_quote_signature(&quote)
            .unwrap_or_else(|e| rt::panic_str(&format!("TDX quote signature invalid: {e}")));
        quote
            .verify_qe_binding()
            .unwrap_or_else(|e| rt::panic_str(&format!("TDX QE report binding invalid: {e}")));

        let task_hash = compute_task_hash(&outlayer_task_meta);
        verify_report_data(&quote, &task_hash)
            .unwrap_or_else(|e| rt::panic_str(&format!("TDX report_data task_hash mismatch: {e}")));

        self.used_nonces.insert(nonce_key);
        self.consumed_task_ids.insert(outlayer_task_meta.task_id);
        receipt.consequence_state = ConsequenceState::RegisteredVerified;
        receipt.foreign_chain_id = None;
        receipt.foreign_tx_hash = None;
        receipt.lender_id = None;
        receipt.verified_finality_evidence = None;

        let id_hex = hex::encode(receipt.receipt_id);
        self.receipts.insert(receipt.receipt_id, receipt);
        id_hex
    }

    // -------------------------------------------------------------------------
    // View Methods
    // -------------------------------------------------------------------------

    /// Fetch a registered `ReceiptV1` by its 64-character hex `receipt_id`.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_receipt(&self, receipt_id_hex: String) -> Option<ReceiptV1> {
        let id = decode_hex_array::<32>(&receipt_id_hex, "receipt_id_hex");
        self.receipts.get(&id).cloned()
    }

    /// Fetch the signed `LoanAuthorizationPacket` for a `receipt_id`.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_loan_authorization(
        &self,
        receipt_id_hex: String,
    ) -> Option<LoanAuthorizationPacket> {
        let id = decode_hex_array::<32>(&receipt_id_hex, "receipt_id_hex");
        self.loan_authorizations.get(&id).cloned()
    }

    /// Fetch all MPC-verified cross-chain credit consequences for `provider_identity`.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_provider_credit_graph(&self, provider_identity: String) -> Vec<ConsequenceNode> {
        self.provider_credit_graph
            .get(&provider_identity)
            .cloned()
            .unwrap_or_default()
    }

    /// Return a self-contained cryptographic consequence proof view for `receipt_id_hex`,
    /// re-verifying the stored MPC `ForeignTx` signature against `foreign_tx_domain_root_pubkey`.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn verify_consequence_proof(&self, receipt_id_hex: String) -> Option<ConsequenceProofView> {
        let id = decode_hex_array::<32>(&receipt_id_hex, "receipt_id_hex");
        let receipt = self.receipts.get(&id)?.clone();
        let loan_authorization = self.loan_authorizations.get(&id).cloned();

        let is_mpc_consequence_verified = if receipt.consequence_state
            == ConsequenceState::ConsumedVerified
        {
            if let Some(ref ev) = receipt.verified_finality_evidence {
                let mpc_sig = MpcSecp256k1Signature::from_r_s_v(
                    &ev.signature_r,
                    &ev.signature_s,
                    ev.signature_v,
                );
                mpc_sig
                    .verify_against_pubkey(&ev.payload_hash, &self.foreign_tx_domain_root_pubkey)
                    .is_ok()
            } else {
                false
            }
        } else {
            false
        };

        Some(ConsequenceProofView {
            receipt,
            loan_authorization,
            is_mpc_consequence_verified,
        })
    }

    /// Compute the `0x`-prefixed 20-byte EVM address (`nearAuthorizedSigner`) derived for this
    /// registry contract (`current_account_id()`) and `self.derivation_path` under
    /// `self.sign_domain_root_pubkey`.
    #[must_use]
    pub fn derive_vault_authorized_signer_evm_address(&self) -> String {
        let derived_pk64 = derive_mpc_secp256k1_pubkey(
            &self.sign_domain_root_pubkey,
            rt::current_account_id().as_str(),
            &self.derivation_path,
        )
        .unwrap_or_else(|e| rt::panic_str(&format!("failed to derive child pubkey: {e}")));
        let evm_addr = pubkey64_to_evm_address(&derived_pk64);
        format!("0x{}", hex::encode(evm_addr))
    }

    /// Total number of approved OutLayer worker measurement sets.
    #[must_use]
    pub fn approved_measurements_count(&self) -> u32 {
        u32::try_from(self.approved_measurements.len()).unwrap_or(u32::MAX)
    }

    /// Check whether a 32-byte `Measurements::digest()` (64-char hex) is approved.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn is_measurement_approved(&self, measurement_digest_hex: String) -> bool {
        let digest = decode_hex_array::<32>(&measurement_digest_hex, "measurement_digest_hex");
        self.approved_measurements.contains_key(&digest)
    }

    /// Check whether an OutLayer TDX attestation `task_id` has already been consumed.
    #[must_use]
    pub fn is_task_id_consumed(&self, task_id: u64) -> bool {
        self.consumed_task_ids.contains(&task_id)
    }

    /// Return whether new loan authorizations are currently paused by owner.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Compute trailing 14-day attested revenue, distinct independent payer count, and resulting
    /// `advance_cap = min(fixed_advance_cap, 1.5x trailing_14d_revenue)` for `provider_identity`.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_trailing_14d_revenue(
        &self,
        provider_identity: String,
        as_of_timestamp: Option<u64>,
    ) -> TrailingRevenueView {
        let cutoff = as_of_timestamp.unwrap_or_else(rt::block_timestamp_secs);
        self.trailing_revenue_view(&provider_identity, cutoff)
    }

    /// Return effective current advance cap (`0` if paused, frozen after default, encumbered, or
    /// below `min_distinct_payers`).
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn compute_advance_cap(
        &self,
        provider_identity: String,
        as_of_timestamp: Option<u64>,
    ) -> U128 {
        if self.paused
            || self
                .active_encumbered_receipt
                .contains_key(&provider_identity)
        {
            return U128(0);
        }
        if let Some(p) = self.provider_profiles.get(&provider_identity) {
            if p.credit_frozen || p.defaults_count > 0 {
                return U128(0);
            }
        }
        let cutoff = as_of_timestamp.unwrap_or_else(rt::block_timestamp_secs);
        self.trailing_revenue_view(&provider_identity, cutoff)
            .advance_cap
    }

    /// Fetch repayment & default profile for `provider_identity`.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_provider_credit_profile(
        &self,
        provider_identity: String,
    ) -> Option<ProviderCreditProfile> {
        self.provider_profiles.get(&provider_identity).cloned()
    }

    /// Fetch the active encumbered `receipt_id` hex string for `provider_identity`, if any.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_active_encumbered_receipt(&self, provider_identity: String) -> Option<String> {
        self.active_encumbered_receipt
            .get(&provider_identity)
            .map(hex::encode)
    }

    /// ERC-8004-compatible reputation summary derived from verified repaid and defaulted loans.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_erc8004_reputation_summary(
        &self,
        provider_identity: String,
    ) -> Erc8004ReputationSummaryView {
        let profile = self
            .provider_profiles
            .get(&provider_identity)
            .cloned()
            .unwrap_or_default();
        let repaid = u64::from(profile.total_loans_repaid);
        let defaulted = u64::from(profile.defaults_count);
        let value =
            i128::from(profile.total_loans_repaid) * 100 - i128::from(profile.defaults_count) * 100;
        Erc8004ReputationSummaryView {
            count: repaid + defaulted,
            value,
            value_decimals: 0,
        }
    }

    fn assert_owner(&self) {
        if rt::predecessor_account_id() != self.owner {
            rt::panic_str("only contract owner may call this method");
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[near]
impl ReceiptRegistry {
    #[init]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(
        owner: AccountId,
        mpc_signer_account: Option<AccountId>,
        configured_base_vault_hex: Option<String>,
    ) -> Self {
        Self::init_internal(owner, mpc_signer_account, configured_base_vault_hex)
    }

    #[private]
    pub fn on_measurements_synced(
        &mut self,
        #[callback_result] call_result: Result<Vec<HexMeasurements>, PromiseError>,
    ) -> u32 {
        self.on_measurements_synced_internal(call_result)
    }

    #[payable]
    #[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
    pub fn authorize_loan(
        &mut self,
        receipt_id_hex: String,
        borrower_evm_address_hex: String,
        principal_amount: U128,
        fee_amount: U128,
        maturity_at: u64,
        base_vault_address_hex: String,
        deadline: u64,
    ) -> OutboundPromise {
        self.authorize_loan_internal(
            receipt_id_hex,
            borrower_evm_address_hex,
            principal_amount,
            fee_amount,
            maturity_at,
            base_vault_address_hex,
            deadline,
        )
    }

    #[private]
    pub fn on_loan_authorization_signed(
        &mut self,
        receipt_id: [u8; 32],
        #[callback_result] call_result: Result<MpcSecp256k1Signature, PromiseError>,
    ) -> Option<LoanAuthorizationPacket> {
        self.on_loan_authorization_signed_internal(receipt_id, call_result)
    }

    #[payable]
    #[allow(clippy::needless_pass_by_value)]
    pub fn verify_loan_consequence(
        &mut self,
        receipt_id_hex: String,
        base_tx_hash_hex: String,
        base_block_hash_hex: String,
        expected_log: EvmLog,
        finality: EvmFinality,
    ) -> OutboundPromise {
        self.verify_loan_consequence_internal(
            receipt_id_hex,
            base_tx_hash_hex,
            base_block_hash_hex,
            expected_log,
            finality,
        )
    }

    #[private]
    pub fn on_foreign_tx_verified(
        &mut self,
        receipt_id: [u8; 32],
        #[callback_result] call_result: Result<VerifyForeignTransactionResponseDto, PromiseError>,
    ) -> bool {
        self.on_foreign_tx_verified_internal(receipt_id, call_result)
    }

    #[payable]
    #[allow(clippy::needless_pass_by_value)]
    pub fn verify_loan_repayment(
        &mut self,
        receipt_id_hex: String,
        base_tx_hash_hex: String,
        base_block_hash_hex: String,
        expected_log: EvmLog,
        finality: EvmFinality,
    ) -> OutboundPromise {
        self.verify_loan_repayment_internal(
            receipt_id_hex,
            base_tx_hash_hex,
            base_block_hash_hex,
            expected_log,
            finality,
        )
    }

    #[private]
    pub fn on_repayment_tx_verified(
        &mut self,
        receipt_id: [u8; 32],
        #[callback_result] call_result: Result<VerifyForeignTransactionResponseDto, PromiseError>,
    ) -> bool {
        self.on_repayment_tx_verified_internal(receipt_id, call_result)
    }

    #[payable]
    #[allow(clippy::needless_pass_by_value)]
    pub fn verify_loan_default(
        &mut self,
        receipt_id_hex: String,
        base_tx_hash_hex: String,
        base_block_hash_hex: String,
        expected_log: EvmLog,
        finality: EvmFinality,
    ) -> OutboundPromise {
        self.verify_loan_default_internal(
            receipt_id_hex,
            base_tx_hash_hex,
            base_block_hash_hex,
            expected_log,
            finality,
        )
    }

    #[private]
    pub fn on_default_tx_verified(
        &mut self,
        receipt_id: [u8; 32],
        #[callback_result] call_result: Result<VerifyForeignTransactionResponseDto, PromiseError>,
    ) -> bool {
        self.on_default_tx_verified_internal(receipt_id, call_result)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl ReceiptRegistry {
    #[must_use]
    pub fn new(
        owner: AccountId,
        mpc_signer_account: Option<AccountId>,
        configured_base_vault_hex: Option<String>,
    ) -> Self {
        Self::init_internal(owner, mpc_signer_account, configured_base_vault_hex)
    }

    pub fn on_measurements_synced(
        &mut self,
        call_result: Result<Vec<HexMeasurements>, PromiseError>,
    ) -> u32 {
        self.on_measurements_synced_internal(call_result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_loan(
        &mut self,
        receipt_id_hex: String,
        borrower_evm_address_hex: String,
        principal_amount: U128,
        fee_amount: U128,
        maturity_at: u64,
        base_vault_address_hex: String,
        deadline: u64,
    ) -> OutboundPromise {
        self.authorize_loan_internal(
            receipt_id_hex,
            borrower_evm_address_hex,
            principal_amount,
            fee_amount,
            maturity_at,
            base_vault_address_hex,
            deadline,
        )
    }

    pub fn on_loan_authorization_signed(
        &mut self,
        receipt_id: [u8; 32],
        call_result: Result<MpcSecp256k1Signature, PromiseError>,
    ) -> Option<LoanAuthorizationPacket> {
        self.on_loan_authorization_signed_internal(receipt_id, call_result)
    }

    pub fn verify_loan_consequence(
        &mut self,
        receipt_id_hex: String,
        base_tx_hash_hex: String,
        base_block_hash_hex: String,
        expected_log: EvmLog,
        finality: EvmFinality,
    ) -> OutboundPromise {
        self.verify_loan_consequence_internal(
            receipt_id_hex,
            base_tx_hash_hex,
            base_block_hash_hex,
            expected_log,
            finality,
        )
    }

    pub fn on_foreign_tx_verified(
        &mut self,
        receipt_id: [u8; 32],
        call_result: Result<VerifyForeignTransactionResponseDto, PromiseError>,
    ) -> bool {
        self.on_foreign_tx_verified_internal(receipt_id, call_result)
    }

    pub fn verify_loan_repayment(
        &mut self,
        receipt_id_hex: String,
        base_tx_hash_hex: String,
        base_block_hash_hex: String,
        expected_log: EvmLog,
        finality: EvmFinality,
    ) -> OutboundPromise {
        self.verify_loan_repayment_internal(
            receipt_id_hex,
            base_tx_hash_hex,
            base_block_hash_hex,
            expected_log,
            finality,
        )
    }

    pub fn on_repayment_tx_verified(
        &mut self,
        receipt_id: [u8; 32],
        call_result: Result<VerifyForeignTransactionResponseDto, PromiseError>,
    ) -> bool {
        self.on_repayment_tx_verified_internal(receipt_id, call_result)
    }

    pub fn verify_loan_default(
        &mut self,
        receipt_id_hex: String,
        base_tx_hash_hex: String,
        base_block_hash_hex: String,
        expected_log: EvmLog,
        finality: EvmFinality,
    ) -> OutboundPromise {
        self.verify_loan_default_internal(
            receipt_id_hex,
            base_tx_hash_hex,
            base_block_hash_hex,
            expected_log,
            finality,
        )
    }

    pub fn on_default_tx_verified(
        &mut self,
        receipt_id: [u8; 32],
        call_result: Result<VerifyForeignTransactionResponseDto, PromiseError>,
    ) -> bool {
        self.on_default_tx_verified_internal(receipt_id, call_result)
    }
}

struct ForeignTxVerificationSpec {
    deposit: NearToken,
    base_tx_hash: [u8; 32],
    base_block_hash: [u8; 32],
    expected_log: EvmLog,
    finality: EvmFinality,
}

impl ReceiptRegistry {
    #[allow(clippy::needless_pass_by_value)]
    fn init_internal(
        owner: AccountId,
        mpc_signer_account: Option<AccountId>,
        configured_base_vault_hex: Option<String>,
    ) -> Self {
        let mpc_signer = mpc_signer_account.unwrap_or_else(|| {
            MPC_SIGNER_TESTNET_ACCOUNT
                .parse()
                .expect("valid default MPC account")
        });
        let outlayer_worker: AccountId = OUTLAYER_WORKER_TESTNET_ACCOUNT
            .parse()
            .expect("valid default OutLayer worker account");
        let configured_base_vault = configured_base_vault_hex
            .as_deref()
            .map(|h| decode_hex_array::<20>(h, "configured_base_vault_hex"));
        let sign_domain_root_pubkey = parse_near_secp256k1_pubkey(TESTNET_SIGN_DOMAIN_0_PUBLIC_KEY)
            .expect("valid default domain 0 pubkey");
        let foreign_tx_domain_root_pubkey =
            parse_near_secp256k1_pubkey(TESTNET_FOREIGN_TX_DOMAIN_3_PUBLIC_KEY)
                .expect("valid default domain 3 pubkey");

        Self {
            owner,
            near_chain_id: "testnet".to_string(),
            mpc_signer_account: mpc_signer,
            outlayer_worker_account: outlayer_worker,
            sign_domain_id: SIGN_DOMAIN_ID,
            foreign_tx_domain_id: FOREIGN_TX_DOMAIN_ID,
            sign_domain_root_pubkey,
            foreign_tx_domain_root_pubkey,
            derivation_path: DEFAULT_DERIVATION_PATH.to_string(),
            base_chain_id: BASE_SEPOLIA_CHAIN_ID,
            configured_base_vault,
            expected_wasm_hashes: BTreeSet::new(),
            approved_measurements: BTreeMap::new(),
            used_nonces: BTreeSet::new(),
            consumed_task_ids: BTreeSet::new(),
            receipts: BTreeMap::new(),
            pending_loan_requests: BTreeMap::new(),
            loan_authorizations: BTreeMap::new(),
            pending_consequence_requests: BTreeMap::new(),
            pending_repayment_requests: BTreeMap::new(),
            pending_default_requests: BTreeMap::new(),
            provider_credit_graph: BTreeMap::new(),
            paused: false,
            fixed_advance_cap: DEFAULT_FIXED_ADVANCE_CAP,
            min_distinct_payers: DEFAULT_MIN_DISTINCT_PAYERS,
            active_encumbered_receipt: BTreeMap::new(),
            active_encumbered_borrower: BTreeMap::new(),
            provider_profiles: BTreeMap::new(),
        }
    }

    fn trailing_revenue_view(
        &self,
        provider_identity: &str,
        as_of_timestamp: u64,
    ) -> TrailingRevenueView {
        let window_start = as_of_timestamp.saturating_sub(TRAILING_REVENUE_WINDOW_SECS);
        let max_created = as_of_timestamp.saturating_add(60);
        let mut eligible_receipts = 0u32;
        let mut total_revenue = 0u128;
        let mut distinct_buyers: BTreeSet<[u8; 32]> = BTreeSet::new();

        for r in self.receipts.values() {
            if r.provider_identity == provider_identity
                && r.outcome == WorkOutcome::Pass
                && !matches!(
                    r.consequence_state,
                    ConsequenceState::RejectedOrFailed | ConsequenceState::DefaultedVerified
                )
                && r.created_at >= window_start
                && r.created_at <= max_created
            {
                eligible_receipts = eligible_receipts.saturating_add(1);
                total_revenue = total_revenue.saturating_add(r.attested_revenue);
                distinct_buyers.insert(r.buyer_pubkey);
            }
        }

        let distinct_payers = u32::try_from(distinct_buyers.len()).unwrap_or(u32::MAX);
        let revenue_150_pct = total_revenue.saturating_mul(3) / 2;
        let advance_cap = if distinct_payers >= self.min_distinct_payers {
            self.fixed_advance_cap.min(revenue_150_pct)
        } else {
            0
        };

        TrailingRevenueView {
            provider_identity: provider_identity.to_string(),
            as_of_timestamp,
            window_secs: TRAILING_REVENUE_WINDOW_SECS,
            eligible_receipts,
            distinct_payers,
            total_revenue: U128(total_revenue),
            fixed_advance_cap: U128(self.fixed_advance_cap),
            min_distinct_payers: self.min_distinct_payers,
            advance_cap: U128(advance_cap),
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn on_measurements_synced_internal(
        &mut self,
        call_result: Result<Vec<HexMeasurements>, PromiseError>,
    ) -> u32 {
        let list = call_result
            .unwrap_or_else(|_| rt::panic_str("failed to sync measurements from OutLayer worker"));
        for m in &list {
            let parsed = Measurements::try_from(m)
                .unwrap_or_else(|e| rt::panic_str(&format!("invalid synced measurement: {e}")));
            self.approved_measurements.insert(parsed.digest(), parsed);
        }
        u32::try_from(self.approved_measurements.len()).unwrap_or(u32::MAX)
    }

    fn validate_authorize_loan_request(
        &self,
        receipt_id: [u8; 32],
        borrower: [u8; 20],
        principal: u128,
        maturity_at: u64,
        base_vault: [u8; 20],
        now: u64,
    ) -> ReceiptV1 {
        if borrower == [0u8; 20] || base_vault == [0u8; 20] || principal == 0 || maturity_at <= now
        {
            rt::panic_str(
                "borrower, base_vault, principal_amount must be non-zero and maturity_at > now",
            );
        }
        if let Some(cfg_vault) = self.configured_base_vault {
            if base_vault != cfg_vault {
                rt::panic_str("base_vault_address does not match configured_base_vault");
            }
        }

        let Some(receipt_ref) = self.receipts.get(&receipt_id).cloned() else {
            rt::panic_str("receipt not found");
        };
        if rt::predecessor_account_id().as_str() != receipt_ref.provider_identity {
            rt::panic_str("only receipt.provider_identity may call authorize_loan");
        }
        if receipt_ref.outcome != WorkOutcome::Pass {
            rt::panic_str("only PASS receipts can authorize loans");
        }
        if receipt_ref.consequence_state != ConsequenceState::RegisteredVerified {
            rt::panic_str("receipt is not in RegisteredVerified state");
        }
        if borrower != receipt_ref.borrower_evm_address {
            rt::panic_str(
                "borrower_evm_address does not match co-signed receipt.borrower_evm_address",
            );
        }
        if principal > receipt_ref.max_credit_principal {
            rt::panic_str("principal_amount exceeds co-signed receipt.max_credit_principal");
        }
        if let Some(profile) = self.provider_profiles.get(&receipt_ref.provider_identity) {
            if profile.credit_frozen || profile.defaults_count > 0 {
                rt::panic_str("provider credit is frozen due to prior default");
            }
        }
        if self
            .active_encumbered_receipt
            .contains_key(&receipt_ref.provider_identity)
            || self.active_encumbered_borrower.contains_key(&borrower)
        {
            rt::panic_str("active unpaid loan must be repaid before drawing a new advance");
        }

        let rev = self.trailing_revenue_view(&receipt_ref.provider_identity, now);
        if rev.distinct_payers < self.min_distinct_payers {
            rt::panic_str("insufficient distinct independent payers in trailing 14-day window");
        }
        if principal > rev.advance_cap.0 {
            rt::panic_str(
                "principal_amount exceeds advance_cap = min(fixed_advance_cap, 1.5x trailing 14d revenue)",
            );
        }
        receipt_ref
    }

    #[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
    fn authorize_loan_internal(
        &mut self,
        receipt_id_hex: String,
        borrower_evm_address_hex: String,
        principal_amount: U128,
        fee_amount: U128,
        maturity_at: u64,
        base_vault_address_hex: String,
        deadline: u64,
    ) -> OutboundPromise {
        if self.paused {
            rt::panic_str("registry is paused by owner");
        }
        let deposit = rt::attached_deposit();
        if deposit < NearToken::from_yoctonear(1) {
            rt::panic_str("attach at least 1 yoctoNEAR for MPC sign");
        }
        let receipt_id = decode_hex_array::<32>(&receipt_id_hex, "receipt_id_hex");
        let borrower =
            decode_hex_array::<20>(&borrower_evm_address_hex, "borrower_evm_address_hex");
        let base_vault = decode_hex_array::<20>(&base_vault_address_hex, "base_vault_address_hex");
        let principal = principal_amount.0;
        let fee = fee_amount.0;
        let now = rt::block_timestamp_secs();

        let receipt_ref = self.validate_authorize_loan_request(
            receipt_id,
            borrower,
            principal,
            maturity_at,
            base_vault,
            now,
        );

        let eip712_digest = eip712_loan_authorization_digest(
            &receipt_id,
            &borrower,
            principal,
            fee,
            maturity_at,
            &receipt_ref.evidence_commitment,
            &base_vault,
            self.base_chain_id,
            deadline,
        );
        let sign_args =
            sign_request_args(&self.derivation_path, &eip712_digest, self.sign_domain_id)
                .unwrap_or_else(|e| rt::panic_str(&format!("invalid MPC sign request: {e}")));
        let args_bytes = serde_json::to_vec(&sign_args).expect("serialize MPC sign args");

        // Optimistic lock BEFORE external cross-contract call (CEI / reentrancy defense)
        if let Some(r) = self.receipts.get_mut(&receipt_id) {
            r.consequence_state = ConsequenceState::LoanAuthorized;
        }
        self.pending_loan_requests.insert(
            receipt_id,
            PendingLoanAuthorization {
                receipt_id,
                borrower_evm_address: borrower,
                principal_amount: principal,
                fee_amount: fee,
                maturity_at,
                evidence_commitment: receipt_ref.evidence_commitment,
                base_vault_address: base_vault,
                chain_id: self.base_chain_id,
                deadline,
                eip712_digest,
            },
        );

        #[cfg(target_arch = "wasm32")]
        {
            Promise::new(self.mpc_signer_account.clone())
                .function_call("sign".to_string(), args_bytes, deposit, MPC_CALL_GAS)
                .then(
                    ext_self::ext(rt::current_account_id())
                        .with_static_gas(CALLBACK_GAS)
                        .on_loan_authorization_signed(receipt_id),
                )
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            OutboundPromise {
                receiver_id: self.mpc_signer_account.clone(),
                method_name: "sign".to_string(),
                args: args_bytes,
                deposit_yocto: deposit.as_yoctonear(),
                gas: MPC_CALL_GAS.as_gas(),
                callback_method: "on_loan_authorization_signed".to_string(),
            }
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn on_loan_authorization_signed_internal(
        &mut self,
        receipt_id: [u8; 32],
        call_result: Result<MpcSecp256k1Signature, PromiseError>,
    ) -> Option<LoanAuthorizationPacket> {
        let Some(pending) = self.pending_loan_requests.remove(&receipt_id) else {
            rt::panic_str("no pending loan authorization for receipt_id");
        };

        let Ok(mpc_sig) = call_result else {
            if let Some(r) = self.receipts.get_mut(&receipt_id) {
                r.consequence_state = ConsequenceState::RegisteredVerified;
            }
            return None;
        };

        let Ok(derived_pk64) = derive_mpc_secp256k1_pubkey(
            &self.sign_domain_root_pubkey,
            rt::current_account_id().as_str(),
            &self.derivation_path,
        ) else {
            if let Some(r) = self.receipts.get_mut(&receipt_id) {
                r.consequence_state = ConsequenceState::RegisteredVerified;
            }
            return None;
        };

        let Ok((r, s, v)) = mpc_sig.verify_against_pubkey(&pending.eip712_digest, &derived_pk64)
        else {
            if let Some(rec) = self.receipts.get_mut(&receipt_id) {
                rec.consequence_state = ConsequenceState::RegisteredVerified;
            }
            return None;
        };

        let packet = LoanAuthorizationPacket {
            receipt_id: pending.receipt_id,
            borrower_evm_address: pending.borrower_evm_address,
            principal_amount: pending.principal_amount,
            fee_amount: pending.fee_amount,
            maturity_at: pending.maturity_at,
            evidence_commitment: pending.evidence_commitment,
            base_vault_address: pending.base_vault_address,
            chain_id: pending.chain_id,
            deadline: pending.deadline,
            eip712_digest: pending.eip712_digest,
            signature_r: r,
            signature_s: s,
            signature_v: v,
        };
        self.loan_authorizations.insert(receipt_id, packet.clone());
        Some(packet)
    }

    fn build_and_send_foreign_tx_verification(
        &self,
        spec: ForeignTxVerificationSpec,
        callback_method: &str,
        receipt_id: [u8; 32],
    ) -> ([u8; 32], OutboundPromise) {
        let payload = base_block_and_log_payload(
            spec.base_tx_hash,
            spec.finality,
            spec.base_block_hash,
            spec.expected_log,
        )
        .unwrap_or_else(|e| {
            rt::panic_str(&format!("failed to build Base foreign tx payload: {e}"))
        });
        let expected_payload_hash = payload
            .compute_msg_hash()
            .unwrap_or_else(|e| rt::panic_str(&format!("failed to hash foreign tx payload: {e}")));
        let args = verify_foreign_transaction_args(
            &payload.request,
            self.foreign_tx_domain_id,
            Some(expected_payload_hash),
        )
        .unwrap_or_else(|e| rt::panic_str(&format!("invalid foreign tx args: {e}")));
        let args_bytes =
            serde_json::to_vec(&args).expect("serialize verify_foreign_transaction args");

        #[cfg(not(target_arch = "wasm32"))]
        let _ = receipt_id;

        #[cfg(target_arch = "wasm32")]
        let promise = {
            let cb = match callback_method {
                "on_foreign_tx_verified" => ext_self::ext(rt::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .on_foreign_tx_verified(receipt_id),
                "on_repayment_tx_verified" => ext_self::ext(rt::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .on_repayment_tx_verified(receipt_id),
                _ => ext_self::ext(rt::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .on_default_tx_verified(receipt_id),
            };
            Promise::new(self.mpc_signer_account.clone())
                .function_call(
                    "verify_foreign_transaction".to_string(),
                    args_bytes,
                    spec.deposit,
                    MPC_CALL_GAS,
                )
                .then(cb)
        };
        #[cfg(not(target_arch = "wasm32"))]
        let promise = OutboundPromise {
            receiver_id: self.mpc_signer_account.clone(),
            method_name: "verify_foreign_transaction".to_string(),
            args: args_bytes,
            deposit_yocto: spec.deposit.as_yoctonear(),
            gas: MPC_CALL_GAS.as_gas(),
            callback_method: callback_method.to_string(),
        };
        (expected_payload_hash, promise)
    }

    fn verify_foreign_tx_response(
        &self,
        expected_payload_hash: &[u8; 32],
        call_result: Result<VerifyForeignTransactionResponseDto, PromiseError>,
    ) -> Option<VerifiedFinalityEvidence> {
        let resp = call_result.ok()?;
        if &resp.payload_hash.0 != expected_payload_hash {
            return None;
        }
        let (sig_r, sig_s, sig_v) = resp
            .signature
            .verify_against_pubkey(expected_payload_hash, &self.foreign_tx_domain_root_pubkey)
            .ok()?;
        Some(VerifiedFinalityEvidence {
            payload_hash: *expected_payload_hash,
            signature_r: sig_r,
            signature_s: sig_s,
            signature_v: sig_v,
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn verify_loan_consequence_internal(
        &mut self,
        receipt_id_hex: String,
        base_tx_hash_hex: String,
        base_block_hash_hex: String,
        expected_log: EvmLog,
        finality: EvmFinality,
    ) -> OutboundPromise {
        let deposit = rt::attached_deposit();
        if deposit < NearToken::from_yoctonear(1) {
            rt::panic_str("attach at least 1 yoctoNEAR for verify_foreign_transaction");
        }
        let receipt_id = decode_hex_array::<32>(&receipt_id_hex, "receipt_id_hex");
        let base_tx_hash = decode_hex_array::<32>(&base_tx_hash_hex, "base_tx_hash_hex");
        let base_block_hash = decode_hex_array::<32>(&base_block_hash_hex, "base_block_hash_hex");

        let Some(loan_auth) = self.loan_authorizations.get(&receipt_id).cloned() else {
            rt::panic_str("loan authorization packet not found for receipt_id");
        };
        let evidence_commitment = {
            let Some(receipt) = self.receipts.get(&receipt_id) else {
                rt::panic_str("receipt not found");
            };
            if receipt.consequence_state != ConsequenceState::LoanAuthorized {
                rt::panic_str("receipt must be in LoanAuthorized state");
            }
            receipt.evidence_commitment
        };

        let lender_id = verify_loan_drawn_log(
            &expected_log,
            &loan_auth.base_vault_address,
            &base_tx_hash,
            &base_block_hash,
            &receipt_id,
            &loan_auth.borrower_evm_address,
            loan_auth.principal_amount,
            &evidence_commitment,
        )
        .unwrap_or_else(|e| rt::panic_str(&format!("invalid LoanDrawn log: {e}")));

        let (expected_payload_hash, promise) = self.build_and_send_foreign_tx_verification(
            ForeignTxVerificationSpec {
                deposit,
                base_tx_hash,
                base_block_hash,
                expected_log,
                finality,
            },
            "on_foreign_tx_verified",
            receipt_id,
        );

        if let Some(receipt) = self.receipts.get_mut(&receipt_id) {
            receipt.consequence_state = ConsequenceState::VerificationPending;
        }
        self.pending_consequence_requests.insert(
            receipt_id,
            PendingConsequenceVerification {
                receipt_id,
                base_tx_hash,
                base_block_hash,
                lender_id,
                expected_payload_hash,
            },
        );
        promise
    }

    #[allow(clippy::needless_pass_by_value)]
    fn on_foreign_tx_verified_internal(
        &mut self,
        receipt_id: [u8; 32],
        call_result: Result<VerifyForeignTransactionResponseDto, PromiseError>,
    ) -> bool {
        let Some(pending) = self.pending_consequence_requests.remove(&receipt_id) else {
            rt::panic_str("no pending consequence verification for receipt_id");
        };

        let Some(finality_evidence) =
            self.verify_foreign_tx_response(&pending.expected_payload_hash, call_result)
        else {
            if let Some(r) = self.receipts.get_mut(&receipt_id) {
                r.consequence_state = ConsequenceState::LoanAuthorized;
            }
            return false;
        };

        let Some(loan_auth) = self.loan_authorizations.get(&receipt_id).cloned() else {
            if let Some(r) = self.receipts.get_mut(&receipt_id) {
                r.consequence_state = ConsequenceState::LoanAuthorized;
            }
            return false;
        };
        let Some(receipt) = self.receipts.get_mut(&receipt_id) else {
            return false;
        };

        receipt.consequence_state = ConsequenceState::ConsumedVerified;
        receipt.foreign_chain_id = Some(BASE_SEPOLIA_CAIP2.to_string());
        receipt.foreign_tx_hash = Some(pending.base_tx_hash);
        receipt.lender_id = Some(hex::encode(pending.lender_id));
        receipt.verified_finality_evidence = Some(finality_evidence.clone());

        self.active_encumbered_receipt
            .insert(receipt.provider_identity.clone(), receipt_id);
        self.active_encumbered_borrower
            .insert(loan_auth.borrower_evm_address, receipt_id);
        let profile = self
            .provider_profiles
            .entry(receipt.provider_identity.clone())
            .or_default();
        profile.total_loans_drawn = profile.total_loans_drawn.saturating_add(1);

        let node = ConsequenceNode {
            receipt_id,
            provider_identity: receipt.provider_identity.clone(),
            work_category: receipt.work_category.clone(),
            evidence_commitment: receipt.evidence_commitment,
            confidential_settlement_commitment: receipt.confidential_settlement_commitment,
            borrower_evm_address: loan_auth.borrower_evm_address,
            principal_amount: loan_auth.principal_amount,
            base_vault_address: loan_auth.base_vault_address,
            foreign_chain_id: BASE_SEPOLIA_CAIP2.to_string(),
            foreign_tx_hash: pending.base_tx_hash,
            foreign_block_hash: pending.base_block_hash,
            lender_id: pending.lender_id,
            verified_finality_evidence: finality_evidence,
        };
        self.provider_credit_graph
            .entry(receipt.provider_identity.clone())
            .or_default()
            .push(node);

        true
    }

    #[allow(clippy::needless_pass_by_value)]
    fn verify_loan_repayment_internal(
        &mut self,
        receipt_id_hex: String,
        base_tx_hash_hex: String,
        base_block_hash_hex: String,
        expected_log: EvmLog,
        finality: EvmFinality,
    ) -> OutboundPromise {
        let deposit = rt::attached_deposit();
        if deposit < NearToken::from_yoctonear(1) {
            rt::panic_str("attach at least 1 yoctoNEAR for verify_foreign_transaction");
        }
        let receipt_id = decode_hex_array::<32>(&receipt_id_hex, "receipt_id_hex");
        let base_tx_hash = decode_hex_array::<32>(&base_tx_hash_hex, "base_tx_hash_hex");
        let base_block_hash = decode_hex_array::<32>(&base_block_hash_hex, "base_block_hash_hex");

        let Some(loan_auth) = self.loan_authorizations.get(&receipt_id).cloned() else {
            rt::panic_str("loan authorization packet not found for receipt_id");
        };
        let evidence_commitment = {
            let Some(receipt) = self.receipts.get(&receipt_id) else {
                rt::panic_str("receipt not found");
            };
            if receipt.consequence_state != ConsequenceState::ConsumedVerified {
                rt::panic_str("receipt must be in ConsumedVerified state to verify repayment");
            }
            receipt.evidence_commitment
        };

        let (lender_id, amount_paid, remaining_balance) = verify_loan_repaid_log(
            &expected_log,
            &loan_auth.base_vault_address,
            &base_tx_hash,
            &base_block_hash,
            &receipt_id,
            &loan_auth.borrower_evm_address,
            &evidence_commitment,
        )
        .unwrap_or_else(|e| rt::panic_str(&format!("invalid LoanRepaid log: {e}")));

        let (expected_payload_hash, promise) = self.build_and_send_foreign_tx_verification(
            ForeignTxVerificationSpec {
                deposit,
                base_tx_hash,
                base_block_hash,
                expected_log,
                finality,
            },
            "on_repayment_tx_verified",
            receipt_id,
        );

        if let Some(receipt) = self.receipts.get_mut(&receipt_id) {
            receipt.consequence_state = ConsequenceState::RepaymentVerificationPending;
        }
        self.pending_repayment_requests.insert(
            receipt_id,
            PendingRepaymentVerification {
                receipt_id,
                base_tx_hash,
                base_block_hash,
                lender_id,
                amount_paid,
                remaining_balance,
                expected_payload_hash,
            },
        );
        promise
    }

    #[allow(clippy::needless_pass_by_value)]
    fn on_repayment_tx_verified_internal(
        &mut self,
        receipt_id: [u8; 32],
        call_result: Result<VerifyForeignTransactionResponseDto, PromiseError>,
    ) -> bool {
        let Some(pending) = self.pending_repayment_requests.remove(&receipt_id) else {
            rt::panic_str("no pending repayment verification for receipt_id");
        };
        let Some(finality_evidence) =
            self.verify_foreign_tx_response(&pending.expected_payload_hash, call_result)
        else {
            if let Some(r) = self.receipts.get_mut(&receipt_id) {
                r.consequence_state = ConsequenceState::ConsumedVerified;
            }
            return false;
        };

        let Some(loan_auth) = self.loan_authorizations.get(&receipt_id).cloned() else {
            return false;
        };
        let Some(receipt) = self.receipts.get_mut(&receipt_id) else {
            return false;
        };

        if pending.remaining_balance == 0 {
            receipt.consequence_state = ConsequenceState::RepaidVerified;
            receipt.foreign_tx_hash = Some(pending.base_tx_hash);
            receipt.verified_finality_evidence = Some(finality_evidence);
            self.active_encumbered_receipt
                .remove(&receipt.provider_identity);
            self.active_encumbered_borrower
                .remove(&loan_auth.borrower_evm_address);
            let profile = self
                .provider_profiles
                .entry(receipt.provider_identity.clone())
                .or_default();
            profile.total_loans_repaid = profile.total_loans_repaid.saturating_add(1);
            profile.cumulative_repaid_principal = profile
                .cumulative_repaid_principal
                .saturating_add(loan_auth.principal_amount);
        } else {
            receipt.consequence_state = ConsequenceState::ConsumedVerified;
        }
        true
    }

    #[allow(clippy::needless_pass_by_value)]
    fn verify_loan_default_internal(
        &mut self,
        receipt_id_hex: String,
        base_tx_hash_hex: String,
        base_block_hash_hex: String,
        expected_log: EvmLog,
        finality: EvmFinality,
    ) -> OutboundPromise {
        let deposit = rt::attached_deposit();
        if deposit < NearToken::from_yoctonear(1) {
            rt::panic_str("attach at least 1 yoctoNEAR for verify_foreign_transaction");
        }
        let receipt_id = decode_hex_array::<32>(&receipt_id_hex, "receipt_id_hex");
        let base_tx_hash = decode_hex_array::<32>(&base_tx_hash_hex, "base_tx_hash_hex");
        let base_block_hash = decode_hex_array::<32>(&base_block_hash_hex, "base_block_hash_hex");

        let Some(loan_auth) = self.loan_authorizations.get(&receipt_id).cloned() else {
            rt::panic_str("loan authorization packet not found for receipt_id");
        };
        let evidence_commitment = {
            let Some(receipt) = self.receipts.get(&receipt_id) else {
                rt::panic_str("receipt not found");
            };
            if receipt.consequence_state != ConsequenceState::ConsumedVerified {
                rt::panic_str("receipt must be in ConsumedVerified state to verify default");
            }
            receipt.evidence_commitment
        };

        let (lender_id, unpaid_principal, first_loss_absorbed) = verify_loan_defaulted_log(
            &expected_log,
            &loan_auth.base_vault_address,
            &base_tx_hash,
            &base_block_hash,
            &receipt_id,
            &loan_auth.borrower_evm_address,
            &evidence_commitment,
        )
        .unwrap_or_else(|e| rt::panic_str(&format!("invalid LoanDefaulted log: {e}")));

        let (expected_payload_hash, promise) = self.build_and_send_foreign_tx_verification(
            ForeignTxVerificationSpec {
                deposit,
                base_tx_hash,
                base_block_hash,
                expected_log,
                finality,
            },
            "on_default_tx_verified",
            receipt_id,
        );

        if let Some(receipt) = self.receipts.get_mut(&receipt_id) {
            receipt.consequence_state = ConsequenceState::DefaultVerificationPending;
        }
        self.pending_default_requests.insert(
            receipt_id,
            PendingDefaultVerification {
                receipt_id,
                base_tx_hash,
                base_block_hash,
                lender_id,
                unpaid_principal,
                first_loss_absorbed,
                expected_payload_hash,
            },
        );
        promise
    }

    #[allow(clippy::needless_pass_by_value)]
    fn on_default_tx_verified_internal(
        &mut self,
        receipt_id: [u8; 32],
        call_result: Result<VerifyForeignTransactionResponseDto, PromiseError>,
    ) -> bool {
        let Some(pending) = self.pending_default_requests.remove(&receipt_id) else {
            rt::panic_str("no pending default verification for receipt_id");
        };
        let Some(finality_evidence) =
            self.verify_foreign_tx_response(&pending.expected_payload_hash, call_result)
        else {
            if let Some(r) = self.receipts.get_mut(&receipt_id) {
                r.consequence_state = ConsequenceState::ConsumedVerified;
            }
            return false;
        };

        let Some(loan_auth) = self.loan_authorizations.get(&receipt_id).cloned() else {
            return false;
        };
        let Some(receipt) = self.receipts.get_mut(&receipt_id) else {
            return false;
        };

        receipt.consequence_state = ConsequenceState::DefaultedVerified;
        receipt.foreign_tx_hash = Some(pending.base_tx_hash);
        receipt.verified_finality_evidence = Some(finality_evidence);
        self.active_encumbered_receipt
            .remove(&receipt.provider_identity);
        self.active_encumbered_borrower
            .remove(&loan_auth.borrower_evm_address);
        let profile = self
            .provider_profiles
            .entry(receipt.provider_identity.clone())
            .or_default();
        profile.defaults_count = profile.defaults_count.saturating_add(1);
        profile.credit_frozen = true;
        true
    }
}

fn decode_hex_array<const N: usize>(hex_str: &str, field: &'static str) -> [u8; N] {
    let stripped = hex_str
        .trim()
        .strip_prefix("0x")
        .or_else(|| hex_str.trim().strip_prefix("0X"))
        .unwrap_or_else(|| hex_str.trim());
    let bytes = hex::decode(stripped)
        .unwrap_or_else(|e| rt::panic_str(&format!("invalid hex in {field}: {e}")));
    bytes.as_slice().try_into().unwrap_or_else(|_| {
        rt::panic_str(&format!(
            "{field} must decode to {N} bytes, got {}",
            bytes.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use k256::ecdsa::SigningKey as Secp256k1SigningKey;
    use k256::elliptic_curve::PrimeField;
    use k256::Scalar;
    use receipt_core::eip712::{encode_loan_drawn_data, recover_eip712_signer};
    use receipt_core::hashing;
    use receipt_core::mpc_foreign_tx::{loan_drawn_topic0, Hash160, Hash256};
    use receipt_core::mpc_sign::{derive_mpc_tweak, format_near_secp256k1_pubkey};
    use receipt_core::signing::{sign_payload, Party};
    use receipt_core::tdx::OutLayerAttestationRecord;

    const WORKER_MEASUREMENTS_JSON: &str =
        include_str!("../../receipt-core/tests/fixtures/worker_approved_measurements.json");
    const ATTESTATION_1500_JSON: &str =
        include_str!("../../receipt-core/tests/fixtures/outlayer_attestation_1500.json");

    fn setup_context(predecessor: &str, deposit_yocto: u128) {
        rt::set_test_context("receipt-registry.testnet", predecessor, deposit_yocto);
    }

    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    fn build_additional_signed_receipt(
        contract: &mut ReceiptRegistry,
        buyer_sk: &Ed25519SigningKey,
        provider_sk: &Ed25519SigningKey,
        attestation_json: &str,
        nonce: u64,
        created_at: u64,
        attested_revenue: u128,
        max_credit_principal: u128,
    ) -> (ReceiptV1, Vec<u8>, TaskHashInputs) {
        let record: OutLayerAttestationRecord = serde_json::from_str(attestation_json).unwrap();
        let quote_bytes = base64::engine::general_purpose::STANDARD
            .decode(record.tdx_quote.trim())
            .unwrap();
        let parsed_quote = TdxQuote::parse(&quote_bytes).unwrap();
        let task_meta = record.to_v1_task_inputs().unwrap();
        let wasm_hash = task_meta.wasm_hash.unwrap();
        let input_hash = task_meta.input_hash.unwrap();
        let output_hash = hashing::enclave_output_hash(WorkOutcome::Pass, &task_meta.output_hash);
        setup_context("owner.testnet", 0);
        contract.add_expected_wasm_hash(hex::encode(wasm_hash));

        let settlement_commitment = hashing::confidential_settlement_commitment(
            &[0x66u8; 32],
            attested_revenue,
            &[0x88u8; 32],
            &[0x77u8; 32],
        );
        let evidence = hashing::evidence_commitment(
            &wasm_hash,
            &input_hash,
            &output_hash,
            &settlement_commitment,
        );
        let provider_identity = "provider.testnet".to_string();
        let receipt_id = hashing::receipt_id(&provider_identity, nonce, &evidence);
        let mut receipt = ReceiptV1 {
            receipt_id,
            schema_version: 1,
            provider_identity,
            work_category: "ai_acceptance_validation".to_string(),
            outcome: WorkOutcome::Pass,
            verifier_measurement: parsed_quote.measurements.digest(),
            wasm_hash,
            input_hash,
            output_hash,
            evidence_commitment: evidence,
            buyer_pubkey: buyer_sk.verifying_key().to_bytes(),
            provider_pubkey: provider_sk.verifying_key().to_bytes(),
            buyer_signature: [0u8; 64],
            provider_signature: [0u8; 64],
            nonce,
            created_at,
            confidential_settlement_commitment: settlement_commitment,
            borrower_evm_address: [0x22u8; 20],
            max_credit_principal,
            attested_revenue,
            consequence_state: ConsequenceState::RegisteredVerified,
            foreign_chain_id: None,
            foreign_tx_hash: None,
            lender_id: None,
            verified_finality_evidence: None,
        };
        let payload = receipt.signing_payload();
        receipt.buyer_signature = sign_payload(
            Party::Buyer,
            buyer_sk,
            "testnet",
            "receipt-registry.testnet",
            &payload,
        )
        .unwrap();
        receipt.provider_signature = sign_payload(
            Party::Provider,
            provider_sk,
            "testnet",
            "receipt-registry.testnet",
            &payload,
        )
        .unwrap();
        (receipt, quote_bytes, task_meta)
    }

    struct TestFixtures {
        contract: ReceiptRegistry,
        sign_root_secret: Scalar,
        foreign_tx_root_secret: Scalar,
        receipt: ReceiptV1,
        quote_bytes: Vec<u8>,
        task_meta: TaskHashInputs,
    }

    #[allow(clippy::too_many_lines)]
    fn build_fixtures() -> TestFixtures {
        rt::set_test_timestamp(1_771_590_000);
        setup_context("owner.testnet", 0);
        let vault_hex = "5555555555555555555555555555555555555555";
        let mut contract = ReceiptRegistry::new(
            "owner.testnet".parse().unwrap(),
            Some("v1.signer-prod.testnet".parse().unwrap()),
            Some(vault_hex.to_string()),
        );
        // Allow single-receipt legacy unit fixture tests unless overridden in multi-payer tests
        contract.set_underwriting_policy(U128(250_000_000), 1);

        // Configure deterministic test MPC root keys for domain 0 (Sign) and domain 3 (ForeignTx)
        let sign_root_secret = Scalar::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
        let sign_root_sk = Secp256k1SigningKey::from_bytes(&sign_root_secret.to_bytes()).unwrap();
        let sign_root_ep = sign_root_sk.verifying_key().to_encoded_point(false);
        let mut sign_root_pk64 = [0u8; 64];
        sign_root_pk64.copy_from_slice(&sign_root_ep.as_bytes()[1..65]);

        let foreign_tx_root_secret = Scalar::from_u128(0x9999_aaaa_bbbb_cccc_dddd_eeee_ffff_0001);
        let foreign_tx_root_sk =
            Secp256k1SigningKey::from_bytes(&foreign_tx_root_secret.to_bytes()).unwrap();
        let foreign_tx_root_ep = foreign_tx_root_sk.verifying_key().to_encoded_point(false);
        let mut foreign_tx_root_pk64 = [0u8; 64];
        foreign_tx_root_pk64.copy_from_slice(&foreign_tx_root_ep.as_bytes()[1..65]);

        contract.set_domain_root_pubkeys(
            format_near_secp256k1_pubkey(&sign_root_pk64),
            format_near_secp256k1_pubkey(&foreign_tx_root_pk64),
        );

        // Sync genuine OutLayer worker approved measurements
        let sync_call = contract.sync_approved_measurements();
        assert_eq!(sync_call.receiver_id.as_str(), "worker.outlayer.testnet");
        assert_eq!(sync_call.method_name, "get_approved_measurements");
        let hex_measurements: Vec<HexMeasurements> =
            serde_json::from_str(WORKER_MEASUREMENTS_JSON).unwrap();
        let count = contract.on_measurements_synced(Ok(hex_measurements));
        assert_eq!(count, 129);
        assert_eq!(contract.approved_measurements_count(), 129);

        // Load genuine OutLayer attestation 1500
        let record: OutLayerAttestationRecord =
            serde_json::from_str(ATTESTATION_1500_JSON).unwrap();
        let quote_bytes = base64::engine::general_purpose::STANDARD
            .decode(record.tdx_quote.trim())
            .unwrap();
        let parsed_quote = TdxQuote::parse(&quote_bytes).unwrap();
        let task_meta = record.to_v1_task_inputs().unwrap();

        let wasm_hash = task_meta.wasm_hash.unwrap();
        let input_hash = task_meta.input_hash.unwrap();
        let output_hash = hashing::enclave_output_hash(WorkOutcome::Pass, &task_meta.output_hash);
        contract.add_expected_wasm_hash(hex::encode(wasm_hash));

        // Build and co-sign ReceiptV1 bound to genuine OutLayer quote 1500
        let buyer_sk = Ed25519SigningKey::from_bytes(&[0x10u8; 32]);
        let provider_sk = Ed25519SigningKey::from_bytes(&[0x20u8; 32]);
        let settlement_commitment = hashing::confidential_settlement_commitment(
            &[0x66u8; 32],
            250_000_000,
            &[0x88u8; 32],
            &[0x77u8; 32],
        );
        let evidence = hashing::evidence_commitment(
            &wasm_hash,
            &input_hash,
            &output_hash,
            &settlement_commitment,
        );
        let provider_identity = "provider.testnet".to_string();
        let nonce = 1u64;
        let receipt_id = hashing::receipt_id(&provider_identity, nonce, &evidence);

        let mut receipt = ReceiptV1 {
            receipt_id,
            schema_version: 1,
            provider_identity,
            work_category: "ai_acceptance_validation".to_string(),
            outcome: WorkOutcome::Pass,
            verifier_measurement: parsed_quote.measurements.digest(),
            wasm_hash,
            input_hash,
            output_hash,
            evidence_commitment: evidence,
            buyer_pubkey: buyer_sk.verifying_key().to_bytes(),
            provider_pubkey: provider_sk.verifying_key().to_bytes(),
            buyer_signature: [0u8; 64],
            provider_signature: [0u8; 64],
            nonce,
            created_at: 1_771_587_262,
            confidential_settlement_commitment: settlement_commitment,
            borrower_evm_address: [0x22u8; 20],
            max_credit_principal: 250_000_000,
            attested_revenue: 250_000_000,
            consequence_state: ConsequenceState::RegisteredVerified,
            foreign_chain_id: None,
            foreign_tx_hash: None,
            lender_id: None,
            verified_finality_evidence: None,
        };
        let payload = receipt.signing_payload();
        receipt.buyer_signature = sign_payload(
            Party::Buyer,
            &buyer_sk,
            "testnet",
            "receipt-registry.testnet",
            &payload,
        )
        .unwrap();
        receipt.provider_signature = sign_payload(
            Party::Provider,
            &provider_sk,
            "testnet",
            "receipt-registry.testnet",
            &payload,
        )
        .unwrap();

        TestFixtures {
            contract,
            sign_root_secret,
            foreign_tx_root_secret,
            receipt,
            quote_bytes,
            task_meta,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn full_lifecycle_genuine_quote_to_consumed_verified_consequence_graph() {
        let mut f = build_fixtures();

        // 1. Register receipt with genuine OutLayer TDX quote 1500
        setup_context("provider.testnet", 0);
        let id_hex = f.contract.register_receipt(
            f.receipt.clone(),
            f.quote_bytes.clone(),
            f.task_meta.clone(),
        );
        assert_eq!(id_hex, hex::encode(f.receipt.receipt_id));

        let stored = f.contract.get_receipt(id_hex.clone()).unwrap();
        assert_eq!(
            stored.consequence_state,
            ConsequenceState::RegisteredVerified
        );

        // 2. Authorize loan on Base Sepolia
        setup_context("provider.testnet", 1);
        let borrower_hex = "2222222222222222222222222222222222222222";
        let vault_hex = "5555555555555555555555555555555555555555";
        let principal = 250_000_000u128;
        let deadline = 1_800_000_000u64;

        let sign_call = f.contract.authorize_loan(
            id_hex.clone(),
            borrower_hex.to_string(),
            U128(principal),
            U128(5_000_000),
            1_772_200_000,
            vault_hex.to_string(),
            deadline,
        );
        assert_eq!(sign_call.receiver_id.as_str(), "v1.signer-prod.testnet");
        assert_eq!(sign_call.method_name, "sign");
        let sign_json: serde_json::Value = serde_json::from_slice(&sign_call.args).unwrap();
        assert_eq!(sign_json["request"]["domain_id"], 0);
        assert_eq!(sign_json["request"]["path"], "receipt-credit-vault-v1");

        // State must be optimistically locked to LoanAuthorized before callback
        assert_eq!(
            f.contract
                .get_receipt(id_hex.clone())
                .unwrap()
                .consequence_state,
            ConsequenceState::LoanAuthorized
        );

        // Simulate MPC threshold signing with derived child key (domain 0)
        let pending_loan = f
            .contract
            .pending_loan_requests
            .get(&f.receipt.receipt_id)
            .unwrap()
            .clone();
        let tweak = derive_mpc_tweak("receipt-registry.testnet", DEFAULT_DERIVATION_PATH);
        let tweak_scalar = Scalar::from_repr(tweak.into()).unwrap();
        let child_sk =
            Secp256k1SigningKey::from_bytes(&(f.sign_root_secret + tweak_scalar).to_bytes())
                .unwrap();
        let (sig, rec_id) = child_sk
            .sign_prehash_recoverable(&pending_loan.eip712_digest)
            .unwrap();
        let mpc_sig = MpcSecp256k1Signature::from_r_s_v(
            &sig.r().to_bytes().into(),
            &sig.s().to_bytes().into(),
            rec_id.to_byte(),
        );

        setup_context("receipt-registry.testnet", 0);
        let packet = f
            .contract
            .on_loan_authorization_signed(f.receipt.receipt_id, Ok(mpc_sig))
            .expect("loan authorization callback should succeed");

        // Verify that ecrecover on the packet matches derive_vault_authorized_signer_evm_address()
        let recovered_evm = recover_eip712_signer(
            &packet.eip712_digest,
            &packet.signature_r,
            &packet.signature_s,
            packet.signature_v,
        )
        .unwrap();
        assert_eq!(
            format!("0x{}", hex::encode(recovered_evm)),
            f.contract.derive_vault_authorized_signer_evm_address()
        );

        // 3. Verify Base Sepolia LoanDrawn consequence via MPC ForeignTx (domain 3)
        setup_context("provider.testnet", 1);
        let base_tx_hash = [0xaa; 32];
        let base_block_hash = [0xbb; 32];
        let lender_id = [0xcc; 32];
        let mut borrower_topic = [0u8; 32];
        borrower_topic[12..32].copy_from_slice(&[0x22; 20]);

        let expected_log = EvmLog {
            removed: false,
            log_index: 0,
            transaction_index: 0,
            transaction_hash: Hash256(base_tx_hash),
            block_hash: Hash256(base_block_hash),
            block_number: 9_876_543,
            address: Hash160([0x55; 20]),
            data: encode_loan_drawn_data(principal, &f.receipt.evidence_commitment),
            topics: vec![
                Hash256(loan_drawn_topic0()),
                Hash256(f.receipt.receipt_id),
                Hash256(borrower_topic),
                Hash256(lender_id),
            ],
        };

        let verify_call = f.contract.verify_loan_consequence(
            id_hex.clone(),
            hex::encode(base_tx_hash),
            hex::encode(base_block_hash),
            expected_log,
            EvmFinality::Finalized,
        );
        assert_eq!(verify_call.receiver_id.as_str(), "v1.signer-prod.testnet");
        assert_eq!(verify_call.method_name, "verify_foreign_transaction");
        let verify_json: serde_json::Value = serde_json::from_slice(&verify_call.args).unwrap();
        assert_eq!(verify_json["request"]["domain_id"], 3);
        assert_eq!(verify_json["request"]["payload_version"], 1);
        assert_eq!(
            verify_json["request"]["request"]["Base"]["finality"],
            "Finalized"
        );
        assert_eq!(
            f.contract
                .get_receipt(id_hex.clone())
                .unwrap()
                .consequence_state,
            ConsequenceState::VerificationPending
        );

        let pending_ver = f
            .contract
            .pending_consequence_requests
            .get(&f.receipt.receipt_id)
            .unwrap()
            .clone();

        // Sign expected_payload_hash directly with domain 3 root key (no tweak for ForeignTx!)
        let domain3_sk =
            Secp256k1SigningKey::from_bytes(&f.foreign_tx_root_secret.to_bytes()).unwrap();
        let (ftx_sig, ftx_rec) = domain3_sk
            .sign_prehash_recoverable(&pending_ver.expected_payload_hash)
            .unwrap();
        let ftx_response = VerifyForeignTransactionResponseDto {
            payload_hash: Hash256(pending_ver.expected_payload_hash),
            signature: MpcSecp256k1Signature::from_r_s_v(
                &ftx_sig.r().to_bytes().into(),
                &ftx_sig.s().to_bytes().into(),
                ftx_rec.to_byte(),
            ),
        };

        setup_context("receipt-registry.testnet", 0);
        let ok = f
            .contract
            .on_foreign_tx_verified(f.receipt.receipt_id, Ok(ftx_response));
        assert!(ok);

        // 4. Verify Consequence Graph & ConsequenceProofView
        let proof = f.contract.verify_consequence_proof(id_hex.clone()).unwrap();
        assert!(proof.is_mpc_consequence_verified);
        assert_eq!(
            proof.receipt.consequence_state,
            ConsequenceState::ConsumedVerified
        );
        assert_eq!(
            proof.receipt.foreign_chain_id.as_deref(),
            Some("eip155:84532")
        );
        assert_eq!(proof.receipt.foreign_tx_hash, Some(base_tx_hash));
        assert_eq!(
            proof.receipt.lender_id.as_deref(),
            Some(hex::encode(lender_id).as_str())
        );

        let graph = f
            .contract
            .get_provider_credit_graph("provider.testnet".to_string());
        assert_eq!(graph.len(), 1);
        assert_eq!(graph[0].receipt_id, f.receipt.receipt_id);
        assert_eq!(graph[0].principal_amount, principal);
        assert_eq!(graph[0].foreign_tx_hash, base_tx_hash);
    }

    #[test]
    #[should_panic(expected = "receipt outcome is not PASS")]
    fn fail_outcome_receipt_rejected() {
        let mut f = build_fixtures();
        f.receipt.outcome = WorkOutcome::Fail;
        setup_context("provider.testnet", 0);
        f.contract
            .register_receipt(f.receipt, f.quote_bytes, f.task_meta);
    }

    #[test]
    #[should_panic(expected = "nonce 1 already used by provider")]
    fn replayed_nonce_rejected() {
        let mut f = build_fixtures();
        setup_context("provider.testnet", 0);
        f.contract.register_receipt(
            f.receipt.clone(),
            f.quote_bytes.clone(),
            f.task_meta.clone(),
        );
        f.contract
            .register_receipt(f.receipt, f.quote_bytes, f.task_meta);
    }

    #[test]
    #[should_panic(expected = "receipt.verifier_measurement does not match TDX quote measurements")]
    fn tampered_quote_measurement_bytes_rejected() {
        let mut f = build_fixtures();
        f.quote_bytes[200] ^= 0x01;
        setup_context("provider.testnet", 0);
        f.contract
            .register_receipt(f.receipt, f.quote_bytes, f.task_meta);
    }

    #[test]
    #[should_panic(expected = "TDX quote signature invalid")]
    fn tampered_quote_signature_or_header_rejected() {
        let mut f = build_fixtures();
        // Offset 60 is inside tee_tcb_svn (signed body, outside mrtd/rtmr0..3)
        f.quote_bytes[60] ^= 0x01;
        setup_context("provider.testnet", 0);
        f.contract
            .register_receipt(f.receipt, f.quote_bytes, f.task_meta);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn failed_or_forged_callbacks_roll_back_state_and_never_mark_verified() {
        let mut f = build_fixtures();
        setup_context("provider.testnet", 0);
        let id_hex = f.contract.register_receipt(
            f.receipt.clone(),
            f.quote_bytes.clone(),
            f.task_meta.clone(),
        );

        // Authorize loan
        setup_context("provider.testnet", 1);
        let _ = f.contract.authorize_loan(
            id_hex.clone(),
            "2222222222222222222222222222222222222222".to_string(),
            U128(100_000_000),
            U128(2_000_000),
            1_772_200_000,
            "5555555555555555555555555555555555555555".to_string(),
            1_800_000_000,
        );

        // Simulate MPC sign failure -> rolls back to RegisteredVerified
        setup_context("receipt-registry.testnet", 0);
        let res = f
            .contract
            .on_loan_authorization_signed(f.receipt.receipt_id, Err(PromiseError::Failed));
        assert!(res.is_none());
        assert_eq!(
            f.contract
                .get_receipt(id_hex.clone())
                .unwrap()
                .consequence_state,
            ConsequenceState::RegisteredVerified
        );

        // Retry authorize_loan and succeed
        setup_context("provider.testnet", 1);
        let _ = f.contract.authorize_loan(
            id_hex.clone(),
            "2222222222222222222222222222222222222222".to_string(),
            U128(100_000_000),
            U128(2_000_000),
            1_772_200_000,
            "5555555555555555555555555555555555555555".to_string(),
            1_800_000_000,
        );
        let pending_loan = f
            .contract
            .pending_loan_requests
            .get(&f.receipt.receipt_id)
            .unwrap()
            .clone();
        let tweak = derive_mpc_tweak("receipt-registry.testnet", DEFAULT_DERIVATION_PATH);
        let tweak_scalar = Scalar::from_repr(tweak.into()).unwrap();
        let child_sk =
            Secp256k1SigningKey::from_bytes(&(f.sign_root_secret + tweak_scalar).to_bytes())
                .unwrap();
        let (sig, rec_id) = child_sk
            .sign_prehash_recoverable(&pending_loan.eip712_digest)
            .unwrap();
        setup_context("receipt-registry.testnet", 0);
        assert!(f
            .contract
            .on_loan_authorization_signed(
                f.receipt.receipt_id,
                Ok(MpcSecp256k1Signature::from_r_s_v(
                    &sig.r().to_bytes().into(),
                    &sig.s().to_bytes().into(),
                    rec_id.to_byte(),
                )),
            )
            .is_some());

        // Start verify_loan_consequence
        setup_context("provider.testnet", 1);
        let base_tx_hash = [0xaa; 32];
        let base_block_hash = [0xbb; 32];
        let mut borrower_topic = [0u8; 32];
        borrower_topic[12..32].copy_from_slice(&[0x22; 20]);
        let expected_log = EvmLog {
            removed: false,
            log_index: 0,
            transaction_index: 0,
            transaction_hash: Hash256(base_tx_hash),
            block_hash: Hash256(base_block_hash),
            block_number: 100,
            address: Hash160([0x55; 20]),
            data: encode_loan_drawn_data(100_000_000, &f.receipt.evidence_commitment),
            topics: vec![
                Hash256(loan_drawn_topic0()),
                Hash256(f.receipt.receipt_id),
                Hash256(borrower_topic),
                Hash256([0xcc; 32]),
            ],
        };
        let _ = f.contract.verify_loan_consequence(
            id_hex.clone(),
            hex::encode(base_tx_hash),
            hex::encode(base_block_hash),
            expected_log,
            EvmFinality::Finalized,
        );
        let pending_ver = f
            .contract
            .pending_consequence_requests
            .get(&f.receipt.receipt_id)
            .unwrap()
            .clone();

        // Forge callback signature using wrong key (sign_root_secret instead of foreign_tx_root_secret)
        let wrong_sk = Secp256k1SigningKey::from_bytes(&f.sign_root_secret.to_bytes()).unwrap();
        let (bad_sig, bad_rec) = wrong_sk
            .sign_prehash_recoverable(&pending_ver.expected_payload_hash)
            .unwrap();
        let forged_resp = VerifyForeignTransactionResponseDto {
            payload_hash: Hash256(pending_ver.expected_payload_hash),
            signature: MpcSecp256k1Signature::from_r_s_v(
                &bad_sig.r().to_bytes().into(),
                &bad_sig.s().to_bytes().into(),
                bad_rec.to_byte(),
            ),
        };

        setup_context("receipt-registry.testnet", 0);
        let verified = f
            .contract
            .on_foreign_tx_verified(f.receipt.receipt_id, Ok(forged_resp));
        assert!(!verified);
        assert_eq!(
            f.contract
                .get_receipt(id_hex.clone())
                .unwrap()
                .consequence_state,
            ConsequenceState::LoanAuthorized
        );
        assert_eq!(
            f.contract
                .get_provider_credit_graph("provider.testnet".to_string()),
            Vec::<ConsequenceNode>::new()
        );
    }

    #[test]
    #[should_panic(expected = "receipt signature verification failed")]
    fn invalid_buyer_signature_rejected() {
        let mut f = build_fixtures();
        f.receipt.buyer_signature[0] ^= 0x01;
        setup_context("provider.testnet", 0);
        f.contract
            .register_receipt(f.receipt, f.quote_bytes, f.task_meta);
    }

    #[test]
    #[should_panic(expected = "wasm_hash is not in expected_wasm_hashes allowlist")]
    fn unapproved_wasm_hash_rejected() {
        let mut f = build_fixtures();
        setup_context("owner.testnet", 0);
        f.contract.expected_wasm_hashes.clear();
        f.contract.add_expected_wasm_hash(hex::encode([0x99u8; 32]));
        setup_context("provider.testnet", 0);
        f.contract
            .register_receipt(f.receipt, f.quote_bytes, f.task_meta);
    }

    #[test]
    #[should_panic(expected = "receipt is not in RegisteredVerified state")]
    fn double_authorize_loan_rejected() {
        let mut f = build_fixtures();
        setup_context("provider.testnet", 0);
        let id_hex = f.contract.register_receipt(
            f.receipt.clone(),
            f.quote_bytes.clone(),
            f.task_meta.clone(),
        );
        setup_context("provider.testnet", 1);
        let _ = f.contract.authorize_loan(
            id_hex.clone(),
            "2222222222222222222222222222222222222222".to_string(),
            U128(100_000_000),
            U128(2_000_000),
            1_772_200_000,
            "5555555555555555555555555555555555555555".to_string(),
            1_800_000_000,
        );
        // Second call while already LoanAuthorized must panic
        let _ = f.contract.authorize_loan(
            id_hex,
            "2222222222222222222222222222222222222222".to_string(),
            U128(100_000_000),
            U128(2_000_000),
            1_772_200_000,
            "5555555555555555555555555555555555555555".to_string(),
            1_800_000_000,
        );
    }

    #[test]
    #[should_panic(expected = "invalid LoanDrawn log")]
    fn forged_loan_drawn_log_principal_rejected() {
        let mut f = build_fixtures();
        setup_context("provider.testnet", 0);
        let id_hex = f.contract.register_receipt(
            f.receipt.clone(),
            f.quote_bytes.clone(),
            f.task_meta.clone(),
        );
        setup_context("provider.testnet", 1);
        let _ = f.contract.authorize_loan(
            id_hex.clone(),
            "2222222222222222222222222222222222222222".to_string(),
            U128(100_000_000),
            U128(2_000_000),
            1_772_200_000,
            "5555555555555555555555555555555555555555".to_string(),
            1_800_000_000,
        );
        let pending_loan = f
            .contract
            .pending_loan_requests
            .get(&f.receipt.receipt_id)
            .unwrap()
            .clone();
        let tweak = derive_mpc_tweak("receipt-registry.testnet", DEFAULT_DERIVATION_PATH);
        let tweak_scalar = Scalar::from_repr(tweak.into()).unwrap();
        let child_sk =
            Secp256k1SigningKey::from_bytes(&(f.sign_root_secret + tweak_scalar).to_bytes())
                .unwrap();
        let (sig, rec_id) = child_sk
            .sign_prehash_recoverable(&pending_loan.eip712_digest)
            .unwrap();
        setup_context("receipt-registry.testnet", 0);
        assert!(f
            .contract
            .on_loan_authorization_signed(
                f.receipt.receipt_id,
                Ok(MpcSecp256k1Signature::from_r_s_v(
                    &sig.r().to_bytes().into(),
                    &sig.s().to_bytes().into(),
                    rec_id.to_byte(),
                )),
            )
            .is_some());

        setup_context("provider.testnet", 1);
        let base_tx_hash = [0xaa; 32];
        let base_block_hash = [0xbb; 32];
        let mut borrower_topic = [0u8; 32];
        borrower_topic[12..32].copy_from_slice(&[0x22; 20]);
        // Tamper principal in log data (999_999_999 instead of 100_000_000)
        let forged_log = EvmLog {
            removed: false,
            log_index: 0,
            transaction_index: 0,
            transaction_hash: Hash256(base_tx_hash),
            block_hash: Hash256(base_block_hash),
            block_number: 100,
            address: Hash160([0x55; 20]),
            data: encode_loan_drawn_data(999_999_999, &f.receipt.evidence_commitment),
            topics: vec![
                Hash256(loan_drawn_topic0()),
                Hash256(f.receipt.receipt_id),
                Hash256(borrower_topic),
                Hash256([0xcc; 32]),
            ],
        };
        let _ = f.contract.verify_loan_consequence(
            id_hex,
            hex::encode(base_tx_hash),
            hex::encode(base_block_hash),
            forged_log,
            EvmFinality::Finalized,
        );
    }

    #[test]
    #[should_panic(
        expected = "borrower_evm_address does not match co-signed receipt.borrower_evm_address"
    )]
    fn authorize_loan_rejects_mismatched_borrower_address() {
        let mut f = build_fixtures();
        setup_context("provider.testnet", 0);
        let id_hex = f.contract.register_receipt(
            f.receipt.clone(),
            f.quote_bytes.clone(),
            f.task_meta.clone(),
        );
        setup_context("provider.testnet", 1);
        let _ = f.contract.authorize_loan(
            id_hex,
            "3333333333333333333333333333333333333333".to_string(),
            U128(100_000_000),
            U128(2_000_000),
            1_772_200_000,
            "5555555555555555555555555555555555555555".to_string(),
            1_800_000_000,
        );
    }

    #[test]
    #[should_panic(expected = "principal_amount exceeds co-signed receipt.max_credit_principal")]
    fn authorize_loan_rejects_principal_exceeding_receipt_credit_limit() {
        let mut f = build_fixtures();
        setup_context("provider.testnet", 0);
        let id_hex = f.contract.register_receipt(
            f.receipt.clone(),
            f.quote_bytes.clone(),
            f.task_meta.clone(),
        );
        setup_context("provider.testnet", 1);
        let _ = f.contract.authorize_loan(
            id_hex,
            "2222222222222222222222222222222222222222".to_string(),
            U128(250_000_001),
            U128(2_000_000),
            1_772_200_000,
            "5555555555555555555555555555555555555555".to_string(),
            1_800_000_000,
        );
    }

    #[test]
    #[should_panic(expected = "only receipt.provider_identity may call authorize_loan")]
    fn authorize_loan_rejects_non_provider_caller() {
        let mut f = build_fixtures();
        setup_context("provider.testnet", 0);
        let id_hex = f.contract.register_receipt(
            f.receipt.clone(),
            f.quote_bytes.clone(),
            f.task_meta.clone(),
        );
        setup_context("attacker.testnet", 1);
        let _ = f.contract.authorize_loan(
            id_hex,
            "2222222222222222222222222222222222222222".to_string(),
            U128(100_000_000),
            U128(2_000_000),
            1_772_200_000,
            "5555555555555555555555555555555555555555".to_string(),
            1_800_000_000,
        );
    }

    #[test]
    #[should_panic(expected = "outlayer task_id 1500 already consumed by a registered receipt")]
    fn replayed_quote_task_id_with_fresh_nonce_rejected() {
        let mut f = build_fixtures();
        setup_context("provider.testnet", 0);
        f.contract.register_receipt(
            f.receipt.clone(),
            f.quote_bytes.clone(),
            f.task_meta.clone(),
        );
        assert!(f.contract.is_task_id_consumed(f.task_meta.task_id));

        let buyer_sk = Ed25519SigningKey::from_bytes(&[0x10u8; 32]);
        let provider_sk = Ed25519SigningKey::from_bytes(&[0x20u8; 32]);
        let mut replayed = f.receipt;
        replayed.nonce = 2;
        replayed.receipt_id = hashing::receipt_id(
            &replayed.provider_identity,
            replayed.nonce,
            &replayed.evidence_commitment,
        );
        let payload = replayed.signing_payload();
        replayed.buyer_signature = sign_payload(
            Party::Buyer,
            &buyer_sk,
            "testnet",
            "receipt-registry.testnet",
            &payload,
        )
        .unwrap();
        replayed.provider_signature = sign_payload(
            Party::Provider,
            &provider_sk,
            "testnet",
            "receipt-registry.testnet",
            &payload,
        )
        .unwrap();

        f.contract
            .register_receipt(replayed, f.quote_bytes, f.task_meta);
    }

    #[test]
    #[should_panic(
        expected = "receipt.output_hash does not commit receipt.outcome into outlayer_task_meta.output_hash"
    )]
    fn fail_committed_enclave_output_hash_rejected_when_claiming_pass() {
        let mut f = build_fixtures();
        setup_context("provider.testnet", 0);

        let buyer_sk = Ed25519SigningKey::from_bytes(&[0x10u8; 32]);
        let provider_sk = Ed25519SigningKey::from_bytes(&[0x20u8; 32]);

        let fail_output_hash =
            hashing::enclave_output_hash(WorkOutcome::Fail, &f.task_meta.output_hash);
        let evidence = hashing::evidence_commitment(
            &f.receipt.wasm_hash,
            &f.receipt.input_hash,
            &fail_output_hash,
            &f.receipt.confidential_settlement_commitment,
        );
        f.receipt.output_hash = fail_output_hash;
        f.receipt.evidence_commitment = evidence;
        f.receipt.receipt_id =
            hashing::receipt_id(&f.receipt.provider_identity, f.receipt.nonce, &evidence);
        f.receipt.outcome = WorkOutcome::Pass;
        let payload = f.receipt.signing_payload();
        f.receipt.buyer_signature = sign_payload(
            Party::Buyer,
            &buyer_sk,
            "testnet",
            "receipt-registry.testnet",
            &payload,
        )
        .unwrap();
        f.receipt.provider_signature = sign_payload(
            Party::Provider,
            &provider_sk,
            "testnet",
            "receipt-registry.testnet",
            &payload,
        )
        .unwrap();

        f.contract
            .register_receipt(f.receipt, f.quote_bytes, f.task_meta);
    }

    const ATTESTATION_3000_JSON: &str =
        include_str!("../../receipt-core/tests/fixtures/outlayer_attestation_3000.json");

    #[test]
    fn advance_cap_enforces_1_5x_trailing_14d_revenue_and_fixed_cap() {
        let mut f = build_fixtures();
        setup_context("owner.testnet", 0);
        f.contract.set_underwriting_policy(U128(5_000_000), 2);
        rt::set_test_timestamp(1_771_590_000);

        let buyer1 = Ed25519SigningKey::from_bytes(&[0x10u8; 32]);
        let buyer2 = Ed25519SigningKey::from_bytes(&[0x11u8; 32]);
        let provider_sk = Ed25519SigningKey::from_bytes(&[0x20u8; 32]);

        let (r1, q1, tm1) = build_additional_signed_receipt(
            &mut f.contract,
            &buyer1,
            &provider_sk,
            ATTESTATION_1500_JSON,
            10,
            1_771_587_262,
            1_000_000, // $1.00
            10_000_000,
        );
        let (r2, q2, tm2) = build_additional_signed_receipt(
            &mut f.contract,
            &buyer2,
            &provider_sk,
            ATTESTATION_3000_JSON,
            11,
            1_771_588_000,
            1_000_000, // $1.00 -> total = $2.00, 1.5x = $3.00 < fixed_cap $5.00
            10_000_000,
        );

        setup_context("provider.testnet", 0);
        let _ = f.contract.register_receipt(r1, q1, tm1);
        let id2 = f.contract.register_receipt(r2, q2, tm2);

        let rev = f
            .contract
            .get_trailing_14d_revenue("provider.testnet".into(), None);
        assert_eq!(rev.total_revenue.0, 2_000_000);
        assert_eq!(rev.distinct_payers, 2);
        assert_eq!(rev.advance_cap.0, 3_000_000);

        // Requesting 3_000_001 (> 1.5x $2.00 = $3.00) must panic
        setup_context("provider.testnet", 1);
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            f.contract.authorize_loan(
                id2.clone(),
                "2222222222222222222222222222222222222222".into(),
                U128(3_000_001),
                U128(60_000),
                1_772_200_000,
                "5555555555555555555555555555555555555555".into(),
                1_800_000_000,
            );
        }));
        assert!(res.is_err());

        // Requesting 3_000_000 succeeds
        let _ = f.contract.authorize_loan(
            id2,
            "2222222222222222222222222222222222222222".into(),
            U128(3_000_000),
            U128(60_000),
            1_772_200_000,
            "5555555555555555555555555555555555555555".into(),
            1_800_000_000,
        );
    }

    #[test]
    fn advance_cap_excludes_receipts_older_than_14_days() {
        let mut f = build_fixtures();
        setup_context("owner.testnet", 0);
        f.contract.set_underwriting_policy(U128(5_000_000), 2);

        let buyer1 = Ed25519SigningKey::from_bytes(&[0x10u8; 32]);
        let buyer2 = Ed25519SigningKey::from_bytes(&[0x11u8; 32]);
        let provider_sk = Ed25519SigningKey::from_bytes(&[0x20u8; 32]);

        let (r1, q1, tm1) = build_additional_signed_receipt(
            &mut f.contract,
            &buyer1,
            &provider_sk,
            ATTESTATION_1500_JSON,
            20,
            1_770_000_000, // older than 14 days at t=1_771_590_000 (diff = 1,590,000 > 1,209,600)
            4_000_000,
            5_000_000,
        );
        let (r2, q2, tm2) = build_additional_signed_receipt(
            &mut f.contract,
            &buyer2,
            &provider_sk,
            ATTESTATION_3000_JSON,
            21,
            1_771_588_000,
            2_000_000,
            5_000_000,
        );
        setup_context("provider.testnet", 0);
        let _ = f.contract.register_receipt(r1, q1, tm1);
        let _ = f.contract.register_receipt(r2, q2, tm2);

        rt::set_test_timestamp(1_771_590_000);
        let rev = f
            .contract
            .get_trailing_14d_revenue("provider.testnet".into(), None);
        assert_eq!(rev.eligible_receipts, 1);
        assert_eq!(rev.distinct_payers, 1);
        assert_eq!(rev.total_revenue.0, 2_000_000);
        assert_eq!(rev.advance_cap.0, 0);
    }

    #[test]
    #[should_panic(expected = "insufficient distinct independent payers in trailing 14-day window")]
    fn distinct_independent_payers_required_rejects_single_buyer_wash_trade() {
        let mut f = build_fixtures();
        setup_context("owner.testnet", 0);
        f.contract.set_underwriting_policy(U128(5_000_000), 2);

        let same_buyer = Ed25519SigningKey::from_bytes(&[0x10u8; 32]);
        let provider_sk = Ed25519SigningKey::from_bytes(&[0x20u8; 32]);

        let (r1, q1, tm1) = build_additional_signed_receipt(
            &mut f.contract,
            &same_buyer,
            &provider_sk,
            ATTESTATION_1500_JSON,
            30,
            1_771_587_262,
            3_000_000,
            5_000_000,
        );
        let (r2, q2, tm2) = build_additional_signed_receipt(
            &mut f.contract,
            &same_buyer,
            &provider_sk,
            ATTESTATION_3000_JSON,
            31,
            1_771_588_000,
            3_000_000,
            5_000_000,
        );
        setup_context("provider.testnet", 0);
        let _ = f.contract.register_receipt(r1, q1, tm1);
        let id2 = f.contract.register_receipt(r2, q2, tm2);

        let rev = f
            .contract
            .get_trailing_14d_revenue("provider.testnet".into(), None);
        assert_eq!(rev.distinct_payers, 1);
        assert_eq!(rev.advance_cap.0, 0);

        setup_context("provider.testnet", 1);
        let _ = f.contract.authorize_loan(
            id2,
            "2222222222222222222222222222222222222222".into(),
            U128(4_000_000),
            U128(80_000),
            1_772_200_000,
            "5555555555555555555555555555555555555555".into(),
            1_800_000_000,
        );
    }

    #[test]
    #[should_panic(expected = "registry is paused by owner")]
    fn paused_registry_rejects_authorize_loan() {
        let mut f = build_fixtures();
        setup_context("provider.testnet", 0);
        let id_hex = f.contract.register_receipt(
            f.receipt.clone(),
            f.quote_bytes.clone(),
            f.task_meta.clone(),
        );
        setup_context("owner.testnet", 0);
        f.contract.set_paused(true);
        assert!(f.contract.is_paused());
        assert_eq!(
            f.contract
                .compute_advance_cap("provider.testnet".into(), None)
                .0,
            0
        );

        setup_context("provider.testnet", 1);
        let _ = f.contract.authorize_loan(
            id_hex,
            "2222222222222222222222222222222222222222".into(),
            U128(100_000_000),
            U128(2_000_000),
            1_772_200_000,
            "5555555555555555555555555555555555555555".into(),
            1_800_000_000,
        );
    }
}
