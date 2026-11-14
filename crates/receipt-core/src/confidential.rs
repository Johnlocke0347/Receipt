//! Confidential settlement adapter.
//!
//! NEAR Intents is mainnet-only (OutLayer `API.md`), so RECEIPT exposes one trait with two
//! clearly labeled implementations:
//!
//! * [`OneClickIntentBuilder`]: builds the live 1Click Confidential Intents quote request and
//!   the NEP-413 signed intent payload. It performs **no network I/O**; the orchestrator sends it.
//! * [`TestnetConfidentialSettlementBridge`]: **testnet stand-in**. No funds move; it produces
//!   the same salted `confidential_settlement_commitment` so the rest of the pipeline is
//!   exercised end to end. Receipts produced this way carry [`SettlementMode::TestnetBridge`].

use borsh::BorshSerialize;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::error::ReceiptError;
use crate::hashing::{confidential_settlement_commitment, sha256_concat};

/// NEP-413 message tag: `2^31 + 413`.
pub const NEP413_TAG: u32 = 2_147_484_061;

/// Which settlement path produced a commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementMode {
    /// Real 1Click / Confidential Intents settlement (mainnet).
    Live1Click,
    /// Testnet stand-in: commitment only, no funds moved.
    TestnetBridge,
}

/// Private commercial terms. These never appear in a [`crate::receipt::ReceiptV1`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateTerms {
    /// 32-byte intent identifier (for live mode, the NEP-413 payload hash).
    pub intent_id: [u8; 32],
    /// Settlement amount in the asset's smallest unit.
    pub amount: u128,
    /// Currency / asset identifier (e.g. `nep141:usdc.near`).
    pub currency: String,
    /// Buyer-chosen random salt (hiding factor).
    pub buyer_salt: [u8; 32],
}

/// Output of a settlement adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementOutcome {
    /// Commitment placed in the receipt.
    pub commitment: [u8; 32],
    /// Which path produced it.
    pub mode: SettlementMode,
}

/// Common interface for settlement backends.
pub trait ConfidentialSettlementAdapter {
    /// Produce the settlement commitment for `terms`.
    ///
    /// # Errors
    /// Implementation-specific failures (invalid terms).
    fn settle(&self, terms: &PrivateTerms) -> Result<SettlementOutcome, ReceiptError>;
}

/// `SHA256(currency)`.
#[must_use]
pub fn currency_hash(currency: &str) -> [u8; 32] {
    sha256_concat(&[currency.as_bytes()])
}

/// Commitment for `terms` (shared by every adapter).
#[must_use]
pub fn commit_terms(terms: &PrivateTerms) -> [u8; 32] {
    confidential_settlement_commitment(
        &terms.intent_id,
        terms.amount,
        &currency_hash(&terms.currency),
        &terms.buyer_salt,
    )
}

fn validate_terms(terms: &PrivateTerms) -> Result<(), ReceiptError> {
    if terms.amount == 0 {
        return Err(ReceiptError::InvalidInput("amount must be > 0".into()));
    }
    if terms.currency.is_empty() {
        return Err(ReceiptError::InvalidInput(
            "currency must not be empty".into(),
        ));
    }
    if terms.buyer_salt == [0u8; 32] {
        return Err(ReceiptError::InvalidInput(
            "buyer_salt must be random, not all zero".into(),
        ));
    }
    Ok(())
}

/// Testnet stand-in for Confidential Intents. See module docs.
#[derive(Clone, Copy, Debug, Default)]
pub struct TestnetConfidentialSettlementBridge;

impl ConfidentialSettlementAdapter for TestnetConfidentialSettlementBridge {
    fn settle(&self, terms: &PrivateTerms) -> Result<SettlementOutcome, ReceiptError> {
        validate_terms(terms)?;
        Ok(SettlementOutcome {
            commitment: commit_terms(terms),
            mode: SettlementMode::TestnetBridge,
        })
    }
}

/// 1Click `POST /v0/quote` request body for a confidential-intents swap/transfer.
///
/// Field names follow the public 1Click API; verify against the live schema before mainnet use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OneClickQuoteRequest {
    /// `true` requests a dry-run quote without a deposit address.
    pub dry: bool,
    /// `EXACT_INPUT` or `EXACT_OUTPUT`.
    pub swap_type: String,
    /// Slippage in basis points.
    pub slippage_tolerance: u32,
    /// Origin asset id.
    pub origin_asset: String,
    /// Always `CONFIDENTIAL_INTENTS` for this adapter.
    pub deposit_type: String,
    /// Destination asset id.
    pub destination_asset: String,
    /// Amount in smallest units, as a decimal string.
    pub amount: String,
    /// Refund address.
    pub refund_to: String,
    /// Recipient address.
    pub recipient: String,
    /// RFC 3339 deadline.
    pub deadline: String,
}

/// NEP-413 payload.
#[derive(BorshSerialize)]
struct Nep413Payload<'a> {
    message: &'a str,
    nonce: [u8; 32],
    recipient: &'a str,
    callback_url: Option<&'a str>,
}

/// A NEP-413 signed intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedIntent {
    /// SHA-256 of `borsh(tag) || borsh(payload)` (also usable as `intent_id`).
    pub intent_hash: [u8; 32],
    /// Ed25519 signature over `intent_hash`.
    pub signature: [u8; 64],
    /// Signer public key.
    pub public_key: [u8; 32],
}

/// Builder for live 1Click requests and NEP-413 intents. No network I/O.
#[derive(Clone, Copy, Debug, Default)]
pub struct OneClickIntentBuilder;

impl OneClickIntentBuilder {
    /// Build a dry-run confidential quote request.
    ///
    /// # Errors
    /// Fails on zero amount or empty identifiers.
    pub fn quote_request(
        &self,
        origin_asset: &str,
        destination_asset: &str,
        amount: u128,
        refund_to: &str,
        recipient: &str,
        deadline_rfc3339: &str,
    ) -> Result<OneClickQuoteRequest, ReceiptError> {
        if amount == 0
            || [
                origin_asset,
                destination_asset,
                refund_to,
                recipient,
                deadline_rfc3339,
            ]
            .iter()
            .any(|s| s.is_empty())
        {
            return Err(ReceiptError::InvalidInput(
                "empty identifier or zero amount".into(),
            ));
        }
        Ok(OneClickQuoteRequest {
            dry: true,
            swap_type: "EXACT_INPUT".into(),
            slippage_tolerance: 100,
            origin_asset: origin_asset.into(),
            deposit_type: "CONFIDENTIAL_INTENTS".into(),
            destination_asset: destination_asset.into(),
            amount: amount.to_string(),
            refund_to: refund_to.into(),
            recipient: recipient.into(),
            deadline: deadline_rfc3339.into(),
        })
    }

    /// Sign `message` as a NEP-413 intent for `recipient`.
    ///
    /// # Errors
    /// Fails if Borsh serialization fails.
    pub fn sign_nep413(
        &self,
        key: &SigningKey,
        message: &str,
        nonce: [u8; 32],
        recipient: &str,
    ) -> Result<SignedIntent, ReceiptError> {
        let payload = Nep413Payload {
            message,
            nonce,
            recipient,
            callback_url: None,
        };
        let mut bytes =
            borsh::to_vec(&NEP413_TAG).map_err(|e| ReceiptError::Serialization(e.to_string()))?;
        bytes.extend(
            borsh::to_vec(&payload).map_err(|e| ReceiptError::Serialization(e.to_string()))?,
        );
        let intent_hash = sha256_concat(&[&bytes]);
        Ok(SignedIntent {
            intent_hash,
            signature: key.sign(&intent_hash).to_bytes(),
            public_key: key.verifying_key().to_bytes(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn terms() -> PrivateTerms {
        PrivateTerms {
            intent_id: [1; 32],
            amount: 1_000,
            currency: "nep141:usdc".into(),
            buyer_salt: [9; 32],
        }
    }

    #[test]
    fn bridge_is_labeled_and_deterministic() {
        let a = TestnetConfidentialSettlementBridge
            .settle(&terms())
            .unwrap();
        assert_eq!(a.mode, SettlementMode::TestnetBridge);
        assert_eq!(
            a,
            TestnetConfidentialSettlementBridge
                .settle(&terms())
                .unwrap()
        );
    }

    #[test]
    fn salt_hides_amount_from_dictionary_attack() {
        let mut t2 = terms();
        t2.buyer_salt = [8; 32];
        assert_ne!(commit_terms(&terms()), commit_terms(&t2));
    }

    #[test]
    fn invalid_terms_rejected() {
        let mut t = terms();
        t.amount = 0;
        assert!(TestnetConfidentialSettlementBridge.settle(&t).is_err());
        let mut t = terms();
        t.buyer_salt = [0; 32];
        assert!(TestnetConfidentialSettlementBridge.settle(&t).is_err());
        let mut t = terms();
        t.currency.clear();
        assert!(TestnetConfidentialSettlementBridge.settle(&t).is_err());
    }

    #[test]
    fn quote_request_serializes_camel_case() {
        let q = OneClickIntentBuilder
            .quote_request("a", "b", 5, "r", "x", "2030-01-01T00:00:00Z")
            .unwrap();
        let v = serde_json::to_value(&q).unwrap();
        assert_eq!(v["depositType"], "CONFIDENTIAL_INTENTS");
        assert_eq!(v["amount"], "5");
        assert_eq!(v["dry"], true);
        assert!(OneClickIntentBuilder
            .quote_request("a", "b", 0, "r", "x", "d")
            .is_err());
    }

    #[test]
    fn nep413_signature_verifies_and_binds_message() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let s = OneClickIntentBuilder
            .sign_nep413(&key, "pay", [4; 32], "intents.near")
            .unwrap();
        let vk = VerifyingKey::from_bytes(&s.public_key).unwrap();
        vk.verify(&s.intent_hash, &Signature::from_bytes(&s.signature))
            .unwrap();
        let other = OneClickIntentBuilder
            .sign_nep413(&key, "pay2", [4; 32], "intents.near")
            .unwrap();
        assert_ne!(s.intent_hash, other.intent_hash);
    }
}
