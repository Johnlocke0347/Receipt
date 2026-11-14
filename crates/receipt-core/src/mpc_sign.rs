//! NEAR Chain Signatures KDF (`near-mpc-recovery v0.1.0 epsilon derivation:`) and wire DTOs for
//! `v1.signer-prod.testnet::sign` (`domain_id: 0`) and
//! `v1.signer-prod.testnet::verify_foreign_transaction` (`domain_id: 3`).

use borsh::{BorshDeserialize, BorshSerialize};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar, U256};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::eip712::pubkey64_to_evm_address;
use crate::error::ReceiptError;
use crate::mpc_foreign_tx::Hash256;

/// Canonical NEAR Chain Signatures & Foreign-Tx MPC contract on NEAR Testnet.
pub const MPC_SIGNER_TESTNET_ACCOUNT: &str = "v1.signer-prod.testnet";
/// Secp256k1 `DomainPurpose::Sign` domain ID on `v1.signer-prod.testnet`.
pub const SIGN_DOMAIN_ID: u64 = 0;
/// Canonical derivation path used by `near-receipt-registry` for `ReceiptCreditVault` loan authorizations.
pub const DEFAULT_DERIVATION_PATH: &str = "receipt-credit-vault-v1";
/// Live `domain_id: 0` (`DomainPurpose::Sign`, Secp256k1) root public key on `v1.signer-prod.testnet`.
pub const TESTNET_SIGN_DOMAIN_0_PUBLIC_KEY: &str =
    "secp256k1:4NfTiv3UsGahebgTaHyD9vF8KYKMBnfd6kh94mK6xv8fGBiJB8TBtFMP5WWXz6B89Ac1fbpzPwAvoyQebemHFwx3";
/// Live `domain_id: 3` (`DomainPurpose::ForeignTx`, Secp256k1) root public key on `v1.signer-prod.testnet`.
pub const TESTNET_FOREIGN_TX_DOMAIN_3_PUBLIC_KEY: &str =
    "secp256k1:2KGCoy2pZt7n85QfJnQzCT1eHySuNpquUfNc8ySpRbr15F5kqU7agJYjfo5RkrzNd4tZimDFv2wAZri7RRZ32qj1";
/// Upstream epsilon KDF domain-separation prefix (`near-mpc-crypto-types/src/kdf.rs`).
pub const EPSILON_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

/// Compressed secp256k1 affine point DTO (`big_r`) returned by `v1.signer-prod.testnet`.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AffinePointDto {
    /// 66-character lowercase hex string of a 33-byte SEC1 compressed point (`02`/`03` || X).
    pub affine_point: String,
}

/// Secp256k1 scalar DTO (`s`) returned by `v1.signer-prod.testnet`.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ScalarDto {
    /// 64-character lowercase hex string of a 32-byte big-endian scalar.
    pub scalar: String,
}

/// Wire representation of `SignatureResponse::Secp256k1` returned by `v1.signer-prod.testnet::sign`
/// and embedded in `VerifyForeignTransactionResponse`.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MpcSecp256k1Signature {
    /// Signature scheme tag (must be `"Secp256k1"`).
    pub scheme: String,
    /// Compressed nonce point `R`.
    pub big_r: AffinePointDto,
    /// Signature scalar `s`.
    pub s: ScalarDto,
    /// Recovery ID (`0` or `1`).
    pub recovery_id: u8,
}

/// Wire representation of `VerifyForeignTransactionResponse` returned by
/// `v1.signer-prod.testnet::verify_foreign_transaction`.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VerifyForeignTransactionResponseDto {
    /// 32-byte SHA-256 hash of `Borsh(ForeignTxSignPayload::V1)` signed by the MPC network.
    pub payload_hash: Hash256,
    /// Threshold ECDSA signature over `payload_hash` under the `domain_id: 3` root key.
    pub signature: MpcSecp256k1Signature,
}

impl MpcSecp256k1Signature {
    /// Construct an [`MpcSecp256k1Signature`] from `(r, s, v_or_recovery_id)`.
    #[must_use]
    pub fn from_r_s_v(r: &[u8; 32], s: &[u8; 32], v_or_recovery_id: u8) -> Self {
        let rec_id = if v_or_recovery_id >= 27 {
            v_or_recovery_id - 27
        } else {
            v_or_recovery_id
        };
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02 + (rec_id & 1);
        compressed[1..33].copy_from_slice(r);
        Self {
            scheme: "Secp256k1".to_string(),
            big_r: AffinePointDto {
                affine_point: hex::encode(compressed),
            },
            s: ScalarDto {
                scalar: hex::encode(s),
            },
            recovery_id: rec_id,
        }
    }

    /// Decode `(r, s, v)` where `v` is `27 + (recovery_id & 1)`, validating the compressed point
    /// encoding of `big_r` and scalar encoding of `s`.
    ///
    /// # Errors
    /// Returns [`ReceiptError::BadSignature`] if the scheme is not `"Secp256k1"` or any field is
    /// malformed.
    pub fn to_r_s_v(&self) -> Result<([u8; 32], [u8; 32], u8), ReceiptError> {
        if self.scheme != "Secp256k1" {
            return Err(ReceiptError::BadSignature(
                "MPC signature scheme != Secp256k1",
            ));
        }
        if self.recovery_id > 3 {
            return Err(ReceiptError::BadSignature("MPC recovery_id out of range"));
        }
        let r_bytes = hex::decode(self.big_r.affine_point.trim())
            .map_err(|_| ReceiptError::BadSignature("invalid hex in big_r.affine_point"))?;
        if r_bytes.len() != 33 || (r_bytes[0] != 0x02 && r_bytes[0] != 0x03) {
            return Err(ReceiptError::BadSignature(
                "big_r.affine_point must be 33-byte compressed SEC1 point",
            ));
        }
        let ep = EncodedPoint::from_bytes(&r_bytes)
            .map_err(|_| ReceiptError::BadSignature("invalid SEC1 point in big_r"))?;
        if Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep)).is_none() {
            return Err(ReceiptError::BadSignature(
                "big_r is not on secp256k1 curve",
            ));
        }
        // Note: When cait-sith in near/mpc normalizes high-s (s -> n - s), it flips
        // `recovery_id ^= 1` without flipping `big_r.affine_point[0]`. Therefore `recovery_id`
        // (and not `r_bytes[0]`) is the authoritative recovery parity for ecrecover.
        let s_bytes = hex::decode(self.s.scalar.trim())
            .map_err(|_| ReceiptError::BadSignature("invalid hex in s.scalar"))?;
        let s: [u8; 32] = s_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ReceiptError::BadSignature("s.scalar must be 32 bytes"))?;
        let mut r = [0u8; 32];
        r.copy_from_slice(&r_bytes[1..33]);
        Ok((r, s, 27 + (self.recovery_id & 1)))
    }

    /// Cryptographically verify this MPC signature over `msg_hash` against `expected_pubkey_64`
    /// (uncompressed 64-byte `X || Y` secp256k1 public key) and return `(r, s, v)`.
    ///
    /// # Errors
    /// Returns [`ReceiptError::BadSignature`] if the signature is invalid or does not recover to
    /// `expected_pubkey_64`.
    pub fn verify_against_pubkey(
        &self,
        msg_hash: &[u8; 32],
        expected_pubkey_64: &[u8; 64],
    ) -> Result<([u8; 32], [u8; 32], u8), ReceiptError> {
        let (r, s, v) = self.to_r_s_v()?;
        let rec_id = RecoveryId::from_byte(self.recovery_id)
            .ok_or(ReceiptError::BadSignature("invalid MPC recovery_id"))?;
        let sig = Signature::from_scalars(r, s)
            .map_err(|_| ReceiptError::BadSignature("invalid secp256k1 r/s in MPC signature"))?;
        let recovered_vk = VerifyingKey::recover_from_prehash(msg_hash, &sig, rec_id)
            .map_err(|_| ReceiptError::BadSignature("failed to recover MPC signer key"))?;
        let uncompressed = recovered_vk.to_encoded_point(false);
        let bytes = uncompressed.as_bytes();
        if bytes.len() != 65 || &bytes[1..65] != expected_pubkey_64 {
            return Err(ReceiptError::BadSignature(
                "MPC signature does not match expected domain public key",
            ));
        }
        Ok((r, s, v))
    }
}

/// Build the JSON arguments for `v1.signer-prod.testnet::sign`:
/// `{ "request": { "path": path, "payload_v2": { "Ecdsa": hex(digest) }, "domain_id": domain_id } }`.
///
/// Validates that `ecdsa_digest` is a non-zero valid secp256k1 scalar, matching the precondition
/// enforced by `v1.signer-prod.testnet`.
///
/// # Errors
/// Returns [`ReceiptError::InvalidInput`] if `ecdsa_digest` is not a valid non-zero secp256k1 scalar.
pub fn sign_request_args(
    path: &str,
    ecdsa_digest: &[u8; 32],
    domain_id: u64,
) -> Result<serde_json::Value, ReceiptError> {
    let scalar_opt = Scalar::from_repr((*ecdsa_digest).into());
    let scalar: Scalar = Option::from(scalar_opt).ok_or_else(|| {
        ReceiptError::InvalidInput("ECDSA payload digest overflows secp256k1 scalar modulus".into())
    })?;
    if bool::from(scalar.is_zero()) {
        return Err(ReceiptError::InvalidInput(
            "ECDSA payload digest cannot be zero".into(),
        ));
    }
    Ok(serde_json::json!({
        "request": {
            "path": path,
            "payload_v2": {
                "Ecdsa": hex::encode(ecdsa_digest),
            },
            "domain_id": domain_id,
        }
    }))
}

/// Parse a NEAR `"secp256k1:<bs58>"` public key string into its 64-byte uncompressed `X || Y`
/// representation, verifying that the point lies on the secp256k1 curve.
///
/// # Errors
/// Returns [`ReceiptError::BadPublicKey`] if the prefix, Base58 encoding, length, or curve point
/// is invalid.
pub fn parse_near_secp256k1_pubkey(pk_str: &str) -> Result<[u8; 64], ReceiptError> {
    let b58_part = pk_str
        .trim()
        .strip_prefix("secp256k1:")
        .ok_or(ReceiptError::BadPublicKey("missing secp256k1: prefix"))?;
    let raw = bs58::decode(b58_part)
        .into_vec()
        .map_err(|_| ReceiptError::BadPublicKey("invalid base58 in secp256k1 key"))?;
    let pk64: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| ReceiptError::BadPublicKey("secp256k1 key must decode to 64 bytes"))?;
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..65].copy_from_slice(&pk64);
    let ep = EncodedPoint::from_bytes(sec1)
        .map_err(|_| ReceiptError::BadPublicKey("invalid SEC1 encoding"))?;
    if Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep)).is_none() {
        return Err(ReceiptError::BadPublicKey(
            "point is not on secp256k1 curve",
        ));
    }
    Ok(pk64)
}

/// Format a 64-byte uncompressed secp256k1 public key (`X || Y`) as `"secp256k1:<bs58>"`.
#[must_use]
pub fn format_near_secp256k1_pubkey(pubkey_64: &[u8; 64]) -> String {
    format!("secp256k1:{}", bs58::encode(pubkey_64).into_string())
}

/// Compute the NEAR Chain Signatures epsilon derivation tweak:
/// `SHA3_256("near-mpc-recovery v0.1.0 epsilon derivation:{predecessor_id},{path}")`.
///
/// Matches `near-mpc-crypto-types::kdf::derive_tweak` in `near/mpc`.
#[must_use]
pub fn derive_mpc_tweak(predecessor_id: &str, path: &str) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(format!("{EPSILON_DERIVATION_PREFIX}{predecessor_id},{path}").as_bytes());
    hasher.finalize().into()
}

/// Derive a child uncompressed 64-byte secp256k1 public key (`X || Y`) from a root 64-byte public
/// key, caller `predecessor_id`, and `path`:
/// `derived_pubkey = Generator * Scalar(derive_tweak(predecessor_id, path)) + root_pubkey`.
///
/// Matches `near-mpc-crypto-types::kdf::derive_key_secp256k1` in `near/mpc`.
///
/// # Errors
/// Returns [`ReceiptError::BadPublicKey`] if the root public key is invalid or the tweak scalar is
/// out of range.
pub fn derive_mpc_secp256k1_pubkey(
    root_pubkey_64: &[u8; 64],
    predecessor_id: &str,
    path: &str,
) -> Result<[u8; 64], ReceiptError> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..65].copy_from_slice(root_pubkey_64);
    let ep = EncodedPoint::from_bytes(sec1)
        .map_err(|_| ReceiptError::BadPublicKey("invalid SEC1 root pubkey"))?;
    let root_affine: AffinePoint = Option::from(AffinePoint::from_encoded_point(&ep))
        .ok_or(ReceiptError::BadPublicKey("root pubkey not on secp256k1"))?;

    let tweak_bytes = derive_mpc_tweak(predecessor_id, path);
    let scalar: Scalar = Option::from(Scalar::from_repr(tweak_bytes.into()))
        .unwrap_or_else(|| <Scalar as Reduce<U256>>::reduce_bytes(&tweak_bytes.into()));

    let derived_proj = ProjectivePoint::GENERATOR * scalar + ProjectivePoint::from(root_affine);
    let derived_affine = derived_proj.to_affine();
    let derived_ep = derived_affine.to_encoded_point(false);
    let bytes = derived_ep.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(ReceiptError::BadPublicKey(
            "derived secp256k1 point is identity",
        ));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes[1..65]);
    Ok(out)
}

/// Derive the 20-byte EVM address (`nearAuthorizedSigner`) controlled by `(predecessor_id, path)`
/// under `root_near_pk` (e.g. [`TESTNET_SIGN_DOMAIN_0_PUBLIC_KEY`]).
///
/// # Errors
/// Propagates [`ReceiptError::BadPublicKey`] if `root_near_pk` is invalid.
pub fn derive_mpc_evm_address(
    root_near_pk: &str,
    predecessor_id: &str,
    path: &str,
) -> Result<[u8; 20], ReceiptError> {
    let root_pk64 = parse_near_secp256k1_pubkey(root_near_pk)?;
    let derived_pk64 = derive_mpc_secp256k1_pubkey(&root_pk64, predecessor_id, path)?;
    Ok(pubkey64_to_evm_address(&derived_pk64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    #[test]
    fn live_testnet_domain_keys_parse_and_roundtrip() {
        let pk0 = parse_near_secp256k1_pubkey(TESTNET_SIGN_DOMAIN_0_PUBLIC_KEY).unwrap();
        assert_eq!(
            format_near_secp256k1_pubkey(&pk0),
            TESTNET_SIGN_DOMAIN_0_PUBLIC_KEY
        );

        let pk3 = parse_near_secp256k1_pubkey(TESTNET_FOREIGN_TX_DOMAIN_3_PUBLIC_KEY).unwrap();
        assert_eq!(
            format_near_secp256k1_pubkey(&pk3),
            TESTNET_FOREIGN_TX_DOMAIN_3_PUBLIC_KEY
        );
        assert_ne!(pk0, pk3);

        // Compare our local KDF derivation against live v1.signer-prod.testnet::derived_public_key
        // for (predecessor: "receipt-registry.testnet", path: "receipt-credit-vault-v1", domain_id: 0)
        let derived_pk64 =
            derive_mpc_secp256k1_pubkey(&pk0, "receipt-registry.testnet", DEFAULT_DERIVATION_PATH)
                .unwrap();
        assert_eq!(
            format_near_secp256k1_pubkey(&derived_pk64),
            "secp256k1:4BUaArkKFhhnaUmFaxQ3ZDFJKScvpShfeQSo2rsDgLMj3SvfFCuVvZgtDbsntZYmgShfPynEJhYm6GiuEShHvzMS"
        );
    }

    #[test]
    fn child_signing_key_matches_derived_public_key_and_evm_address() {
        let root_secret = Scalar::from_u128(0x1234_5678_9abc_def0_1122_3344_5566_7788);
        let root_sk = SigningKey::from_bytes(&root_secret.to_bytes()).unwrap();
        let root_vk_ep = root_sk.verifying_key().to_encoded_point(false);
        let mut root_pk64 = [0u8; 64];
        root_pk64.copy_from_slice(&root_vk_ep.as_bytes()[1..65]);
        let root_near_pk = format_near_secp256k1_pubkey(&root_pk64);

        let predecessor = "receipt-registry.testnet";
        let path = DEFAULT_DERIVATION_PATH;

        // Public derivation
        let derived_pk64 = derive_mpc_secp256k1_pubkey(&root_pk64, predecessor, path).unwrap();
        let derived_evm_addr = derive_mpc_evm_address(&root_near_pk, predecessor, path).unwrap();

        // Private scalar addition (matching MPC node threshold signing)
        let tweak = derive_mpc_tweak(predecessor, path);
        let tweak_scalar = Scalar::from_repr(tweak.into()).unwrap();
        let child_scalar = root_secret + tweak_scalar;
        let child_sk = SigningKey::from_bytes(&child_scalar.to_bytes()).unwrap();
        let child_vk_ep = child_sk.verifying_key().to_encoded_point(false);
        assert_eq!(&child_vk_ep.as_bytes()[1..65], &derived_pk64);

        // Sign a digest with child_sk and verify via MpcSecp256k1Signature
        let msg_hash = [0x42u8; 32];
        let (sig, rec_id) = child_sk.sign_prehash_recoverable(&msg_hash).unwrap();
        let r: [u8; 32] = sig.r().to_bytes().into();
        let s: [u8; 32] = sig.s().to_bytes().into();
        let mpc_sig = MpcSecp256k1Signature::from_r_s_v(&r, &s, rec_id.to_byte());

        let (out_r, out_s, out_v) = mpc_sig
            .verify_against_pubkey(&msg_hash, &derived_pk64)
            .unwrap();
        assert_eq!(out_r, r);
        assert_eq!(out_s, s);
        let recovered_addr =
            crate::eip712::recover_eip712_signer(&msg_hash, &out_r, &out_s, out_v).unwrap();
        assert_eq!(recovered_addr, derived_evm_addr);
    }

    #[test]
    fn sign_request_args_shape_matches_v1_signer_prod_testnet() {
        let digest = [0x55u8; 32];
        let val = sign_request_args(DEFAULT_DERIVATION_PATH, &digest, SIGN_DOMAIN_ID).unwrap();
        assert_eq!(val["request"]["path"], "receipt-credit-vault-v1");
        assert_eq!(val["request"]["domain_id"], 0);
        assert_eq!(val["request"]["payload_v2"]["Ecdsa"], "55".repeat(32));

        // Zero digest rejected
        assert!(sign_request_args(DEFAULT_DERIVATION_PATH, &[0u8; 32], SIGN_DOMAIN_ID).is_err());
    }
}
