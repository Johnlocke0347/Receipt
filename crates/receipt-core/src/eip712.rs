//! EIP-712 Loan Authorization digest, `LoanAuthorizationPacket`, secp256k1 `ecrecover`, and
//! `LoanDrawn` event log verification shared between the NEAR `ReceiptRegistry` contract and the
//! Base Sepolia `ReceiptCreditVault` contract.

use borsh::{BorshDeserialize, BorshSerialize};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::error::ReceiptError;
use crate::hexser;
use crate::mpc_foreign_tx::{loan_drawn_topic0, EvmLog};

/// Base Sepolia chain ID (`84532`).
pub const BASE_SEPOLIA_CHAIN_ID: u64 = 84532;
/// CAIP-2 chain identifier for Base Sepolia.
pub const BASE_SEPOLIA_CAIP2: &str = "eip155:84532";
/// Canonical EIP-712 domain type string.
pub const EIP712_DOMAIN_TYPE_STR: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
/// EIP-712 domain name of `ReceiptCreditVault.sol`.
pub const EIP712_DOMAIN_NAME: &str = "ReceiptCreditVault";
/// EIP-712 domain version of `ReceiptCreditVault.sol`.
pub const EIP712_DOMAIN_VERSION: &str = "1";
/// Canonical EIP-712 struct type string for loan authorization.
pub const LOAN_AUTHORIZATION_TYPE_STR: &str =
    "LoanAuthorization(bytes32 receiptId,address borrower,uint256 principal,bytes32 evidenceCommitment,uint256 deadline)";

/// Signed loan authorization packet stored by `near-receipt-registry` and consumed by
/// `ReceiptCreditVault.drawCredit` on Base Sepolia.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LoanAuthorizationPacket {
    /// Receipt identifier (`bytes32`).
    #[serde(with = "hexser")]
    pub receipt_id: [u8; 32],
    /// Borrower EVM address on Base Sepolia (`address`).
    #[serde(with = "hexser")]
    pub borrower_evm_address: [u8; 20],
    /// Authorized loan principal in minimal credit token units (`uint256`).
    pub principal_amount: u128,
    /// Evidence commitment bound into the receipt (`bytes32`).
    #[serde(with = "hexser")]
    pub evidence_commitment: [u8; 32],
    /// Verifying `ReceiptCreditVault` contract address on Base Sepolia (`address`).
    #[serde(with = "hexser")]
    pub base_vault_address: [u8; 20],
    /// Target EVM chain ID (`84532` for Base Sepolia).
    pub chain_id: u64,
    /// Authorization expiry UNIX timestamp in seconds (`uint256`).
    pub deadline: u64,
    /// 32-byte EIP-712 digest signed by NEAR Chain Signatures (`domain_id: 0`).
    #[serde(with = "hexser")]
    pub eip712_digest: [u8; 32],
    /// secp256k1 signature `r` (`bytes32`).
    #[serde(with = "hexser")]
    pub signature_r: [u8; 32],
    /// secp256k1 signature `s` (`bytes32`).
    #[serde(with = "hexser")]
    pub signature_s: [u8; 32],
    /// EVM recovery byte `v` (`27` or `28`).
    pub signature_v: u8,
}

/// Compute `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
#[must_use]
pub fn eip712_domain_typehash() -> [u8; 32] {
    Keccak256::digest(EIP712_DOMAIN_TYPE_STR.as_bytes()).into()
}

/// Compute `keccak256("LoanAuthorization(bytes32 receiptId,address borrower,uint256 principal,bytes32 evidenceCommitment,uint256 deadline)")`.
#[must_use]
pub fn loan_authorization_typehash() -> [u8; 32] {
    Keccak256::digest(LOAN_AUTHORIZATION_TYPE_STR.as_bytes()).into()
}

/// Compute the EIP-712 domain separator for `ReceiptCreditVault`:
/// `keccak256(abi.encode(TYPEHASH, keccak256("ReceiptCreditVault"), keccak256("1"), chainId, verifyingContract))`.
#[must_use]
pub fn eip712_domain_separator(chain_id: u64, verifying_contract: &[u8; 20]) -> [u8; 32] {
    let type_hash = eip712_domain_typehash();
    let name_hash: [u8; 32] = Keccak256::digest(EIP712_DOMAIN_NAME.as_bytes()).into();
    let version_hash: [u8; 32] = Keccak256::digest(EIP712_DOMAIN_VERSION.as_bytes()).into();

    let mut encoded = [0u8; 160];
    encoded[0..32].copy_from_slice(&type_hash);
    encoded[32..64].copy_from_slice(&name_hash);
    encoded[64..96].copy_from_slice(&version_hash);
    encoded[120..128].copy_from_slice(&chain_id.to_be_bytes());
    encoded[140..160].copy_from_slice(verifying_contract);

    Keccak256::digest(encoded).into()
}

/// Compute the EIP-712 struct hash for `LoanAuthorization`:
/// `keccak256(abi.encode(LOAN_AUTH_TYPEHASH, receiptId, borrower, principal, evidenceCommitment, deadline))`.
#[must_use]
pub fn loan_authorization_struct_hash(
    receipt_id: &[u8; 32],
    borrower: &[u8; 20],
    principal: u128,
    evidence_commitment: &[u8; 32],
    deadline: u64,
) -> [u8; 32] {
    let type_hash = loan_authorization_typehash();
    let mut encoded = [0u8; 192];
    encoded[0..32].copy_from_slice(&type_hash);
    encoded[32..64].copy_from_slice(receipt_id);
    encoded[76..96].copy_from_slice(borrower);
    encoded[112..128].copy_from_slice(&principal.to_be_bytes());
    encoded[128..160].copy_from_slice(evidence_commitment);
    encoded[184..192].copy_from_slice(&deadline.to_be_bytes());

    Keccak256::digest(encoded).into()
}

/// Compute the 32-byte EIP-712 signing digest (`\x19\x01 || domainSeparator || structHash`)
/// signed by NEAR Chain Signatures (`domain_id: 0`, path `"receipt-credit-vault-v1"`) and verified
/// by `ReceiptCreditVault.drawCredit` on Base Sepolia.
#[must_use]
pub fn eip712_loan_authorization_digest(
    receipt_id: &[u8; 32],
    borrower: &[u8; 20],
    principal: u128,
    evidence_commitment: &[u8; 32],
    verifying_contract: &[u8; 20],
    chain_id: u64,
    deadline: u64,
) -> [u8; 32] {
    let domain_sep = eip712_domain_separator(chain_id, verifying_contract);
    let struct_hash = loan_authorization_struct_hash(
        receipt_id,
        borrower,
        principal,
        evidence_commitment,
        deadline,
    );
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(&domain_sep);
    buf[34..66].copy_from_slice(&struct_hash);
    Keccak256::digest(buf).into()
}

/// Derive a 20-byte EVM address from an uncompressed 64-byte secp256k1 public key (`X || Y`).
#[must_use]
pub fn pubkey64_to_evm_address(pubkey_64: &[u8; 64]) -> [u8; 20] {
    let hash: [u8; 32] = Keccak256::digest(pubkey_64).into();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

/// Recover the 20-byte EVM signer address from a 32-byte digest and `(r, s, v)`, enforcing EIP-2
/// low-`s` malleability protection (`v` in `{27, 28}` and `s <= n / 2`).
///
/// # Errors
/// Returns [`ReceiptError::BadSignature`] if `(r, s, v)` is malformed, malleable (high-`s`), or
/// cannot recover a valid secp256k1 public key.
pub fn recover_eip712_signer(
    digest: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    v: u8,
) -> Result<[u8; 20], ReceiptError> {
    let rec_byte = match v {
        27 | 28 => v - 27,
        0 | 1 => v,
        _ => return Err(ReceiptError::BadSignature("invalid recovery v")),
    };
    let recovery_id =
        RecoveryId::from_byte(rec_byte).ok_or(ReceiptError::BadSignature("invalid recovery_id"))?;
    let sig = Signature::from_scalars(*r, *s)
        .map_err(|_| ReceiptError::BadSignature("invalid secp256k1 r/s scalars"))?;
    if bool::from(sig.s().is_high()) {
        return Err(ReceiptError::BadSignature("malleable high-s signature"));
    }
    let vk = VerifyingKey::recover_from_prehash(digest, &sig, recovery_id)
        .map_err(|_| ReceiptError::BadSignature("ecrecover failed"))?;
    let encoded = vk.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(ReceiptError::BadSignature("invalid recovered point"));
    }
    let mut pk64 = [0u8; 64];
    pk64.copy_from_slice(&bytes[1..65]);
    Ok(pubkey64_to_evm_address(&pk64))
}

/// Encode the `0x`-prefixed ABI data payload (`abi.encode(uint256 principal, bytes32 evidenceCommitment)`)
/// emitted in `LoanDrawn` on Base Sepolia.
#[must_use]
pub fn encode_loan_drawn_data(principal: u128, evidence_commitment: &[u8; 32]) -> String {
    let mut data = [0u8; 64];
    data[16..32].copy_from_slice(&principal.to_be_bytes());
    data[32..64].copy_from_slice(evidence_commitment);
    format!("0x{}", hex::encode(data))
}

/// Strictly validate an extracted [`EvmLog`] against the expected `LoanDrawn` event parameters and
/// return the 32-byte `lenderId` (`topics[3]`) emitted by `ReceiptCreditVault`.
///
/// Checks:
/// 1. `!log.removed` (no chain reorg).
/// 2. `log.address` matches `expected_vault`.
/// 3. `log.transaction_hash` matches `expected_tx_hash`.
/// 4. `log.block_hash` matches `expected_block_hash`.
/// 5. `log.topics` has length 4:
///    - `topics[0] == keccak256("LoanDrawn(bytes32,address,uint256,bytes32,bytes32)")`
///    - `topics[1] == expected_receipt_id`
///    - `topics[2] == abi.encode(expected_borrower)` (12 zero bytes + 20-byte address)
///    - `topics[3] == lenderId` (non-zero 32-byte identifier)
/// 6. `log.data` is 64 bytes: `abi.encode(expected_principal, expected_evidence_commitment)`.
///
/// # Errors
/// Returns [`ReceiptError::InvalidInput`] on any mismatch.
#[allow(clippy::too_many_arguments)]
pub fn verify_loan_drawn_log(
    log: &EvmLog,
    expected_vault: &[u8; 20],
    expected_tx_hash: &[u8; 32],
    expected_block_hash: &[u8; 32],
    expected_receipt_id: &[u8; 32],
    expected_borrower: &[u8; 20],
    expected_principal: u128,
    expected_evidence_commitment: &[u8; 32],
) -> Result<[u8; 32], ReceiptError> {
    if log.removed {
        return Err(ReceiptError::InvalidInput(
            "LoanDrawn log has removed=true".into(),
        ));
    }
    if &log.address.0 != expected_vault {
        return Err(ReceiptError::InvalidInput(
            "LoanDrawn log address does not match configured vault".into(),
        ));
    }
    if &log.transaction_hash.0 != expected_tx_hash {
        return Err(ReceiptError::InvalidInput(
            "LoanDrawn log transaction_hash mismatch".into(),
        ));
    }
    if &log.block_hash.0 != expected_block_hash {
        return Err(ReceiptError::InvalidInput(
            "LoanDrawn log block_hash mismatch".into(),
        ));
    }
    if log.topics.len() != 4 {
        return Err(ReceiptError::InvalidInput(format!(
            "LoanDrawn log must have 4 topics, got {}",
            log.topics.len()
        )));
    }
    if log.topics[0].0 != loan_drawn_topic0() {
        return Err(ReceiptError::InvalidInput(
            "LoanDrawn topic0 signature mismatch".into(),
        ));
    }
    if &log.topics[1].0 != expected_receipt_id {
        return Err(ReceiptError::InvalidInput(
            "LoanDrawn topic1 (receiptId) mismatch".into(),
        ));
    }
    let mut expected_borrower_topic = [0u8; 32];
    expected_borrower_topic[12..32].copy_from_slice(expected_borrower);
    if log.topics[2].0 != expected_borrower_topic {
        return Err(ReceiptError::InvalidInput(
            "LoanDrawn topic2 (borrower) mismatch".into(),
        ));
    }
    let lender_id = log.topics[3].0;
    if lender_id == [0u8; 32] {
        return Err(ReceiptError::InvalidInput(
            "LoanDrawn topic3 (lenderId) cannot be zero".into(),
        ));
    }

    let Some(raw_hex) = log.data.strip_prefix("0x") else {
        return Err(ReceiptError::InvalidInput(
            "LoanDrawn log.data must be 0x-prefixed lowercase hex".into(),
        ));
    };
    let data_bytes = hex::decode(raw_hex)
        .map_err(|e| ReceiptError::InvalidInput(format!("invalid hex in LoanDrawn data: {e}")))?;
    if data_bytes.len() != 64 {
        return Err(ReceiptError::InvalidInput(format!(
            "LoanDrawn data must be 64 bytes, got {}",
            data_bytes.len()
        )));
    }
    if data_bytes[0..16] != [0u8; 16] || data_bytes[16..32] != expected_principal.to_be_bytes() {
        return Err(ReceiptError::InvalidInput(
            "LoanDrawn data principal mismatch".into(),
        ));
    }
    if &data_bytes[32..64] != expected_evidence_commitment {
        return Err(ReceiptError::InvalidInput(
            "LoanDrawn data evidenceCommitment mismatch".into(),
        ));
    }

    Ok(lender_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc_foreign_tx::{Hash160, Hash256};
    use k256::ecdsa::SigningKey;

    #[test]
    fn eip712_roundtrip_sign_and_recover() {
        let sk = SigningKey::from_bytes(&[0x33u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let pt = vk.to_encoded_point(false);
        let mut pk64 = [0u8; 64];
        pk64.copy_from_slice(&pt.as_bytes()[1..65]);
        let expected_signer = pubkey64_to_evm_address(&pk64);

        let receipt_id = [0x11u8; 32];
        let borrower = [0x22u8; 20];
        let principal = 250_000_000u128; // 250 USDC (6 decimals)
        let evidence = [0x44u8; 32];
        let vault = [0x55u8; 20];
        let deadline = 1_800_000_000u64;

        let digest = eip712_loan_authorization_digest(
            &receipt_id,
            &borrower,
            principal,
            &evidence,
            &vault,
            BASE_SEPOLIA_CHAIN_ID,
            deadline,
        );

        let (sig, rec_id) = sk.sign_prehash_recoverable(&digest).unwrap();
        let r: [u8; 32] = sig.r().to_bytes().into();
        let s: [u8; 32] = sig.s().to_bytes().into();
        let v = 27 + rec_id.to_byte();

        let recovered = recover_eip712_signer(&digest, &r, &s, v).unwrap();
        assert_eq!(recovered, expected_signer);

        // Tampering with principal changes the digest and recovers a different signer
        let tampered_digest = eip712_loan_authorization_digest(
            &receipt_id,
            &borrower,
            principal + 1,
            &evidence,
            &vault,
            BASE_SEPOLIA_CHAIN_ID,
            deadline,
        );
        let wrong_signer = recover_eip712_signer(&tampered_digest, &r, &s, v).unwrap();
        assert_ne!(wrong_signer, expected_signer);
    }

    #[test]
    fn verify_loan_drawn_log_enforces_all_fields() {
        let vault = [0x11u8; 20];
        let tx_hash = [0x22u8; 32];
        let block_hash = [0x33u8; 32];
        let receipt_id = [0x44u8; 32];
        let borrower = [0x55u8; 20];
        let lender_id = [0x66u8; 32];
        let principal = 100_000_000u128;
        let evidence = [0x77u8; 32];

        let mut borrower_topic = [0u8; 32];
        borrower_topic[12..32].copy_from_slice(&borrower);

        let valid_log = EvmLog {
            removed: false,
            log_index: 0,
            transaction_index: 0,
            transaction_hash: Hash256(tx_hash),
            block_hash: Hash256(block_hash),
            block_number: 12345,
            address: Hash160(vault),
            data: encode_loan_drawn_data(principal, &evidence),
            topics: vec![
                Hash256(loan_drawn_topic0()),
                Hash256(receipt_id),
                Hash256(borrower_topic),
                Hash256(lender_id),
            ],
        };

        let extracted_lender = verify_loan_drawn_log(
            &valid_log,
            &vault,
            &tx_hash,
            &block_hash,
            &receipt_id,
            &borrower,
            principal,
            &evidence,
        )
        .unwrap();
        assert_eq!(extracted_lender, lender_id);

        // Removed log rejected
        let mut removed_log = valid_log.clone();
        removed_log.removed = true;
        assert!(verify_loan_drawn_log(
            &removed_log,
            &vault,
            &tx_hash,
            &block_hash,
            &receipt_id,
            &borrower,
            principal,
            &evidence,
        )
        .is_err());

        // Wrong evidence commitment rejected
        assert!(verify_loan_drawn_log(
            &valid_log,
            &vault,
            &tx_hash,
            &block_hash,
            &receipt_id,
            &borrower,
            principal,
            &[0x99u8; 32],
        )
        .is_err());
    }
}
