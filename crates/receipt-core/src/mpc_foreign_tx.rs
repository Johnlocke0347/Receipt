//! Borsh-compatible replicas of the `near-mpc-contract-interface` foreign-chain types.
//!
//! Source of truth: `near/mpc` `crates/near-mpc-contract-interface/src/types/foreign_chain/`
//! (`sign_payload.rs`, `rpc_request.rs`, `request.rs`, `chains/evm.rs`). Borsh encodes enum
//! variants by declaration index, so non-EVM variants are not modelled but their indices are
//! preserved via [`EvmChain`] / explicit tag bytes. A golden test pins the hash against the
//! upstream insta snapshot for `ForeignTxSignPayload::V1` (Ethereum).

use borsh::io::{Result as IoResult, Write};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::error::ReceiptError;
use crate::hexser;

/// Upstream cap on extractors per request.
pub const MAX_EXTRACTORS_PER_REQUEST: usize = 32;
/// `DomainPurpose::ForeignTx` domain used for `verify_foreign_transaction` on testnet.
pub const FOREIGN_TX_DOMAIN_ID: u64 = 3;
/// Signature canonical event signature of the Base Sepolia vault event.
pub const LOAN_DRAWN_SIGNATURE: &str = "LoanDrawn(bytes32,address,uint256,bytes32,bytes32)";

/// 32-byte hash (hex in JSON).
#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
pub struct Hash256(#[serde(with = "hexser")] pub [u8; 32]);

/// 20-byte hash / EVM address (hex in JSON).
#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
pub struct Hash160(#[serde(with = "hexser")] pub [u8; 20]);

/// EVM transaction id.
#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
pub struct EvmTxId(#[serde(with = "hexser")] pub [u8; 32]);

/// EVM finality level.
#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
pub enum EvmFinality {
    /// Latest block (fast demo mode only).
    Latest,
    /// Safe block.
    Safe,
    /// Finalized block.
    Finalized,
}

/// Value to extract from the transaction (discriminants are part of the Borsh encoding).
#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum EvmExtractor {
    /// Block hash containing the transaction.
    BlockHash = 0,
    /// Log at `log_index`.
    Log {
        /// Index of the log within the transaction receipt.
        log_index: u64,
    } = 1,
}

/// EVM log as returned by the MPC nodes.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EvmLog {
    /// Reorg flag.
    pub removed: bool,
    /// Log index.
    pub log_index: u64,
    /// Transaction index.
    pub transaction_index: u64,
    /// Transaction hash.
    pub transaction_hash: Hash256,
    /// Block hash.
    pub block_hash: Hash256,
    /// Block number.
    pub block_number: u64,
    /// Emitting contract.
    pub address: Hash160,
    /// `0x`-prefixed data string, exactly as upstream carries it.
    pub data: String,
    /// Topics.
    pub topics: Vec<Hash256>,
}

/// Extracted EVM value.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum EvmExtractedValue {
    /// Block hash.
    BlockHash(Hash256),
    /// Log.
    Log(EvmLog),
}

/// EVM RPC request body.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EvmRpcRequest {
    /// Transaction to verify.
    pub tx_id: EvmTxId,
    /// Extractors (at most [`MAX_EXTRACTORS_PER_REQUEST`]).
    pub extractors: Vec<EvmExtractor>,
    /// Finality requirement.
    pub finality: EvmFinality,
}

/// EVM chains with their upstream `ForeignChainRpcRequest` variant index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EvmChain {
    /// `Abstract`.
    Abstract = 0,
    /// `Ethereum`.
    Ethereum = 1,
    /// `Bnb`.
    Bnb = 5,
    /// `Base`.
    Base = 6,
    /// `Arbitrum`.
    Arbitrum = 7,
    /// `Polygon`.
    Polygon = 8,
    /// `HyperEvm`.
    HyperEvm = 9,
    /// `Avalanche`.
    Avalanche = 13,
    /// `Adi`.
    Adi = 14,
}

impl EvmChain {
    /// Upstream JSON variant name.
    #[must_use]
    pub fn json_name(self) -> &'static str {
        match self {
            EvmChain::Abstract => "Abstract",
            EvmChain::Ethereum => "Ethereum",
            EvmChain::Bnb => "Bnb",
            EvmChain::Base => "Base",
            EvmChain::Arbitrum => "Arbitrum",
            EvmChain::Polygon => "Polygon",
            EvmChain::HyperEvm => "HyperEvm",
            EvmChain::Avalanche => "Avalanche",
            EvmChain::Adi => "Adi",
        }
    }
}

/// `ForeignChainRpcRequest` restricted to EVM chains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignChainRpcRequest {
    /// Target chain.
    pub chain: EvmChain,
    /// Request body.
    pub request: EvmRpcRequest,
}

impl ForeignChainRpcRequest {
    /// Base (Sepolia in testnet) request, as used by RECEIPT.
    #[must_use]
    pub fn base(request: EvmRpcRequest) -> Self {
        Self {
            chain: EvmChain::Base,
            request,
        }
    }
}

impl BorshSerialize for ForeignChainRpcRequest {
    fn serialize<W: Write>(&self, writer: &mut W) -> IoResult<()> {
        BorshSerialize::serialize(&(self.chain as u8), writer)?;
        BorshSerialize::serialize(&self.request, writer)
    }
}

/// `ExtractedValue` restricted to the EVM variant (upstream variant index 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractedValue(pub EvmExtractedValue);

const EXTRACTED_VALUE_EVM_TAG: u8 = 1;

impl BorshSerialize for ExtractedValue {
    fn serialize<W: Write>(&self, writer: &mut W) -> IoResult<()> {
        BorshSerialize::serialize(&EXTRACTED_VALUE_EVM_TAG, writer)?;
        BorshSerialize::serialize(&self.0, writer)
    }
}

/// `ForeignTxSignPayload::V1` (variant index 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignTxSignPayloadV1 {
    /// Original request.
    pub request: ForeignChainRpcRequest,
    /// Values in extractor order.
    pub values: Vec<ExtractedValue>,
}

impl BorshSerialize for ForeignTxSignPayloadV1 {
    fn serialize<W: Write>(&self, writer: &mut W) -> IoResult<()> {
        BorshSerialize::serialize(&0u8, writer)?; // ForeignTxSignPayload::V1
        BorshSerialize::serialize(&self.request, writer)?;
        BorshSerialize::serialize(&self.values, writer)
    }
}

impl ForeignTxSignPayloadV1 {
    /// `SHA256(Borsh(ForeignTxSignPayload::V1))`: the `expected_payload_hash`.
    ///
    /// # Errors
    /// Fails if Borsh serialization fails.
    pub fn compute_msg_hash(&self) -> Result<[u8; 32], ReceiptError> {
        let bytes = borsh::to_vec(self).map_err(|e| ReceiptError::Serialization(e.to_string()))?;
        Ok(Sha256::digest(bytes).into())
    }
}

/// Build the expected payload for a Base transaction whose extractors are
/// `[BlockHash, Log { log_index }]`.
///
/// # Errors
/// Fails if `log.block_hash != block_hash` or `log.log_index != log_index`.
pub fn base_block_and_log_payload(
    tx_id: [u8; 32],
    finality: EvmFinality,
    block_hash: [u8; 32],
    log: EvmLog,
) -> Result<ForeignTxSignPayloadV1, ReceiptError> {
    if log.block_hash.0 != block_hash {
        return Err(ReceiptError::InvalidInput(
            "log.block_hash != block_hash".into(),
        ));
    }
    if log.transaction_hash.0 != tx_id {
        return Err(ReceiptError::InvalidInput(
            "log.transaction_hash != tx_id".into(),
        ));
    }
    let extractors = vec![
        EvmExtractor::BlockHash,
        EvmExtractor::Log {
            log_index: log.log_index,
        },
    ];
    Ok(ForeignTxSignPayloadV1 {
        request: ForeignChainRpcRequest::base(EvmRpcRequest {
            tx_id: EvmTxId(tx_id),
            extractors,
            finality,
        }),
        values: vec![
            ExtractedValue(EvmExtractedValue::BlockHash(Hash256(block_hash))),
            ExtractedValue(EvmExtractedValue::Log(log)),
        ],
    })
}

/// JSON body for `v1.signer-prod.testnet::verify_foreign_transaction`.
///
/// # Errors
/// Fails if the request exceeds the extractor cap or JSON encoding fails.
pub fn verify_foreign_transaction_args(
    request: &ForeignChainRpcRequest,
    domain_id: u64,
    expected_payload_hash: Option<[u8; 32]>,
) -> Result<serde_json::Value, ReceiptError> {
    if request.request.extractors.len() > MAX_EXTRACTORS_PER_REQUEST {
        return Err(ReceiptError::InvalidInput("too many extractors".into()));
    }
    let body = serde_json::to_value(&request.request)
        .map_err(|e| ReceiptError::Serialization(e.to_string()))?;
    let mut args = serde_json::json!({
        "request": { request.chain.json_name(): body },
        "domain_id": domain_id,
        "payload_version": 1,
    });
    if let Some(h) = expected_payload_hash {
        args["expected_payload_hash"] = serde_json::Value::String(hex::encode(h));
    }
    Ok(serde_json::json!({ "request": args }))
}

/// Keccak-256 topic0 of [`LOAN_DRAWN_SIGNATURE`].
#[must_use]
pub fn loan_drawn_topic0() -> [u8; 32] {
    Keccak256::digest(LOAN_DRAWN_SIGNATURE.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth_payload() -> ForeignTxSignPayloadV1 {
        ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest {
                chain: EvmChain::Ethereum,
                request: EvmRpcRequest {
                    tx_id: EvmTxId([0xab; 32]),
                    extractors: vec![EvmExtractor::BlockHash],
                    finality: EvmFinality::Finalized,
                },
            },
            values: vec![ExtractedValue(EvmExtractedValue::BlockHash(Hash256(
                [0xef; 32],
            )))],
        }
    }

    /// Upstream snapshot: `foreign_tx_sign_payload_v1_ethereum__should_have_consistent_hash`.
    #[test]
    fn matches_upstream_golden_hash() {
        assert_eq!(
            hex::encode(eth_payload().compute_msg_hash().unwrap()),
            "2ab97999d1e015730271c7d6cbb298af76fd1de7af81926b42a8877bc4f5794e"
        );
    }

    fn log(tx: [u8; 32], block: [u8; 32]) -> EvmLog {
        EvmLog {
            removed: false,
            log_index: 0,
            transaction_index: 1,
            transaction_hash: Hash256(tx),
            block_hash: Hash256(block),
            block_number: 42,
            address: Hash160([9; 20]),
            data: "0x".into(),
            topics: vec![Hash256(loan_drawn_topic0())],
        }
    }

    #[test]
    fn base_variant_index_is_six() {
        let p = base_block_and_log_payload(
            [1; 32],
            EvmFinality::Finalized,
            [2; 32],
            log([1; 32], [2; 32]),
        )
        .unwrap();
        let bytes = borsh::to_vec(&p).unwrap();
        assert_eq!(&bytes[..2], &[0, 6]);
    }

    #[test]
    fn mismatched_log_rejected() {
        assert!(base_block_and_log_payload(
            [1; 32],
            EvmFinality::Finalized,
            [2; 32],
            log([1; 32], [3; 32])
        )
        .is_err());
        assert!(base_block_and_log_payload(
            [1; 32],
            EvmFinality::Finalized,
            [2; 32],
            log([5; 32], [2; 32])
        )
        .is_err());
    }

    #[test]
    fn payload_hash_changes_with_log_contents() {
        let a = base_block_and_log_payload(
            [1; 32],
            EvmFinality::Finalized,
            [2; 32],
            log([1; 32], [2; 32]),
        )
        .unwrap();
        let mut l = log([1; 32], [2; 32]);
        l.data = "0x01".into();
        let b = base_block_and_log_payload([1; 32], EvmFinality::Finalized, [2; 32], l).unwrap();
        assert_ne!(a.compute_msg_hash().unwrap(), b.compute_msg_hash().unwrap());
    }

    #[test]
    fn args_json_shape_matches_upstream() {
        let p = base_block_and_log_payload(
            [1; 32],
            EvmFinality::Finalized,
            [2; 32],
            log([1; 32], [2; 32]),
        )
        .unwrap();
        let args = verify_foreign_transaction_args(&p.request, FOREIGN_TX_DOMAIN_ID, Some([7; 32]))
            .unwrap();
        let r = &args["request"];
        assert_eq!(r["domain_id"], 3);
        assert_eq!(r["payload_version"], 1);
        assert_eq!(r["request"]["Base"]["finality"], "Finalized");
        assert_eq!(r["request"]["Base"]["extractors"][0], "BlockHash");
        assert_eq!(r["request"]["Base"]["extractors"][1]["Log"]["log_index"], 0);
        assert_eq!(r["expected_payload_hash"], "07".repeat(32));
    }

    #[test]
    fn extractor_cap_enforced() {
        let req = ForeignChainRpcRequest::base(EvmRpcRequest {
            tx_id: EvmTxId([0; 32]),
            extractors: vec![EvmExtractor::BlockHash; MAX_EXTRACTORS_PER_REQUEST + 1],
            finality: EvmFinality::Safe,
        });
        assert!(verify_foreign_transaction_args(&req, 3, None).is_err());
    }

    #[test]
    fn loan_drawn_topic_is_stable() {
        assert_eq!(loan_drawn_topic0().len(), 32);
        assert_ne!(loan_drawn_topic0(), [0u8; 32]);
    }
}
