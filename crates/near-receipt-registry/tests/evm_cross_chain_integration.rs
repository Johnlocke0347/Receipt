//! Cross-stack integration test executing `near-receipt-registry` alongside the compiled
//! Base Sepolia Solidity contracts (`MockCreditUSDC.sol` and `ReceiptCreditVault.sol`) inside
//! an in-memory EVM (`revm`, `chain_id = 84532`).

use base64::Engine;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use k256::ecdsa::SigningKey as Secp256k1SigningKey;
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use near_receipt_registry::{set_test_context, ReceiptRegistry, U128};
use receipt_core::eip712::{eip712_domain_separator, BASE_SEPOLIA_CHAIN_ID};
use receipt_core::hashing;
use receipt_core::mpc_foreign_tx::{EvmFinality, EvmLog, Hash160, Hash256};
use receipt_core::mpc_sign::{
    derive_mpc_tweak, format_near_secp256k1_pubkey, MpcSecp256k1Signature,
    VerifyForeignTransactionResponseDto, DEFAULT_DERIVATION_PATH,
};
use receipt_core::receipt::{ConsequenceState, ReceiptV1, WorkOutcome};
use receipt_core::signing::{sign_payload, Party};
use receipt_core::tdx::{HexMeasurements, OutLayerAttestationRecord, TdxQuote};
use revm::db::{CacheDB, EmptyDB};
use revm::primitives::{
    keccak256, AccountInfo, Address, Bytes, ExecutionResult, Log, Output, TransactTo, TxEnv, U256,
};
use revm::Evm;

const MOCK_USDC_BIN_HEX: &str =
    include_str!("../../../contracts/base-sepolia/artifacts/MockCreditUSDC_sol_MockCreditUSDC.bin");
const VAULT_BIN_HEX: &str = include_str!(
    "../../../contracts/base-sepolia/artifacts/ReceiptCreditVault_sol_ReceiptCreditVault.bin"
);
const WORKER_MEASUREMENTS_JSON: &str =
    include_str!("../../receipt-core/tests/fixtures/worker_approved_measurements.json");
const ATTESTATION_1500_JSON: &str =
    include_str!("../../receipt-core/tests/fixtures/outlayer_attestation_1500.json");

fn selector(sig: &str) -> [u8; 4] {
    let h = keccak256(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

fn abi_word_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..32].copy_from_slice(addr);
    w
}

fn abi_word_u128(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..32].copy_from_slice(&v.to_be_bytes());
    w
}

fn abi_word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&v.to_be_bytes());
    w
}

fn abi_word_u8(v: u8) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = v;
    w
}

fn deploy_contract(
    db: &mut CacheDB<EmptyDB>,
    deployer: Address,
    init_code: Vec<u8>,
    block_timestamp: u64,
) -> Address {
    let mut evm = Evm::builder()
        .with_db(db)
        .modify_cfg_env(|cfg| {
            cfg.chain_id = BASE_SEPOLIA_CHAIN_ID;
        })
        .modify_block_env(|b| {
            b.number = U256::from(10_000_000u64);
            b.timestamp = U256::from(block_timestamp);
        })
        .modify_tx_env(|tx: &mut TxEnv| {
            tx.caller = deployer;
            tx.transact_to = TransactTo::Create;
            tx.data = Bytes::from(init_code);
            tx.gas_limit = 5_000_000;
        })
        .build();

    let result = evm.transact_commit().expect("EVM deploy tx failed");
    match result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(addr)),
            ..
        } => addr,
        other => panic!("unexpected deploy result: {other:?}"),
    }
}

fn call_contract(
    db: &mut CacheDB<EmptyDB>,
    caller: Address,
    to: Address,
    calldata: Vec<u8>,
    block_timestamp: u64,
) -> ExecutionResult {
    let mut evm = Evm::builder()
        .with_db(db)
        .modify_cfg_env(|cfg| {
            cfg.chain_id = BASE_SEPOLIA_CHAIN_ID;
        })
        .modify_block_env(|b| {
            b.number = U256::from(10_000_001u64);
            b.timestamp = U256::from(block_timestamp);
        })
        .modify_tx_env(|tx: &mut TxEnv| {
            tx.caller = caller;
            tx.transact_to = TransactTo::Call(to);
            tx.data = Bytes::from(calldata);
            tx.gas_limit = 1_000_000;
        })
        .build();

    evm.transact_commit().expect("EVM call failed")
}

#[allow(clippy::too_many_arguments)]
fn encode_draw_credit_call(
    receipt_id: &[u8; 32],
    borrower: &[u8; 20],
    principal: u128,
    evidence_commitment: &[u8; 32],
    deadline: u64,
    v: u8,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 32 * 8);
    data.extend_from_slice(&selector(
        "drawCredit(bytes32,address,uint256,bytes32,uint256,uint8,bytes32,bytes32)",
    ));
    data.extend_from_slice(receipt_id);
    data.extend_from_slice(&abi_word_address(borrower));
    data.extend_from_slice(&abi_word_u128(principal));
    data.extend_from_slice(evidence_commitment);
    data.extend_from_slice(&abi_word_u64(deadline));
    data.extend_from_slice(&abi_word_u8(v));
    data.extend_from_slice(r);
    data.extend_from_slice(s);
    data
}

#[test]
#[allow(clippy::too_many_lines)]
fn end_to_end_near_registry_to_base_sepolia_evm_vault_and_back() {
    let mut db = CacheDB::new(EmptyDB::default());
    let deployer = Address::from([0x11u8; 20]);
    let borrower_bytes = [0x22u8; 20];
    let borrower = Address::from(borrower_bytes);
    db.insert_account_info(
        deployer,
        AccountInfo {
            balance: U256::from(10_000_000_000_000_000_000u128),
            ..Default::default()
        },
    );
    db.insert_account_info(
        borrower,
        AccountInfo {
            balance: U256::from(1_000_000_000_000_000_000u128),
            ..Default::default()
        },
    );

    let now_ts = 1_771_590_000u64;

    // 1. Deploy MockCreditUSDC(initialSupply = 1_000_000_000_000)
    let mut usdc_init = hex::decode(MOCK_USDC_BIN_HEX.trim()).expect("decode MockCreditUSDC bin");
    usdc_init.extend_from_slice(&abi_word_u128(1_000_000_000_000));
    let usdc_addr = deploy_contract(&mut db, deployer, usdc_init, now_ts);

    // 2. Initialize NEAR ReceiptRegistry and configure deterministic MPC domain 0 & domain 3 keys
    set_test_context("receipt-registry.testnet", "owner.testnet", 0);
    let mut registry = ReceiptRegistry::new(
        "owner.testnet".parse().unwrap(),
        Some("v1.signer-prod.testnet".parse().unwrap()),
        None,
    );

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

    registry.set_domain_root_pubkeys(
        format_near_secp256k1_pubkey(&sign_root_pk64),
        format_near_secp256k1_pubkey(&foreign_tx_root_pk64),
    );

    // Sync genuine OutLayer worker approved measurements (129 sets)
    let hex_measurements: Vec<HexMeasurements> =
        serde_json::from_str(WORKER_MEASUREMENTS_JSON).unwrap();
    assert_eq!(registry.on_measurements_synced(Ok(hex_measurements)), 129);

    // Compute nearAuthorizedSigner EVM address derived for receipt-registry.testnet
    let authorized_signer_hex = registry.derive_vault_authorized_signer_evm_address();
    let authorized_signer_bytes: [u8; 20] =
        hex::decode(authorized_signer_hex.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap();

    // 3. Deploy ReceiptCreditVault(nearAuthorizedSigner, creditToken, lenderId)
    let lender_id = [0xccu8; 32];
    let mut vault_init = hex::decode(VAULT_BIN_HEX.trim()).expect("decode ReceiptCreditVault bin");
    vault_init.extend_from_slice(&abi_word_address(&authorized_signer_bytes));
    vault_init.extend_from_slice(&abi_word_address(usdc_addr.as_slice().try_into().unwrap()));
    vault_init.extend_from_slice(&lender_id);
    let vault_addr = deploy_contract(&mut db, deployer, vault_init, now_ts);
    let vault_bytes: [u8; 20] = vault_addr.as_slice().try_into().unwrap();

    // Fund ReceiptCreditVault with 500_000_000_000 mUSDC
    let mut transfer_call = Vec::with_capacity(4 + 64);
    transfer_call.extend_from_slice(&selector("transfer(address,uint256)"));
    transfer_call.extend_from_slice(&abi_word_address(&vault_bytes));
    transfer_call.extend_from_slice(&abi_word_u128(500_000_000_000));
    assert!(call_contract(&mut db, deployer, usdc_addr, transfer_call, now_ts).is_success());

    // Pin deployed Base Sepolia vault address on NEAR ReceiptRegistry
    registry.set_configured_base_vault(hex::encode(vault_bytes));

    // 4. Verify ReceiptCreditVault.DOMAIN_SEPARATOR() matches receipt_core::eip712_domain_separator
    let dom_res = call_contract(
        &mut db,
        deployer,
        vault_addr,
        selector("DOMAIN_SEPARATOR()").to_vec(),
        now_ts,
    );
    let ExecutionResult::Success {
        output: Output::Call(dom_bytes),
        ..
    } = dom_res
    else {
        panic!("DOMAIN_SEPARATOR() call failed");
    };
    assert_eq!(
        dom_bytes.as_ref(),
        &eip712_domain_separator(BASE_SEPOLIA_CHAIN_ID, &vault_bytes)
    );

    // 5. Register genuine OutLayer TDX quote 1500 receipt on NEAR ReceiptRegistry
    let record: OutLayerAttestationRecord = serde_json::from_str(ATTESTATION_1500_JSON).unwrap();
    let quote_bytes = base64::engine::general_purpose::STANDARD
        .decode(record.tdx_quote.trim())
        .unwrap();
    let parsed_quote = TdxQuote::parse(&quote_bytes).unwrap();
    let task_meta = record.to_v1_task_inputs().unwrap();
    let wasm_hash = task_meta.wasm_hash.unwrap();
    let input_hash = task_meta.input_hash.unwrap();
    let output_hash = task_meta.output_hash;
    registry.add_expected_wasm_hash(hex::encode(wasm_hash));

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
    let receipt_id = hashing::receipt_id("provider.testnet", 1, &evidence);

    let mut receipt = ReceiptV1 {
        receipt_id,
        schema_version: 1,
        provider_identity: "provider.testnet".to_string(),
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
        nonce: 1,
        created_at: 1_771_587_262,
        confidential_settlement_commitment: settlement_commitment,
        borrower_evm_address: borrower_bytes,
        max_credit_principal: 250_000_000,
        consequence_state: ConsequenceState::RegisteredVerified,
        foreign_chain_id: None,
        foreign_tx_hash: None,
        lender_id: None,
        verified_finality_evidence: None,
    };
    let signing_bytes = receipt.signing_payload();
    receipt.buyer_signature = sign_payload(
        Party::Buyer,
        &buyer_sk,
        "testnet",
        "receipt-registry.testnet",
        &signing_bytes,
    )
    .unwrap();
    receipt.provider_signature = sign_payload(
        Party::Provider,
        &provider_sk,
        "testnet",
        "receipt-registry.testnet",
        &signing_bytes,
    )
    .unwrap();

    set_test_context("receipt-registry.testnet", "provider.testnet", 0);
    let id_hex = registry.register_receipt(receipt.clone(), quote_bytes, task_meta);
    assert_eq!(id_hex, hex::encode(receipt_id));

    // 6. Authorize loan on NEAR ReceiptRegistry and produce MPC Chain Signatures packet
    let principal = 250_000_000u128;
    let deadline = now_ts + 3600;
    set_test_context("receipt-registry.testnet", "provider.testnet", 1);
    let _ = registry.authorize_loan(
        id_hex.clone(),
        hex::encode(borrower_bytes),
        U128(principal),
        hex::encode(vault_bytes),
        deadline,
    );

    let pending_loan = registry
        .pending_loan_requests
        .get(&receipt_id)
        .unwrap()
        .clone();

    // Verify ReceiptCreditVault.computeLoanDigest(...) on EVM equals pending_loan.eip712_digest
    let mut digest_call = Vec::with_capacity(4 + 32 * 5);
    digest_call.extend_from_slice(&selector(
        "computeLoanDigest(bytes32,address,uint256,bytes32,uint256)",
    ));
    digest_call.extend_from_slice(&receipt_id);
    digest_call.extend_from_slice(&abi_word_address(&borrower_bytes));
    digest_call.extend_from_slice(&abi_word_u128(principal));
    digest_call.extend_from_slice(&evidence);
    digest_call.extend_from_slice(&abi_word_u64(deadline));
    let ExecutionResult::Success {
        output: Output::Call(evm_digest),
        ..
    } = call_contract(&mut db, deployer, vault_addr, digest_call, now_ts)
    else {
        panic!("computeLoanDigest failed");
    };
    assert_eq!(evm_digest.as_ref(), &pending_loan.eip712_digest);

    // Produce NEAR Chain Signatures child key signature over pending_loan.eip712_digest
    let tweak = derive_mpc_tweak("receipt-registry.testnet", DEFAULT_DERIVATION_PATH);
    let tweak_scalar = Scalar::from_repr(tweak.into()).unwrap();
    let child_sk =
        Secp256k1SigningKey::from_bytes(&(sign_root_secret + tweak_scalar).to_bytes()).unwrap();
    let (sig, rec_id) = child_sk
        .sign_prehash_recoverable(&pending_loan.eip712_digest)
        .unwrap();
    set_test_context("receipt-registry.testnet", "receipt-registry.testnet", 0);
    let packet = registry
        .on_loan_authorization_signed(
            receipt_id,
            Ok(MpcSecp256k1Signature::from_r_s_v(
                &sig.r().to_bytes().into(),
                &sig.s().to_bytes().into(),
                rec_id.to_byte(),
            )),
        )
        .expect("on_loan_authorization_signed should return packet");

    // 7. Negative EVM checks on ReceiptCreditVault.drawCredit(...)
    // 7a. Expired deadline -> reverts with AuthorizationExpired(uint256,uint256)
    let expired_call = encode_draw_credit_call(
        &packet.receipt_id,
        &packet.borrower_evm_address,
        packet.principal_amount,
        &packet.evidence_commitment,
        packet.deadline,
        packet.signature_v,
        &packet.signature_r,
        &packet.signature_s,
    );
    let expired_res = call_contract(&mut db, borrower, vault_addr, expired_call, deadline + 1);
    let ExecutionResult::Revert {
        output: rev_out, ..
    } = expired_res
    else {
        panic!("expected revert on expired deadline");
    };
    assert_eq!(
        &rev_out[0..4],
        &selector("AuthorizationExpired(uint256,uint256)")
    );

    // 7b. Tampered principal -> reverts with InvalidNearSignature(address,address)
    let tampered_principal_call = encode_draw_credit_call(
        &packet.receipt_id,
        &packet.borrower_evm_address,
        packet.principal_amount + 1,
        &packet.evidence_commitment,
        packet.deadline,
        packet.signature_v,
        &packet.signature_r,
        &packet.signature_s,
    );
    let tampered_res = call_contract(
        &mut db,
        borrower,
        vault_addr,
        tampered_principal_call,
        now_ts,
    );
    let ExecutionResult::Revert {
        output: rev_out, ..
    } = tampered_res
    else {
        panic!("expected revert on tampered principal");
    };
    assert_eq!(
        &rev_out[0..4],
        &selector("InvalidNearSignature(address,address)")
    );

    // 7c. Invalid recovery byte v = 29 -> reverts with InvalidSignatureScalars()
    let bad_v_call = encode_draw_credit_call(
        &packet.receipt_id,
        &packet.borrower_evm_address,
        packet.principal_amount,
        &packet.evidence_commitment,
        packet.deadline,
        29,
        &packet.signature_r,
        &packet.signature_s,
    );
    let bad_v_res = call_contract(&mut db, borrower, vault_addr, bad_v_call, now_ts);
    let ExecutionResult::Revert {
        output: rev_out, ..
    } = bad_v_res
    else {
        panic!("expected revert on invalid v byte");
    };
    assert_eq!(&rev_out[0..4], &selector("InvalidSignatureScalars()"));

    // 7d. High-s malleable signature -> reverts with InvalidSignatureScalars()
    let neg_s = -sig.s().as_ref();
    let high_s_bytes: [u8; 32] = neg_s.to_bytes().into();
    let flipped_v = if packet.signature_v == 27 { 28 } else { 27 };
    let high_s_call = encode_draw_credit_call(
        &packet.receipt_id,
        &packet.borrower_evm_address,
        packet.principal_amount,
        &packet.evidence_commitment,
        packet.deadline,
        flipped_v,
        &packet.signature_r,
        &high_s_bytes,
    );
    let high_s_res = call_contract(&mut db, borrower, vault_addr, high_s_call, now_ts);
    let ExecutionResult::Revert {
        output: rev_out, ..
    } = high_s_res
    else {
        panic!("expected revert on high-s signature");
    };
    assert_eq!(&rev_out[0..4], &selector("InvalidSignatureScalars()"));

    // 8. Positive EVM execution of ReceiptCreditVault.drawCredit(...)
    let valid_draw_call = encode_draw_credit_call(
        &packet.receipt_id,
        &packet.borrower_evm_address,
        packet.principal_amount,
        &packet.evidence_commitment,
        packet.deadline,
        packet.signature_v,
        &packet.signature_r,
        &packet.signature_s,
    );
    let draw_res = call_contract(
        &mut db,
        borrower,
        vault_addr,
        valid_draw_call.clone(),
        now_ts,
    );
    let ExecutionResult::Success { logs, .. } = draw_res else {
        panic!("valid drawCredit should succeed on EVM");
    };
    // ReceiptCreditVault emits LoanDrawn FIRST (log_index 0), before MockCreditUSDC.Transfer (log_index 1)
    assert_eq!(logs.len(), 2);
    let evm_loan_drawn_log: &Log = &logs[0];
    assert_eq!(evm_loan_drawn_log.address, vault_addr);
    assert_eq!(evm_loan_drawn_log.data.topics().len(), 4);

    // Check borrower MockCreditUSDC balance == principal (250_000_000)
    let mut bal_call = Vec::with_capacity(4 + 32);
    bal_call.extend_from_slice(&selector("balanceOf(address)"));
    bal_call.extend_from_slice(&abi_word_address(&borrower_bytes));
    let ExecutionResult::Success {
        output: Output::Call(bal_bytes),
        ..
    } = call_contract(&mut db, borrower, usdc_addr, bal_call, now_ts)
    else {
        panic!("balanceOf failed");
    };
    assert_eq!(bal_bytes.as_ref(), &abi_word_u128(principal));

    // 8b. Replaying the same receiptId on ReceiptCreditVault reverts with ReceiptAlreadyConsumed(bytes32)
    let replay_res = call_contract(&mut db, borrower, vault_addr, valid_draw_call, now_ts);
    let ExecutionResult::Revert {
        output: rev_out, ..
    } = replay_res
    else {
        panic!("expected revert on replayed receiptId");
    };
    assert_eq!(&rev_out[0..4], &selector("ReceiptAlreadyConsumed(bytes32)"));
    assert_eq!(&rev_out[4..36], &receipt_id);

    // 9. Feed the real EVM LoanDrawn log (log_index: 0) emitted by ReceiptCreditVault back into
    //    NEAR ReceiptRegistry::verify_loan_consequence -> on_foreign_tx_verified!
    let base_tx_hash = [0xa1u8; 32];
    let base_block_hash = [0xb2u8; 32];
    let topics: Vec<Hash256> = evm_loan_drawn_log
        .data
        .topics()
        .iter()
        .map(|t| Hash256(t.0))
        .collect();
    let near_evm_log = EvmLog {
        removed: false,
        log_index: 0,
        transaction_index: 0,
        transaction_hash: Hash256(base_tx_hash),
        block_hash: Hash256(base_block_hash),
        block_number: 10_000_001,
        address: Hash160(vault_bytes),
        data: format!("0x{}", hex::encode(&evm_loan_drawn_log.data.data)),
        topics,
    };

    set_test_context("receipt-registry.testnet", "provider.testnet", 1);
    let verify_promise = registry.verify_loan_consequence(
        id_hex.clone(),
        hex::encode(base_tx_hash),
        hex::encode(base_block_hash),
        near_evm_log,
        EvmFinality::Finalized,
    );
    assert_eq!(verify_promise.method_name, "verify_foreign_transaction");

    let pending_ver = registry
        .pending_consequence_requests
        .get(&receipt_id)
        .unwrap()
        .clone();
    let (ftx_sig, ftx_rec) = foreign_tx_root_sk
        .sign_prehash_recoverable(&pending_ver.expected_payload_hash)
        .unwrap();
    set_test_context("receipt-registry.testnet", "receipt-registry.testnet", 0);
    let verified = registry.on_foreign_tx_verified(
        receipt_id,
        Ok(VerifyForeignTransactionResponseDto {
            payload_hash: Hash256(pending_ver.expected_payload_hash),
            signature: MpcSecp256k1Signature::from_r_s_v(
                &ftx_sig.r().to_bytes().into(),
                &ftx_sig.s().to_bytes().into(),
                ftx_rec.to_byte(),
            ),
        }),
    );
    assert!(verified);

    // 10. Assert final ConsequenceProofView and Provider Credit Graph
    let proof = registry.verify_consequence_proof(id_hex).unwrap();
    assert!(proof.is_mpc_consequence_verified);
    assert_eq!(
        proof.receipt.consequence_state,
        ConsequenceState::ConsumedVerified
    );
    assert_eq!(proof.receipt.foreign_tx_hash, Some(base_tx_hash));
    assert_eq!(
        proof.receipt.lender_id.as_deref(),
        Some(hex::encode(lender_id).as_str())
    );
}
