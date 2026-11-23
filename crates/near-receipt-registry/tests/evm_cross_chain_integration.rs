//! Cross-stack integration tests executing `near-receipt-registry` alongside the compiled
//! Base Sepolia Solidity contracts (`MockCreditUSDC.sol`, `AgentPayoutProxy`, and `ReceiptCreditVault.sol`)
//! inside an in-memory EVM (`revm`, `chain_id = 84532`).

use base64::Engine;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use k256::ecdsa::SigningKey as Secp256k1SigningKey;
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use near_receipt_registry::{set_test_context, set_test_timestamp, ReceiptRegistry, U128};
use receipt_core::eip712::{eip712_domain_separator, BASE_SEPOLIA_CHAIN_ID};
use receipt_core::hashing;
use receipt_core::mpc_foreign_tx::{EvmFinality, EvmLog, Hash160, Hash256};
use receipt_core::mpc_sign::{
    derive_mpc_tweak, format_near_secp256k1_pubkey, MpcSecp256k1Signature,
    VerifyForeignTransactionResponseDto, DEFAULT_DERIVATION_PATH,
};
use receipt_core::receipt::{ConsequenceState, ReceiptV1, WorkOutcome};
use receipt_core::signing::{sign_payload, Party};
use receipt_core::tdx::{HexMeasurements, OutLayerAttestationRecord, TaskHashInputs, TdxQuote};
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
const ATTESTATION_3000_JSON: &str =
    include_str!("../../receipt-core/tests/fixtures/outlayer_attestation_3000.json");

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

fn abi_word_u16(v: u16) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[30..32].copy_from_slice(&v.to_be_bytes());
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
            tx.gas_limit = 8_000_000;
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
            tx.gas_limit = 3_000_000;
        })
        .build();

    evm.transact_commit().expect("EVM call failed")
}

#[allow(clippy::too_many_arguments)]
fn encode_vault_init(
    near_signer: &[u8; 20],
    credit_token: &[u8; 20],
    lender_id: &[u8; 32],
    hard_per_agent_cap: u128,
    grace_period_secs: u64,
    holdback_bps: u16,
    min_first_loss_bps: u16,
    junior_yield_bps: u16,
) -> Vec<u8> {
    let mut init = hex::decode(VAULT_BIN_HEX.trim()).expect("decode ReceiptCreditVault bin");
    init.extend_from_slice(&abi_word_address(near_signer));
    init.extend_from_slice(&abi_word_address(credit_token));
    init.extend_from_slice(lender_id);
    init.extend_from_slice(&abi_word_u128(hard_per_agent_cap));
    init.extend_from_slice(&abi_word_u64(grace_period_secs));
    init.extend_from_slice(&abi_word_u16(holdback_bps));
    init.extend_from_slice(&abi_word_u16(min_first_loss_bps));
    init.extend_from_slice(&abi_word_u16(junior_yield_bps));
    init
}

#[allow(clippy::too_many_arguments)]
fn encode_draw_credit_call(
    receipt_id: &[u8; 32],
    borrower: &[u8; 20],
    principal: u128,
    fee_amount: u128,
    maturity_at: u64,
    evidence_commitment: &[u8; 32],
    deadline: u64,
    v: u8,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 32 * 10);
    data.extend_from_slice(&selector(
        "drawCredit(bytes32,address,uint256,uint256,uint64,bytes32,uint256,uint8,bytes32,bytes32)",
    ));
    data.extend_from_slice(receipt_id);
    data.extend_from_slice(&abi_word_address(borrower));
    data.extend_from_slice(&abi_word_u128(principal));
    data.extend_from_slice(&abi_word_u128(fee_amount));
    data.extend_from_slice(&abi_word_u64(maturity_at));
    data.extend_from_slice(evidence_commitment);
    data.extend_from_slice(&abi_word_u64(deadline));
    data.extend_from_slice(&abi_word_u8(v));
    data.extend_from_slice(r);
    data.extend_from_slice(s);
    data
}

fn call_view_u128(
    db: &mut CacheDB<EmptyDB>,
    caller: Address,
    target: Address,
    sig: &str,
    now_ts: u64,
) -> u128 {
    let ExecutionResult::Success {
        output: Output::Call(out),
        ..
    } = call_contract(db, caller, target, selector(sig).to_vec(), now_ts)
    else {
        panic!("view call {sig} failed");
    };
    u128::from_be_bytes(out[16..32].try_into().unwrap())
}

fn erc20_balance_of(
    db: &mut CacheDB<EmptyDB>,
    caller: Address,
    token: Address,
    owner: &[u8; 20],
    now_ts: u64,
) -> u128 {
    let mut call = Vec::with_capacity(36);
    call.extend_from_slice(&selector("balanceOf(address)"));
    call.extend_from_slice(&abi_word_address(owner));
    let ExecutionResult::Success {
        output: Output::Call(out),
        ..
    } = call_contract(db, caller, token, call, now_ts)
    else {
        panic!("balanceOf failed");
    };
    u128::from_be_bytes(out[16..32].try_into().unwrap())
}

fn erc20_approve(
    db: &mut CacheDB<EmptyDB>,
    owner: Address,
    token: Address,
    spender: &[u8; 20],
    amount: u128,
    now_ts: u64,
) {
    let mut call = Vec::with_capacity(68);
    call.extend_from_slice(&selector("approve(address,uint256)"));
    call.extend_from_slice(&abi_word_address(spender));
    call.extend_from_slice(&abi_word_u128(amount));
    assert!(call_contract(db, owner, token, call, now_ts).is_success());
}

fn erc20_transfer(
    db: &mut CacheDB<EmptyDB>,
    from: Address,
    token: Address,
    to: &[u8; 20],
    amount: u128,
    now_ts: u64,
) {
    let mut call = Vec::with_capacity(68);
    call.extend_from_slice(&selector("transfer(address,uint256)"));
    call.extend_from_slice(&abi_word_address(to));
    call.extend_from_slice(&abi_word_u128(amount));
    assert!(call_contract(db, from, token, call, now_ts).is_success());
}

fn log_to_evm_log(
    log: &Log,
    tx_hash: [u8; 32],
    block_hash: [u8; 32],
    vault_bytes: [u8; 20],
) -> EvmLog {
    EvmLog {
        removed: false,
        log_index: 0,
        transaction_index: 0,
        transaction_hash: Hash256(tx_hash),
        block_hash: Hash256(block_hash),
        block_number: 10_000_001,
        address: Hash160(vault_bytes),
        data: format!("0x{}", hex::encode(&log.data.data)),
        topics: log.data.topics().iter().map(|t| Hash256(t.0)).collect(),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_signed_receipt_from_attestation(
    attestation_json: &str,
    buyer_sk: &Ed25519SigningKey,
    provider_sk: &Ed25519SigningKey,
    borrower_bytes: [u8; 20],
    max_credit_principal: u128,
    attested_revenue: u128,
    nonce: u64,
    created_at: u64,
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
    let settlement = hashing::confidential_settlement_commitment(
        &[0x66u8; 32],
        attested_revenue,
        &[0x88u8; 32],
        &[0x77u8; 32],
    );
    let evidence = hashing::evidence_commitment(&wasm_hash, &input_hash, &output_hash, &settlement);
    let receipt_id = hashing::receipt_id("provider.testnet", nonce, &evidence);
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
        nonce,
        created_at,
        confidential_settlement_commitment: settlement,
        borrower_evm_address: borrower_bytes,
        max_credit_principal,
        attested_revenue,
        consequence_state: ConsequenceState::RegisteredVerified,
        foreign_chain_id: None,
        foreign_tx_hash: None,
        lender_id: None,
        verified_finality_evidence: None,
    };
    let signing_bytes = receipt.signing_payload();
    receipt.buyer_signature = sign_payload(
        Party::Buyer,
        buyer_sk,
        "testnet",
        "receipt-registry.testnet",
        &signing_bytes,
    )
    .unwrap();
    receipt.provider_signature = sign_payload(
        Party::Provider,
        provider_sk,
        "testnet",
        "receipt-registry.testnet",
        &signing_bytes,
    )
    .unwrap();
    (receipt, quote_bytes, task_meta)
}

struct EvmTestEnv {
    db: CacheDB<EmptyDB>,
    deployer: Address,
    borrower: Address,
    borrower_bytes: [u8; 20],
    payer: Address,
    usdc_addr: Address,
    vault_addr: Address,
    vault_bytes: [u8; 20],
    proxy_addr: Address,
    proxy_bytes: [u8; 20],
    lender_id: [u8; 32],
    registry: ReceiptRegistry,
    sign_root_secret: Scalar,
    foreign_tx_root_sk: Secp256k1SigningKey,
}

#[allow(clippy::too_many_lines)]
fn setup_stack(now_ts: u64, hard_per_agent_cap: u128, min_distinct_payers: u32) -> EvmTestEnv {
    let mut db = CacheDB::new(EmptyDB::default());
    let deployer = Address::from([0x11u8; 20]);
    let borrower_bytes = [0x22u8; 20];
    let borrower = Address::from(borrower_bytes);
    let payer = Address::from([0x33u8; 20]);
    for acct in [deployer, borrower, payer] {
        db.insert_account_info(
            acct,
            AccountInfo {
                balance: U256::from(10_000_000_000_000_000_000u128),
                ..Default::default()
            },
        );
    }

    let mut usdc_init = hex::decode(MOCK_USDC_BIN_HEX.trim()).expect("decode MockCreditUSDC bin");
    usdc_init.extend_from_slice(&abi_word_u128(1_000_000_000_000));
    let usdc_addr = deploy_contract(&mut db, deployer, usdc_init, now_ts);
    let usdc_bytes: [u8; 20] = usdc_addr.as_slice().try_into().unwrap();
    erc20_transfer(
        &mut db,
        deployer,
        usdc_addr,
        &[0x33u8; 20],
        100_000_000,
        now_ts,
    );

    set_test_timestamp(now_ts);
    set_test_context("receipt-registry.testnet", "owner.testnet", 0);
    let mut registry = ReceiptRegistry::new(
        "owner.testnet".parse().unwrap(),
        Some("v1.signer-prod.testnet".parse().unwrap()),
        None,
    );
    registry.set_underwriting_policy(U128(hard_per_agent_cap), min_distinct_payers);

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
    let hex_measurements: Vec<HexMeasurements> =
        serde_json::from_str(WORKER_MEASUREMENTS_JSON).unwrap();
    assert_eq!(registry.on_measurements_synced(Ok(hex_measurements)), 129);

    let authorized_signer_hex = registry.derive_vault_authorized_signer_evm_address();
    let authorized_signer_bytes: [u8; 20] =
        hex::decode(authorized_signer_hex.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap();

    let lender_id = [0xccu8; 32];
    let vault_init = encode_vault_init(
        &authorized_signer_bytes,
        &usdc_bytes,
        &lender_id,
        hard_per_agent_cap,
        60,   // gracePeriodSecs
        500,  // 5% provider holdback
        1500, // 15% min first-loss coverage
        4000, // 40% fee yield to junior pool
    );
    let vault_addr = deploy_contract(&mut db, deployer, vault_init, now_ts);
    let vault_bytes: [u8; 20] = vault_addr.as_slice().try_into().unwrap();
    registry.set_configured_base_vault(hex::encode(vault_bytes));

    // Seed junior first-loss pool ($50) and senior pool ($200) via depositFirstLoss/depositSeniorLiquidity
    erc20_approve(
        &mut db,
        deployer,
        usdc_addr,
        &vault_bytes,
        250_000_000,
        now_ts,
    );
    let mut fl_call = Vec::with_capacity(36);
    fl_call.extend_from_slice(&selector("depositFirstLoss(uint256)"));
    fl_call.extend_from_slice(&abi_word_u128(50_000_000));
    assert!(call_contract(&mut db, deployer, vault_addr, fl_call, now_ts).is_success());

    let mut sl_call = Vec::with_capacity(36);
    sl_call.extend_from_slice(&selector("depositSeniorLiquidity(uint256)"));
    sl_call.extend_from_slice(&abi_word_u128(200_000_000));
    assert!(call_contract(&mut db, deployer, vault_addr, sl_call, now_ts).is_success());

    // Deploy vault-controlled AgentPayoutProxy
    let mut deploy_proxy_call = Vec::with_capacity(36);
    deploy_proxy_call.extend_from_slice(&selector("deployAgentPayoutProxy(address)"));
    deploy_proxy_call.extend_from_slice(&abi_word_address(&borrower_bytes));
    let ExecutionResult::Success {
        output: Output::Call(proxy_out),
        ..
    } = call_contract(&mut db, deployer, vault_addr, deploy_proxy_call, now_ts)
    else {
        panic!("deployAgentPayoutProxy failed");
    };
    let proxy_bytes: [u8; 20] = proxy_out[12..32].try_into().unwrap();
    let proxy_addr = Address::from(proxy_bytes);

    EvmTestEnv {
        db,
        deployer,
        borrower,
        borrower_bytes,
        payer,
        usdc_addr,
        vault_addr,
        vault_bytes,
        proxy_addr,
        proxy_bytes,
        lender_id,
        registry,
        sign_root_secret,
        foreign_tx_root_sk,
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn end_to_end_near_registry_to_base_sepolia_evm_vault_and_back() {
    let now_ts = 1_771_590_000u64;
    let mut env = setup_stack(now_ts, 250_000_000, 1);

    let dom_res = call_contract(
        &mut env.db,
        env.deployer,
        env.vault_addr,
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
        &eip712_domain_separator(BASE_SEPOLIA_CHAIN_ID, &env.vault_bytes)
    );

    let buyer_sk = Ed25519SigningKey::from_bytes(&[0x10u8; 32]);
    let provider_sk = Ed25519SigningKey::from_bytes(&[0x20u8; 32]);
    let (receipt, quote_bytes, task_meta) = build_signed_receipt_from_attestation(
        ATTESTATION_1500_JSON,
        &buyer_sk,
        &provider_sk,
        env.borrower_bytes,
        250_000_000,
        200_000_000,
        1,
        1_771_587_262,
    );
    env.registry
        .add_expected_wasm_hash(hex::encode(receipt.wasm_hash));

    set_test_context("receipt-registry.testnet", "provider.testnet", 0);
    let id_hex = env
        .registry
        .register_receipt(receipt.clone(), quote_bytes, task_meta);

    let principal = 250_000_000u128;
    let fee_amount = 5_000_000u128;
    let maturity_at = now_ts + 86_400;
    let deadline = now_ts + 3600;
    set_test_context("receipt-registry.testnet", "provider.testnet", 1);
    let _ = env.registry.authorize_loan(
        id_hex.clone(),
        hex::encode(env.borrower_bytes),
        U128(principal),
        U128(fee_amount),
        maturity_at,
        hex::encode(env.vault_bytes),
        deadline,
    );

    let pending_loan = env
        .registry
        .pending_loan_requests
        .get(&receipt.receipt_id)
        .unwrap()
        .clone();

    let tweak = derive_mpc_tweak("receipt-registry.testnet", DEFAULT_DERIVATION_PATH);
    let tweak_scalar = Scalar::from_repr(tweak.into()).unwrap();
    let child_sk =
        Secp256k1SigningKey::from_bytes(&(env.sign_root_secret + tweak_scalar).to_bytes()).unwrap();
    let (sig, rec_id) = child_sk
        .sign_prehash_recoverable(&pending_loan.eip712_digest)
        .unwrap();
    set_test_context("receipt-registry.testnet", "receipt-registry.testnet", 0);
    let packet = env
        .registry
        .on_loan_authorization_signed(
            receipt.receipt_id,
            Ok(MpcSecp256k1Signature::from_r_s_v(
                &sig.r().to_bytes().into(),
                &sig.s().to_bytes().into(),
                rec_id.to_byte(),
            )),
        )
        .unwrap();

    // Negative EVM checks: expired deadline, tampered principal, bad v, high-s, and vault pause
    let valid_call = encode_draw_credit_call(
        &packet.receipt_id,
        &packet.borrower_evm_address,
        packet.principal_amount,
        packet.fee_amount,
        packet.maturity_at,
        &packet.evidence_commitment,
        packet.deadline,
        packet.signature_v,
        &packet.signature_r,
        &packet.signature_s,
    );
    let ExecutionResult::Revert { output, .. } = call_contract(
        &mut env.db,
        env.borrower,
        env.vault_addr,
        valid_call.clone(),
        deadline + 1,
    ) else {
        panic!("expected AuthorizationExpired");
    };
    assert_eq!(
        &output[0..4],
        &selector("AuthorizationExpired(uint256,uint256)")
    );

    let tampered_call = encode_draw_credit_call(
        &packet.receipt_id,
        &packet.borrower_evm_address,
        packet.principal_amount - 1,
        packet.fee_amount,
        packet.maturity_at,
        &packet.evidence_commitment,
        packet.deadline,
        packet.signature_v,
        &packet.signature_r,
        &packet.signature_s,
    );
    let ExecutionResult::Revert { output, .. } = call_contract(
        &mut env.db,
        env.borrower,
        env.vault_addr,
        tampered_call,
        now_ts,
    ) else {
        panic!("expected InvalidNearSignature");
    };
    assert_eq!(
        &output[0..4],
        &selector("InvalidNearSignature(address,address)")
    );

    // Owner pause switch blocks drawCredit until unpause()
    assert!(call_contract(
        &mut env.db,
        env.deployer,
        env.vault_addr,
        selector("pause()").to_vec(),
        now_ts
    )
    .is_success());
    let ExecutionResult::Revert { output, .. } = call_contract(
        &mut env.db,
        env.borrower,
        env.vault_addr,
        valid_call.clone(),
        now_ts,
    ) else {
        panic!("expected VaultPaused");
    };
    assert_eq!(&output[0..4], &selector("VaultPaused()"));
    assert!(call_contract(
        &mut env.db,
        env.deployer,
        env.vault_addr,
        selector("unpause()").to_vec(),
        now_ts
    )
    .is_success());

    // Valid drawCredit succeeds; LoanDrawn at log_index 0; net disbursement = 250 - 5% = 237.5 USDC
    let ExecutionResult::Success { logs, .. } = call_contract(
        &mut env.db,
        env.borrower,
        env.vault_addr,
        valid_call.clone(),
        now_ts,
    ) else {
        panic!("drawCredit failed");
    };
    assert_eq!(logs.len(), 2);
    assert_eq!(
        erc20_balance_of(
            &mut env.db,
            env.borrower,
            env.usdc_addr,
            &env.borrower_bytes,
            now_ts
        ),
        237_500_000
    );

    // Verify LoanDrawn consequence on NEAR -> ConsumedVerified
    let base_tx_hash = [0xa1u8; 32];
    let base_block_hash = [0xb2u8; 32];
    let evm_log = log_to_evm_log(&logs[0], base_tx_hash, base_block_hash, env.vault_bytes);
    set_test_context("receipt-registry.testnet", "provider.testnet", 1);
    let _ = env.registry.verify_loan_consequence(
        id_hex.clone(),
        hex::encode(base_tx_hash),
        hex::encode(base_block_hash),
        evm_log,
        EvmFinality::Finalized,
    );
    let pending_ver = env
        .registry
        .pending_consequence_requests
        .get(&receipt.receipt_id)
        .unwrap()
        .clone();
    let (ftx_sig, ftx_rec) = env
        .foreign_tx_root_sk
        .sign_prehash_recoverable(&pending_ver.expected_payload_hash)
        .unwrap();
    set_test_context("receipt-registry.testnet", "receipt-registry.testnet", 0);
    assert!(env.registry.on_foreign_tx_verified(
        receipt.receipt_id,
        Ok(VerifyForeignTransactionResponseDto {
            payload_hash: Hash256(pending_ver.expected_payload_hash),
            signature: MpcSecp256k1Signature::from_r_s_v(
                &ftx_sig.r().to_bytes().into(),
                &ftx_sig.s().to_bytes().into(),
                ftx_rec.to_byte(),
            ),
        }),
    ));
    let proof = env.registry.verify_consequence_proof(id_hex).unwrap();
    assert!(proof.is_mpc_consequence_verified);
    assert_eq!(
        proof.receipt.consequence_state,
        ConsequenceState::ConsumedVerified
    );
    assert_eq!(
        proof.receipt.lender_id.as_deref(),
        Some(hex::encode(env.lender_id).as_str())
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn x402_revenue_advance_borrow_earn_auto_skim_repay_end_to_end() {
    let now_ts = 1_771_590_000u64;
    // $5 hard per-agent cap, minimum 2 distinct independent payers
    let mut env = setup_stack(now_ts, 5_000_000, 2);

    // Register 2 distinct-payer receipts ($2.00 each -> $4.00 trailing revenue -> advance_cap = min($5, $6) = $5)
    let buyer1 = Ed25519SigningKey::from_bytes(&[0x10u8; 32]);
    let buyer2 = Ed25519SigningKey::from_bytes(&[0x11u8; 32]);
    let provider_sk = Ed25519SigningKey::from_bytes(&[0x20u8; 32]);

    let (r1, q1, tm1) = build_signed_receipt_from_attestation(
        ATTESTATION_1500_JSON,
        &buyer1,
        &provider_sk,
        env.borrower_bytes,
        5_000_000,
        2_000_000,
        10,
        1_771_587_262,
    );
    let (r2, q2, tm2) = build_signed_receipt_from_attestation(
        ATTESTATION_3000_JSON,
        &buyer2,
        &provider_sk,
        env.borrower_bytes,
        5_000_000,
        2_000_000,
        11,
        1_771_588_000,
    );
    set_test_context("receipt-registry.testnet", "owner.testnet", 0);
    env.registry
        .add_expected_wasm_hash(hex::encode(r1.wasm_hash));
    env.registry
        .add_expected_wasm_hash(hex::encode(r2.wasm_hash));
    set_test_context("receipt-registry.testnet", "provider.testnet", 0);
    let _ = env.registry.register_receipt(r1, q1, tm1);
    let id2 = env.registry.register_receipt(r2.clone(), q2, tm2);

    // Authorize $4.00 principal + $0.08 fee (2%)
    let principal = 4_000_000u128;
    let fee_amount = 80_000u128;
    let maturity_at = now_ts + 86_400;
    let deadline = now_ts + 3600;
    set_test_context("receipt-registry.testnet", "provider.testnet", 1);
    let _ = env.registry.authorize_loan(
        id2.clone(),
        hex::encode(env.borrower_bytes),
        U128(principal),
        U128(fee_amount),
        maturity_at,
        hex::encode(env.vault_bytes),
        deadline,
    );
    let pending = env
        .registry
        .pending_loan_requests
        .get(&r2.receipt_id)
        .unwrap()
        .clone();
    let tweak = derive_mpc_tweak("receipt-registry.testnet", DEFAULT_DERIVATION_PATH);
    let tweak_scalar = Scalar::from_repr(tweak.into()).unwrap();
    let child_sk =
        Secp256k1SigningKey::from_bytes(&(env.sign_root_secret + tweak_scalar).to_bytes()).unwrap();
    let (sig, rec_id) = child_sk
        .sign_prehash_recoverable(&pending.eip712_digest)
        .unwrap();
    set_test_context("receipt-registry.testnet", "receipt-registry.testnet", 0);
    let packet = env
        .registry
        .on_loan_authorization_signed(
            r2.receipt_id,
            Ok(MpcSecp256k1Signature::from_r_s_v(
                &sig.r().to_bytes().into(),
                &sig.s().to_bytes().into(),
                rec_id.to_byte(),
            )),
        )
        .unwrap();

    // BORROW on Base: drawCredit sends $3.80 ($4.00 - 5% holdback $0.20)
    let draw_call = encode_draw_credit_call(
        &packet.receipt_id,
        &packet.borrower_evm_address,
        packet.principal_amount,
        packet.fee_amount,
        packet.maturity_at,
        &packet.evidence_commitment,
        packet.deadline,
        packet.signature_v,
        &packet.signature_r,
        &packet.signature_s,
    );
    let ExecutionResult::Success {
        logs: draw_logs, ..
    } = call_contract(&mut env.db, env.borrower, env.vault_addr, draw_call, now_ts)
    else {
        panic!("drawCredit failed");
    };
    assert_eq!(
        erc20_balance_of(
            &mut env.db,
            env.borrower,
            env.usdc_addr,
            &env.borrower_bytes,
            now_ts
        ),
        3_800_000
    );

    // Verify draw on NEAR -> ConsumedVerified & active encumbrance set
    let draw_tx = [0xd1u8; 32];
    let draw_blk = [0xd2u8; 32];
    set_test_context("receipt-registry.testnet", "provider.testnet", 1);
    let _ = env.registry.verify_loan_consequence(
        id2.clone(),
        hex::encode(draw_tx),
        hex::encode(draw_blk),
        log_to_evm_log(&draw_logs[0], draw_tx, draw_blk, env.vault_bytes),
        EvmFinality::Finalized,
    );
    let pver = env
        .registry
        .pending_consequence_requests
        .get(&r2.receipt_id)
        .unwrap()
        .clone();
    let (fs, fr) = env
        .foreign_tx_root_sk
        .sign_prehash_recoverable(&pver.expected_payload_hash)
        .unwrap();
    set_test_context("receipt-registry.testnet", "receipt-registry.testnet", 0);
    assert!(env.registry.on_foreign_tx_verified(
        r2.receipt_id,
        Ok(VerifyForeignTransactionResponseDto {
            payload_hash: Hash256(pver.expected_payload_hash),
            signature: MpcSecp256k1Signature::from_r_s_v(
                &fs.r().to_bytes().into(),
                &fs.s().to_bytes().into(),
                fr.to_byte()
            ),
        }),
    ));
    assert!(env
        .registry
        .get_active_encumbered_receipt("provider.testnet".into())
        .is_some());

    // EARN: Independent x402 payer sends $6.00 to AgentPayoutProxy (agent cannot pull it directly!)
    erc20_transfer(
        &mut env.db,
        env.payer,
        env.usdc_addr,
        &env.proxy_bytes,
        6_000_000,
        now_ts,
    );
    let ExecutionResult::Revert {
        output: proxy_rev, ..
    } = call_contract(
        &mut env.db,
        env.borrower,
        env.proxy_addr,
        selector("pullToVault()").to_vec(),
        now_ts,
    )
    else {
        panic!("agent must NOT be able to pull directly from payout proxy");
    };
    assert_eq!(&proxy_rev[0..4], &selector("OnlyVault()"));

    // REPAY AT SOURCE: vault.sweepAgentPayout skims $4.08 ($4.00 principal + $0.08 fee),
    // releases $0.20 holdback, and forwards $2.12 to borrower; LoanRepaid emitted at log_index 0
    let mut sweep_call = Vec::with_capacity(36);
    sweep_call.extend_from_slice(&selector("sweepAgentPayout(address)"));
    sweep_call.extend_from_slice(&abi_word_address(&env.borrower_bytes));
    let ExecutionResult::Success {
        logs: repay_logs, ..
    } = call_contract(
        &mut env.db,
        env.deployer,
        env.vault_addr,
        sweep_call,
        now_ts,
    )
    else {
        panic!("sweepAgentPayout failed");
    };
    // Borrower ends with $3.80 + $2.12 = $5.92 ($6.00 earned minus $0.08 fee)
    assert_eq!(
        erc20_balance_of(
            &mut env.db,
            env.borrower,
            env.usdc_addr,
            &env.borrower_bytes,
            now_ts
        ),
        5_920_000
    );
    // Vault reserves grew by exact $0.08 fee (40% = 32_000 to junior, 60% = 48_000 to senior)
    assert_eq!(
        call_view_u128(
            &mut env.db,
            env.deployer,
            env.vault_addr,
            "juniorFirstLossReserve()",
            now_ts
        ),
        50_032_000
    );
    assert_eq!(
        call_view_u128(
            &mut env.db,
            env.deployer,
            env.vault_addr,
            "seniorLiquidityReserve()",
            now_ts
        ),
        200_048_000
    );

    // Feed LoanRepaid (log_index 0) back to NEAR Registry -> RepaidVerified + encumbrance cleared!
    let rep_tx = [0xe1u8; 32];
    let rep_blk = [0xe2u8; 32];
    set_test_context("receipt-registry.testnet", "provider.testnet", 1);
    let _ = env.registry.verify_loan_repayment(
        id2.clone(),
        hex::encode(rep_tx),
        hex::encode(rep_blk),
        log_to_evm_log(&repay_logs[0], rep_tx, rep_blk, env.vault_bytes),
        EvmFinality::Finalized,
    );
    let prep = env
        .registry
        .pending_repayment_requests
        .get(&r2.receipt_id)
        .unwrap()
        .clone();
    let (rs, rr) = env
        .foreign_tx_root_sk
        .sign_prehash_recoverable(&prep.expected_payload_hash)
        .unwrap();
    set_test_context("receipt-registry.testnet", "receipt-registry.testnet", 0);
    assert!(env.registry.on_repayment_tx_verified(
        r2.receipt_id,
        Ok(VerifyForeignTransactionResponseDto {
            payload_hash: Hash256(prep.expected_payload_hash),
            signature: MpcSecp256k1Signature::from_r_s_v(
                &rs.r().to_bytes().into(),
                &rs.s().to_bytes().into(),
                rr.to_byte()
            ),
        }),
    ));
    assert_eq!(
        env.registry.get_receipt(id2).unwrap().consequence_state,
        ConsequenceState::RepaidVerified
    );
    assert!(env
        .registry
        .get_active_encumbered_receipt("provider.testnet".into())
        .is_none());
    let rep_sum = env
        .registry
        .get_erc8004_reputation_summary("provider.testnet".into());
    assert_eq!(rep_sum.count, 1);
    assert_eq!(rep_sum.value, 100);
}

#[test]
#[allow(clippy::too_many_lines)]
fn default_waterfall_slashes_bond_and_junior_pool_and_freezes_near_credit() {
    let now_ts = 1_771_590_000u64;
    let mut env = setup_stack(now_ts, 5_000_000, 1);

    let buyer1 = Ed25519SigningKey::from_bytes(&[0x10u8; 32]);
    let provider_sk = Ed25519SigningKey::from_bytes(&[0x20u8; 32]);
    let (r1, q1, tm1) = build_signed_receipt_from_attestation(
        ATTESTATION_1500_JSON,
        &buyer1,
        &provider_sk,
        env.borrower_bytes,
        4_000_000,
        4_000_000,
        100,
        1_771_587_262,
    );
    set_test_context("receipt-registry.testnet", "owner.testnet", 0);
    env.registry
        .add_expected_wasm_hash(hex::encode(r1.wasm_hash));
    set_test_context("receipt-registry.testnet", "provider.testnet", 0);
    let id1 = env.registry.register_receipt(r1.clone(), q1, tm1);

    let principal = 4_000_000u128;
    let fee_amount = 80_000u128;
    let maturity_at = now_ts + 1_000;
    let deadline = now_ts + 500;
    set_test_context("receipt-registry.testnet", "provider.testnet", 1);
    let _ = env.registry.authorize_loan(
        id1.clone(),
        hex::encode(env.borrower_bytes),
        U128(principal),
        U128(fee_amount),
        maturity_at,
        hex::encode(env.vault_bytes),
        deadline,
    );
    let pending = env
        .registry
        .pending_loan_requests
        .get(&r1.receipt_id)
        .unwrap()
        .clone();
    let tweak = derive_mpc_tweak("receipt-registry.testnet", DEFAULT_DERIVATION_PATH);
    let tweak_scalar = Scalar::from_repr(tweak.into()).unwrap();
    let child_sk =
        Secp256k1SigningKey::from_bytes(&(env.sign_root_secret + tweak_scalar).to_bytes()).unwrap();
    let (sig, rec_id) = child_sk
        .sign_prehash_recoverable(&pending.eip712_digest)
        .unwrap();
    set_test_context("receipt-registry.testnet", "receipt-registry.testnet", 0);
    let packet = env
        .registry
        .on_loan_authorization_signed(
            r1.receipt_id,
            Ok(MpcSecp256k1Signature::from_r_s_v(
                &sig.r().to_bytes().into(),
                &sig.s().to_bytes().into(),
                rec_id.to_byte(),
            )),
        )
        .unwrap();

    let draw_call = encode_draw_credit_call(
        &packet.receipt_id,
        &packet.borrower_evm_address,
        packet.principal_amount,
        packet.fee_amount,
        packet.maturity_at,
        &packet.evidence_commitment,
        packet.deadline,
        packet.signature_v,
        &packet.signature_r,
        &packet.signature_s,
    );
    let ExecutionResult::Success {
        logs: draw_logs, ..
    } = call_contract(&mut env.db, env.borrower, env.vault_addr, draw_call, now_ts)
    else {
        panic!("drawCredit failed");
    };
    let draw_tx = [0xf1u8; 32];
    let draw_blk = [0xf2u8; 32];
    set_test_context("receipt-registry.testnet", "provider.testnet", 1);
    let _ = env.registry.verify_loan_consequence(
        id1.clone(),
        hex::encode(draw_tx),
        hex::encode(draw_blk),
        log_to_evm_log(&draw_logs[0], draw_tx, draw_blk, env.vault_bytes),
        EvmFinality::Finalized,
    );
    let pver = env
        .registry
        .pending_consequence_requests
        .get(&r1.receipt_id)
        .unwrap()
        .clone();
    let (fs, fr) = env
        .foreign_tx_root_sk
        .sign_prehash_recoverable(&pver.expected_payload_hash)
        .unwrap();
    set_test_context("receipt-registry.testnet", "receipt-registry.testnet", 0);
    assert!(env.registry.on_foreign_tx_verified(
        r1.receipt_id,
        Ok(VerifyForeignTransactionResponseDto {
            payload_hash: Hash256(pver.expected_payload_hash),
            signature: MpcSecp256k1Signature::from_r_s_v(
                &fs.r().to_bytes().into(),
                &fs.s().to_bytes().into(),
                fr.to_byte()
            ),
        }),
    ));

    // Too early for markDefaulted (maturity_at + 60 = now_ts + 1060)
    let mut def_call = Vec::with_capacity(36);
    def_call.extend_from_slice(&selector("markDefaulted(bytes32)"));
    def_call.extend_from_slice(&r1.receipt_id);
    let ExecutionResult::Revert {
        output: early_rev, ..
    } = call_contract(
        &mut env.db,
        env.deployer,
        env.vault_addr,
        def_call.clone(),
        maturity_at + 60,
    )
    else {
        panic!("expected LoanNotExpired");
    };
    assert_eq!(
        &early_rev[0..4],
        &selector("LoanNotExpired(bytes32,uint256,uint256)")
    );

    // Past maturity + grace period -> markDefaulted slashes holdback ($0.20) + junior pool ($3.80), senior untouched ($200)
    let ExecutionResult::Success { logs: def_logs, .. } = call_contract(
        &mut env.db,
        env.deployer,
        env.vault_addr,
        def_call,
        maturity_at + 61,
    ) else {
        panic!("markDefaulted failed after expiry");
    };
    assert_eq!(
        call_view_u128(
            &mut env.db,
            env.deployer,
            env.vault_addr,
            "juniorFirstLossReserve()",
            now_ts
        ),
        46_200_000
    );
    assert_eq!(
        call_view_u128(
            &mut env.db,
            env.deployer,
            env.vault_addr,
            "seniorLiquidityReserve()",
            now_ts
        ),
        200_000_000
    );

    // Feed LoanDefaulted (log_index 0) back to NEAR Registry -> DefaultedVerified + credit_frozen = true!
    let def_tx = [0x91u8; 32];
    let def_blk = [0x92u8; 32];
    set_test_context("receipt-registry.testnet", "deployer.testnet", 1);
    let _ = env.registry.verify_loan_default(
        id1.clone(),
        hex::encode(def_tx),
        hex::encode(def_blk),
        log_to_evm_log(&def_logs[0], def_tx, def_blk, env.vault_bytes),
        EvmFinality::Finalized,
    );
    let pdef = env
        .registry
        .pending_default_requests
        .get(&r1.receipt_id)
        .unwrap()
        .clone();
    let (ds, dr) = env
        .foreign_tx_root_sk
        .sign_prehash_recoverable(&pdef.expected_payload_hash)
        .unwrap();
    set_test_context("receipt-registry.testnet", "receipt-registry.testnet", 0);
    assert!(env.registry.on_default_tx_verified(
        r1.receipt_id,
        Ok(VerifyForeignTransactionResponseDto {
            payload_hash: Hash256(pdef.expected_payload_hash),
            signature: MpcSecp256k1Signature::from_r_s_v(
                &ds.r().to_bytes().into(),
                &ds.s().to_bytes().into(),
                dr.to_byte()
            ),
        }),
    ));
    assert_eq!(
        env.registry.get_receipt(id1).unwrap().consequence_state,
        ConsequenceState::DefaultedVerified
    );
    assert_eq!(
        env.registry
            .compute_advance_cap("provider.testnet".into(), None)
            .0,
        0
    );
    let def_sum = env
        .registry
        .get_erc8004_reputation_summary("provider.testnet".into());
    assert_eq!(def_sum.count, 1);
    assert_eq!(def_sum.value, -100);
}
