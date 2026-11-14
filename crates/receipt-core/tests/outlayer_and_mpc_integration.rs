//! Integration tests against genuine OutLayer Intel TDX quote v4 fixtures, real
//! `worker.outlayer.testnet::get_approved_measurements` allowlists, and genuine Intel DCAP
//! collateral (`dcap-qvl` v0.3.11), plus authoritative byte-level verification of the NEAR MPC
//! `ForeignTxSignPayload::V1` Base payload.

use receipt_core::mpc_foreign_tx::{
    base_block_and_log_payload, loan_drawn_topic0, verify_foreign_transaction_args, EvmChain,
    EvmExtractedValue, EvmExtractor, EvmFinality, EvmLog, EvmRpcRequest, EvmTxId, ExtractedValue,
    ForeignChainRpcRequest, ForeignTxSignPayloadV1, Hash160, Hash256, FOREIGN_TX_DOMAIN_ID,
};
use receipt_core::tdx::{
    compute_task_hash, parse_collateral_json, verify_attestation, verify_dcap_quote,
    verify_full_dcap_attestation, verify_quote_signature, verify_report_data, ApprovedMeasurements,
    Measurements, OutLayerAttestationRecord, TdxQuote,
};
use receipt_core::ReceiptError;
use sha2::{Digest, Sha256};

const APPROVED_MEASUREMENTS_JSON: &str = include_str!("fixtures/worker_approved_measurements.json");
const ATTESTATION_1500_JSON: &str = include_str!("fixtures/outlayer_attestation_1500.json");
const ATTESTATION_3000_JSON: &str = include_str!("fixtures/outlayer_attestation_3000.json");
const ATTESTATION_REQ_1_JSON: &str = include_str!("fixtures/outlayer_attestation_req_1.json");
const COLLATERAL_JSON: &str = include_str!("fixtures/outlayer_collateral.json");
const COLLATERAL_3000_JSON: &str = include_str!("fixtures/outlayer_collateral_3000.json");

fn load_allowlist() -> ApprovedMeasurements {
    ApprovedMeasurements::from_json_str(APPROVED_MEASUREMENTS_JSON)
        .expect("worker_approved_measurements.json must parse")
}

fn load_record(json: &str) -> OutLayerAttestationRecord {
    serde_json::from_str(json).expect("attestation fixture must parse")
}

/// Establishes that the genuine 129-entry allowlist fetched from
/// `worker.outlayer.testnet::get_approved_measurements` parses cleanly into 48-byte `(mrtd, rtmr0..3)`
/// tuples and contains the expected initial entry.
#[test]
fn genuine_worker_approved_measurements_parse_and_lookup() {
    let allowlist = load_allowlist();
    assert_eq!(allowlist.len(), 129);
    assert!(!allowlist.is_empty());

    let first = Measurements::from_hex_strs(
        "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
        "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96",
        "a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15",
        "24847f5c5a2360d030bc4f7b8577ce32e87c4d051452c937e91220cab69542daef83433947c492b9c201182fc9769bbe",
        "d711dca04728ed904261e600267e0b827c3d28f9d778a1a8cb688a05d7a9e434c7c925a1f53f658b4148063a84ae6009",
    )
    .unwrap();
    assert!(allowlist.contains(&first));
}

/// Establishes that genuine OutLayer attestation `task_id = 1500` (`id = 791`, `request_id = 243`,
/// caller `nearcast-oracle.testnet`):
/// 1. Parses as a 5010-byte Intel TDX v4 quote.
/// 2. Passes attestation-key ECDSA P-256 signature verification over the 632-byte header+TD10 body.
/// 3. Passes QE report binding (`qe_report.report_data[0..32] == SHA256(att_key || qe_auth_data)`).
/// 4. Extracts measurements that match the `worker.outlayer.testnet` approved measurement set.
/// 5. Recomputes the exact V1 `task_hash` (`64b8cd7b...a442`) binding `wasm_hash`, `input_hash`,
///    `output_hash`, `repo_url`, `commit_hash`, `build_target`, `block_height`,
///    `caller_account_id`, `timestamp`, and `attached_usd` into `report_data[0..32]`.
#[test]
fn genuine_outlayer_attestation_1500_verifies_structure_measurements_and_bindings() {
    let allowlist = load_allowlist();
    let rec = load_record(ATTESTATION_1500_JSON);
    let raw = TdxQuote::decode_bytes(&rec.tdx_quote).unwrap();
    assert_eq!(raw.len(), 5010);

    let quote = TdxQuote::parse(&raw).unwrap();
    assert_eq!(quote.version, 4);
    verify_quote_signature(&quote).unwrap();
    quote.verify_qe_binding().unwrap();
    assert!(allowlist.contains(&quote.measurements));

    let task = rec.to_v1_task_inputs().unwrap();
    let task_hash = compute_task_hash(&task);
    assert_eq!(
        hex::encode(task_hash),
        "64b8cd7bf8be52d253b3e642fb5e8bd9d86cbe0f786dca91ff5224998ad8a442"
    );
    verify_report_data(&quote, &task_hash).unwrap();
    verify_attestation(&quote, &allowlist, &task).unwrap();
}

/// Establishes that genuine OutLayer attestation `task_id = 3000` (`id = 2161`, `request_id = 985`,
/// caller `kampy.testnet`, pre-compiled WASM without `repo_url`/`commit_hash`):
/// 1. Parses and passes ECDSA P-256 quote signature and QE report binding.
/// 2. Matches a distinct approved worker measurement set (`rtmr1 = e8601b64942f...`) in
///    `worker.outlayer.testnet`.
/// 3. Binds its `wasm_hash`, `input_hash`, and `output_hash` into `report_data[0..32]`
///    (`aef14288...0944`).
#[test]
fn genuine_outlayer_attestation_3000_verifies_structure_measurements_and_bindings() {
    let allowlist = load_allowlist();
    let rec = load_record(ATTESTATION_3000_JSON);
    let quote = TdxQuote::parse_encoded(&rec.tdx_quote).unwrap();
    let task = rec.to_v1_task_inputs().unwrap();
    assert_eq!(
        hex::encode(compute_task_hash(&task)),
        "aef14288cfed834f155b808573459bb839fdc4a3b5fe84eb9ca5161398320944"
    );
    verify_attestation(&quote, &allowlist, &task).unwrap();
}

/// Establishes that tampering with `wasm_hash` (code binding), `input_hash` (input binding),
/// `output_hash` (output binding), or quote bytes on a genuine OutLayer quote is deterministically
/// rejected.
#[test]
fn genuine_quote_rejects_tampered_code_input_output_and_quote_bytes() {
    let allowlist = load_allowlist();
    let rec = load_record(ATTESTATION_1500_JSON);
    let mut raw = TdxQuote::decode_bytes(&rec.tdx_quote).unwrap();
    let quote = TdxQuote::parse(&raw).unwrap();
    let base_task = rec.to_v1_task_inputs().unwrap();

    // 1. Tampered wasm_hash (code binding)
    let mut bad_code = base_task.clone();
    bad_code.wasm_hash = Some([0xaa; 32]);
    assert_eq!(
        verify_attestation(&quote, &allowlist, &bad_code),
        Err(ReceiptError::ReportDataMismatch)
    );

    // 2. Tampered input_hash (input binding)
    let mut bad_input = base_task.clone();
    bad_input.input_hash = Some([0xbb; 32]);
    assert_eq!(
        verify_attestation(&quote, &allowlist, &bad_input),
        Err(ReceiptError::ReportDataMismatch)
    );

    // 3. Tampered output_hash (output binding)
    let mut bad_output = base_task.clone();
    bad_output.output_hash = [0xcc; 32];
    assert_eq!(
        verify_attestation(&quote, &allowlist, &bad_output),
        Err(ReceiptError::ReportDataMismatch)
    );

    // 4. Tampered quote byte inside TD10 report body breaks hardware ECDSA signature
    raw[200] ^= 0x01;
    let tampered_quote = TdxQuote::parse(&raw).unwrap();
    assert!(matches!(
        verify_attestation(&tampered_quote, &allowlist, &base_task),
        Err(ReceiptError::QuoteSignature(_))
    ));
}

/// Establishes that historical OutLayer attestation `request_id = 1` (`task_id = 772`,
/// `timestamp = 1768057938`):
/// 1. Has a valid hardware TDX v4 signature, valid QE binding, and valid legacy V0 `report_data`
///    binding (`873adee5...2076`).
/// 2. Has retired worker measurements (`rtmr1 = 90c97d4e...`) that are no longer in the current
///    `worker.outlayer.testnet` approved list, and is therefore rejected by `verify_attestation`
///    with `MeasurementNotApproved`.
#[test]
fn genuine_historical_retired_worker_quote_req_1_rejected_by_current_allowlist() {
    let allowlist = load_allowlist();
    let rec = load_record(ATTESTATION_REQ_1_JSON);
    let quote = TdxQuote::parse_encoded(&rec.tdx_quote).unwrap();

    verify_quote_signature(&quote).unwrap();
    quote.verify_qe_binding().unwrap();

    let v0_task = rec.to_v0_task_inputs().unwrap();
    assert_eq!(
        hex::encode(compute_task_hash(&v0_task)),
        "873adee55427107bd49b2439d0c27c0a9b03448596b0b0607e0979ce8fb82076"
    );
    verify_report_data(&quote, &compute_task_hash(&v0_task)).unwrap();

    assert_eq!(
        verify_attestation(&quote, &allowlist, &v0_task),
        Err(ReceiptError::MeasurementNotApproved)
    );
}

/// Establishes full Intel DCAP verification (`dcap-qvl` v0.3.11) over genuine OutLayer TDX
/// quotes (`1500`, `3000`, and `req_1`) using genuine Intel collateral fetched from
/// `https://testnet-api.outlayer.ai/public/collateral?fmspc=20a06f000000&at=1771587262`:
/// - Validates PCK certificate chain -> Intel SGX PCK Platform CA -> Intel SGX Root CA.
/// - Checks Root CA CRL and PCK CRL revocations.
/// - Verifies Intel TCB Info (v3) and QE Identity (v2) ECDSA signatures and validity windows.
/// - Confirms `status == "UpToDate"` and `advisory_ids.is_empty()`.
/// - Confirms `dcap-qvl` rejects expired/out-of-window verification timestamps and tampered
///   collateral signatures.
#[test]
fn genuine_quotes_pass_full_intel_dcap_qvl_verification_with_real_collateral() {
    let allowlist = load_allowlist();
    let collateral = parse_collateral_json(COLLATERAL_JSON).unwrap();

    // Attestation 1500: full DCAP + allowlist + V1 task_hash
    let rec_1500 = load_record(ATTESTATION_1500_JSON);
    let raw_1500 = TdxQuote::decode_bytes(&rec_1500.tdx_quote).unwrap();
    let task_1500 = rec_1500.to_v1_task_inputs().unwrap();
    let summary_1500 = verify_full_dcap_attestation(
        &raw_1500,
        &collateral,
        rec_1500.timestamp,
        &allowlist,
        &task_1500,
    )
    .unwrap();
    assert_eq!(summary_1500.status, "UpToDate");
    assert_eq!(summary_1500.advisory_ids, Vec::<String>::new());

    // Attestation 3000: full DCAP + allowlist + V1 task_hash at its exact execution timestamp
    // (1_788_057_326 = 2026-08-30T02:35:26Z) with its platform FMSPC collateral (b0c06f000000).
    let collateral_3000 = parse_collateral_json(COLLATERAL_3000_JSON).unwrap();
    let rec_3000 = load_record(ATTESTATION_3000_JSON);
    let raw_3000 = TdxQuote::decode_bytes(&rec_3000.tdx_quote).unwrap();
    let task_3000 = rec_3000.to_v1_task_inputs().unwrap();
    let summary_3000 = verify_full_dcap_attestation(
        &raw_3000,
        &collateral_3000,
        rec_3000.timestamp,
        &allowlist,
        &task_3000,
    )
    .unwrap();
    assert_eq!(summary_3000.status, "UpToDate");
    assert_eq!(summary_3000.advisory_ids, Vec::<String>::new());

    // Negative DCAP check 0: wrong FMSPC collateral (20a06f000000 vs b0c06f000000) is rejected by dcap-qvl
    assert!(matches!(
        verify_dcap_quote(&raw_3000, &collateral, rec_3000.timestamp),
        Err(ReceiptError::DcapVerification(_))
    ));

    // Historical req_1 passes cryptographic DCAP verification, even though its worker measurement is retired
    let rec_1 = load_record(ATTESTATION_REQ_1_JSON);
    let raw_1 = TdxQuote::decode_bytes(&rec_1.tdx_quote).unwrap();
    let summary_1 = verify_dcap_quote(&raw_1, &collateral, rec_1500.timestamp).unwrap();
    assert_eq!(summary_1.status, "UpToDate");

    // Negative DCAP check 1: timestamp far in the future (after collateral nextUpdate / cert expiry) fails
    assert!(matches!(
        verify_dcap_quote(&raw_1500, &collateral, 4_000_000_000),
        Err(ReceiptError::DcapVerification(_))
    ));

    // Negative DCAP check 2: corrupted TCB info signature fails DCAP verification
    let mut bad_collateral = collateral;
    bad_collateral.tcb_info_signature[0] ^= 0xff;
    assert!(matches!(
        verify_dcap_quote(&raw_1500, &bad_collateral, rec_1500.timestamp),
        Err(ReceiptError::DcapVerification(_))
    ));
}

/// Authoritative byte-level and hash-level compatibility check for the Base-specific
/// `ForeignTxSignPayload::V1` against upstream `near-mpc-contract-interface` and `near-mpc-sdk`:
/// 1. Verifies that an Ethereum-only vs Base-only payload with identical `EvmRpcRequest` and
///    `ExtractedValue` differs in Borsh bytes at and only at byte index `1` (`0x01` for
///    `ForeignChainRpcRequest::Ethereum` vs `0x06` for `ForeignChainRpcRequest::Base`), anchored
///    directly to the upstream Ethereum insta snapshot (`2ab97999...794e`).
/// 2. Verifies the exact Borsh byte layout of RECEIPT's Base `[BlockHash, Log { log_index: 0 }]`
///    payload against a field-by-field reference encoding constructed from the upstream struct
///    definitions in `crates/near-mpc-contract-interface/src/types/foreign_chain/chains/evm.rs`.
#[test]
fn base_foreign_tx_payload_matches_authoritative_upstream_borsh_layout() {
    // Part 1: Differential check against upstream Ethereum snapshot vector
    let req_body = EvmRpcRequest {
        tx_id: EvmTxId([0xab; 32]),
        extractors: vec![EvmExtractor::BlockHash],
        finality: EvmFinality::Finalized,
    };
    let extracted = vec![ExtractedValue(EvmExtractedValue::BlockHash(Hash256(
        [0xef; 32],
    )))];
    let eth_payload = ForeignTxSignPayloadV1 {
        request: ForeignChainRpcRequest {
            chain: EvmChain::Ethereum,
            request: req_body.clone(),
        },
        values: extracted.clone(),
    };
    let base_simple = ForeignTxSignPayloadV1 {
        request: ForeignChainRpcRequest {
            chain: EvmChain::Base,
            request: req_body,
        },
        values: extracted,
    };
    assert_eq!(
        hex::encode(eth_payload.compute_msg_hash().unwrap()),
        "2ab97999d1e015730271c7d6cbb298af76fd1de7af81926b42a8877bc4f5794e"
    );
    let eth_bytes = borsh::to_vec(&eth_payload).unwrap();
    let base_simple_bytes = borsh::to_vec(&base_simple).unwrap();
    assert_eq!(eth_bytes.len(), base_simple_bytes.len());
    assert_eq!(eth_bytes[0], 0u8); // ForeignTxSignPayload::V1 discriminant
    assert_eq!(eth_bytes[1], 1u8); // ForeignChainRpcRequest::Ethereum discriminant
    assert_eq!(base_simple_bytes[1], 6u8); // ForeignChainRpcRequest::Base discriminant
    assert_eq!(eth_bytes[2..], base_simple_bytes[2..]);

    // Part 2: Full Base [BlockHash, Log { log_index: 0 }] byte-by-byte verification
    let tx_id = [0x11u8; 32];
    let block_hash = [0x22u8; 32];
    let vault_addr = [0x33u8; 20];
    let topic0 = loan_drawn_topic0();
    let receipt_id = [0x44u8; 32];
    let data_str = "0x0000000000000000000000000000000000000000000000000000000005f5e100";

    let log = EvmLog {
        removed: false,
        log_index: 0,
        transaction_index: 2,
        transaction_hash: Hash256(tx_id),
        block_hash: Hash256(block_hash),
        block_number: 12_345_678,
        address: Hash160(vault_addr),
        data: data_str.to_string(),
        topics: vec![Hash256(topic0), Hash256(receipt_id)],
    };

    let payload =
        base_block_and_log_payload(tx_id, EvmFinality::Finalized, block_hash, log).unwrap();
    let actual_bytes = borsh::to_vec(&payload).unwrap();

    // Construct reference Borsh stream field-by-field per upstream near-mpc-contract-interface:
    let mut expected_bytes = Vec::new();
    expected_bytes.push(0u8); // ForeignTxSignPayload::V1 = 0
    expected_bytes.push(6u8); // ForeignChainRpcRequest::Base = 6
    expected_bytes.extend_from_slice(&tx_id); // EvmRpcRequest.tx_id: [u8; 32]
    expected_bytes.extend_from_slice(&2u32.to_le_bytes()); // extractors len = 2
    expected_bytes.push(0u8); // EvmExtractor::BlockHash = 0
    expected_bytes.push(1u8); // EvmExtractor::Log = 1
    expected_bytes.extend_from_slice(&0u64.to_le_bytes()); // log_index = 0
    expected_bytes.push(2u8); // EvmFinality::Finalized = 2 (Latest=0, Safe=1, Finalized=2)
    expected_bytes.extend_from_slice(&2u32.to_le_bytes()); // values len = 2
                                                           // values[0]: ExtractedValue::EvmExtractedValue(1) -> EvmExtractedValue::BlockHash(0)
    expected_bytes.push(1u8);
    expected_bytes.push(0u8);
    expected_bytes.extend_from_slice(&block_hash);
    // values[1]: ExtractedValue::EvmExtractedValue(1) -> EvmExtractedValue::Log(1)
    expected_bytes.push(1u8);
    expected_bytes.push(1u8);
    expected_bytes.push(0u8); // removed = false
    expected_bytes.extend_from_slice(&0u64.to_le_bytes()); // log_index = 0
    expected_bytes.extend_from_slice(&2u64.to_le_bytes()); // transaction_index = 2
    expected_bytes.extend_from_slice(&tx_id); // transaction_hash
    expected_bytes.extend_from_slice(&block_hash); // block_hash
    expected_bytes.extend_from_slice(&12_345_678u64.to_le_bytes()); // block_number
    expected_bytes.extend_from_slice(&vault_addr); // address
    expected_bytes.extend_from_slice(&u32::try_from(data_str.len()).unwrap().to_le_bytes());
    expected_bytes.extend_from_slice(data_str.as_bytes());
    expected_bytes.extend_from_slice(&2u32.to_le_bytes()); // topics len = 2
    expected_bytes.extend_from_slice(&topic0);
    expected_bytes.extend_from_slice(&receipt_id);

    assert_eq!(actual_bytes, expected_bytes);
    let expected_hash: [u8; 32] = Sha256::digest(&expected_bytes).into();
    assert_eq!(payload.compute_msg_hash().unwrap(), expected_hash);

    let args = verify_foreign_transaction_args(
        &payload.request,
        FOREIGN_TX_DOMAIN_ID,
        Some(expected_hash),
    )
    .unwrap();
    assert_eq!(args["request"]["domain_id"], 3);
    assert_eq!(args["request"]["payload_version"], 1);
    assert_eq!(
        args["request"]["expected_payload_hash"],
        hex::encode(expected_hash)
    );
}
