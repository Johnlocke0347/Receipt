# RECEIPT — Progress Log & Phase 1 Remediation Report

## Phase 1 Summary Table

| Task | Status | Notes |
| :-- | :-- | :-- |
| **1.1** Workspace + `uv` env + `PROGRESS.md` | **Verified** | `Cargo.toml`, `pyproject.toml`, `.gitignore`, `src/receipt_orchestrator`, `tests/` |
| **1.2** `crates/receipt-core` | **Verified** | `receipt`, `signing`, `hashing`, `confidential`, `tdx` (+ `dcap-qvl`), `mpc_foreign_tx` |
| **1.3** `crates/acceptance-verifier-wasm` | **Verified** | Clean reproducible builds for `wasm32-wasip1` and `wasm32-wasip2`; executed & verified in Wasmtime `50.0.1` |
| **1.4** Real OutLayer TDX Quotes, Allowlist & MPC Tests | **Verified** | 53 total Rust tests pass (38 unit in `receipt-core`, 7 genuine OutLayer/MPC integration tests in `outlayer_and_mpc_integration.rs`, 8 unit in `acceptance-verifier-wasm`) |

---

## 1. Rust Toolchain Repair & WASI Target Installation

1. **Pre-Repair Inspection**:
   - Active toolchain: `stable-x86_64-pc-windows-gnu` (default), alongside `stable-x86_64-pc-windows-msvc`, `nightly-*`, and `1.91.0-*`.
   - `rustup override list` confirmed no other projects had directory overrides tied to `stable-x86_64-pc-windows-gnu`.
   - No background `cargo`/`rustc` processes were running.
2. **Non-Destructive `rustup` Reinstall**:
   - Uninstalled and cleanly reinstalled `stable-x86_64-pc-windows-gnu` using `rustup toolchain uninstall stable-x86_64-pc-windows-gnu` followed by `rustup toolchain install stable-x86_64-pc-windows-gnu` and `rustup component add rustfmt clippy`.
   - Note: Reinstalling `stable-x86_64-pc-windows-gnu` updated the channel from `rustc 1.98.1 (48a229cea 2026-09-01)` to the latest stable release `rustc 1.100.0 (0ef1bc386 2026-11-09)` / `cargo 1.100.0 (3acc79c0c 2026-11-05)` (`rustup 1.29.3`).
3. **Sequential WASI Target Installation**:
   - Executed `rustup target add wasm32-wasip1`, verified via `rustup target list --installed`.
   - Executed `rustup target add wasm32-wasip2`, verified via `rustup target list --installed`.
   - Final installed targets on `stable-x86_64-pc-windows-gnu`:
     - `wasm32-wasip1` (`rust-std-wasm32-wasip1`)
     - `wasm32-wasip2` (`rust-std-wasm32-wasip2`)
     - `x86_64-pc-windows-gnu` (`rust-std-x86_64-pc-windows-gnu`, `cargo`, `clippy`, `rustfmt`, `rust-mingw`)

---

## 2. Clean WASM Builds, Hashes & Reproducibility

### 2.1 Build Commands
Executed three completely independent clean builds into separate output directories (`--target-dir target_clean_1`, `--target-dir target_clean_2`, and fresh `target/` after `Remove-Item -Recurse -Force`):
```powershell
cargo build --release -p acceptance-verifier-wasm --target wasm32-wasip1 --target-dir target_clean_1
cargo build --release -p acceptance-verifier-wasm --target wasm32-wasip2 --target-dir target_clean_1
cargo build --release -p acceptance-verifier-wasm --target wasm32-wasip1 --target-dir target_clean_2
cargo build --release -p acceptance-verifier-wasm --target wasm32-wasip2 --target-dir target_clean_2
```

### 2.2 Artifact Hashes & Reproducibility Comparison

| Target | Pre-Repair Hash (`rustc 1.98.1`) | Clean Build 1 (`target_clean_1`, `rustc 1.100.0`) | Clean Build 2 (`target_clean_2`, `rustc 1.100.0`) | Default Clean Build (`target/`, `rustc 1.100.0`) | Size (bytes) |
| :-- | :-- | :-- | :-- | :-- | :-- |
| `wasm32-wasip1` | `ab1376a4e2c16c85f1ed21781a9350c76e3bc13091a55f261ea7ac0f632a4516` (115,939 B) | `9465bd664f1cfa7ce54731ba4b5c411b4444ebde9064351b5e2b1761cc467dd1` | `9465bd664f1cfa7ce54731ba4b5c411b4444ebde9064351b5e2b1761cc467dd1` | `9465bd664f1cfa7ce54731ba4b5c411b4444ebde9064351b5e2b1761cc467dd1` | `115,266` |
| `wasm32-wasip2` | `eacf22935be0e7f09056c6377f133899572b27a25497ed2b6d53c59da26154ed` (135,172 B) | `19606e33d6ac2566bc40c3defd173248939d474f60589466160042da389d358a` | `19606e33d6ac2566bc40c3defd173248939d474f60589466160042da389d358a` | `19606e33d6ac2566bc40c3defd173248939d474f60589466160042da389d358a` | `135,395` |

- **Why hashes changed relative to pre-repair**: Reinstalling `stable-x86_64-pc-windows-gnu` updated `rustc` from `1.98.1` to `1.100.0` (and regenerated `Cargo.lock` with current compatible crate versions).
- **Local Reproducibility**: Across all three independent clean target directories (`target_clean_1`, `target_clean_2`, and `target`) under `rustc 1.100.0`, both `wasm32-wasip1` and `wasm32-wasip2` produced **bit-for-bit identical** binaries and SHA-256 digests.

---

## 3. WASI Runtime Verification (`wasmtime 50.0.1`)

Executed both compiled artifacts (`target\wasm32-wasip1\release\acceptance-verifier-wasm.wasm` and `target\wasm32-wasip2\release\acceptance-verifier-wasm.wasm`) using official Bytecode Alliance **`wasmtime 50.0.1 (c307ec81d 2026-10-29)`** (`x86_64-windows`):

| Target | Test Case | Exit Code | Output (`stdout` / `stderr`) |
| :-- | :-- | :-- | :-- |
| `wasm32-wasip1` | `valid_pass` (`invariants_checked=12`, `score=98`) | `0` | `{"schema":"RECEIPT_ACCEPTANCE_OUT_V1","outcome":"PASS","wasm_self_version":"1.0.0","confidential_settlement_commitment":"abab...","deliverable_hash":"1620110cdc5feee4d3d9a85e8b64f4bdc83bacb7da9e7087e33a78a3403a5da0","criteria_hash":"e783b11eeb82efa31c9047dcb8dc613ae19f16747fc2278d6d49016b7ed0b7a8","evaluated_metrics":{"invariants_checked":12,"score":98}}` |
| `wasm32-wasip1` | `valid_fail` (`invariants_checked=8`, `score=75`) | `0` | `{"schema":"RECEIPT_ACCEPTANCE_OUT_V1","outcome":"FAIL","wasm_self_version":"1.0.0","confidential_settlement_commitment":"abab...","deliverable_hash":"38b1f92df05a4d69ab5fe6a3623dd61817cf10a96adacf271656b96ce73f8115","criteria_hash":"e783b11eeb82efa31c9047dcb8dc613ae19f16747fc2278d6d49016b7ed0b7a8","evaluated_metrics":{"invariants_checked":8,"score":75}}` |
| `wasm32-wasip1` | `malformed_json` (`"{malformed"`) | `1` | `parse error: key must be a string at line 1 column 2` |
| `wasm32-wasip1` | `invalid_hex` (`job_spec_commitment="zz"`) | `1` | `job_spec_commitment must be 64 hex characters` |
| `wasm32-wasip2` | `valid_pass` (`invariants_checked=12`, `score=98`) | `0` | Identical JSON & hashes to `wasm32-wasip1` |
| `wasm32-wasip2` | `valid_fail` (`invariants_checked=8`, `score=75`) | `0` | Identical JSON & hashes to `wasm32-wasip1` |
| `wasm32-wasip2` | `malformed_json` (`"{malformed"`) | `1` | `parse error: key must be a string at line 1 column 2` |
| `wasm32-wasip2` | `invalid_hex` (`job_spec_commitment="zz"`) | `1` | `job_spec_commitment must be 64 hex characters` |

---

## 4. Genuine OutLayer Evidence & Full Intel DCAP Verification (Task 1.4)

### 4.1 Fixture Provenance (Retrieved `2026-11-13T18:01:26Z` – `18:24:53Z`)
Stored in [`crates/receipt-core/tests/fixtures/`](../crates/receipt-core/tests/fixtures):
1. **`worker_approved_measurements.json`** (`69,145` bytes, **129 approved 5-measurement sets**):
   - Source: NEAR Testnet RPC `query` (`call_function`) on `worker.outlayer.testnet::get_approved_measurements({})`.
2. **`outlayer_attestation_1500.json`** (`id = 791`, `task_id = 1500`, `request_id = 243`, `timestamp = 1771587262`):
   - Source: `GET https://testnet-api.outlayer.ai/attestations/1500`
   - Caller: `nearcast-oracle.testnet`, Repo: `https://github.com/loca555/nearcast-espn-oracle`, Commit: `5824309d7510982d5f37a601e2aeb19474b34d04`, Target: `wasm32-wasip2`.
   - `wasm_hash`: `7fc0e454eb5a681ff043d11f598fb22f796b49dffd04a9cfb837b0db255d4e6c`
   - `input_hash`: `f857577a025c4406c92698e0f7f1caa6891d09672e175f512767a0fd9a112369`
   - `output_hash`: `a47b7703e6d6f92b07c8a62a8f2ca76663385151f922bf5cd9acb35268f3cfa4`
   - Quote size: `5010` bytes (`sig_len = 4304` at offset `632..4940` + `70` trailing zero-padding bytes from Phala `dstack`).
   - Platform FMSPC (from embedded PCK leaf certificate OID `1.2.840.113741.1.13.1.4`): `20a06f000000`.
   - Measurements: **Present in `worker.outlayer.testnet` allowlist** (`mrtd = f06dfda6...`, `rtmr1 = a7b52327...`).
   - `report_data[0..32]` (`64b8cd7bf8be52d253b3e642fb5e8bd9d86cbe0f786dca91ff5224998ad8a442`): Matches OutLayer V1 `task_hash` exactly.
3. **`outlayer_attestation_3000.json`** (`id = 2161`, `task_id = 3000`, `request_id = 985`, `timestamp = 1788057326`):
   - Source: `GET https://testnet-api.outlayer.ai/attestations/3000`
   - Caller: `kampy.testnet`, pre-compiled WASM execution (`repo_url = None`, `commit_hash = None`), Target: `wasm32-wasip2`.
   - `wasm_hash`: `0eeb1b8747d5080e1d69f26603c61576ddb51793323ca8f9b518eb28ebae116d`
   - `input_hash`: `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a`
   - `output_hash`: `9a9523833a70e96b7c904ff56070c91a9cad360ff9422d491b2acc78abffc05c`
   - Platform FMSPC: `b0c06f000000`.
   - Measurements: **Present in `worker.outlayer.testnet` allowlist** (`mrtd = f06dfda6...`, `rtmr1 = e8601b64...`).
   - `report_data[0..32]` (`aef14288cfed834f155b808573459bb839fdc4a3b5fe84eb9ca5161398320944`): Matches OutLayer V1 `task_hash` exactly.
4. **`outlayer_attestation_req_1.json`** (`id = 212`, `request_id = 1`, `task_id = 772`, `timestamp = 1768057938`):
   - Source: `GET https://testnet-api.outlayer.ai/attestations/by-request/1`
   - Early historical execution using legacy V0 `task_hash` (`873adee55427107bd49b2439d0c27c0a9b03448596b0b0607e0979ce8fb82076`) and a now-retired worker measurement (`rtmr1 = 90c97d4e...`). Used to prove that genuine hardware quotes from retired workers pass cryptographic DCAP verification but are rejected by `verify_attestation` with `ReceiptError::MeasurementNotApproved`.
5. **`outlayer_collateral.json` & `outlayer_collateral_3000.json`**:
   - Source: `GET https://testnet-api.outlayer.ai/public/collateral?fmspc=20a06f000000&at=1771587262` and `GET https://testnet-api.outlayer.ai/public/collateral?fmspc=b0c06f000000&at=1788057326`.
   - Contains Intel SGX Root CA & Platform CA chains, Root CA CRL, PCK CRL, signed Intel TCB Info (v3), and signed Intel QE Identity (v2).

### 4.2 Important Protocol Discovery Fixed During Remediation
Inspecting upstream `out-layer/outlayer` (`worker/src/tdx_attestation.rs::generate_task_attestation`) and real quotes revealed two critical details that synthetic tests did not catch:
1. OutLayer hashes `wasm_hash`, `input_hash`, and `output_hash` into `task_hash` as **64-character lowercase ASCII hex strings** (`wh.as_bytes()`), not raw 32-byte arrays, and `attached_usd` as an ASCII decimal string (`"0"`). [`compute_task_hash`](../crates/receipt-core/src/tdx.rs#L454-L479) was updated to match upstream and verified against real quotes `1500`, `3000`, and `req_1`.
2. Real Phala `dstack` quotes (`5010` bytes) include `70` trailing zero-padding bytes after `636 + sig_len` (`4940`). [`TdxQuote::parse`](../crates/receipt-core/src/tdx.rs#L179-L259) now bounds certification data by `sig_len` and verifies that any trailing bytes after `636 + sig_len` are strictly `0x00`.

### 4.3 Full Intel DCAP Verification (`dcap-qvl v0.3.11`)
Integrated `dcap-qvl = { version = "0.3.11", default-features = false, features = ["contract", "borsh", "std", "rustcrypto"] }` in [`crates/receipt-core/src/tdx.rs`](../crates/receipt-core/src/tdx.rs#L614-L694) (`verify_dcap_quote` and `verify_full_dcap_attestation`).
- Validates the PCK certificate chain up to the pinned Intel SGX Root CA.
- Checks Root CA CRL and PCK CRL revocations.
- Verifies Intel TCB Info and QE Identity signatures, FMSPC match, and validity windows.
- Enforces `status == "UpToDate"` and `advisory_ids.is_empty()`.

---

## 5. Base-Specific MPC Payload Compatibility (Part C)

Audited upstream `near/mpc` (`crates/near-mpc-contract-interface/src/types/foreign_chain/` and `crates/near-mpc-sdk/src/foreign_chain/{base.rs,evm.rs}`):
- `Base` uses the exact same `EvmRpcRequest` and `EvmExtractedValue` structures as `Ethereum`; the only difference in `ForeignChainRpcRequest` is the enum discriminant (`Ethereum = 1`, `Base = 6`).
- Added [`base_foreign_tx_payload_matches_authoritative_upstream_borsh_layout`](../crates/receipt-core/tests/outlayer_and_mpc_integration.rs#L247-L343) which proves:
  1. Differential equivalence against the upstream Ethereum insta snapshot (`2ab97999d1e015730271c7d6cbb298af76fd1de7af81926b42a8877bc4f5794e`): serialized bytes for `Ethereum` vs `Base` are identical at every byte except index `1` (`0x01` vs `0x06`).
  2. Byte-for-byte equality between `base_block_and_log_payload` (`[BlockHash, Log { log_index: 0 }]`) and an independent field-by-field Borsh reference encoding constructed directly from the upstream struct definitions.
- Note on `signing.rs`: The length-prefixed Ed25519 co-signature digest (`chain_id` and `registry_id` prefixed with `u32` LE lengths) is preserved for Buyer/Provider receipt co-signing on `ReceiptRegistry`; it is completely separate from the MPC `ForeignTxSignPayload::V1` Borsh encoding.

---

## 6. Verification Categorization

### Verified
- **Rust Toolchain & Sequential WASI Targets**: `stable-x86_64-pc-windows-gnu` (`rustc 1.100.0`), `wasm32-wasip1`, `wasm32-wasip2`, `clippy`, `rustfmt`.
- **Clean Reproducible WASM Builds**: 3 independent clean builds produced identical SHA-256 hashes (`wasm32-wasip1`: `9465bd664f1cfa7ce54731ba4b5c411b4444ebde9064351b5e2b1761cc467dd1`, `wasm32-wasip2`: `19606e33d6ac2566bc40c3defd173248939d474f60589466160042da389d358a`).
- **WASI Runtime Execution**: Both WASI artifacts executed and verified under `wasmtime 50.0.1` across valid (`PASS`/`FAIL`) and invalid inputs.
- **Genuine OutLayer Quote & Allowlist Verification**: Tested against real quotes `1500`, `3000`, and `req_1` and the 129-entry `worker.outlayer.testnet` measurement allowlist.
- **Full Intel DCAP Verification**: Implemented and verified with `dcap-qvl` (`0.3.11`) and genuine Intel collateral for FMSPCs `20a06f000000` and `b0c06f000000`.
- **Base MPC Payload Compatibility**: Verified at the byte and SHA-256 level against upstream `near-mpc-contract-interface`.
- **Workspace Test & Lint Suite**:
  - `cargo fmt --all --check` (exit 0)
  - `cargo clippy --workspace --all-targets -- -D warnings` (exit 0)
  - `cargo test --workspace` (53 passed, 0 failed)
  - `uv run pytest -q`, `uv run ruff check .`, `uv run mypy .` (all pass)

### Partially Verified
- **Confidential Intents Adapter**: `TestnetConfidentialSettlementBridge` commitment derivation and `OneClickIntentBuilder` NEP-413 signing are unit-tested; live 1Click API calls are deferred to Phase 3 orchestrator integration.

---

## Phase 2 Summary Table (Smart Contracts: NEAR Receipt Registry & Base Sepolia Credit Vault)

| Task | Status | Notes |
| :-- | :-- | :-- |
| **2.1** `crates/near-receipt-registry` (`near-sdk` v5) | **Verified** | Approved measurement allowlist & `worker.outlayer.testnet` sync, `register_receipt`, `authorize_loan` (`domain_id: 0`), `verify_loan_consequence` (`domain_id: 3`), Consequence Graph views |
| **2.2** Compile `near-receipt-registry` to WASM + State-Machine Tests | **Verified** | `near_receipt_registry.wasm` (`726,274` B, SHA-256 `8899fef6...`); 10 unit/negative tests + 1 full cross-stack EVM integration test |
| **2.3** Base Sepolia `MockCreditUSDC.sol` & `ReceiptCreditVault.sol` | **Verified** | Compiled via `solc 0.8.24 --optimize`; verified end-to-end in `revm` (`chain_id = 84532`) against NEAR `ReceiptRegistry` |

---

## 7. Phase 2 Implementation & Verification Details

### 7.1 `crates/receipt-core` Extensions (`eip712` & `mpc_sign`)
1. **[`crates/receipt-core/src/eip712.rs`](../crates/receipt-core/src/eip712.rs)**:
   - Implements [`LoanAuthorizationPacket`](../crates/receipt-core/src/eip712.rs#L33-L63), [`eip712_domain_separator`](../crates/receipt-core/src/eip712.rs#L80-L93), [`loan_authorization_struct_hash`](../crates/receipt-core/src/eip712.rs#L98-L120), [`eip712_loan_authorization_digest`](../crates/receipt-core/src/eip712.rs#L126-L148), [`recover_eip712_signer`](../crates/receipt-core/src/eip712.rs#L162-L195) (enforcing EIP-2 low-`s` canonical signatures), and [`verify_loan_drawn_log`](../crates/receipt-core/src/eip712.rs#L219-L330).
2. **[`crates/receipt-core/src/mpc_sign.rs`](../crates/receipt-core/src/mpc_sign.rs)**:
   - Implements the upstream `near/mpc` additive secp256k1 KDF (`SHA3_256("near-mpc-recovery v0.1.0 epsilon derivation:{predecessor_id},{path}")`) in [`derive_mpc_tweak`](../crates/receipt-core/src/mpc_sign.rs#L207-L216), [`derive_mpc_secp256k1_pubkey`](../crates/receipt-core/src/mpc_sign.rs#L256-L285), and [`derive_mpc_evm_address`](../crates/receipt-core/src/mpc_sign.rs#L292-L300).
   - Verified against live `v1.signer-prod.testnet` RPC (`https://test.rpc.fastnear.com`):
     - `public_key({"domain_id": 0})`: `secp256k1:4NfTiv3UsGahebgTaHyD9vF8KYKMBnfd6kh94mK6xv8fGBiJB8TBtFMP5WWXz6B89Ac1fbpzPwAvoyQebemHFwx3`
     - `public_key({"domain_id": 3})`: `secp256k1:2KGCoy2pZt7n85QfJnQzCT1eHySuNpquUfNc8ySpRbr15F5kqU7agJYjfo5RkrzNd4tZimDFv2wAZri7RRZ32qj1`
     - `derived_public_key({"path": "receipt-credit-vault-v1", "predecessor": "receipt-registry.testnet", "domain_id": 0})`: `secp256k1:4BUaArkKFhhnaUmFaxQ3ZDFJKScvpShfeQSo2rsDgLMj3SvfFCuVvZgtDbsntZYmgShfPynEJhYm6GiuEShHvzMS` (matches `derive_mpc_secp256k1_pubkey` byte-for-byte in unit test [`live_testnet_domain_keys_parse_and_roundtrip`](../crates/receipt-core/src/mpc_sign.rs#L308-L334)).

### 7.2 `crates/near-receipt-registry` (`near-sdk` v5)
Implemented in [`crates/near-receipt-registry/src/lib.rs`](../crates/near-receipt-registry/src/lib.rs):
- **Measurement Management**: `add_approved_measurement`, `add_approved_measurements_batch`, `sync_approved_measurements` (cross-contract call to `worker.outlayer.testnet::get_approved_measurements`), and `on_measurements_synced`.
- **Receipt Registration (`register_receipt`)**:
  - Enforces `WorkOutcome::Pass`, canonical `evidence_commitment` and `receipt_id`, optional `expected_wasm_hashes` allowlist, `(provider_pubkey, nonce)` replay protection, Buyer + Provider domain-separated Ed25519 co-signatures, OutLayer task metadata bindings (`wasm_hash`, `input_hash`, `output_hash`), TDX Quote v4 binary parsing, approved worker measurement membership, ECDSA P-256 quote signature + QE report binding, and `report_data[0..32] == task_hash`.
- **Cross-Chain Loan Authorization (`authorize_loan` -> `on_loan_authorization_signed`)**:
  - Optimistically transitions `consequence_state` from `RegisteredVerified` to `LoanAuthorized` before invoking `v1.signer-prod.testnet::sign` (`domain_id: 0`, path `"receipt-credit-vault-v1"`).
  - Callback verifies the returned threshold secp256k1 signature `(big_r, s, recovery_id)` against the KDF-derived child public key before persisting `LoanAuthorizationPacket`; rolls state back to `RegisteredVerified` if the promise fails or signature is invalid.
- **Cross-Chain Consequence Verification (`verify_loan_consequence` -> `on_foreign_tx_verified`)**:
  - Validates the Base Sepolia `LoanDrawn` `EvmLog` (`!removed`, `address == base_vault_address`, `transaction_hash`, `block_hash`, `topics[0..4]`, and ABI-encoded `(principal, evidenceCommitment)`), computes `expected_payload_hash = SHA256(Borsh(ForeignTxSignPayload::V1))`, transitions state to `VerificationPending`, and invokes `v1.signer-prod.testnet::verify_foreign_transaction` (`domain_id: 3`, `ForeignChainRpcRequest::Base`).
  - Callback verifies `resp.payload_hash == expected_payload_hash` and cryptographically verifies `resp.signature` against `foreign_tx_domain_root_pubkey` (`domain_id: 3`) before transitioning the receipt to `ConsumedVerified` and appending a `ConsequenceNode` to `provider_credit_graph`.

### 7.3 Base Sepolia Solidity Contracts (`contracts/base-sepolia/`)
- **[`MockCreditUSDC.sol`](../contracts/base-sepolia/MockCreditUSDC.sol)**: 6-decimal ERC-20 testnet credit asset (`mUSDC`) with owner-gated `mint`.
- **[`ReceiptCreditVault.sol`](../contracts/base-sepolia/ReceiptCreditVault.sol)**:
  - Stores `immutable nearAuthorizedSigner`, `immutable creditToken`, `immutable lenderId`, `immutable DOMAIN_SEPARATOR`, and `mapping(bytes32 => bool) public consumedReceipts`.
  - `drawCredit` enforces `block.timestamp <= deadline`, non-zero parameters, `!consumedReceipts[receiptId]`, EIP-2 low-`s` (`uint256(s) <= SECP256K1N_HALF`) and `v in {27, 28}`, and `ecrecover(digest, v, r, s) == nearAuthorizedSigner`.
  - Updates `consumedReceipts[receiptId] = true` and emits `LoanDrawn` **before** calling `creditToken.transfer(borrower, principal)` so `LoanDrawn` is deterministically at `log_index: 0` in the transaction receipt for NEAR MPC `EvmExtractor::Log { log_index: 0 }`.

### 7.4 Phase 2 Artifact Hashes & Sizes

| Artifact | Size (bytes) | SHA-256 |
| :-- | :-- | :-- |
| `target/wasm32-unknown-unknown/release/near_receipt_registry.wasm` | `726,274` | `8899fef63f3067861bc3ea065c6d2528b61e182d7a6b8542450a086db0e67e6b` |
| `contracts/base-sepolia/artifacts/MockCreditUSDC_sol_MockCreditUSDC.abi` | `3,346` | `91bfa49ac744945246bdb7eb7c90f8d33b7811d7fb539ea0d9db6d65f7bf7c86` |
| `contracts/base-sepolia/artifacts/MockCreditUSDC_sol_MockCreditUSDC.bin` | `3,994` | `a5d57b9423de07a63a011d7cf75b4f98ea75390f50683293781868e719736667` |
| `contracts/base-sepolia/artifacts/ReceiptCreditVault_sol_ReceiptCreditVault.abi` | `4,091` | `3e0250af69a9ade0ab0bd676527b3f6884bbbeadc728992bd0a4ac706c36937a` |
| `contracts/base-sepolia/artifacts/ReceiptCreditVault_sol_ReceiptCreditVault.bin` | `5,032` | `9716f0e87ac01b28de36b0a2b47475519f7490ebd11266f8c675b46046232a44` |

### 7.5 Phase 2 Verification Results
- `cargo fmt --all --check`: **Passed** (exit code 0)
- `cargo clippy --workspace --all-targets -- -D warnings`: **Passed** (exit code 0)
- `cargo clippy -p near-receipt-registry --target wasm32-unknown-unknown -- -D warnings`: **Passed** (exit code 0)
- `cargo test --workspace`: **69 passed, 0 failed**:
  - `receipt-core`: 43 unit tests + 7 genuine OutLayer/MPC integration tests = **50 passed**
  - `acceptance-verifier-wasm`: **8 passed**
  - `near-receipt-registry`: 10 unit/negative state-machine tests + 1 `revm` cross-stack EVM integration test ([`evm_cross_chain_integration.rs`](../crates/near-receipt-registry/tests/evm_cross_chain_integration.rs)) = **11 passed**
- `uv run pytest -q`, `uv run ruff check .`, `uv run mypy .`: **All passed** (exit code 0)

### 7.6 Phase 3 Live Testnet Deployment & End-to-End Cross-Chain Verification (`demo_e2e.py`)

Executed [`src/receipt_orchestrator/probe.py`](../src/receipt_orchestrator/probe.py) and [`src/receipt_orchestrator/demo_e2e.py`](../src/receipt_orchestrator/demo_e2e.py) against live **NEAR Testnet** (`receipt-registry.testnet`, `worker.outlayer.testnet`, `v1.signer-prod.testnet`) and **Base Sepolia** (`chainId = 84532`).

#### Live Deployed Contracts & Derived MPC Signer
- **NEAR Receipt Registry Account**: `receipt-registry.testnet`
- **Derived NEAR Chain Signatures Public Key** (`v1.signer-prod.testnet`, `domain_id: 0`, path `"receipt-credit-vault-v1"`):
  `secp256k1:4BUaArkKFhhnaUmFaxQ3ZDFJKScvpShfeQSo2rsDgLMj3SvfFCuVvZgtDbsntZYmgShfPynEJhYm6GiuEShHvzMS`
- **Derived EVM `nearAuthorizedSigner` Address**: `0x6cb5858d8310045e4f2caea4e1231e4980af4e4b`
- **Base Sepolia Deployer / Borrower**: `0xf4e355089852f302a69e6b6cf8b6d83dc09d9a42`
- **Base Sepolia `MockCreditUSDC` Contract**: `0x99ac11cf7b392d27074253937163ad1a82786e8a`
- **Base Sepolia `ReceiptCreditVault` Contract**: `0xf59f9d39f5fb76880bdc64fbcb7613e770d195e8`

#### Complete Live Transaction Hash Ledger

| Step | Network | Operation | Transaction Hash | Result / Verification |
| :-- | :-- | :-- | :-- | :-- |
| **Probe 1** | NEAR Testnet | `v1.signer-prod.testnet::sign` (`domain_id: 0`, path `"receipt-credit-vault-v1"`) | `6qeeviGsTCWp4r2v4ywJsU1hESBMMfWkjaag7tS87BJW` | Recovered `secp256k1:4BUaArk...` (`0x6cb5858d8310045e4f2caea4e1231e4980af4e4b`) |
| **Probe 2** | NEAR Testnet | `v1.signer-prod.testnet::verify_foreign_transaction` (`domain_id: 3`, Base) | `4TuEwQ7Xy9SCssQh1VjTz2qRMCXynQBTBUAECTwNxLtz` | Payload hash `cde13b49ed4f2a412c8f38cb13bdbe654d73dead82f7b3ea363f73e3ca4b853b` matched & recovered Domain 3 key `secp256k1:2KGCoy2p...` |
| **Step 1a** | NEAR Testnet | `DeployContract` (`near_receipt_registry.wasm` -> `receipt-registry.testnet`) | `DEfUmG5F9gsuaYhX7A8Kz9WfZiFjH4CEKJPhYcXQqUv1` | Deployed `near_receipt_registry.wasm` |
| **Step 1b** | NEAR Testnet | `receipt-registry.testnet::new` | `E8PzpxoTcz6xFDshYocegkVCDXpNd4yGzeUfFpfTVkkV` | Initialized contract (`owner = receipt-registry.testnet`, `mpc_signer = v1.signer-prod.testnet`) |
| **Step 1c** | NEAR Testnet | `receipt-registry.testnet::sync_approved_measurements` | `3Wm2R2Jb93ZiXQubfwACCjmFAqJiUWgZ5Wy88sBvSgxj` | Synced `129` approved TDX measurements from `worker.outlayer.testnet`; `derive_vault_authorized_signer_evm_address() == 0x6cb5858d8310045e4f2caea4e1231e4980af4e4b` |
| **Step 2a** | Base Sepolia | Deploy `MockCreditUSDC` (`1,000,000 mUSDC`) | `0xead18ea5db9bc9ed1092ea69a47971259de1f16a806318a5aa49456a40a191d7` | Deployed at `0x99ac11cf7b392d27074253937163ad1a82786e8a` |
| **Step 2b** | Base Sepolia | Deploy `ReceiptCreditVault` (`nearAuthorizedSigner = 0x6cb5858d...`) | `0x26cdc897ca4fbd06af1ddddf23f2c1b416b7ff6af7f8a7e06e2e593943486ad0` | Deployed at `0xf59f9d39f5fb76880bdc64fbcb7613e770d195e8` |
| **Step 2c** | Base Sepolia | `MockCreditUSDC::transfer` (`500,000 mUSDC` -> Vault) | `0xe70d318ebfc8b9cbd1eee78f0b02ec0356e820511facea6069b97bc5e3b6c919` | Vault funded with `500,000,000,000` units (`500,000 mUSDC`) |
| **Step 2d** | NEAR Testnet | `receipt-registry.testnet::set_configured_base_vault` | `DWnTUSxw7TV76ZUWMnbTGy8irtRJ4vbhReoPvoetRsSd` | Pinned `0xf59f9d39f5fb76880bdc64fbcb7613e770d195e8` on NEAR |
| **Step 3a** | NEAR Testnet | `receipt-registry.testnet::add_expected_wasm_hash` | `AiyrJfw5eNE7dqRDCgLeUvLNNXukWhCDJoxzGKqWD66z` | Pinned WASM hash `0eeb1b8747d5080e1d69f26603c61576ddb51793323ca8f9b518eb28ebae116d` |
| **Step 3b** | NEAR Testnet | `receipt-registry.testnet::register_receipt` | `A5QEf2jnvB2nNCRVra249btAjt1h52TSV61AZ4bmQKBu` | Registered `receipt_id = 43b46460703355ceea1364612a7b3efea9a3cc96cf402ddf22ec161521a2768c` (`state = RegisteredVerified`) |
| **Step 4** | NEAR Testnet | `receipt-registry.testnet::authorize_loan` (`v1.signer-prod.testnet::sign`) | `FNsbX3M42GhWhQewi8kKFcNWi2xgASW9kPcYBTq6LeBL` | Signed EIP-712 digest `c6e70dcce037da2dc4b527dd026b01abad9f8076f86d3b2990c8908eda57f23f` (`v=27, r=3ef0e810..., s=15409b44...`) |
| **Step 5** | Base Sepolia | `ReceiptCreditVault::drawCredit` (`250 mUSDC`) | `0xf3ee1f5cfc78729821e7409dcecd31cfd29ae885dde5160435dd88ca9a708283` | Block `0xb8ecab257cf946f17102f6df5c834177169061c4065f5e7de74c59321020365e`, emitted `LoanDrawn` at `logIndex = 0x0`, transferred `250,000,000` units (`250 mUSDC`) |
| **Step 6** | NEAR Testnet | `receipt-registry.testnet::verify_loan_consequence` (`v1.signer-prod.testnet::verify_foreign_transaction`) | `3kgoyP8dr6nANZgzYmsrjp9PB3xPr29uD1oPTR25vJ6Y` | Verified Base Sepolia tx via MPC Domain 3 (`payload_hash = 54ea4b9c877c06831537bbf9b7d6c9be871d7ea15a45c09ce218f28bfeea4143`), `consequence_state = ConsumedVerified`, `is_mpc_consequence_verified = true` |
