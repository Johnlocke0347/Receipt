# OutLayer Live Self-Verifier Integration Status (`docs/OUTLAYER_TODO.md`)

This note documents the exact results obtained when wiring RECEIPT's own deterministic acceptance verifier (`crates/acceptance-verifier-wasm`) through live OutLayer on NEAR Testnet (`outlayer.testnet` and `https://testnet-api.outlayer.ai`).

## 1. What Works Live (`wasm32-wasip1` + FastFS `WasmUrl`)

We compiled `crates/acceptance-verifier-wasm` to `wasm32-wasip1` (`115,266` bytes, SHA-256 `9465bd664f1cfa7ce54731ba4b5c411b4444ebde9064351b5e2b1761cc467dd1`), uploaded it to FastFS via `outlayer.testnet::__fastdata_fastfs`, and executed it inside an OutLayer Intel TDX worker via `outlayer.testnet::request_execution`:

- **FastFS Upload Tx:** `5Ai5kp28FxB3jDZCqR1twmmi9ciToibAvhVsNsmbXTyA`
- **FastFS Content-Addressed URL:** `https://test.fastfs.io/receipt-registry.testnet/outlayer.testnet/9465bd664f1cfa7ce54731ba4b5c411b4444ebde9064351b5e2b1761cc467dd1.wasm` (`HTTP 200`, `115,266` bytes)
- **Live `request_execution` Tx:** `Ggj11PrnUfKt3yfR6abLVbQpvGwgpYxBouC5Up4woMes` (`request_id: 106387`, `task_id: 302974`, block `278679611`)
- **Enclave Resources & Cost:** `114,944` instructions, `227 ms`, `1085900000000000000000` yoctoNEAR charged
- **Enclave Stdout (`RECEIPT_ACCEPTANCE_OUT_V1`):** `outcome: "PASS"` (`413` bytes, `SHA-256 = 417f5acee88fe6831975881550deeb1e5dbebb800ace9999fedb79a9f1676c01`)
- **Attestation Verification (`https://testnet-api.outlayer.ai/attestations/by-request/106387`):**
  - Saved in `crates/receipt-core/tests/fixtures/outlayer_attestation_self.json`
  - `wasm_hash` matches `9465bd664f1cfa7ce54731ba4b5c411b4444ebde9064351b5e2b1761cc467dd1`
  - `input_hash` matches `1dab42aa7ecef3d1c14dabf812e76109f2c87d019f390916e20d7a2e45adf61f`
  - `output_hash` matches `417f5acee88fe6831975881550deeb1e5dbebb800ace9999fedb79a9f1676c01`
  - `tdx_quote.report_data[0..32]` matches recomputed V1 `task_hash`
  - Worker measurements match the live `worker.outlayer.testnet::get_approved_measurements` allowlist

Note: `worker.outlayer.testnet` rotated its active allowlist between the hackathon submission snapshot (`129` measurement sets on 2026-11-13) and post-submission testing (`4` measurement sets on 2026-11-21), making `sync_approved_measurements()` essential before live registration.

## 2. Observed Blockers & Remaining Integration Work

Three secondary OutLayer integration paths were tested and remain blocked or deferred:

1. **On-Chain `GitHub` Source Compilation Disabled on Testnet Coordinator**
   - Calling `outlayer.testnet::request_execution` with `{"GitHub": {"repo": "Johnlocke0347/Receipt", "commit": "92deb5d69c8fca1f5aa1b0a38833f0223ca96ef7", "build_target": "wasm32-wasip2"}}` (`tx: Fp33AuBadXG2rjR54hMgfJHXeKYXfmXhcdFaaUGfjbe4`, `request_id: 106331`) failed with:
     > `"Building from a GitHub repository is not available right now. Build the .wasm locally, upload it to FastFS. Docs: https://app.outlayer.ai/docs/"`
   - **TODO:** Wait for upstream OutLayer GitHub compiler service re-enablement or keep FastFS prebuilt `.wasm` distribution as the canonical deployment path.

2. **`wasm32-wasip2` Component Instantiation Failure under `rustc 1.100.0`**
   - Prebuilt `acceptance-verifier-wasm.wasm` compiled with `rustc 1.100.0` targeting `wasm32-wasip2` (`135,395` bytes, SHA-256 `19606e33d6ac2566bc40c3defd173248939d474f60589466160042da389d358a`) uploaded to FastFS (`tx: 2xMz9W6qXo6N9QKX4Zmj7FCvpSMjvNGYT763tvJNcsMG`) and executed (`tx: FLSgrT7cXpVZwCEY45G6kECARzp2DHT3LpVWq4rLJSKs`, `request_id: 106370`) failed during worker component instantiation with:
     > `"Failed to instantiate component"`
   - Root cause (inspected in `out-layer/outlayer` `worker/src/executor/wasi_p2.rs` vs `wasi_p1.rs`): newer `wasm32-wasip2` component bindings emitted by `rustc 1.100.0` are incompatible with the deployed OutLayer worker's pinned `wasmtime_wasi::p2` host linker, whereas WASI Preview 1 (`wasm32-wasip1`) runs via `preview1::add_to_linker_async`.
   - **TODO:** Pin the exact `rustc`/WIT version supported by OutLayer's `wasi_p2` host linker before switching from `wasm32-wasip1` to `wasm32-wasip2` in live execution.

3. **HTTPS `POST /call/{owner}/{project}` Payment-Key Funding / Registration**
   - `GET https://testnet-api.outlayer.ai/payment-keys/balance` with `OUTLAYER_PAYMENT_KEY` (`wk_...`) returned `400 Invalid X-Payment-Key format. Expected: owner:nonce:key`.
   - `GET https://testnet-api.outlayer.ai/wallet/v1/balance` showed `0` NEAR (`account_id: fb681f2f8a79230d8a880b73ed034df3e3ca2d1f179c28b2a41ae89646c65303`), and `GET /wallet/v1/payment-key` returned `404 no_payment_key` (`"This wallet has no nonce-0 key yet"`).
   - **TODO:** Register an OutLayer project and fund a proper `owner:nonce:key` payment key if HTTPS API invocation is preferred over on-chain `outlayer.testnet::request_execution`.
