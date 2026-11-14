# RECEIPT — Cross-Chain Agent Credit Backed by Private, Attested Work

RECEIPT is a cross-chain reputation and credit primitive for autonomous agents. Every completed job produces a portable work credential that is co-signed by the buyer and provider, attested by an Intel TDX enclave, and turned into cross-chain collateral using NEAR Chain Signatures and MPC Foreign-Chain Verification (`Read RPC`).

**Live Testnet Loop:** A private work receipt is registered on NEAR → authorized for a credit loan via Chain Signatures → drawn on Base Sepolia → verified back on NEAR by the MPC network.

---

## Quick Demo & Verification (2 Minutes)

*   **Demo Video:** `(https://youtu.be/x2wtwXqngII)`
*   **Expected Outcome:** In a single verifiable loop, a TDX-attested `ReceiptV1` registered on `receipt-registry.testnet` unlocks a `250 mUSDC` credit draw on Base Sepolia (`0xf59f9d...95e8`) and is cryptographically verified back on NEAR by `v1.signer-prod.testnet` (`consequence_state = "ConsumedVerified"`, `is_mpc_consequence_verified = true`).

### Verify the Live On-Chain State in 4 Steps ("Do X → See Y")

1. **Query the Verified Consequence Proof on NEAR Testnet (`verify_consequence_proof`):**
   ```bash
   curl -s https://rpc.testnet.near.org -H "Content-Type: application/json" -d '{
     "jsonrpc": "2.0", "id": "1", "method": "query",
     "params": {
       "request_type": "call_function", "finality": "final",
       "account_id": "receipt-registry.testnet",
       "method_name": "verify_consequence_proof",
       "args_base64": "eyJyZWNlaXB0X2lkX2hleCI6IjQzYjQ2NDYwNzAzMzU1Y2VlYTEzNjQ2MTJhN2IzZWZlYTlhM2NjOTZjZjQwMmRkZjIyZWMxNjE1MjFhMjc2OGMifQ=="
     }
   }'
   ```
   **→ See:** JSON response showing `"consequence_state": "ConsumedVerified"`, `"is_mpc_consequence_verified": true`, `"foreign_chain_id": "eip155:84532"`, `"foreign_tx_hash": "f3ee1f5cfc78729821e7409dcecd31cfd29ae885dde5160435dd88ca9a708283"`, and the verified MPC Domain 3 threshold signature `(r, s, v)`.

2. **Verify the Derived MPC EVM Signer on NEAR (`derive_vault_authorized_signer_evm_address`):**
   ```bash
   curl -s https://rpc.testnet.near.org -H "Content-Type: application/json" -d '{
     "jsonrpc": "2.0", "id": "1", "method": "query",
     "params": {
       "request_type": "call_function", "finality": "final",
       "account_id": "receipt-registry.testnet",
       "method_name": "derive_vault_authorized_signer_evm_address",
       "args_base64": "e30="
     }
   }'
   ```
   **→ See:** `"0x6cb5858d8310045e4f2caea4e1231e4980af4e4b"`, matching the `nearAuthorizedSigner` immutable configured on the Base Sepolia `ReceiptCreditVault`.

3. **Inspect the Base Sepolia Credit Draw Receipt (`eth_getTransactionReceipt`):**
   ```bash
   curl -s https://sepolia.base.org -H "Content-Type: application/json" -d '{
     "jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt",
     "params": ["0xf3ee1f5cfc78729821e7409dcecd31cfd29ae885dde5160435dd88ca9a708283"]
   }'
   ```
   **→ See:** `status: "0x1"`, `logs[0]` (`logIndex: "0x0"`) emitted by `0xf59f9d39f5fb76880bdc64fbcb7613e770d195e8` (`LoanDrawn` with `topics[1] = 0x43b46460703355ceea1364612a7b3efea9a3cc96cf402ddf22ec161521a2768c`), and `logs[1]` transferring `250,000,000` (`250 mUSDC`) from the vault to borrower `0xf4e355089852f302a69e6b6cf8b6d83dc09d9a42`.

4. **Run the Full Local Verification Suite (`cargo test` + `pytest`):**
   ```bash
   cargo test --workspace && uv run pytest -q
   ```
   **→ See:** All **69 Rust tests** (including real OutLayer TDX quote v4 DCAP verification, upstream NEAR MPC Borsh payload differential tests, and an in-memory `revm` cross-stack EVM integration test) and Python smoke tests pass.

### Key Live Contracts & Transactions at a Glance

| Surface | Identifier / Transaction Hash | Explorer Link |
| :--- | :--- | :--- |
| **NEAR Receipt Registry** | `receipt-registry.testnet` | [NearBlocks Testnet](https://testnet.nearblocks.io/address/receipt-registry.testnet) |
| **Base Sepolia Credit Vault** | `0xf59f9d39f5fb76880bdc64fbcb7613e770d195e8` | [BaseScan Sepolia](https://sepolia.basescan.org/address/0xf59f9d39f5fb76880bdc64fbcb7613e770d195e8) |
| **Base Sepolia MockCreditUSDC** | `0x99ac11cf7b392d27074253937163ad1a82786e8a` | [BaseScan Sepolia](https://sepolia.basescan.org/address/0x99ac11cf7b392d27074253937163ad1a82786e8a) |
| **Derived MPC EVM Signer** | `0x6cb5858d8310045e4f2caea4e1231e4980af4e4b` | Derived from `v1.signer-prod.testnet` (`domain_id: 0`, path `"receipt-credit-vault-v1"`) |
| **1. Sync OutLayer TDX Measurements** | `3Wm2R2Jb93ZiXQubfwACCjmFAqJiUWgZ5Wy88sBvSgxj` | [NearBlocks Tx](https://testnet.nearblocks.io/txns/3Wm2R2Jb93ZiXQubfwACCjmFAqJiUWgZ5Wy88sBvSgxj) (`129` approved worker measurements) |
| **2. Register Receipt (NEAR)** | `A5QEf2jnvB2nNCRVra249btAjt1h52TSV61AZ4bmQKBu` | [NearBlocks Tx](https://testnet.nearblocks.io/txns/A5QEf2jnvB2nNCRVra249btAjt1h52TSV61AZ4bmQKBu) (`receipt_id = 43b46460...2768c`) |
| **3. Authorize Loan (Chain Signatures)** | `FNsbX3M42GhWhQewi8kKFcNWi2xgASW9kPcYBTq6LeBL` | [NearBlocks Tx](https://testnet.nearblocks.io/txns/FNsbX3M42GhWhQewi8kKFcNWi2xgASW9kPcYBTq6LeBL) (`v1.signer-prod.testnet::sign`, `domain_id: 0`) |
| **4. Draw Credit (Base Sepolia)** | `0xf3ee1f5cfc78729821e7409dcecd31cfd29ae885dde5160435dd88ca9a708283` | [BaseScan Tx](https://sepolia.basescan.org/tx/0xf3ee1f5cfc78729821e7409dcecd31cfd29ae885dde5160435dd88ca9a708283) (`250 mUSDC` drawn) |
| **5. Verify Consequence (NEAR Read RPC)** | `3kgoyP8dr6nANZgzYmsrjp9PB3xPr29uD1oPTR25vJ6Y` | [NearBlocks Tx](https://testnet.nearblocks.io/txns/3kgoyP8dr6nANZgzYmsrjp9PB3xPr29uD1oPTR25vJ6Y) (`verify_foreign_transaction`, `domain_id: 3`) |

---

## Why This Matters (Problem → Solution)

*   **Problem:** Existing agent reputation standards (such as ERC-8004's Reputation Registry) store subjective feedback ("4/5 stars") on a single chain. Subjective ratings are trivially sybil-farmed, cannot be underwritten by deterministic DeFi credit vaults, and force commercial counterparties to expose private pricing and deliverables if they want verifiable history.
*   **Solution:** **RECEIPT** replaces subjective ratings with **cryptographic facts of completed, accepted work**:
    1. Commercial terms stay private behind a salted **Confidential Intents** settlement commitment.
    2. Acceptance evaluation runs deterministically inside an **OutLayer Intel TDX** enclave (`wasm32-wasip1` / `wasm32-wasip2`) whose hardware quote (`MRTD` + `RTMR0..3` + `report_data[0..32] == task_hash`) is verified on NEAR against `worker.outlayer.testnet` and co-signed by both Buyer and Provider.
    3. The verified NEAR receipt directly authorizes an EIP-712 working-capital loan on **Base Sepolia** via **NEAR Chain Signatures** (`domain_id: 0`) and closes the accounting loop back on NEAR via **MPC Foreign-Chain Transaction Verification (`Read RPC`, `domain_id: 3`)**—without trusted relayers or bridges.

---

## Architecture Overview

```mermaid
sequenceDiagram
    autonumber
    actor Buyer as Buyer Agent (Private)
    actor Provider as Provider Agent
    participant CI as NEAR Confidential Intents<br/>(ConfidentialSettlementAdapter)
    participant TDX as OutLayer TDX Enclave<br/>(worker.outlayer.testnet)
    participant Registry as NEAR ReceiptRegistry<br/>(receipt-registry.testnet)
    participant MPC as NEAR MPC Network<br/>(v1.signer-prod.testnet)
    participant Base as Base Sepolia Credit Vault<br/>(0xf59f9d...95e8, Chain ID 84532)

    Note over Buyer,TDX: 1. Private Work Settlement & TDX-Attested Acceptance
    Buyer->>CI: Build salted Confidential Settlement Commitment
    Provider->>TDX: Execute acceptance-verifier-wasm on deliverable & criteria
    TDX-->>Provider: Output (PASS) + Intel TDX Quote v4 (MRTD, RTMR0..3, report_data[0..32] = task_hash)
    Buyer->>Provider: Co-sign ReceiptV1 (Ed25519 domain-separated signature)

    Note over Provider,Registry: 2. On-Chain Receipt Registration & TDX Verification on NEAR
    Registry->>TDX: sync_approved_measurements() (129 approved 5-measurement sets)
    Provider->>Registry: register_receipt(ReceiptV1, tdx_quote_bytes, outlayer_task_meta)
    Registry->>Registry: Verify Buyer/Provider Ed25519 sigs, nonce, PASS, TDX quote P-256 sig, QE binding & task_hash
    Registry-->>Provider: ConsequenceState = RegisteredVerified

    Note over Provider,Base: 3. Chain Signatures Loan Authorization & Base Sepolia Credit Draw
    Provider->>Registry: authorize_loan(receipt_id, borrower, 250 mUSDC, vault, deadline)
    Registry->>MPC: sign(payload_v2 = EIP712(LoanAuthorization), path = "receipt-credit-vault-v1", domain_id = 0)
    MPC-->>Registry: Threshold secp256k1 Signature (r, s, v)
    Provider->>Base: drawCredit(receiptId, borrower, principal, evidenceCommitment, deadline, v, r, s)
    Base->>Base: Verify ecrecover(digest, v, r, s) == nearAuthorizedSigner & !consumedReceipts[receiptId]
    Base-->>Provider: Emit LoanDrawn (logIndex = 0x0) & transfer 250 mUSDC to borrower

    Note over Provider,Registry: 4. MPC Foreign-Chain Verification (Read RPC) & Consequence Graph
    Provider->>Registry: verify_loan_consequence(receipt_id, base_tx_hash, base_block_hash, LoanDrawn log)
    Registry->>Registry: Validate LoanDrawn log & compute expected_payload_hash = SHA256(Borsh(ForeignTxSignPayload::V1))
    Registry->>MPC: verify_foreign_transaction(Base, tx_id, [BlockHash, Log(0)], domain_id = 3, expected_payload_hash)
    MPC->>Base: MPC nodes independently query Base Sepolia RPCs & verify block/log
    MPC-->>Registry: VerifyForeignTransactionResponse { payload_hash, signature (domain_id = 3) }
    Registry->>Registry: Verify payload_hash match & Domain 3 secp256k1 signature -> ConsequenceState = ConsumedVerified
```

---

## Live Testnet Deployments & Execution Evidence

### Live Testnet Deployments
*   **NEAR Registry:** `receipt-registry.testnet`
*   **Base Sepolia Vault:** `0xf59f9d39f5fb76880bdc64fbcb7613e770d195e8`
*   **Base Sepolia MockUSDC:** `0x99ac11cf7b392d27074253937163ad1a82786e8a`
*   **Derived MPC EVM Signer:** `0x6cb5858d8310045e4f2caea4e1231e4980af4e4b` (`secp256k1:4BUaArkKFhhnaUmFaxQ3ZDFJKScvpShfeQSo2rsDgLMj3SvfFCuVvZgtDbsntZYmgShfPynEJhYm6GiuEShHvzMS`)

### End-to-End Execution Evidence (Live)
1.  **Deploy NEAR Registry (`near_receipt_registry.wasm`):** `DEfUmG5F9gsuaYhX7A8Kz9WfZiFjH4CEKJPhYcXQqUv1` (Initialized in `E8PzpxoTcz6xFDshYocegkVCDXpNd4yGzeUfFpfTVkkV`)
2.  **Sync OutLayer TDX Measurements:** `3Wm2R2Jb93ZiXQubfwACCjmFAqJiUWgZ5Wy88sBvSgxj` (129 measurements synced from `worker.outlayer.testnet`)
3.  **Deploy & Fund Base Sepolia Contracts:**
    *   Deploy `MockCreditUSDC`: `0xead18ea5db9bc9ed1092ea69a47971259de1f16a806318a5aa49456a40a191d7`
    *   Deploy `ReceiptCreditVault`: `0x26cdc897ca4fbd06af1ddddf23f2c1b416b7ff6af7f8a7e06e2e593943486ad0`
    *   Fund Vault (`500,000 mUSDC`): `0xe70d318ebfc8b9cbd1eee78f0b02ec0356e820511facea6069b97bc5e3b6c919`
    *   Pin Vault on NEAR: `DWnTUSxw7TV76ZUWMnbTGy8irtRJ4vbhReoPvoetRsSd`
4.  **Register Receipt (NEAR):** `A5QEf2jnvB2nNCRVra249btAjt1h52TSV61AZ4bmQKBu` (`receipt_id = 43b46460703355ceea1364612a7b3efea9a3cc96cf402ddf22ec161521a2768c`, WASM hash pinned in `AiyrJfw5eNE7dqRDCgLeUvLNNXukWhCDJoxzGKqWD66z`)
5.  **Authorize Loan (NEAR Chain Signatures):** `FNsbX3M42GhWhQewi8kKFcNWi2xgASW9kPcYBTq6LeBL`
    *   `eip712_digest`: `c6e70dcce037da2dc4b527dd026b01abad9f8076f86d3b2990c8908eda57f23f`
    *   `r`: `3ef0e810a0eabaa2ca0adfaac46c3b334283cd06a83def3fe0234a6076a79b5a`
    *   `s`: `15409b4471b2de3cea80eb610e1b49385549b2c9da1aca695c02ce4c760cb8a3`
    *   `v`: `27`
6.  **Draw Credit (Base Sepolia):** `0xf3ee1f5cfc78729821e7409dcecd31cfd29ae885dde5160435dd88ca9a708283` (Block `0xb8ecab257cf946f17102f6df5c834177169061c4065f5e7de74c59321020365e`, `logIndex = 0x0`)
7.  **Verify Consequence (NEAR Read RPC):** `3kgoyP8dr6nANZgzYmsrjp9PB3xPr29uD1oPTR25vJ6Y` (`payload_hash = 54ea4b9c877c06831537bbf9b7d6c9be871d7ea15a45c09ce218f28bfeea4143`)

**MPC Domain 3 Signature (Proof of Verification):**
*   `r`: `0106b0af1622112404cb36ee9a20eaff48d863b62323d67750b0dbcf2a867001`
*   `s`: `238f95e757bd6455d5306605b537680227ca099d06b50e745b6f4e2cf802f28a`
*   `v`: `27`

---

## Architecture & Honesty Statement

*   **The Problem:** ERC-8004's Reputation Registry stores subjective feedback. It is chain-specific and easily manipulated. RECEIPT provides cryptographic proof of completed work.
*   **Confidential Intents Bridge:** NEAR's Confidential Intents private shard is mainnet-only and does not execute arbitrary contracts. To demonstrate the loop on testnet, we use a clearly labeled `TestnetConfidentialSettlementBridge` (`crates/receipt-core/src/confidential.rs`) alongside our NEP-413 1Click `OneClickIntentBuilder` to generate the salted commitment (`SHA256("RECEIPT_CONFIDENTIAL_V1" || intent_id || amount_le16 || currency_hash || buyer_salt)`) for the TDX acceptance test.
*   **TEE Capabilities:** Intel TDX proves code, input, and output integrity inside an approved enclave (verified against 129 approved OutLayer measurements on `worker.outlayer.testnet`, plus full off-chain Intel DCAP PCK/CRL/TCB/QE verification via `dcap-qvl` in `crates/receipt-core/src/tdx.rs`). It does not judge subjective fairness; the buyer and provider co-sign the acceptance criteria.
*   **Live Testnet Evidence:** The TDX attestation, Chain Signatures loan authorization, and MPC verification are all live and verifiable on testnet.
- **What the live loop attests:** the live testnet receipt is backed by a genuine OutLayer Intel TDX quote (OutLayer task 3000, WASM hash `0eeb1b87…`), pinned as the expected WASM hash. Our own `acceptance-verifier-wasm` is reproducibly built and tested under wasmtime (wasip1 + wasip2); running it through OutLayer and registering its quote is the next step. The registry's TDX path (DCAP, approved measurements, report_data binding) runs on the live registry against this real quote.
---



## Known Gaps (Testnet Scope)

- **Collusion / sybil pairs:** a buyer and provider controlled by one party can co-sign a fake job. Next: staking, per-pair credit caps, distinct-counterparty limits.
- **Outcome binding:** the registry checks quote ↔ hash binding but does not parse the enclave output, so `PASS` is asserted by the co-signers, and one quote can currently back more than one receipt. Next: commit the outcome inside the enclave output hash and consume quote task IDs on registration.
- **`authorize_loan` is permissionless:** borrower, principal and deadline are caller-supplied. Next: bind borrower + credit limit into the co-signed receipt and restrict the call to the provider.
- **Credit, not yet a loan:** the vault disburses only. Repayment, interest, collateral and liquidation are not built.
- **Self-reported acceptance metrics:** the enclave applies the rules faithfully to the supplied manifest; it cannot verify the manifest's numbers are true.
- **Demo keys:** buyer/provider keys are fixed in `demo_e2e.py`.
- **Trust assumptions:** Intel TDX, OutLayer's 129 approved measurements, NEAR MPC threshold.

## Repository Structure & How to Reproduce

| Path | Description |
| :--- | :--- |
| `crates/receipt-core` | Core cryptographic primitives: `ReceiptV1`, domain-separated Ed25519 co-signing, Intel TDX Quote v4 parser + `dcap-qvl` full DCAP collateral verifier, EIP-712 `LoanAuthorization` & `LoanDrawn` verifier, additive MPC KDF, and Borsh `ForeignTxSignPayload::V1`. |
| `crates/acceptance-verifier-wasm` | Deterministic acceptance verifier compiled to both `wasm32-wasip1` and `wasm32-wasip2` and verified under `wasmtime`. |
| `crates/near-receipt-registry` | NEAR smart contract (`near-sdk` v5) managing approved OutLayer measurements, receipt registration, Chain Signatures loan authorization (`domain_id: 0`), and MPC foreign-tx verification (`domain_id: 3`). Includes `revm` cross-stack EVM integration test. |
| `contracts/base-sepolia` | `ReceiptCreditVault.sol` (EIP-712 signature verification, replay protection, CEI `LoanDrawn` emission) and `MockCreditUSDC.sol`. |
| `src/receipt_orchestrator` | Live testnet probe (`probe.py`) and resumable end-to-end orchestrator (`demo_e2e.py`). |
| `docs/PLAN.md` & `docs/PROGRESS.md` | Full architectural specification, protocol discoveries, and complete verification report. |

### Run All Unit & Cross-Stack Integration Tests (No Credentials Needed)

```bash
# Run all 69 Rust tests (unit + real OutLayer TDX DCAP + upstream MPC Borsh + revm Base Sepolia vault)
cargo test --workspace

# Run WASI builds for the deterministic acceptance verifier
cargo build --release -p acceptance-verifier-wasm --target wasm32-wasip1
cargo build --release -p acceptance-verifier-wasm --target wasm32-wasip2

# Run Python lint, strict type-checking, and test suite
uv run ruff check .
uv run mypy .
uv run pytest -q
```

### Reproduce Live Testnet Probe & Orchestrator

Populate `.env` with `NEAR_ACCOUNT_ID`, `NEAR_PRIVATE_KEY`, `BASE_SEPOLIA_RPC_URL`, `BASE_SEPOLIA_PRIVATE_KEY`, and `OUTLAYER_PAYMENT_KEY`, then run:

```bash
# 1. Probe live v1.signer-prod.testnet::sign (Domain 0) and verify_foreign_transaction (Domain 3)
uv run python -m receipt_orchestrator.probe

# 2. Run or resume the Phase 3 end-to-end deployment and verification loop
uv run python -m receipt_orchestrator.demo_e2e
```
