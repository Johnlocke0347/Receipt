# RECEIPT Design Partner Guide (x402 Revenue Advances)

## The Ask

> **"Route your agent's revenue through RECEIPT for an advance of $X at Y% fee"**

Concretely, for pilot partners on Base Sepolia: route your autonomous agent's incoming x402 USDC settlements through a vault-controlled `AgentPayoutProxy` deployed for your agent address to unlock immediate working-capital advances of **$X up to `min($5.00 pilot cap, 1.5x trailing 14-day attested work revenue)`** at a **2% flat advance fee (`Y = 2%`)**, repaid automatically at the source when buyers pay — before residual revenue (plus your released 5% holdback bond) hits your agent wallet.

* **Current scope:** Testnet prototype only (`MockCreditUSDC` on Base Sepolia + NEAR Testnet). Unaudited; no real USDC or mainnet deployment yet.
* **Required prerequisites from partner agent:**
  * Two or more distinct x402 paying clients (or buyer keys) generating attested completed jobs in the trailing 14 days.
  * Willingness to point x402 payment headers (`payTo`) to your immutable `AgentPayoutProxy` address deployed by `ReceiptCreditVault`.

---

## How Integration Works (4 Steps)

1. **Deploy your immutable `AgentPayoutProxy`:** Call `ReceiptCreditVault.deployAgentPayoutProxy(agentWallet)` once on Base. Only the vault can pull USDC from this proxy; residual funds above debt due are always forwarded directly to `agentWallet`.
2. **Set x402 `payTo = proxyAddress`:** Configure your x402 API / HTTP 402 middleware so buyer settlements land in `AgentPayoutProxy`.
3. **Register attested work receipts on NEAR (`ReceiptRegistry`):** Run acceptance checks in OutLayer (`acceptance-verifier-wasm`) and submit buyer + provider co-signed `ReceiptV1` records binding your `borrower_evm_address`, `max_credit_principal`, and `attested_revenue`.
4. **Borrow & Repay at the Source:** Call `ReceiptRegistry.authorize_loan` -> `ReceiptCreditVault.drawCredit` to receive `95%` net (`5%` holdback bond), let customer x402 payments settle into your proxy, and call `sweepAgentPayout(agentWallet)` (permissionless) to skim `principal + fee` and forward excess + holdback bond cleanly.

---

## One-Command Live Testnet Cycle & Partner Quickstart

For outside builders with no author keys or prebuilt artifacts, start with **[`PARTNER_QUICKSTART.md`](./PARTNER_QUICKSTART.md)**:
* **Zero-key live replay (~1 min):** `uv run python -m receipt_orchestrator.partner_quickstart --replay`
* **Isolated BYO testnet wallet (< 15 min):** `PARTNER_BASE_SEPOLIA_KEY=0x... uv run python -m receipt_orchestrator.partner_quickstart --live --build-wasm`

For the project maintainer script (requires `cargo build --release -p near-receipt-registry --target wasm32-unknown-unknown`, `.env` credentials `NEAR_PRIVATE_KEY`, `BASE_SEPOLIA_RPC_URL`, `BASE_SEPOLIA_PRIVATE_KEY`, and a fresh `NEAR_ADVANCE_REGISTRY_ACCOUNT_ID` not already owned by another key):

```bash
uv run python -m receipt_orchestrator.advance_cycle
```

### Latest Verified Testnet Run Output (`advance_flow_v3`)

Executed against dedicated testnet deployment [`config/deployments.json`](./config/deployments.json) (`advance_flow_v3`):

* **NEAR Registry Account:** `receipt-advance-20261123.testnet` (`deploy tx`: `9ozUnbaRMRdes6y7DSLhRGR7CrjneLRWgaXSQnKfNA8Z`)
* **Derived MPC EVM Signer:** `0x52922c2dab12bfd5d692f713445c0c6b7fc9567f`
* **Base Sepolia `MockCreditUSDC`:** `0x86727613c06aa4e2ea9da0e60870c9707f661284`
* **Base Sepolia `ReceiptCreditVault` (`$5` hard cap):** `0xeeb53bf1a753ecc9cfc82c00fa7f61f7df57dbda`
* **Agent Payout Proxy:** `0xbaaf339444fbf398c0523e6b45991fe902e8c44c`

| Stage | Action | Verified Testnet Transaction Hash |
| :--- | :--- | :--- |
| **TDX Attestations** | OutLayer `wasm32-wasip1` job #1 & job #2 | `6x6BQse4Wo9wvxgKthcS5mDZ5LZiai3mHeASEcWcNnMo` · `ERQKT4WZY8A9TS7b1ygmNvEndmfvYfey2JhBLfeBvZRe` |
| **Register Receipts** | 2 distinct-buyer `ReceiptV1` (`$2.00` rev each -> `$5.00` cap) | `FjDa9BkuochEqjjoJjUmoTnG8PxGPC9MbyxFtpECU1pa` · `27RHoz6JwsVTvBfH3R7v98KRmNaFbrVxoEUy6PiS3QbS` |
| **BORROW (NEAR)** | `authorize_loan` (`$4.00` + `$0.08` fee, 2%) | `B4tRyX6Eync7kgjMEhybf273vRb6r5ZChJCy2nDzeHns` |
| **BORROW (Base)** | `drawCredit` (`$3.80` net to borrower, `$0.20` bond) | `0xaf8b3b2f3e834b1f44279a105a6ca3652fa4f6c469ce8b1a0f1088b165fe59ce` |
| **BORROW (MPC Proof)** | `verify_loan_consequence` -> `ConsumedVerified` | `DW5sGDw5TNpbvJRUonFWy1yA8FBvSzYsvAYhLwhSbeqh` |
| **EARN (x402 -> Proxy)** | `$6.00` `mcUSDC` settled into `AgentPayoutProxy` | `0xab5d9192535608538b0c5ebe3d4ba056212346109edfcc6aae95262c823cbbd3` |
| **REPAY AT SOURCE** | `sweepAgentPayout` (`$4.08` skimmed, `$2.12` w/ `$0.20` bond forwarded) | `0xab2de771c0942ec9521fbee26ce019c78da52dd64bb0137a2abab99486621b91` |
| **REPAY (MPC Proof)** | `verify_loan_repayment` -> `RepaidVerified`, encumbrance cleared | `CKwmHPYTvG7JtMvyaZp8B6ss4qWDe4SEQzzVAhAGitVE` |
| **ERC-8004 Summary** | Queried on NEAR & Base Vault after sweep | `count = 1`, `value = 100`, `value_decimals = 0` |
