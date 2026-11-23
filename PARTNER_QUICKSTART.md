# RECEIPT Partner Quickstart (< 15 Minutes, Zero Author Keys)

Outside builders can inspect the recorded live testnet cycle immediately (**Path A**, zero keys or faucets) or deploy and run their own isolated `borrow -> earn -> repay` stack on NEAR Testnet + Base Sepolia (**Path B**, < 15 minutes using only a throwaway Base Sepolia wallet and public faucets).

---

## Path A: Zero-Key Live On-Chain Replay (< 1 Minute)

No `.env`, no wallets, no faucets, and no Rust toolchain needed. From a fresh clone:

```bash
git clone https://github.com/Johnlocke0347/Receipt.git
cd Receipt
uv run python -m receipt_orchestrator.partner_quickstart --replay
```

This connects read-only to public `https://rpc.testnet.near.org` and `https://sepolia.base.org` and independently verifies the recorded `advance_flow_v3` cycle from [`config/deployments.json`](./config/deployments.json):
* **BORROW:** Decodes `LoanDrawn` and ERC-20 `Transfer` from Base Sepolia `drawCredit` (`$4.00` principal, `$3.80` net disbursed, `$0.20` holdback bond).
* **EARN:** Verifies incoming `$6.00 mcUSDC` settled directly to vault-controlled `AgentPayoutProxy`.
* **REPAY AT SOURCE:** Decodes `LoanRepaid` (`$4.08` skimmed = `$4.00` principal + `$0.08` fee, `remainingBalance = $0.00`) and `$2.12` forwarded back to the agent (`$1.92` residual + released `$0.20` bond).
* **LIVE STATE:** Checks NEAR MPC verification txs (`authorize_loan`, `verify_loan_consequence`, `verify_loan_repayment`), cleared encumbrance (`None`), live vault `hardPerAgentCap` (`$5.00`), and ERC-8004 summary counters on both chains (`count=1, value=100`).

---

## Path B: Run Your Own Isolated `borrow -> earn -> repay` Stack (< 15 Minutes)

### 1. Prerequisites

* Python 3.12+ with [`uv`](https://docs.astral.sh/uv/)
* Rust toolchain with WASM target: `rustup target add wasm32-unknown-unknown`
* Optional Node/`npx` (runs `wasm-opt -Oz` to shrink the contract WASM from `688,956` B to `565,596` B, lowering NEAR storage stake from `~6.89 NEAR` to `~5.66 NEAR`)
* One fresh throwaway EVM key funded with **`~0.001` Base Sepolia ETH** from a public faucet (Coinbase Developer Platform, Alchemy, or QuickNode Base Sepolia Faucet)

### 2. Run With Your Own Testnet Wallet (Auto-Provisions Fresh NEAR Testnet Account)

Do **not** reuse any author account. Export your throwaway Base Sepolia key and pass `--live --build-wasm`:

```bash
# PowerShell
$env:PARTNER_BASE_SEPOLIA_KEY = "0x<YOUR_THROWAWAY_BASE_SEPOLIA_PRIVATE_KEY>"
uv run python -m receipt_orchestrator.partner_quickstart --live --build-wasm
```

```bash
# macOS / Linux
export PARTNER_BASE_SEPOLIA_KEY="0x<YOUR_THROWAWAY_BASE_SEPOLIA_PRIVATE_KEY>"
uv run python -m receipt_orchestrator.partner_quickstart --live --build-wasm
```

What the script does automatically (never touching mainnet or author accounts):
1. Checks your Base Sepolia ETH balance (`>= 0.0005 ETH`) via public `https://sepolia.base.org`.
2. Compiles and optimizes `target/wasm32-unknown-unknown/release/near_receipt_registry_opt.wasm` (`scripts/build_registry_wasm.py`).
3. Generates a fresh Ed25519 keypair and creates an isolated `receipt-partner-<8hex>.testnet` account via public `https://helper.testnet.near.org/account` (`10 NEAR` testnet faucet, saved in gitignored `artifacts/partner_session.json`).
4. Deploys your own `ReceiptRegistry`, `MockCreditUSDC` (or uses `BASE_CREDIT_TOKEN_ADDRESS` if set), `ReceiptCreditVault` (`$5` hard cap), and `AgentPayoutProxy`, runs two live OutLayer TDX jobs (`worker.outlayer.testnet`), borrows `$4.00`, settles `$6.00` into your proxy, sweeps `$4.08` + forwards `$2.12`, and verifies `RepaidVerified` on NEAR.
