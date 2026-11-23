# RECEIPT Threat Model

**Status:** Unaudited testnet prototype (`MockCreditUSDC` on Base Sepolia + NEAR Testnet). Do not use with real user funds until the external audit and mainnet operational gates are completed.

---

## 1. Intel TDX Hardware, Side-Channels, Freshness & Replay

* **Hardware & Collateral Trust Base:** RECEIPT verifies Intel TDX Quote v4 headers (`version = 4`, `tee_type = 0x81`), PCK certificate chains, TCB levels, Quoting Enclave report binding, and `MRTD` / `RTMR0..3` registers (`crates/receipt-core/src/tdx.rs`) against the measurement allowlist synced from `worker.outlayer.testnet`. Any undetected Intel TDX microarchitectural vulnerability, compromised Quoting Enclave signing key, or unpatched microcode side-channel breaks hardware soundness.
* **What TDX Does and Does Not Prove:** TDX proves `acceptance-verifier-wasm` deterministically produced `raw_output_hash` on `input_hash` inside an approved enclave (`report_data[0..32] == task_hash`). It does **not** prove side-channel confidentiality if sensitive secrets were held in clear (mitigated here because the enclave evaluates hashed commitments and acceptance scores rather than decryption keys) and does not prove off-chain truth of self-reported deliverables.
* **Attestation Freshness & Replay:**
  * **Intra-enclave replay** is prevented by tracking `consumed_task_ids: BTreeSet<u64>` in `ReceiptRegistry::register_receipt`, enforcing per-provider replay nonces (`used_nonces`), pinning expected `wasm_hash` values, and committing `WorkOutcome` (`Pass = 1`) into `enclave_output_hash`.
  * **Window staleness:** Trailing 14-day revenue uses `receipt.created_at`, which is signed by both buyer and provider and sanity-checked against `block_timestamp_secs` (`+60s` clock-skew tolerance), rather than currently enforcing strict equality with `outlayer_task_meta.timestamp`. Colluding buyers/providers could backdate `created_at` within the 14-day window; tightening `created_at` against `outlayer_task_meta.timestamp` on-chain is recommended prior to mainnet.

---

## 2. NEAR Chain Signatures MPC Trust Assumptions

* **Domain 0 (`v1.signer-prod.testnet::sign`, threshold secp256k1):**
  * Base `ReceiptCreditVault` trusts a single derived EVM address (`nearAuthorizedSigner`) derived deterministically from `(mpc_root_pubkey, registry_account_id, "receipt-credit-vault-v1")`.
  * Compromise of more than the MPC threshold of signers allows forging EIP-712 `LoanAuthorization` approvals on Base.
  * Compromise or malicious upgrade of the NEAR `ReceiptRegistry` account itself also grants authority to call `v1.signer::sign` under the same derivation path; mainnet deployment **must** transfer registry ownership to a multisig and lock or govern WASM upgrades.
* **Domain 3 (`verify_foreign_transaction`, NEAR Read RPC):**
  * NEAR `ReceiptRegistry` does not run an EVM light client. Instead, `v1.signer::verify_foreign_transaction` instructs NEAR MPC nodes to query Base RPC nodes independently and sign `SHA256(Borsh(ForeignTxSignPayload::V1))` asserting `blockHash` + `Log(0)` extraction.
  * **RPC & Finality Assumptions:** Honest majority across MPC nodes' configured Base RPC providers is assumed. In testnet workflows (`advance_cycle.py`, `demo_e2e.py`), finality is requested as `"Latest"` to keep demo latency ~10s; `"Latest"` exposes a short window where an L2 sequencer reorg could invalidate a verified log. Production configuration **must** enforce `"Finalized"` (`EvmFinality::Finalized`) inside `ReceiptRegistry`.

---

## 3. Revenue-Attestation & Wash-Trade Risk

The central economic attack on revenue-backed undercollateralized credit is **wash-trading**: an attacker controls one provider key and `N` buyer keys, runs tiny cheap jobs through OutLayer, self-signs inflated `attested_revenue` claims, borrows up to the cap, and walks away without repaying.

| Defense Implemented | How It Constrains Attackers | Residual Risk |
| :--- | :--- | :--- |
| **`min_distinct_payers >= 2`** | Rejects single-buyer circular self-attestation (`distinct_payers < 2` panics in `authorize_loan`). | An attacker can trivially generate 2 or more cheap Ed25519 keypairs (Sybil buyers). |
| **Trailing 14-day window & `1.5x` multiplier** | Prevents ancient stale receipts from permanently inflating borrowing capacity. | Sybil receipts created over a few days still count toward the window. |
| **Hard `$5.00` per-agent cap + single active encumbrance** | Bounds max gross exposure per agent identity to `$5.00` (and net pool loss to `$4.75` after 5% holdback) with zero stacking across receipts. | An attacker who creates fresh NEAR accounts + fresh Base addresses can attack multiple `$5` caps unless gated by identity / facilitator allowlisting. |
| **Permadefault freeze on default** | Once a borrower misses repayment beyond `maturityAt + gracePeriodSecs`, both Base vault (`defaultedBorrower`) and NEAR registry (`credit_frozen`, `defaults_count > 0`) permanently reject new draws. | Does not deter one-shot Sybil default if identity creation costs less than `$4.75`. |

**Honest conclusion:** Purely on-chain `Ed25519` buyer pubkey diversity (`min_distinct_payers`) catches accidental or naive single-counterparty loops, **not** a determined Sybil attacker. Real-capital pilots must additionally require **attested x402 facilitator payment proofs** (or observed historical inflows through `AgentPayoutProxy`) before increasing limits above `$5`.

---

## 4. Smart-Contract Risk

* **`log_index: 0` Emission Invariant:** `ReceiptRegistry::verify_loan_consequence`, `verify_loan_repayment`, and `verify_loan_default` inspect `Log(0)` via MPC Read RPC. `ReceiptCreditVault` deliberately emits `LoanDrawn`, `LoanRepaid`, and `LoanDefaulted` **before** ERC-20 `transfer`/`pullToVault` calls so the protocol event is always at `logIndex == 0`. Refactoring event order breaks cross-chain verification.
* **Checks-Effects-Interactions (CEI):** Vault storage mutations (`consumedReceipts`, `activeLoanByBorrower`, `loans[].state`, reserves) occur before external ERC-20 `transfer` and `AgentPayoutProxy.pullToVault()` calls; still **unaudited** and excludes fee-on-transfer or rebasing ERC-20 tokens.
* **Revenue Diversion (Agent Bypass):** `AgentPayoutProxy` cannot prevent an agent from advertising a *different* wallet address to future off-chain customers once a loan is drawn. If no inflows arrive at the proxy before `maturityAt + gracePeriodSecs`, lenders rely on `markDefaulted` freezing the identity and absorbing principal loss via the 3-tier waterfall.
* **Owner Centralization:** Vault `owner` can `pause()`/`unpause()` and change `hardPerAgentCap`; NEAR `owner` can `set_paused(bool)`, `set_underwriting_policy`, and `set_configured_base_vault`. No timelock exists on owner calls in this prototype.
* **Integer Bounds:** Principal and fee fit `uint128` (`<= 3.4e38`, orders of magnitude above USD supplies); time calculations rely on EVM `block.timestamp` and NEAR `block_timestamp` with small cross-chain skew assumptions.

---

## 5. Attacks Fixed in Post-Submission Hardening

Each vulnerability below existed in the Nov 14 hackathon snapshot (`submission-2026-11-14`) and is documented with failing-then-passing regression evidence in [`SECURITY-HARDENING.md`](./SECURITY-HARDENING.md):

1. **Unbound `borrower_evm_address` & `max_credit_principal` (`210fd36`):** Previously, anyone knowing a registered `receipt_id` could authorize a loan to an attacker-chosen EVM address or arbitrary principal. Now both fields are Borsh-serialized into `ReceiptSigningPayloadV1` under buyer/provider Ed25519 co-signatures and checked in `authorize_loan`.
2. **Permissionless `authorize_loan` (`54d0a37`):** Previously, third-party accounts could front-run `authorize_loan` and lock a provider's receipt in `LoanAuthorized`. Now `authorize_loan` panics unless `rt::predecessor_account_id() == receipt.provider_identity`.
3. **Replayable OutLayer `task_id` quotes (`04322dd`):** Previously, one valid TDX quote (`task_id`) could be replayed across fresh receipts by bumping `nonce` and recomputing `receipt_id`. Now `consumed_task_ids: BTreeSet<u64>` makes every `task_id` single-use.
4. **Uncommitted `WorkOutcome` in enclave output hash (`e3e6535`):** Previously, a `FAIL` TDX stdout could potentially pass hash checks if claimed as `Pass` inside `ReceiptV1` without domain separation. Now `receipt.output_hash` must equal `SHA256("RECEIPT_OUTCOME_OUTPUT_V1" || [outcome as u8] || raw_output_hash)` while `outlayer_task_meta.output_hash` still binds TDX `report_data[0..32]`.

---

## 6. Breakeven Default Math

Let:
* $A$ = gross advance principal (`principal`, in USD)
* $f$ = flat fee rate (`feeAmount / A`)
* $h$ = provider holdback fraction withheld in the vault until full repayment (`providerHoldbackBps / 10_000`, `5%` in pilot)
* $p$ = per-loan default probability (assuming $0\%$ external recovery beyond seizing the agent's locked holdback bond $h A$)

Per loan cycle:
* With probability $1 - p$: loan repays; lenders earn $+f A$ (holdback $h A$ is returned to the borrower).
* With probability $p$: loan defaults; holdback $h A$ is slashed first, leaving net pool loss $L_{\text{net}} = (1 - h) A$ (borne first by `juniorFirstLossReserve`, then `seniorLiquidityReserve`).

Setting expected lender return to zero:
$$(1 - p) \cdot f A - p \cdot (1 - h) A = 0 \implies p^* = \frac{f}{f + (1 - h)}$$

| Advance Fee $f$ | Breakeven Default Rate $p^*$ ($h = 0\%$) | Breakeven Default Rate $p^*$ ($h = 5\%$) | $A = \$5$ Max Net Loss ($h = 5\%$) | $A = \$50$ Max Net Loss ($h = 5\%$) | $A = \$250$ Max Net Loss ($h = 5\%$) |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **1.0%** | `0.99%` | `1.04%` | `$4.75` (`$0.05` fee) | `$47.50` (`$0.50` fee) | `$237.50` (`$2.50` fee) |
| **2.0%** *(pilot)* | `1.96%` | **`2.06%`** | **`$4.75`** (`$0.10` fee) | `$47.50` (`$1.00` fee) | `$237.50` (`$5.00` fee) |
| **3.0%** | `2.91%` | `3.06%` | `$4.75` (`$0.15` fee) | `$47.50` (`$1.50` fee) | `$237.50` (`$7.50` fee) |
| **5.0%** | `4.76%` | `5.00%` | `$4.75` (`$0.25` fee) | `$47.50` (`$2.50` fee) | `$237.50` (`$12.50` fee) |

With `juniorFirstLossReserve = $50` (`$5` cap, $h = 5\%$), junior LP capital absorbs $\lfloor 50 / 4.75 \rfloor = 10$ simultaneous full `$5` defaults (after holdbacks) before senior LP capital sees \$1 of principal impairment. Because `minFirstLossCoverageBps = 15%`, junior reserve must stay above `15%` of `totalActivePrincipal` before any new `drawCredit` succeeds.
