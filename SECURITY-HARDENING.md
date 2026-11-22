# Security Hardening Report (`hardening-post-submission`)

The original hackathon submission is preserved unmodified on [`main`](https://github.com/Johnlocke0347/Receipt/tree/main) and tag [`submitted-v1`](https://github.com/Johnlocke0347/Receipt/tree/submitted-v1) at commit `b55fedf1929d3ced523b9fa51f33119216834625` (the tag was corrected from `92deb5d69c8fca1f5aa1b0a38833f0223ca96ef7`).

This document records the four post-submission security vulnerabilities identified in `submitted-v1`, their exact fixes on branch `hardening-post-submission`, the committing SHA-1 hashes, and the negative regression tests (including failing runs with each fix temporarily omitted and passing runs with the fix restored).

---

## Summary Table

| # | Vulnerability (`submitted-v1`) | Fix Summary | Commit Hash | Proving Tests |
| :- | :--- | :--- | :--- | :--- |
| 1 | Unbound borrower & credit limit (`authorize_loan` accepted arbitrary borrower EVM address & principal) | Bound `borrower_evm_address` and `max_credit_principal` into `ReceiptSigningPayloadV1` / `ReceiptV1`, validated non-zero on registration, enforced equality/cap in `authorize_loan` | [`210fd3600c27d67696eaa76c628609ff19a3ccc2`](https://github.com/Johnlocke0347/Receipt/commit/210fd3600c27d67696eaa76c628609ff19a3ccc2) | `signing::tests::tampered_borrower_or_credit_limit_rejected_by_signature`, `tests::authorize_loan_rejects_mismatched_borrower_address`, `tests::authorize_loan_rejects_principal_exceeding_receipt_credit_limit` |
| 2 | Permissionless `authorize_loan` caller (any NEAR account could lock a `RegisteredVerified` receipt) | Enforced `rt::predecessor_account_id().as_str() == receipt.provider_identity` inside `authorize_loan_internal` | [`54d0a3730824aa91866133ca8ee19964ba4c1ab7`](https://github.com/Johnlocke0347/Receipt/commit/54d0a3730824aa91866133ca8ee19964ba4c1ab7) | `tests::authorize_loan_rejects_non_provider_caller` (plus verified failing run when guard omitted) |
| 3 | Reusable OutLayer TDX quote `task_id` across incrementing `nonce` values | Added `consumed_task_ids: BTreeSet<u64>` replay guard + `is_task_id_consumed` view in `ReceiptRegistry` | [`04322dd8f31bf2655a92af1c15cc29f01401c4c2`](https://github.com/Johnlocke0347/Receipt/commit/04322dd8f31bf2655a92af1c15cc29f01401c4c2) | `tests::replayed_quote_task_id_with_fresh_nonce_rejected` |
| 4 | Outcome (`Pass`/`Fail`) not cryptographically committed into `receipt.output_hash` | Added `hashing::enclave_output_hash(outcome, raw_enclave_output_hash)` (`RECEIPT_OUTCOME_OUTPUT_V1`) and enforced it in `register_receipt` | [`e3e6535b695c024a66a576fff204c6cb3013f9d2`](https://github.com/Johnlocke0347/Receipt/commit/e3e6535b695c024a66a576fff204c6cb3013f9d2) | `hashing::tests::outcome_changes_enclave_output_hash`, `tests::fail_committed_enclave_output_hash_rejected_when_claiming_pass` |

*(Apache-2.0 `LICENSE` added prior to hardening fixes in [`c8d3e9ac7dcad2df1f6342a03d3eee6808748ff2`](https://github.com/Johnlocke0347/Receipt/commit/c8d3e9ac7dcad2df1f6342a03d3eee6808748ff2); `Cargo.toml`, `pyproject.toml`, and Solidity SPDX headers aligned to `Apache-2.0` in [`4df2e5be9b834c8d63287468dbda8d6c2b166638`](https://github.com/Johnlocke0347/Receipt/commit/4df2e5be9b834c8d63287468dbda8d6c2b166638).)*

---

## Vulnerability Details

### 1. Unbound Borrower EVM Address & Credit Limit
- **Hole in `submitted-v1`:** `ReceiptSigningPayloadV1` and `ReceiptV1` did not carry the authorized borrower address or maximum loan amount. `ReceiptRegistry::authorize_loan` accepted arbitrary `borrower_evm_address_hex` and `principal_amount` from the caller without validating against co-signed commercial credit bounds.
- **Fix (`210fd3600c27d67696eaa76c628609ff19a3ccc2`):**
  - Added `borrower_evm_address: [u8; 20]` and `max_credit_principal: u128` to both `ReceiptSigningPayloadV1` and `ReceiptV1` (`crates/receipt-core/src/receipt.rs`) and `ReceiptParams` (`crates/receipt-core/src/signing.rs`).
  - Rejected zero borrower address or zero credit limit inside `ReceiptV1::validate_structure`.
  - Enforced `borrower == receipt.borrower_evm_address` and `principal <= receipt.max_credit_principal` inside `ReceiptRegistry::authorize_loan_internal` (`crates/near-receipt-registry/src/lib.rs`).
- **Proving Tests:**
  - `receipt_core::signing::tests::tampered_borrower_or_credit_limit_rejected_by_signature`
  - `near_receipt_registry::tests::authorize_loan_rejects_mismatched_borrower_address`
  - `near_receipt_registry::tests::authorize_loan_rejects_principal_exceeding_receipt_credit_limit`
- **Observed Failing Run Without Fix (`authorize_loan_internal` borrower/limit guards removed):**
  ```text
  running 1 test
  test tests::authorize_loan_rejects_mismatched_borrower_address - should panic ... FAILED

  failures:

  ---- tests::authorize_loan_rejects_mismatched_borrower_address stdout ----
  note: test did not panic as expected at crates/near-receipt-registry/src/lib.rs:1969:8

  failures:
      tests::authorize_loan_rejects_mismatched_borrower_address

  test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.08s
  ```
  ```text
  running 1 test
  test tests::authorize_loan_rejects_principal_exceeding_receipt_credit_limit - should panic ... FAILED

  failures:

  ---- tests::authorize_loan_rejects_principal_exceeding_receipt_credit_limit stdout ----
  note: test did not panic as expected at crates/near-receipt-registry/src/lib.rs:1989:8

  failures:
      tests::authorize_loan_rejects_principal_exceeding_receipt_credit_limit

  test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.08s
  ```
- **Observed Passing Run With Fix Restored:**
  ```text
  running 1 test

  thread 'tests::authorize_loan_rejects_mismatched_borrower_address' (3992) panicked at crates/near-receipt-registry/src/lib.rs:270:9:
  borrower_evm_address does not match co-signed receipt.borrower_evm_address
  note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
  test tests::authorize_loan_rejects_mismatched_borrower_address - should panic ... ok

  test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.07s
  ```
  ```text
  running 1 test

  thread 'tests::authorize_loan_rejects_principal_exceeding_receipt_credit_limit' (18756) panicked at crates/near-receipt-registry/src/lib.rs:270:9:
  principal_amount exceeds co-signed receipt.max_credit_principal
  note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
  test tests::authorize_loan_rejects_principal_exceeding_receipt_credit_limit - should panic ... ok

  test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.07s
  ```

### 2. Missing Provider Authorization on `authorize_loan`
- **Hole in `submitted-v1`:** `ReceiptRegistry::authorize_loan_internal` did not inspect `rt::predecessor_account_id()`. Any third-party account on NEAR could call `authorize_loan` on a `RegisteredVerified` receipt, locking `consequence_state` to `LoanAuthorized` (griefing / front-running loan terms such as `deadline`).
- **Fix (`54d0a3730824aa91866133ca8ee19964ba4c1ab7`):**
  - Enforced `if rt::predecessor_account_id().as_str() != receipt.provider_identity { rt::panic_str("only receipt.provider_identity may call authorize_loan"); }` in `crates/near-receipt-registry/src/lib.rs`.
- **Proving Test:** `near_receipt_registry::tests::authorize_loan_rejects_non_provider_caller`
- **Observed Failing Run Without Fix:**
  Running `cargo test -p near-receipt-registry authorize_loan_rejects_non_provider_caller -- --nocapture` before adding the guard failed as expected because `attacker.testnet` was allowed to authorize the loan:
  ```text
  running 1 test
  test tests::authorize_loan_rejects_non_provider_caller - should panic ... FAILED

  failures:

  ---- tests::authorize_loan_rejects_non_provider_caller stdout ----
  note: test did not panic as expected at crates/near-receipt-registry/src/lib.rs:1983:8

  failures:
      tests::authorize_loan_rejects_non_provider_caller

  test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.09s
  ```
- **Observed Passing Run With Fix:**
  ```text
  running 1 test

  thread 'tests::authorize_loan_rejects_non_provider_caller' (11600) panicked at crates/near-receipt-registry/src/lib.rs:270:9:
  only receipt.provider_identity may call authorize_loan
  note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
  test tests::authorize_loan_rejects_non_provider_caller - should panic ... ok

  test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.09s
  ```

### 3. Quote `task_id` Replay Across Fresh Nonces
- **Hole in `submitted-v1`:** `ReceiptRegistry::register_receipt` enforced `(provider_pubkey, nonce)` uniqueness, but did not track consumed OutLayer `task_id` values. Re-signing new receipts with `nonce = 2, 3, ...` allowed a single genuine OutLayer TDX quote (`task_id`) to register multiple independent receipts.
- **Fix (`04322dd8f31bf2655a92af1c15cc29f01401c4c2`):**
  - Added `pub consumed_task_ids: BTreeSet<u64>` to `ReceiptRegistry` state (`crates/near-receipt-registry/src/lib.rs`).
  - Rejected duplicate `outlayer_task_meta.task_id` before registration and inserted `task_id` upon successful registration, exposed via `is_task_id_consumed(task_id)`.
- **Proving Test:** `near_receipt_registry::tests::replayed_quote_task_id_with_fresh_nonce_rejected`
- **Observed Failing Run Without Fix (`consumed_task_ids` check removed):**
  ```text
  running 1 test
  test tests::replayed_quote_task_id_with_fresh_nonce_rejected - should panic ... FAILED

  failures:

  ---- tests::replayed_quote_task_id_with_fresh_nonce_rejected stdout ----
  note: test did not panic as expected at crates/near-receipt-registry/src/lib.rs:2029:8

  failures:
      tests::replayed_quote_task_id_with_fresh_nonce_rejected

  test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.13s
  ```
- **Observed Passing Run With Fix Restored:**
  ```text
  running 1 test

  thread 'tests::replayed_quote_task_id_with_fresh_nonce_rejected' (10468) panicked at crates/near-receipt-registry/src/lib.rs:270:9:
  outlayer task_id 1500 already consumed by a registered receipt
  note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
  test tests::replayed_quote_task_id_with_fresh_nonce_rejected - should panic ... ok

  test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.10s
  ```

### 4. Uncommitted Enclave Outcome in `output_hash`
- **Hole in `submitted-v1`:** `ReceiptRegistry::register_receipt` required `receipt.outcome == WorkOutcome::Pass` and `receipt.output_hash == outlayer_task_meta.output_hash`, but did not domain-commit the `WorkOutcome` into `receipt.output_hash`. Colluding parties could wrap a `Fail`-derived output hash into a `Pass` receipt.
- **Fix (`e3e6535b695c024a66a576fff204c6cb3013f9d2`):**
  - Added `enclave_output_hash(outcome, raw_enclave_output_hash) = SHA256("RECEIPT_OUTCOME_OUTPUT_V1" || [outcome as u8] || raw_enclave_output_hash)` in `crates/receipt-core/src/hashing.rs`.
  - Verified inside `ReceiptRegistry::register_receipt` that `receipt.output_hash == enclave_output_hash(receipt.outcome, &outlayer_task_meta.output_hash)` while `task_meta.output_hash` remains bound directly inside TDX `report_data[0..32]`.
- **Proving Tests:**
  - `receipt_core::hashing::tests::outcome_changes_enclave_output_hash`
  - `near_receipt_registry::tests::fail_committed_enclave_output_hash_rejected_when_claiming_pass`
- **Observed Failing Run Without Fix (`expected_output_hash` commitment check removed):**
  ```text
  running 1 test
  test tests::fail_committed_enclave_output_hash_rejected_when_claiming_pass - should panic ... FAILED

  failures:

  ---- tests::fail_committed_enclave_output_hash_rejected_when_claiming_pass stdout ----
  note: test did not panic as expected at crates/near-receipt-registry/src/lib.rs:2074:8

  failures:
      tests::fail_committed_enclave_output_hash_rejected_when_claiming_pass

  test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.20s
  ```
- **Observed Passing Run With Fix Restored:**
  ```text
  running 1 test

  thread 'tests::fail_committed_enclave_output_hash_rejected_when_claiming_pass' (5440) panicked at crates/near-receipt-registry/src/lib.rs:270:9:
  receipt.output_hash does not commit receipt.outcome into outlayer_task_meta.output_hash
  note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
  test tests::fail_committed_enclave_output_hash_rejected_when_claiming_pass - should panic ... ok

  test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.11s
  ```

---

## OutLayer Verifier Integration Status

See [`docs/OUTLAYER_TODO.md`](./docs/OUTLAYER_TODO.md) for the live FastFS `wasm32-wasip1` execution evidence (`request_id: 106387`, `task_id: 302974`) and documented blockers on `GitHub` source compilation, `wasm32-wasip2` component instantiation, and custody API payment keys.
