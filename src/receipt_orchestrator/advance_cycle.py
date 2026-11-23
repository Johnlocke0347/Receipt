"""End-to-end live testnet x402 revenue-advance cycle for RECEIPT.

Runs on NEAR Testnet + Base Sepolia (MockCreditUSDC) against a dedicated
deployment profile (`advance_flow_v3`), leaving `submission-2026-11-14` and
`hardening_v2` untouched:

1. Deploy `near_receipt_registry.wasm`, sync OutLayer measurements, set policy
   (`fixed_advance_cap = $5`, `min_distinct_payers = 2`).
2. Deploy `ReceiptCreditVault` (hard cap `$5`, 5% holdback, 15% junior reserve,
   40% junior fee yield), fund first-loss + senior pools, and deploy a
   vault-controlled `AgentPayoutProxy` for the borrower agent.
3. Execute `acceptance-verifier-wasm` twice via OutLayer (`wasm32-wasip1`) and
   register two co-signed `ReceiptV1` records from distinct independent buyers.
4. BORROW: `authorize_loan` -> Base Sepolia `drawCredit` -> `verify_loan_consequence`.
5. EARN: settle incoming x402 mcUSDC directly into the agent's `AgentPayoutProxy`.
6. REPAY AT SOURCE: `sweepAgentPayout` skims principal + fee before forwarding
   residual + holdback bond to the agent -> NEAR `verify_loan_repayment`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import httpx
import nacl.signing
from dotenv import dotenv_values

from receipt_orchestrator.demo_e2e import (
    BASE_SEPOLIA_CHAIN_ID,
    DEPLOYMENTS_CONFIG_PATH,
    MOCK_USDC_BIN_PATH,
    OUTLAYER_API_BASE,
    OUTLAYER_WASIP1_WASM_HASH,
    OUTLAYER_WASIP1_WASM_URL,
    REPO_ROOT,
    VAULT_BIN_PATH,
    WASM_REGISTRY_PATH,
    abi_word_address,
    abi_word_uint,
    borsh_str,
    derive_evm_address_from_privkey,
    ensure_near_account,
    evm_rpc_call,
    keccak256,
    near_deploy_wasm,
    near_function_call,
    near_view_call,
    selector,
    sign_and_send_evm_tx,
)

DEFAULT_ADVANCE_REGISTRY_ACCOUNT = "receipt-advance-20261123.testnet"
ADVANCE_CHECKPOINT_PATH = REPO_ROOT / "artifacts" / "advance_cycle_checkpoint.json"
OPT_WASM_REGISTRY_PATH = WASM_REGISTRY_PATH.with_name("near_receipt_registry_opt.wasm")


def resolve_registry_wasm_path() -> tuple[Path, bool]:
    """Return `(wasm_path, is_optimized)`, preferring `near_receipt_registry_opt.wasm`."""
    if OPT_WASM_REGISTRY_PATH.exists():
        return OPT_WASM_REGISTRY_PATH, True
    if WASM_REGISTRY_PATH.exists():
        return WASM_REGISTRY_PATH, False
    raise FileNotFoundError(
        f"Missing compiled NEAR registry WASM at {WASM_REGISTRY_PATH}. "
        "Run `uv run python scripts/build_registry_wasm.py` or "
        "`cargo build --release -p near-receipt-registry --target wasm32-unknown-unknown`."
    )


def load_advance_checkpoint(path: Path = ADVANCE_CHECKPOINT_PATH) -> dict[str, Any]:
    """Load persisted live cycle checkpoint state if present."""
    if not path.exists():
        return {}
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def save_advance_checkpoint(
    state: dict[str, Any], path: Path = ADVANCE_CHECKPOINT_PATH
) -> None:
    """Persist live cycle checkpoint state atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def compute_job_settlement_commitment(attested_revenue: int, label: str) -> bytes:
    """Derive a salted 32-byte confidential settlement commitment."""
    intent_id = hashlib.sha256(f"RECEIPT_ADVANCE_INTENT_{label}".encode()).digest()
    currency_hash = hashlib.sha256(b"mcUSDC:base-sepolia:84532").digest()
    buyer_salt = hashlib.sha256(f"RECEIPT_ADVANCE_SALT_{label}".encode()).digest()
    return hashlib.sha256(
        b"RECEIPT_CONFIDENTIAL_V1"
        + intent_id
        + attested_revenue.to_bytes(16, "little")
        + currency_hash
        + buyer_salt
    ).digest()


def execute_outlayer_job(
    caller_account: str,
    near_priv_key: str,
    job_label: str,
    attested_revenue: int,
) -> tuple[str, dict[str, Any]]:
    """Run our FastFS `acceptance-verifier-wasm` live inside OutLayer Intel TDX."""
    settlement_hex = compute_job_settlement_commitment(attested_revenue, job_label).hex()
    job_spec_hex = hashlib.sha256(f"RECEIPT_ADVANCE_JOB_{job_label}".encode()).hexdigest()
    test_suite_hex = hashlib.sha256(f"RECEIPT_ADVANCE_SUITE_{job_label}".encode()).hexdigest()
    input_data = json.dumps(
        {
            "job_spec_commitment": job_spec_hex,
            "confidential_settlement_commitment": settlement_hex,
            "deliverable_payload": {
                "audit_findings": [{"id": 1, "sev": "low", "job": job_label}],
                "invariants_checked": 12,
                "test_suite_digest": test_suite_hex,
                "deterministic_score": 98,
            },
            "acceptance_rules": {
                "min_invariants": 10,
                "required_test_digest": test_suite_hex,
                "min_score": 90,
            },
        },
        separators=(",", ":"),
    )
    args = {
        "source": {
            "WasmUrl": {
                "url": OUTLAYER_WASIP1_WASM_URL,
                "hash": OUTLAYER_WASIP1_WASM_HASH,
                "build_target": "wasm32-wasip1",
            }
        },
        "resource_limits": {
            "max_instructions": 1_000_000_000,
            "max_memory_mb": 128,
            "max_execution_seconds": 60,
        },
        "input_data": input_data,
        "response_format": "Json",
    }
    exec_tx, outcome = near_function_call(
        caller_account,
        near_priv_key,
        "outlayer.testnet",
        "request_execution",
        args,
        gas=300_000_000_000_000,
        deposit=50_000_000_000_000_000_000_000,
    )
    status = outcome.get("status", {})
    sv_b64 = status.get("SuccessValue") if isinstance(status, dict) else None
    if not isinstance(sv_b64, str) or not sv_b64:
        raise RuntimeError(f"OutLayer execution produced no output ({job_label}): {outcome}")
    sv_bytes = base64.b64decode(sv_b64)
    ver_out = cast(dict[str, Any], json.loads(sv_bytes.decode("utf-8")))
    if ver_out.get("outcome") != "PASS":
        raise RuntimeError(f"OutLayer returned non-PASS ({job_label}): {ver_out}")

    req_id: int | None = None
    for receipt_out in outcome.get("receipts_outcome", []):
        for log_entry in receipt_out.get("outcome", {}).get("logs", []):
            if "execution_requested" in log_entry:
                ev = json.loads(log_entry.removeprefix("EVENT_JSON:"))
                req_data = json.loads(ev["data"][0]["request_data"])
                req_id = int(req_data["request_id"])
    if req_id is None:
        raise RuntimeError(f"Missing OutLayer request_id in tx {exec_tx}")

    attestation: dict[str, Any] | None = None
    for _ in range(25):
        resp = httpx.get(f"{OUTLAYER_API_BASE}/attestations/by-request/{req_id}", timeout=15.0)
        if resp.status_code == 200:
            attestation = cast(dict[str, Any], resp.json())
            break
        time.sleep(2.0)
    if attestation is None:
        raise RuntimeError(f"Timed out waiting for OutLayer attestation req_id={req_id}")
    if attestation.get("wasm_hash") != OUTLAYER_WASIP1_WASM_HASH:
        raise RuntimeError(f"Unexpected wasm_hash: {attestation.get('wasm_hash')}")
    if attestation.get("output_hash") != hashlib.sha256(sv_bytes).hexdigest():
        raise RuntimeError("Attestation output_hash mismatch")
    return exec_tx, attestation


def build_signed_revenue_receipt(
    *,
    attestation: dict[str, Any],
    provider_identity: str,
    registry_account_id: str,
    nonce: int,
    borrower_evm: str,
    max_credit_principal: int,
    attested_revenue: int,
    buyer_seed: bytes,
    provider_seed: bytes,
    job_label: str,
) -> tuple[dict[str, Any], list[int], dict[str, Any]]:
    """Construct canonical hardened `ReceiptV1` with `attested_revenue`, quote bytes, and meta."""
    quote_bytes = base64.b64decode(attestation["tdx_quote"].strip())
    mrtd = quote_bytes[184:232]
    rtmrs = quote_bytes[376:568]
    verifier_measurement = hashlib.sha256(mrtd + rtmrs).digest()

    wasm_hash = bytes.fromhex(attestation["wasm_hash"])
    input_hash = bytes.fromhex(attestation["input_hash"])
    raw_output_hash = bytes.fromhex(attestation["output_hash"])
    committed_output_hash = hashlib.sha256(
        b"RECEIPT_OUTCOME_OUTPUT_V1" + b"\x01" + raw_output_hash
    ).digest()
    settlement_commitment = compute_job_settlement_commitment(attested_revenue, job_label)
    evidence_commitment = hashlib.sha256(
        b"RECEIPT_EVIDENCE_V1"
        + wasm_hash
        + input_hash
        + committed_output_hash
        + settlement_commitment
    ).digest()
    receipt_id_bytes = hashlib.sha256(
        b"RECEIPT_ID_V1"
        + provider_identity.encode("utf-8")
        + struct.pack("<Q", nonce)
        + evidence_commitment
    ).digest()

    borrower_bytes = bytes.fromhex(borrower_evm.removeprefix("0x"))
    if len(borrower_bytes) != 20:
        raise ValueError(f"Expected 20-byte borrower address, got {len(borrower_bytes)}")

    buyer_sk = nacl.signing.SigningKey(buyer_seed)
    provider_sk = nacl.signing.SigningKey(provider_seed)
    buyer_pk = bytes(buyer_sk.verify_key)
    provider_pk = bytes(provider_sk.verify_key)
    created_at = int(attestation["timestamp"])

    signing_body = bytearray()
    signing_body += receipt_id_bytes
    signing_body += struct.pack("<H", 1)
    signing_body += borsh_str(provider_identity)
    signing_body += borsh_str("ai_acceptance_validation")
    signing_body += b"\x01"
    signing_body += verifier_measurement
    signing_body += wasm_hash
    signing_body += input_hash
    signing_body += committed_output_hash
    signing_body += evidence_commitment
    signing_body += buyer_pk
    signing_body += provider_pk
    signing_body += struct.pack("<Q", nonce)
    signing_body += struct.pack("<Q", created_at)
    signing_body += settlement_commitment
    signing_body += borrower_bytes
    signing_body += max_credit_principal.to_bytes(16, "little")
    signing_body += attested_revenue.to_bytes(16, "little")

    chain_prefix = borsh_str("testnet") + borsh_str(registry_account_id)
    buyer_digest = hashlib.sha256(
        b"NEAR_RECEIPT_BUYER_SIG_V1" + chain_prefix + bytes(signing_body)
    ).digest()
    provider_digest = hashlib.sha256(
        b"NEAR_RECEIPT_PROVIDER_SIG_V1" + chain_prefix + bytes(signing_body)
    ).digest()

    receipt_dict: dict[str, Any] = {
        "receipt_id": receipt_id_bytes.hex(),
        "schema_version": 1,
        "provider_identity": provider_identity,
        "work_category": "ai_acceptance_validation",
        "outcome": "Pass",
        "verifier_measurement": verifier_measurement.hex(),
        "wasm_hash": wasm_hash.hex(),
        "input_hash": input_hash.hex(),
        "output_hash": committed_output_hash.hex(),
        "evidence_commitment": evidence_commitment.hex(),
        "buyer_pubkey": buyer_pk.hex(),
        "provider_pubkey": provider_pk.hex(),
        "buyer_signature": buyer_sk.sign(buyer_digest).signature.hex(),
        "provider_signature": provider_sk.sign(provider_digest).signature.hex(),
        "nonce": nonce,
        "created_at": created_at,
        "confidential_settlement_commitment": settlement_commitment.hex(),
        "borrower_evm_address": borrower_bytes.hex(),
        "max_credit_principal": max_credit_principal,
        "attested_revenue": attested_revenue,
        "consequence_state": "RegisteredVerified",
        "foreign_chain_id": None,
        "foreign_tx_hash": None,
        "lender_id": None,
        "verified_finality_evidence": None,
    }
    task_meta: dict[str, Any] = {
        "task_type": attestation["task_type"],
        "task_id": int(attestation["task_id"]),
        "repo": attestation.get("repo_url"),
        "commit": attestation.get("commit_hash"),
        "build_target": attestation.get("build_target"),
        "wasm_hash": wasm_hash.hex(),
        "input_hash": input_hash.hex(),
        "output_hash": raw_output_hash.hex(),
        "block_height": attestation.get("block_height"),
        "caller_account_id": attestation.get("caller_account_id"),
        "project_id": attestation.get("project_id"),
        "secrets_ref": attestation.get("secrets_ref"),
        "timestamp": created_at,
        "attached_usd": attestation.get("attached_usd"),
    }
    return receipt_dict, list(quote_bytes), task_meta


def _format_expected_evm_log(raw_log: dict[str, Any]) -> dict[str, Any]:
    return {
        "removed": bool(raw_log.get("removed", False)),
        "log_index": int(raw_log["logIndex"], 16),
        "transaction_index": int(raw_log["transactionIndex"], 16),
        "transaction_hash": raw_log["transactionHash"].removeprefix("0x").lower(),
        "block_hash": raw_log["blockHash"].removeprefix("0x").lower(),
        "block_number": int(raw_log["blockNumber"], 16),
        "address": raw_log["address"].removeprefix("0x").lower(),
        "data": raw_log["data"].lower(),
        "topics": [t.removeprefix("0x").lower() for t in raw_log["topics"]],
    }


def _eth_call_word(rpc_url: str, to_addr: str, calldata: bytes) -> bytes:
    params: list[Any] = [{"to": to_addr, "data": "0x" + calldata.hex()}, "latest"]
    res_hex = cast(str, evm_rpc_call(rpc_url, "eth_call", params))
    return bytes.fromhex(res_hex.removeprefix("0x"))


def _poll_near_view(
    account_id: str,
    method: str,
    args: dict[str, Any],
    predicate: Callable[[object], bool],
    timeout_iters: int = 18,
) -> object:
    last: object = None
    for _ in range(timeout_iters):
        last = near_view_call(account_id, method, args)
        if predicate(last):
            return last
        time.sleep(2.0)
    raise RuntimeError(f"Timed out waiting on NEAR view {method}({args}): last={last}")


def _record_deployment_profile(state: dict[str, Any], registry_account: str) -> None:
    if not DEPLOYMENTS_CONFIG_PATH.exists():
        return
    raw = cast(dict[str, Any], json.loads(DEPLOYMENTS_CONFIG_PATH.read_text(encoding="utf-8")))
    deployments = cast(dict[str, Any], raw.setdefault("deployments", {}))
    deployments["advance_flow_v3"] = {
        "description": (
            "Revenue-advance pilot with AgentPayoutProxy sweep, 1.5x trailing 14d cap, "
            "2 distinct-buyer requirement, $5 hard cap, 3-tier first-loss pool, and MPC repayment"
        ),
        "git_branch": "advance-flow",
        "near_network": "testnet",
        "near_registry_account": registry_account,
        "outlayer_worker_account": "worker.outlayer.testnet",
        "mpc_signer_account": "v1.signer-prod.testnet",
        "evm_network": "base-sepolia",
        "evm_chain_id": BASE_SEPOLIA_CHAIN_ID,
        "derived_mpc_evm_signer": state["authorized_signer_evm"],
        "credit_token_address": state["mock_usdc_address"],
        "credit_token_symbol": "mcUSDC",
        "vault_address": state["vault_address"],
        "agent_payout_proxy_address": state["payout_proxy_address"],
        "evidence_tx": {
            "outlayer_execution_1": state["job1_outlayer_tx"],
            "outlayer_execution_2": state["job2_outlayer_tx"],
            "register_receipt_1": state["job1_register_tx"],
            "register_receipt_2": state["job2_register_tx"],
            "authorize_loan": state["borrow_authorize_tx"],
            "draw_credit": state["borrow_draw_tx"],
            "verify_loan_consequence": state["borrow_verify_tx"],
            "x402_earn_transfer": state["earn_transfer_tx"],
            "sweep_agent_payout": state["repay_sweep_tx"],
            "verify_loan_repayment": state["repay_verify_tx"],
        },
    }
    DEPLOYMENTS_CONFIG_PATH.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def run_advance_cycle(
    *,
    near_priv_key: str,
    registry_account: str,
    base_rpc_url: str,
    base_priv_key: str,
    token_override: str = "",
    wasm_path: Path | None = None,
    checkpoint_path: Path = ADVANCE_CHECKPOINT_PATH,
    update_deployments: bool = True,
) -> dict[str, Any]:
    """Execute the full live testnet borrow -> earn -> repay cycle and print all tx hashes."""
    if not (near_priv_key and base_rpc_url and base_priv_key):
        raise RuntimeError(
            "Missing NEAR_PRIVATE_KEY, BASE_SEPOLIA_RPC_URL, or BASE_SEPOLIA_PRIVATE_KEY"
        )

    def _save(cur: dict[str, Any]) -> None:
        save_advance_checkpoint(cur, checkpoint_path)

    ensure_near_account(registry_account, near_priv_key)
    borrower_evm = derive_evm_address_from_privkey(base_priv_key)
    state = load_advance_checkpoint(checkpoint_path)

    print("=== RECEIPT LIVE X402 ADVANCE CYCLE (BORROW -> EARN -> REPAY) ===", flush=True)
    print(f"NEAR Registry (new) : {registry_account}", flush=True)
    print(f"Agent / Deployer EOA: {borrower_evm} (Base Sepolia)", flush=True)

    # 1. Deploy NEAR ReceiptRegistry, sync TDX measurements, configure $5 cap & min 2 payers
    if not state.get("step1_deploy_wasm_tx"):
        resolved_wasm, _ = resolve_registry_wasm_path() if wasm_path is None else (wasm_path, False)
        state["step1_deploy_wasm_tx"] = near_deploy_wasm(
            registry_account, near_priv_key, resolved_wasm.read_bytes()
        )
        _save(state)

    if not state.get("step1_init_tx"):
        try:
            _ = near_view_call(registry_account, "approved_measurements_count", {})
            state["step1_init_tx"] = "already_initialized"
        except RuntimeError:
            init_tx, _ = near_function_call(
                registry_account,
                near_priv_key,
                registry_account,
                "new",
                {
                    "owner": registry_account,
                    "mpc_signer_account": "v1.signer-prod.testnet",
                    "configured_base_vault_hex": None,
                },
                gas=30_000_000_000_000,
            )
            state["step1_init_tx"] = init_tx
        _save(state)

    if not state.get("step1_sync_tx"):
        sync_tx, _ = near_function_call(
            registry_account,
            near_priv_key,
            registry_account,
            "sync_approved_measurements",
            {},
            gas=100_000_000_000_000,
        )
        state["step1_sync_tx"] = sync_tx
        _save(state)

    if not state.get("step1_policy_tx"):
        pol_tx, _ = near_function_call(
            registry_account,
            near_priv_key,
            registry_account,
            "set_underwriting_policy",
            {"fixed_advance_cap": "5000000", "min_distinct_payers": 2},
            gas=30_000_000_000_000,
        )
        state["step1_policy_tx"] = pol_tx
        _save(state)

    onchain_signer = cast(
        str, near_view_call(registry_account, "derive_vault_authorized_signer_evm_address", {})
    )
    print(f"[1] NEAR Registry Ready  tx={state['step1_deploy_wasm_tx']}", flush=True)

    # 2. Deploy MockCreditUSDC (or use config override), ReceiptCreditVault, LP pools, PayoutProxy
    if not state.get("step2_deploy_usdc_tx"):
        if token_override:
            state["step2_deploy_usdc_tx"] = "configured_external_token"
            state["mock_usdc_address"] = token_override
        else:
            usdc_bin = bytes.fromhex(MOCK_USDC_BIN_PATH.read_text(encoding="utf-8").strip())
            usdc_tx, usdc_rcpt = sign_and_send_evm_tx(
                base_rpc_url,
                base_priv_key,
                None,
                usdc_bin + abi_word_uint(1_000_000_000_000),
                gas_limit=1_500_000,
            )
            state["step2_deploy_usdc_tx"] = usdc_tx
            state["mock_usdc_address"] = usdc_rcpt["contractAddress"]
        _save(state)
    usdc_address = str(state["mock_usdc_address"])

    if not state.get("step2_deploy_vault_tx"):
        vault_bin = bytes.fromhex(VAULT_BIN_PATH.read_text(encoding="utf-8").strip())
        lender_id_bytes = keccak256(b"RECEIPT_BASE_SEPOLIA_VAULT_V3")
        vault_init = (
            vault_bin
            + abi_word_address(onchain_signer)
            + abi_word_address(usdc_address)
            + lender_id_bytes
            + abi_word_uint(5_000_000)  # hardPerAgentCap = $5.00
            + abi_word_uint(60)  # gracePeriodSecs = 60s
            + abi_word_uint(500)  # providerHoldbackBps = 5%
            + abi_word_uint(1500)  # minFirstLossCoverageBps = 15%
            + abi_word_uint(4000)  # juniorYieldShareBps = 40%
        )
        vault_tx, vault_rcpt = sign_and_send_evm_tx(
            base_rpc_url, base_priv_key, None, vault_init, gas_limit=4_000_000
        )
        state["step2_deploy_vault_tx"] = vault_tx
        state["vault_address"] = vault_rcpt["contractAddress"]
        state["authorized_signer_evm"] = onchain_signer
        _save(state)
    vault_address = str(state["vault_address"])

    if not state.get("step2_near_vault_tx"):
        nv_tx, _ = near_function_call(
            registry_account,
            near_priv_key,
            registry_account,
            "set_configured_base_vault",
            {"vault_address_hex": vault_address.removeprefix("0x")},
            gas=30_000_000_000_000,
        )
        state["step2_near_vault_tx"] = nv_tx
        _save(state)

    if not state.get("step2_approve_tx"):
        app_tx, _ = sign_and_send_evm_tx(
            base_rpc_url,
            base_priv_key,
            usdc_address,
            selector("approve(address,uint256)")
            + abi_word_address(vault_address)
            + abi_word_uint(250_000_000),
            gas_limit=100_000,
        )
        state["step2_approve_tx"] = app_tx
        _save(state)

    if not state.get("step2_first_loss_tx"):
        fl_tx, _ = sign_and_send_evm_tx(
            base_rpc_url,
            base_priv_key,
            vault_address,
            selector("depositFirstLoss(uint256)") + abi_word_uint(50_000_000),
            gas_limit=200_000,
        )
        state["step2_first_loss_tx"] = fl_tx
        _save(state)

    if not state.get("step2_senior_tx"):
        sl_tx, _ = sign_and_send_evm_tx(
            base_rpc_url,
            base_priv_key,
            vault_address,
            selector("depositSeniorLiquidity(uint256)") + abi_word_uint(200_000_000),
            gas_limit=200_000,
        )
        state["step2_senior_tx"] = sl_tx
        _save(state)

    if not state.get("step2_proxy_tx"):
        px_tx, _ = sign_and_send_evm_tx(
            base_rpc_url,
            base_priv_key,
            vault_address,
            selector("deployAgentPayoutProxy(address)") + abi_word_address(borrower_evm),
            gas_limit=800_000,
        )
        proxy_word = _eth_call_word(
            base_rpc_url,
            vault_address,
            selector("agentPayoutProxy(address)") + abi_word_address(borrower_evm),
        )
        state["step2_proxy_tx"] = px_tx
        state["payout_proxy_address"] = "0x" + proxy_word[-20:].hex()
        _save(state)
    proxy_address = str(state["payout_proxy_address"])
    print(
        f"[2] Base Vault + Proxy   token={usdc_address} vault={vault_address} "
        f"proxy={proxy_address}",
        flush=True,
    )

    # 3. Pin wasm hash & run two OutLayer verifications -> register two distinct-buyer receipts
    if not state.get("step3_pin_wasm_tx"):
        pin_tx, _ = near_function_call(
            registry_account,
            near_priv_key,
            registry_account,
            "add_expected_wasm_hash",
            {"wasm_hash_hex": OUTLAYER_WASIP1_WASM_HASH},
            gas=30_000_000_000_000,
        )
        state["step3_pin_wasm_tx"] = pin_tx
        _save(state)

    base_nonce = int(state.get("base_nonce") or int(time.time()))
    state["base_nonce"] = base_nonce
    buyer_seeds = [bytes([0x11] * 32), bytes([0x12] * 32)]
    provider_seed = bytes([0x20] * 32)
    revenue_each = 2_000_000  # $2.00 each -> $4.00 trailing -> 1.5x = $6.00 (capped at $5.00)
    max_credit = 4_000_000  # $4.00 advance requested

    for idx, b_seed in enumerate(buyer_seeds, start=1):
        label = f"job{idx}"
        if not state.get(f"{label}_attestation"):
            out_tx, att = execute_outlayer_job(registry_account, near_priv_key, label, revenue_each)
            state[f"{label}_outlayer_tx"] = out_tx
            state[f"{label}_attestation"] = att
            _save(state)
            if idx == 1:
                time.sleep(2.0)

        receipt_dict, quote_list, task_meta = build_signed_revenue_receipt(
            attestation=cast(dict[str, Any], state[f"{label}_attestation"]),
            provider_identity=registry_account,
            registry_account_id=registry_account,
            nonce=base_nonce + idx - 1,
            borrower_evm=borrower_evm,
            max_credit_principal=max_credit,
            attested_revenue=revenue_each,
            buyer_seed=b_seed,
            provider_seed=provider_seed,
            job_label=label,
        )
        state[f"{label}_receipt_id"] = receipt_dict["receipt_id"]
        if not state.get(f"{label}_register_tx"):
            reg_tx, _ = near_function_call(
                registry_account,
                near_priv_key,
                registry_account,
                "register_receipt",
                {
                    "receipt": receipt_dict,
                    "tdx_quote_bytes": quote_list,
                    "outlayer_task_meta": task_meta,
                },
                gas=150_000_000_000_000,
            )
            state[f"{label}_register_tx"] = reg_tx
            _save(state)

    cap_view = cast(
        dict[str, Any],
        near_view_call(
            registry_account,
            "get_trailing_14d_revenue",
            {"provider_identity": registry_account, "as_of_timestamp": None},
        ),
    )
    cap_u128 = str(
        near_view_call(
            registry_account,
            "compute_advance_cap",
            {"provider_identity": registry_account, "as_of_timestamp": None},
        )
    )
    if (
        int(cap_view["distinct_payers"]) < 2
        or int(cap_view["advance_cap"]) < max_credit
        or cap_u128 != str(cap_view["advance_cap"])
    ):
        raise RuntimeError(f"Unexpected trailing revenue cap view: {cap_view} vs {cap_u128}")
    print(
        f"[3] 2 Distinct-Buyer Receipts Registered  distinct_payers={cap_view['distinct_payers']} "
        f"trailing_rev={cap_view['total_revenue']} cap={cap_view['advance_cap']}",
        flush=True,
    )

    target_receipt_id = str(state["job2_receipt_id"])
    principal_amount = 4_000_000  # $4.00
    fee_amount = 80_000  # $0.08 (2%)

    # 4. BORROW: NEAR authorize_loan -> Base Sepolia drawCredit -> NEAR verify_loan_consequence
    if not state.get("borrow_authorize_tx"):
        now_sec = int(time.time())
        auth_tx, _ = near_function_call(
            registry_account,
            near_priv_key,
            registry_account,
            "authorize_loan",
            {
                "receipt_id_hex": target_receipt_id,
                "borrower_evm_address_hex": borrower_evm.removeprefix("0x"),
                "principal_amount": str(principal_amount),
                "fee_amount": str(fee_amount),
                "maturity_at": now_sec + 86400,
                "base_vault_address_hex": vault_address.removeprefix("0x"),
                "deadline": now_sec + 7200,
            },
            gas=150_000_000_000_000,
            deposit=1,
        )
        state["borrow_authorize_tx"] = auth_tx
        _save(state)

    loan_packet = cast(
        dict[str, Any],
        _poll_near_view(
            registry_account,
            "get_loan_authorization",
            {"receipt_id_hex": target_receipt_id},
            lambda x: x is not None,
        ),
    )

    if not state.get("borrow_draw_tx"):
        draw_calldata = (
            selector(
                "drawCredit(bytes32,address,uint256,uint256,uint64,bytes32,uint256,uint8,bytes32,bytes32)"
            )
            + bytes.fromhex(loan_packet["receipt_id"])
            + abi_word_address(loan_packet["borrower_evm_address"])
            + abi_word_uint(int(loan_packet["principal_amount"]))
            + abi_word_uint(int(loan_packet["fee_amount"]))
            + abi_word_uint(int(loan_packet["maturity_at"]))
            + bytes.fromhex(loan_packet["evidence_commitment"])
            + abi_word_uint(int(loan_packet["deadline"]))
            + abi_word_uint(int(loan_packet["signature_v"]))
            + bytes.fromhex(loan_packet["signature_r"])
            + bytes.fromhex(loan_packet["signature_s"])
        )
        draw_tx, draw_rcpt = sign_and_send_evm_tx(
            base_rpc_url, base_priv_key, vault_address, draw_calldata, gas_limit=450_000
        )
        state["borrow_draw_tx"] = draw_tx
        state["borrow_draw_block_hash"] = draw_rcpt["blockHash"]
        state["borrow_draw_log0"] = draw_rcpt["logs"][0]
        _save(state)

    if not state.get("borrow_verify_tx"):
        time.sleep(6.0)
        verify_tx, _ = near_function_call(
            registry_account,
            near_priv_key,
            registry_account,
            "verify_loan_consequence",
            {
                "receipt_id_hex": target_receipt_id,
                "base_tx_hash_hex": str(state["borrow_draw_tx"]).removeprefix("0x"),
                "base_block_hash_hex": str(state["borrow_draw_block_hash"]).removeprefix("0x"),
                "expected_log": _format_expected_evm_log(
                    cast(dict[str, Any], state["borrow_draw_log0"])
                ),
                "finality": "Latest",
            },
            gas=150_000_000_000_000,
            deposit=1,
        )
        state["borrow_verify_tx"] = verify_tx
        _save(state)

    _poll_near_view(
        registry_account,
        "verify_consequence_proof",
        {"receipt_id_hex": target_receipt_id},
        lambda x: isinstance(x, dict) and bool(x.get("is_mpc_consequence_verified")),
    )
    print(
        f"[4] BORROW ($4.00 drawn, $3.80 net / $0.20 bond)  "
        f"auth={state['borrow_authorize_tx']} draw={state['borrow_draw_tx']} "
        f"verify={state['borrow_verify_tx']}",
        flush=True,
    )

    # 5. EARN: x402 revenue ($6.00) settles directly into vault-controlled AgentPayoutProxy
    if not state.get("earn_transfer_tx"):
        earn_tx, _ = sign_and_send_evm_tx(
            base_rpc_url,
            base_priv_key,
            usdc_address,
            selector("transfer(address,uint256)")
            + abi_word_address(proxy_address)
            + abi_word_uint(6_000_000),
            gas_limit=120_000,
        )
        state["earn_transfer_tx"] = earn_tx
        _save(state)
    print(f"[5] EARN ($6.00 x402 USDC -> PayoutProxy)  tx={state['earn_transfer_tx']}", flush=True)

    # 6. REPAY AT SOURCE: sweepAgentPayout -> skim $4.08, release $0.20 bond, forward $2.12 net
    if not state.get("repay_sweep_tx"):
        sweep_tx, sweep_rcpt = sign_and_send_evm_tx(
            base_rpc_url,
            base_priv_key,
            vault_address,
            selector("sweepAgentPayout(address)") + abi_word_address(borrower_evm),
            gas_limit=400_000,
        )
        state["repay_sweep_tx"] = sweep_tx
        state["repay_sweep_block_hash"] = sweep_rcpt["blockHash"]
        state["repay_sweep_log0"] = sweep_rcpt["logs"][0]
        _save(state)

    if not state.get("repay_verify_tx"):
        time.sleep(6.0)
        repay_v_tx, _ = near_function_call(
            registry_account,
            near_priv_key,
            registry_account,
            "verify_loan_repayment",
            {
                "receipt_id_hex": target_receipt_id,
                "base_tx_hash_hex": str(state["repay_sweep_tx"]).removeprefix("0x"),
                "base_block_hash_hex": str(state["repay_sweep_block_hash"]).removeprefix("0x"),
                "expected_log": _format_expected_evm_log(
                    cast(dict[str, Any], state["repay_sweep_log0"])
                ),
                "finality": "Latest",
            },
            gas=150_000_000_000_000,
            deposit=1,
        )
        state["repay_verify_tx"] = repay_v_tx
        _save(state)

    final_receipt = cast(
        dict[str, Any],
        _poll_near_view(
            registry_account,
            "get_receipt",
            {"receipt_id_hex": target_receipt_id},
            lambda x: isinstance(x, dict) and x.get("consequence_state") == "RepaidVerified",
        ),
    )
    encumbered = near_view_call(
        registry_account, "get_active_encumbered_receipt", {"provider_identity": registry_account}
    )
    if encumbered is not None:
        raise RuntimeError(f"Expected encumbrance cleared after repayment, got {encumbered}")

    near_rep = near_view_call(
        registry_account, "get_erc8004_reputation_summary", {"provider_identity": registry_account}
    )
    evm_rep_bytes = _eth_call_word(
        base_rpc_url,
        vault_address,
        selector("getErc8004ReputationSummary(address)") + abi_word_address(borrower_evm),
    )
    evm_count = int.from_bytes(evm_rep_bytes[0:32], "big")
    evm_val = int.from_bytes(evm_rep_bytes[32:64], "big", signed=True)
    evm_dec = int.from_bytes(evm_rep_bytes[64:96], "big")

    if update_deployments:
        _record_deployment_profile(state, registry_account)
    print(
        f"[6] REPAY AT SOURCE ($4.08 skimmed, $2.12 forwarded)  "
        f"sweep={state['repay_sweep_tx']} verify={state['repay_verify_tx']}",
        flush=True,
    )
    print(
        f"[7] Verified Final State:\n"
        f"    consequence_state          = {final_receipt['consequence_state']}\n"
        f"    active_encumbered_receipt  = {encumbered}\n"
        f"    near_erc8004_summary       = {near_rep}\n"
        f"    base_erc8004_summary       = (count={evm_count}, value={evm_val}, "
        f"decimals={evm_dec})",
        flush=True,
    )
    return state


def main() -> None:
    """CLI entrypoint reading `.env` / environment and running the live advance cycle."""
    env = {**dotenv_values(REPO_ROOT / ".env"), **os.environ}
    run_advance_cycle(
        near_priv_key=(env.get("NEAR_PRIVATE_KEY") or "").strip(),
        registry_account=(
            (env.get("NEAR_ADVANCE_REGISTRY_ACCOUNT_ID") or "").strip()
            or DEFAULT_ADVANCE_REGISTRY_ACCOUNT
        ),
        base_rpc_url=(env.get("BASE_SEPOLIA_RPC_URL") or "").strip(),
        base_priv_key=(env.get("BASE_SEPOLIA_PRIVATE_KEY") or "").strip(),
        token_override=(env.get("BASE_CREDIT_TOKEN_ADDRESS") or "").strip(),
    )


if __name__ == "__main__":
    main()
