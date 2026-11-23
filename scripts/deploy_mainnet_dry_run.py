"""DRY-RUN-ONLY mainnet deployment planner & testnet gas estimator for RECEIPT.

Safety guarantees:
1. Requires `--dry-run` explicitly and NEVER accepts or implements live mainnet broadcast.
2. NEVER reads or requests mainnet private keys.
3. Queries ONLY Base Sepolia testnet JSON-RPC (`eth_estimateGas`, `eth_gasPrice`)
   and refuses any Base Mainnet (`8453`) or NEAR Mainnet RPC URL for live RPC probes.
4. Enforces the pilot `$5.00` USDC hard per-agent cap (`5_000_000` minimal 6-decimal units)
   and includes owner pause switch checks on both chains (`pause()` / `set_paused(true)`).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, cast

import httpx
from dotenv import dotenv_values

from receipt_orchestrator.advance_cycle import resolve_registry_wasm_path
from receipt_orchestrator.demo_e2e import (
    BASE_SEPOLIA_CHAIN_ID,
    DEPLOYMENTS_CONFIG_PATH,
    REPO_ROOT,
    VAULT_BIN_PATH,
    abi_word_address,
    abi_word_uint,
    keccak256,
)

HARD_PER_AGENT_CAP_UNITS = 5_000_000  # $5.00 USDC (6 decimals)
DEFAULT_BASE_SEPOLIA_RPC = "https://sepolia.base.org"
DEFAULT_BASE_MAINNET_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
DEFAULT_NEAR_MAINNET_MPC = "v1.signer"


class DryRunGuardError(ValueError):
    """Raised when safety invariants for dry-run-only execution are violated."""


def validate_safety_guards(
    *,
    dry_run: bool,
    testnet_rpc_url: str,
    hard_cap_units: int,
) -> None:
    """Ensure execution stays read-only on testnet with bounded pilot cap."""
    if not dry_run:
        raise DryRunGuardError(
            "Refusing to run without `--dry-run`. Mainnet broadcasting is intentionally disabled."
        )
    lowered = testnet_rpc_url.lower()
    if "mainnet" in lowered or "sepolia" not in lowered:
        raise DryRunGuardError(
            f"Refusing non-testnet estimation RPC URL `{testnet_rpc_url}`. Testnet RPC only."
        )
    if hard_cap_units <= 0 or hard_cap_units > HARD_PER_AGENT_CAP_UNITS:
        raise DryRunGuardError(
            f"Hard per-agent cap must stay within (0, {HARD_PER_AGENT_CAP_UNITS}] "
            f"($5.00 max pilot cap); got {hard_cap_units}."
        )


def load_mainnet_reference() -> dict[str, Any]:
    """Read mainnet reference metadata from config/deployments.json."""
    if not DEPLOYMENTS_CONFIG_PATH.exists():
        return {}
    raw = cast(dict[str, Any], json.loads(DEPLOYMENTS_CONFIG_PATH.read_text(encoding="utf-8")))
    return cast(dict[str, Any], raw.get("mainnet_reference", {}))


def load_testnet_reference_profile() -> dict[str, Any]:
    """Load latest deployed Base Sepolia profile (v3 if present, else v2) for read-only calls."""
    if not DEPLOYMENTS_CONFIG_PATH.exists():
        return {}
    raw = cast(dict[str, Any], json.loads(DEPLOYMENTS_CONFIG_PATH.read_text(encoding="utf-8")))
    deployments = cast(dict[str, Any], raw.get("deployments", {}))
    return cast(
        dict[str, Any],
        deployments.get("advance_flow_v3") or deployments.get("hardening_v2") or {},
    )


def estimate_base_sepolia_deployment(
    *,
    rpc_url: str,
    near_authorized_signer: str,
    credit_token: str,
    hard_cap_units: int,
) -> dict[str, Any]:
    """Run read-only Base Sepolia `eth_chainId`, `eth_gasPrice`, and `eth_estimateGas`."""
    chain_hex = cast(
        str,
        httpx.post(
            rpc_url,
            json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
            timeout=20.0,
        ).json()["result"],
    )
    chain_id = int(chain_hex, 16)
    if chain_id != BASE_SEPOLIA_CHAIN_ID:
        raise DryRunGuardError(f"Expected Base Sepolia chainId 84532, got {chain_id}")

    gas_price_hex = cast(
        str,
        httpx.post(
            rpc_url,
            json={"jsonrpc": "2.0", "id": 2, "method": "eth_gasPrice", "params": []},
            timeout=20.0,
        ).json()["result"],
    )
    gas_price_wei = int(gas_price_hex, 16)

    vault_bin = bytes.fromhex(VAULT_BIN_PATH.read_text(encoding="utf-8").strip())
    lender_id = keccak256(b"RECEIPT_BASE_MAINNET_PILOT_V1")
    deploy_data = (
        vault_bin
        + abi_word_address(near_authorized_signer)
        + abi_word_address(credit_token)
        + lender_id
        + abi_word_uint(hard_cap_units)
        + abi_word_uint(86_400)  # gracePeriodSecs = 24h
        + abi_word_uint(500)  # providerHoldbackBps = 5%
        + abi_word_uint(1500)  # minFirstLossCoverageBps = 15%
        + abi_word_uint(4000)  # juniorYieldShareBps = 40%
    )
    est_resp = httpx.post(
        rpc_url,
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "eth_estimateGas",
            "params": [{"data": "0x" + deploy_data.hex()}],
        },
        timeout=25.0,
    ).json()
    if "error" in est_resp:
        raise RuntimeError(f"Base Sepolia eth_estimateGas failed: {est_resp['error']}")
    deploy_gas = int(est_resp["result"], 16)

    return {
        "estimation_chain_id": chain_id,
        "gas_price_wei": gas_price_wei,
        "vault_deploy_gas": deploy_gas,
        "vault_deploy_eth_at_sepolia_price": (deploy_gas * gas_price_wei) / 1e18,
        "vault_bytecode_bytes": len(vault_bin),
        "deploy_payout_proxy_budget_gas": 400_000,
        "draw_credit_budget_gas": 260_000,
        "sweep_agent_payout_budget_gas": 160_000,
        "pause_switch_budget_gas": 50_000,
    }


def render_dry_run_report(
    *,
    near_registry_target: str,
    near_mpc_signer: str,
    base_token_address: str,
    derived_signer_placeholder: str,
    hard_cap_units: int,
    evm_est: dict[str, Any],
    wasm_bytes: int,
    wasm_filename: str = "near_receipt_registry_opt.wasm",
) -> str:
    """Format exact mainnet commands, safety configuration, and gas estimates."""
    near_storage_yocto = wasm_bytes * 10**19
    near_storage_near = near_storage_yocto / 1e24
    lender_id_hex = "0x" + keccak256(b"RECEIPT_BASE_MAINNET_PILOT_V1").hex()
    init_args = (
        f'{{"owner":"<MAINNET_MULTISIG_OR_OWNER.near>",'
        f'"mpc_signer_account":"{near_mpc_signer}","configured_base_vault_hex":null}}'
    )
    policy_args = f'{{"fixed_advance_cap":"{hard_cap_units}","min_distinct_payers":2}}'
    l2_eth_est = (evm_est["vault_deploy_gas"] * 10_000_000) / 1e18
    sepolia_eth_est = evm_est["vault_deploy_eth_at_sepolia_price"]
    est_cid = evm_est["estimation_chain_id"]
    lines = [
        "=== RECEIPT MAINNET DEPLOYMENT DRY-RUN (NO TRANSACTIONS BROADCAST) ===",
        f"Target NEAR Mainnet Registry : {near_registry_target}",
        f"Target NEAR MPC Signer       : {near_mpc_signer} (v1.signer on mainnet)",
        f"Target Base Mainnet Token    : {base_token_address} (Real USDC, 6 decimals)",
        f"Hard Per-Agent Cap           : {hard_cap_units} units ($5.00 USDC)",
        "Owner Pause Switch           : ReceiptCreditVault::pause() + NEAR set_paused(bool)",
        "",
        f"--- Live Base Sepolia Testnet Gas Estimation (chainId={est_cid}) ---",
        f"Compiled ReceiptCreditVault bytecode : {evm_est['vault_bytecode_bytes']} bytes",
        f"Estimated ReceiptCreditVault deploy  : {evm_est['vault_deploy_gas']} gas",
        f"Testnet observed gasPrice            : {evm_est['gas_price_wei']} wei",
        f"Cost at Base Sepolia gasPrice        : {sepolia_eth_est:.8f} ETH",
        f"Cost @ 0.01 gwei L2 gas              : {l2_eth_est:.6f} ETH",
        (
            "Method gas budgets                   : "
            f"deployAgentPayoutProxy ~{evm_est['deploy_payout_proxy_budget_gas']}, "
            f"drawCredit ~{evm_est['draw_credit_budget_gas']}, "
            f"sweepAgentPayout ~{evm_est['sweep_agent_payout_budget_gas']}, "
            f"pause ~{evm_est['pause_switch_budget_gas']}"
        ),
        "",
        "--- Compiled NEAR Registry Resource Footprint ---",
        f"Compiled {wasm_filename:<27s} : {wasm_bytes} bytes",
        f"Required NEAR storage stake          : ~{near_storage_near:.4f} NEAR (1e-5 NEAR / byte)",
        "Init / sync / policy Tgas            : 30 Tgas + 100 Tgas + 30 Tgas (< 0.02 NEAR gas)",
        "",
        "--- Exact Commands (NOT EXECUTED; audit & key-ceremony required before mainnet) ---",
        "# 1. Deploy and initialize NEAR Mainnet registry",
        (
            f"near contract deploy {near_registry_target} "
            f"use-file target/wasm32-unknown-unknown/release/{wasm_filename} "
            "without-init-call network-config mainnet"
        ),
        (
            f"near contract call-function as-transaction {near_registry_target} new "
            f"json-args '{init_args}' prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' "
            f"sign-as {near_registry_target} network-config mainnet"
        ),
        (
            f"near contract call-function as-transaction {near_registry_target} "
            f"set_underwriting_policy json-args '{policy_args}' prepaid-gas '30.0 Tgas' "
            "attached-deposit '0 NEAR' sign-as <MAINNET_MULTISIG_OR_OWNER.near> "
            "network-config mainnet"
        ),
        (
            f"near contract call-function as-transaction {near_registry_target} "
            "sync_approved_measurements json-args '{}' prepaid-gas '100.0 Tgas' "
            "attached-deposit '0 NEAR' sign-as <MAINNET_MULTISIG_OR_OWNER.near> "
            "network-config mainnet"
        ),
        "",
        "# 2. Deploy Base Mainnet ReceiptCreditVault (chainId=8453, hard cap $5, real USDC)",
        "forge create contracts/base-sepolia/ReceiptCreditVault.sol:ReceiptCreditVault \\",
        '  --rpc-url "$BASE_MAINNET_RPC_URL" --private-key "$MAINNET_HARDWARE_SIGNER" \\',
        (
            f"  --constructor-args {derived_signer_placeholder} {base_token_address} "
            f"{lender_id_hex} {hard_cap_units} 86400 500 1500 4000"
        ),
        "",
        "# 3. Bind Base vault back into NEAR registry",
        (
            f"near contract call-function as-transaction {near_registry_target} "
            "set_configured_base_vault "
            'json-args \'{"vault_address_hex":"<DEPLOYED_BASE_MAINNET_VAULT_NO_0X>"}\' '
            "prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' "
            "sign-as <MAINNET_MULTISIG_OR_OWNER.near> network-config mainnet"
        ),
        "",
        "# 4. Emergency owner pause switch (both chains)",
        (
            f"near contract call-function as-transaction {near_registry_target} set_paused "
            'json-args \'{"paused":true}\' prepaid-gas \'30.0 Tgas\' attached-deposit \'0 NEAR\' '
            "sign-as <MAINNET_MULTISIG_OR_OWNER.near> network-config mainnet"
        ),
        (
            'cast send <DEPLOYED_BASE_MAINNET_VAULT> "pause()" '
            '--rpc-url "$BASE_MAINNET_RPC_URL" --private-key "$MAINNET_HARDWARE_SIGNER"'
        ),
    ]
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    """Create CLI parser enforcing `--dry-run`."""
    mainnet_ref = load_mainnet_reference()
    parser = argparse.ArgumentParser(
        description="RECEIPT mainnet deployment dry-run planner (testnet estimation only)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Required safety flag. Only estimates gas on Base Sepolia and prints commands.",
    )
    parser.add_argument(
        "--token-address",
        default=str(mainnet_ref.get("credit_token_address") or DEFAULT_BASE_MAINNET_USDC),
        help="Config-driven ERC-20 token address to target on Base Mainnet (default: Base USDC).",
    )
    parser.add_argument(
        "--near-registry",
        default="receipt-registry.near",
        help="Target NEAR Mainnet registry account name for generated command templates.",
    )
    parser.add_argument(
        "--hard-cap-units",
        type=int,
        default=int(mainnet_ref.get("hard_per_agent_cap_units") or HARD_PER_AGENT_CAP_UNITS),
        help="Hard per-agent advance cap in minimal 6-decimal USDC units (max 5000000 = $5).",
    )
    parser.add_argument(
        "--estimation-rpc-url",
        default=None,
        help="Base Sepolia RPC URL for read-only eth_estimateGas (testnet only).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run dry-run validation and print exact mainnet commands + gas estimates."""
    args = build_arg_parser().parse_args(argv)
    env = {**dotenv_values(REPO_ROOT / ".env"), **os.environ}
    est_rpc = (
        args.estimation_rpc_url
        or (env.get("BASE_SEPOLIA_RPC_URL") or "").strip()
        or DEFAULT_BASE_SEPOLIA_RPC
    )
    validate_safety_guards(
        dry_run=bool(args.dry_run),
        testnet_rpc_url=est_rpc,
        hard_cap_units=int(args.hard_cap_units),
    )

    mainnet_ref = load_mainnet_reference()
    testnet_ref = load_testnet_reference_profile()
    derived_signer = str(
        testnet_ref.get("derived_mpc_evm_signer")
        or "0x0000000000000000000000000000000000000001"
    )
    wasm_path, _ = resolve_registry_wasm_path()
    wasm_bytes = wasm_path.stat().st_size

    evm_est = estimate_base_sepolia_deployment(
        rpc_url=est_rpc,
        near_authorized_signer=derived_signer,
        credit_token=str(args.token_address),
        hard_cap_units=int(args.hard_cap_units),
    )
    report = render_dry_run_report(
        near_registry_target=str(args.near_registry),
        near_mpc_signer=str(mainnet_ref.get("mpc_signer_account") or DEFAULT_NEAR_MAINNET_MPC),
        base_token_address=str(args.token_address),
        derived_signer_placeholder="<MPC_DERIVED_EVM_SIGNER_FROM_MAINNET_REGISTRY>",
        hard_cap_units=int(args.hard_cap_units),
        evm_est=evm_est,
        wasm_bytes=wasm_bytes,
        wasm_filename=wasm_path.name,
    )
    print(report, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
