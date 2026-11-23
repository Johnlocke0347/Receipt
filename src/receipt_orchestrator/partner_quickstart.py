"""Partner quickstart CLI: zero-key read-only replay and isolated BYO-wallet live mode."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from typing import Any, cast

import base58
import httpx
import nacl.signing
from dotenv import dotenv_values

from receipt_orchestrator.advance_cycle import (
    resolve_registry_wasm_path,
    run_advance_cycle,
)
from receipt_orchestrator.demo_e2e import (
    DEPLOYMENTS_CONFIG_PATH,
    NEAR_RPC_URL,
    REPO_ROOT,
    abi_word_address,
    derive_evm_address_from_privkey,
    evm_rpc_call,
    keccak256,
    selector,
)

DEFAULT_PUBLIC_BASE_SEPOLIA_RPC = "https://sepolia.base.org"
MIN_PARTNER_ETH_WEI = 500_000_000_000_000  # 0.0005 ETH
PARTNER_SESSION_PATH = REPO_ROOT / "artifacts" / "partner_session.json"
PARTNER_CHECKPOINT_PATH = REPO_ROOT / "artifacts" / "partner_cycle_checkpoint.json"

TOPIC_LOAN_DRAWN = "0x" + keccak256(b"LoanDrawn(bytes32,address,uint256,bytes32,bytes32)").hex()
TOPIC_LOAN_REPAID = (
    "0x" + keccak256(b"LoanRepaid(bytes32,address,uint256,uint256,bytes32,bytes32)").hex()
)
TOPIC_ERC20_TRANSFER = "0x" + keccak256(b"Transfer(address,address,uint256)").hex()


class PartnerQuickstartError(RuntimeError):
    """Raised when partner quickstart prerequisites, safety checks, or verifications fail."""


def validate_testnet_rpc(url: str, label: str) -> str:
    """Reject mainnet URLs so quickstart never interacts with real-funds networks."""
    cleaned = url.strip()
    lowered = cleaned.lower()
    is_testnet = "testnet" in lowered or "sepolia" in lowered
    if not cleaned or "mainnet" in lowered or not is_testnet:
        raise PartnerQuickstartError(
            f"Refusing non-testnet {label} RPC URL `{cleaned}` (must target testnet/sepolia)."
        )
    return cleaned


def decode_loan_drawn_log(raw_log: dict[str, Any]) -> dict[str, Any]:
    """Decode `LoanDrawn(bytes32 indexed receiptId, address indexed borrower, ...)`."""
    topics = [str(t).lower() for t in raw_log.get("topics", [])]
    if len(topics) < 4 or topics[0] != TOPIC_LOAN_DRAWN:
        raise PartnerQuickstartError(f"Expected LoanDrawn topic0, got {topics[:1]}")
    data_hex = str(raw_log.get("data", "")).removeprefix("0x")
    if len(data_hex) < 128:
        raise PartnerQuickstartError(
            f"Truncated LoanDrawn data payload ({len(data_hex)} hex chars)"
        )
    return {
        "receipt_id": topics[1],
        "borrower": "0x" + topics[2][-40:],
        "lender_id": topics[3],
        "principal": int(data_hex[0:64], 16),
        "evidence_commitment": "0x" + data_hex[64:128],
    }


def decode_loan_repaid_log(raw_log: dict[str, Any]) -> dict[str, Any]:
    """Decode `LoanRepaid(bytes32 indexed receiptId, address indexed borrower, ...)`."""
    topics = [str(t).lower() for t in raw_log.get("topics", [])]
    if len(topics) < 4 or topics[0] != TOPIC_LOAN_REPAID:
        raise PartnerQuickstartError(f"Expected LoanRepaid topic0, got {topics[:1]}")
    data_hex = str(raw_log.get("data", "")).removeprefix("0x")
    if len(data_hex) < 192:
        raise PartnerQuickstartError(
            f"Truncated LoanRepaid data payload ({len(data_hex)} hex chars)"
        )
    return {
        "receipt_id": topics[1],
        "borrower": "0x" + topics[2][-40:],
        "amount_paid": int(data_hex[0:64], 16),
        "remaining_balance": int(data_hex[64:128], 16),
        "lender_id": topics[3],
        "evidence_commitment": "0x" + data_hex[128:192],
    }


def find_erc20_transfers(logs: list[dict[str, Any]], token_address: str) -> list[dict[str, Any]]:
    """Extract `(from, to, amount)` records for ERC-20 `Transfer` logs emitted by `token`."""
    target = token_address.lower()
    out: list[dict[str, Any]] = []
    for entry in logs:
        if str(entry.get("address", "")).lower() != target:
            continue
        topics = [str(t).lower() for t in entry.get("topics", [])]
        if len(topics) < 3 or topics[0] != TOPIC_ERC20_TRANSFER:
            continue
        data_hex = str(entry.get("data", "0x0")).removeprefix("0x")
        out.append(
            {
                "from": "0x" + topics[1][-40:],
                "to": "0x" + topics[2][-40:],
                "amount": int(data_hex or "0", 16),
            }
        )
    return out


def _near_view_at(rpc_url: str, account_id: str, method_name: str, args: dict[str, Any]) -> object:
    import base64

    args_b64 = base64.b64encode(json.dumps(args).encode("utf-8")).decode("ascii")
    resp = httpx.post(
        rpc_url,
        json={
            "jsonrpc": "2.0",
            "id": "view",
            "method": "query",
            "params": {
                "request_type": "call_function",
                "finality": "final",
                "account_id": account_id,
                "method_name": method_name,
                "args_base64": args_b64,
            },
        },
        timeout=25.0,
    ).json()
    if "error" in resp or "error" in resp.get("result", {}):
        raise PartnerQuickstartError(f"NEAR view failed ({method_name}): {resp}")
    raw_bytes = bytes(resp["result"]["result"])
    return None if not raw_bytes else cast(object, json.loads(raw_bytes.decode("utf-8")))


def _verify_near_tx_succeeded(rpc_url: str, tx_hash: str, signer_id: str) -> None:
    resp = httpx.post(
        rpc_url,
        json={"jsonrpc": "2.0", "id": "tx", "method": "tx", "params": [tx_hash, signer_id]},
        timeout=25.0,
    ).json()
    result = resp.get("result")
    if not isinstance(result, dict):
        raise PartnerQuickstartError(f"Missing NEAR tx {tx_hash}: {resp}")
    status = result.get("status", {})
    if "Failure" in status:
        raise PartnerQuickstartError(f"NEAR tx {tx_hash} failed: {status}")


def _eth_call_bytes(rpc_url: str, to_addr: str, calldata: bytes) -> bytes:
    params: list[Any] = [{"to": to_addr, "data": "0x" + calldata.hex()}, "latest"]
    res_hex = cast(str, evm_rpc_call(rpc_url, "eth_call", params))
    return bytes.fromhex(res_hex.removeprefix("0x"))


def run_replay_mode(near_rpc: str, base_rpc: str) -> dict[str, Any]:
    """Read-only verification of the recorded `advance_flow_v3` cycle via public RPCs."""
    validate_testnet_rpc(near_rpc, "NEAR")
    validate_testnet_rpc(base_rpc, "Base")

    cfg_raw = cast(dict[str, Any], json.loads(DEPLOYMENTS_CONFIG_PATH.read_text(encoding="utf-8")))
    profile = cast(dict[str, Any], cfg_raw["deployments"]["advance_flow_v3"])
    registry = str(profile["near_registry_account"])
    vault = str(profile["vault_address"]).lower()
    token = str(profile["credit_token_address"]).lower()
    proxy = str(profile["agent_payout_proxy_address"]).lower()
    expected_signer = str(profile["derived_mpc_evm_signer"]).lower()
    ev = cast(dict[str, str], profile["evidence_tx"])

    print("=== RECEIPT READ-ONLY TESTNET REPLAY (0 KEYS / 0 FAUCETS NEEDED) ===", flush=True)
    print(f"NEAR RPC : {near_rpc} ({registry})", flush=True)
    print(f"Base RPC : {base_rpc} (vault={vault}, proxy={proxy})", flush=True)

    # Verify Base Sepolia transaction receipts & balance flows
    draw_rcpt = cast(
        dict[str, Any], evm_rpc_call(base_rpc, "eth_getTransactionReceipt", [ev["draw_credit"]])
    )
    if not draw_rcpt or int(draw_rcpt["status"], 16) != 1:
        raise PartnerQuickstartError(f"Base drawCredit receipt invalid: {draw_rcpt}")
    drawn = decode_loan_drawn_log(draw_rcpt["logs"][0])
    borrower = str(drawn["borrower"]).lower()
    draw_xfers = find_erc20_transfers(draw_rcpt["logs"], token)
    net_disbursed = sum(x["amount"] for x in draw_xfers if x["to"] == borrower)
    holdback_bond = int(drawn["principal"]) - net_disbursed

    earn_rcpt = cast(
        dict[str, Any],
        evm_rpc_call(base_rpc, "eth_getTransactionReceipt", [ev["x402_earn_transfer"]]),
    )
    if not earn_rcpt or int(earn_rcpt["status"], 16) != 1:
        raise PartnerQuickstartError(f"Base earn transfer receipt invalid: {earn_rcpt}")
    earn_xfers = find_erc20_transfers(earn_rcpt["logs"], token)
    x402_incoming = sum(x["amount"] for x in earn_xfers if x["to"] == proxy)

    sweep_rcpt = cast(
        dict[str, Any],
        evm_rpc_call(base_rpc, "eth_getTransactionReceipt", [ev["sweep_agent_payout"]]),
    )
    if not sweep_rcpt or int(sweep_rcpt["status"], 16) != 1:
        raise PartnerQuickstartError(f"Base sweepAgentPayout receipt invalid: {sweep_rcpt}")
    repaid = decode_loan_repaid_log(sweep_rcpt["logs"][0])
    sweep_xfers = find_erc20_transfers(sweep_rcpt["logs"], token)
    forwarded_to_agent = sum(
        x["amount"] for x in sweep_xfers if x["from"] == vault and x["to"] == borrower
    )
    if int(repaid["remaining_balance"]) != 0 or x402_incoming <= 0 or forwarded_to_agent <= 0:
        raise PartnerQuickstartError("Unexpected Base sweep/earn balance accounting")

    # Verify live Base vault contract state
    hard_cap_raw = _eth_call_bytes(base_rpc, vault, selector("hardPerAgentCap()"))
    hard_cap = int.from_bytes(hard_cap_raw, "big")
    paused_flag = int.from_bytes(_eth_call_bytes(base_rpc, vault, selector("paused()")), "big")
    jr_res = int.from_bytes(
        _eth_call_bytes(base_rpc, vault, selector("juniorFirstLossReserve()")), "big"
    )
    sr_res = int.from_bytes(
        _eth_call_bytes(base_rpc, vault, selector("seniorLiquidityReserve()")), "big"
    )
    live_proxy = "0x" + _eth_call_bytes(
        base_rpc, vault, selector("agentPayoutProxy(address)") + abi_word_address(borrower)
    )[-20:].hex()
    rep_calldata = selector("getErc8004ReputationSummary(address)") + abi_word_address(borrower)
    rep_bytes = _eth_call_bytes(base_rpc, vault, rep_calldata)
    evm_rep_count = int.from_bytes(rep_bytes[0:32], "big")
    evm_rep_value = int.from_bytes(rep_bytes[32:64], "big", signed=True)

    # Verify live NEAR registry state & key txs
    meas_count = _near_view_at(near_rpc, registry, "approved_measurements_count", {})
    onchain_signer = str(
        _near_view_at(near_rpc, registry, "derive_vault_authorized_signer_evm_address", {})
    ).lower()
    encumbered = _near_view_at(
        near_rpc, registry, "get_active_encumbered_receipt", {"provider_identity": registry}
    )
    near_rep = cast(
        dict[str, Any],
        _near_view_at(
            near_rpc, registry, "get_erc8004_reputation_summary", {"provider_identity": registry}
        ),
    )
    for tx_key in ("authorize_loan", "verify_loan_consequence", "verify_loan_repayment"):
        _verify_near_tx_succeeded(near_rpc, ev[tx_key], registry)

    if onchain_signer != expected_signer or encumbered is not None or live_proxy != proxy:
        raise PartnerQuickstartError(
            f"State mismatch: signer={onchain_signer} encumbered={encumbered} proxy={live_proxy}"
        )

    summary = {
        "borrower": borrower,
        "principal_drawn_units": drawn["principal"],
        "net_disbursed_units": net_disbursed,
        "holdback_bond_units": holdback_bond,
        "x402_incoming_units": x402_incoming,
        "repaid_skimmed_units": repaid["amount_paid"],
        "remaining_balance_units": repaid["remaining_balance"],
        "forwarded_to_agent_units": forwarded_to_agent,
        "hard_per_agent_cap_units": hard_cap,
        "paused": bool(paused_flag),
        "junior_reserve_units": jr_res,
        "senior_reserve_units": sr_res,
        "near_measurements_count": meas_count,
        "near_erc8004": near_rep,
        "base_erc8004": {"count": evm_rep_count, "value": evm_rep_value},
    }
    print(
        f"[REPLAY OK] 1. BORROW  tx={ev['draw_credit']}\n"
        f"               principal=${drawn['principal']/1e6:.2f}  "
        f"net_to_agent=${net_disbursed/1e6:.2f}  holdback_bond=${holdback_bond/1e6:.2f}\n"
        f"[REPLAY OK] 2. EARN    tx={ev['x402_earn_transfer']}\n"
        f"               x402_to_proxy=${x402_incoming/1e6:.2f} -> {proxy}\n"
        f"[REPLAY OK] 3. REPAY   tx={ev['sweep_agent_payout']}\n"
        f"               skimmed=${repaid['amount_paid']/1e6:.2f}  "
        f"remaining=${repaid['remaining_balance']/1e6:.2f}  "
        f"forwarded_with_bond=${forwarded_to_agent/1e6:.2f}\n"
        f"[REPLAY OK] 4. VERIFY  NEAR authorize={ev['authorize_loan']} | "
        f"draw_proof={ev['verify_loan_consequence']} | repay_proof={ev['verify_loan_repayment']}\n"
        f"[REPLAY OK] 5. STATE   hard_cap=${hard_cap/1e6:.2f} paused={bool(paused_flag)} "
        f"encumbered={encumbered} junior=${jr_res/1e6:.2f} senior=${sr_res/1e6:.2f}\n"
        f"               NEAR ERC-8004={near_rep} | Base ERC-8004=(count={evm_rep_count}, "
        f"value={evm_rep_value})",
        flush=True,
    )
    return summary


def _provision_or_load_partner_near_credentials(env: dict[str, str | None]) -> tuple[str, str]:
    supplied_acct = (env.get("PARTNER_NEAR_ACCOUNT_ID") or "").strip()
    supplied_key = (env.get("PARTNER_NEAR_PRIVATE_KEY") or "").strip()
    if supplied_acct and supplied_key:
        return supplied_acct, supplied_key

    if PARTNER_SESSION_PATH.exists():
        saved = cast(dict[str, Any], json.loads(PARTNER_SESSION_PATH.read_text(encoding="utf-8")))
        if saved.get("near_account_id") and saved.get("near_private_key"):
            return str(saved["near_account_id"]), str(saved["near_private_key"])

    sk = nacl.signing.SigningKey.generate()
    kp_bytes = bytes(sk) + bytes(sk.verify_key)
    priv_b58 = "ed25519:" + base58.b58encode(kp_bytes).decode("ascii")
    account_id = f"receipt-partner-{secrets.token_hex(4)}.testnet"
    PARTNER_SESSION_PATH.parent.mkdir(parents=True, exist_ok=True)
    PARTNER_SESSION_PATH.write_text(
        json.dumps({"near_account_id": account_id, "near_private_key": priv_b58}, indent=2),
        encoding="utf-8",
    )
    print(
        f"[PARTNER SETUP] Provisioning fresh NEAR Testnet account `{account_id}` "
        f"(credentials saved locally to gitignored {PARTNER_SESSION_PATH.name})",
        flush=True,
    )
    return account_id, priv_b58


def run_live_partner_mode(*, base_rpc: str, build_wasm: bool) -> dict[str, Any]:
    """Run an isolated full cycle using ONLY partner's own Base Sepolia wallet + NEAR faucet."""
    validate_testnet_rpc(base_rpc, "Base")
    env = {**dotenv_values(REPO_ROOT / ".env"), **os.environ}
    partner_base_key = (env.get("PARTNER_BASE_SEPOLIA_KEY") or "").strip()
    if not partner_base_key:
        raise PartnerQuickstartError(
            "Missing `PARTNER_BASE_SEPOLIA_KEY` env var for `--live` mode.\n"
            "Set `PARTNER_BASE_SEPOLIA_KEY=0x...` using your own throwaway Base Sepolia wallet "
            "funded with ~0.001 Sepolia ETH from a public faucet (Alchemy / CDP / QuickNode), "
            "or run `--replay` for zero-key live verification."
        )

    partner_evm = derive_evm_address_from_privkey(partner_base_key)
    bal_hex = cast(str, evm_rpc_call(base_rpc, "eth_getBalance", [partner_evm, "latest"]))
    bal_wei = int(bal_hex, 16)
    if bal_wei < MIN_PARTNER_ETH_WEI:
        raise PartnerQuickstartError(
            f"Partner wallet {partner_evm} has {bal_wei / 1e18:.6f} ETH on Base Sepolia "
            f"(< 0.0005 ETH minimum). Fund it from a public Base Sepolia faucet first."
        )

    if build_wasm:
        from scripts.build_registry_wasm import build_and_optimize_wasm

        wasm_path = build_and_optimize_wasm()
    else:
        wasm_path, _ = resolve_registry_wasm_path()

    partner_near_acct, partner_near_key = _provision_or_load_partner_near_credentials(env)
    return run_advance_cycle(
        near_priv_key=partner_near_key,
        registry_account=partner_near_acct,
        base_rpc_url=base_rpc,
        base_priv_key=partner_base_key,
        token_override=(env.get("BASE_CREDIT_TOKEN_ADDRESS") or "").strip(),
        wasm_path=wasm_path,
        checkpoint_path=PARTNER_CHECKPOINT_PATH,
        update_deployments=False,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    """Create CLI parser defaulting safely to read-only `--replay` mode."""
    parser = argparse.ArgumentParser(
        description="RECEIPT partner quickstart (`--replay` read-only default or `--live` BYO key)."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--replay",
        action="store_true",
        help="Read-only replay checking recorded txs and balances on public RPCs (default).",
    )
    mode.add_argument(
        "--live",
        action="store_true",
        help="Deploy your own isolated testnet stack using PARTNER_BASE_SEPOLIA_KEY.",
    )
    parser.add_argument(
        "--build-wasm",
        action="store_true",
        help="With `--live`, compile & optimize near_receipt_registry_opt.wasm automatically.",
    )
    parser.add_argument("--near-rpc", default=NEAR_RPC_URL, help="NEAR Testnet JSON-RPC URL.")
    parser.add_argument(
        "--base-rpc",
        default=os.environ.get("BASE_SEPOLIA_RPC_URL") or DEFAULT_PUBLIC_BASE_SEPOLIA_RPC,
        help="Base Sepolia JSON-RPC URL.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute partner quickstart CLI."""
    args = build_arg_parser().parse_args(argv)
    if args.live:
        run_live_partner_mode(base_rpc=str(args.base_rpc), build_wasm=bool(args.build_wasm))
    else:
        run_replay_mode(near_rpc=str(args.near_rpc), base_rpc=str(args.base_rpc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
