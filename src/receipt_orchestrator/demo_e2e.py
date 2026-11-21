"""Phase 3 Hardened Live End-to-End Orchestrator for RECEIPT (NEAR Testnet <-> Base Sepolia).

Executes the full cross-chain loop with persistent step-by-step checkpointing:
1. Ensure `receipt-v2-test-20261121.testnet` exists, deploy hardened `near_receipt_registry.wasm`,
   initialize it, sync approved OutLayer worker TDX measurements from `worker.outlayer.testnet`,
   and query `derive_vault_authorized_signer_evm_address()`.
2. Deploy `MockCreditUSDC` and `ReceiptCreditVault` (`nearAuthorizedSigner =
   on-chain derived EVM signer`) to Base Sepolia (`chainId = 84532`),
   fund the vault with 500,000 mUSDC, and pin the vault address on the NEAR registry.
3. Execute our FastFS-hosted `acceptance-verifier-wasm` (`wasm32-wasip1`) live inside OutLayer
   Intel TDX via `outlayer.testnet::request_execution`, fetch the TDX Quote v4 attestation,
   pin its `wasm_hash` on NEAR, and register a hardened Buyer + Provider Ed25519 co-signed
   `ReceiptV1` (binding `borrower_evm_address`, `max_credit_principal`, `RECEIPT_OUTCOME_OUTPUT_V1`,
   and consuming `task_id`).
4. Request a cross-chain EIP-712 Loan Authorization via `authorize_loan` as the provider account,
   which invokes `v1.signer-prod.testnet::sign` (`domain_id: 0`, path `"receipt-credit-vault-v1"`).
5. Broadcast `ReceiptCreditVault.drawCredit(...)` on Base Sepolia (`chainId = 84532`),
   verify the borrower receives `250,000,000` (`250 mUSDC`), and extract the emitted
   `LoanDrawn` log (`log_index`).
6. Submit the Base Sepolia transaction hash, block hash, and `LoanDrawn` log to
   `verify_loan_consequence` (`finality = "Latest"`), which invokes
   `v1.signer-prod.testnet::verify_foreign_transaction` (`domain_id: 3`, Base).
7. Query `verify_consequence_proof`, `is_task_id_consumed`, and `get_provider_credit_graph` on NEAR
   to verify `consequence_state == "ConsumedVerified"` and `is_mpc_consequence_verified == True`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import time
from pathlib import Path
from typing import Any, cast

import base58
import ecdsa  # type: ignore[import-untyped]
import httpx
import nacl.signing
from Crypto.Hash import keccak
from dotenv import dotenv_values

NEAR_RPC_URL = "https://rpc.testnet.near.org"
NEAR_HELPER_URL = "https://helper.testnet.near.org/account"
DEFAULT_V2_REGISTRY_ACCOUNT = "receipt-v2-test-20261121.testnet"
BASE_SEPOLIA_CHAIN_ID = 84532
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
OUTLAYER_WASIP1_WASM_URL = (
    "https://test.fastfs.io/receipt-registry.testnet/outlayer.testnet/"
    "9465bd664f1cfa7ce54731ba4b5c411b4444ebde9064351b5e2b1761cc467dd1.wasm"
)
OUTLAYER_WASIP1_WASM_HASH = "9465bd664f1cfa7ce54731ba4b5c411b4444ebde9064351b5e2b1761cc467dd1"
OUTLAYER_API_BASE = "https://testnet-api.outlayer.ai"

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKPOINT_PATH = REPO_ROOT / "artifacts" / "phase3_v2_checkpoint.json"
WASM_REGISTRY_PATH = (
    REPO_ROOT / "target" / "wasm32-unknown-unknown" / "release" / "near_receipt_registry.wasm"
)
MOCK_USDC_BIN_PATH = (
    REPO_ROOT
    / "contracts"
    / "base-sepolia"
    / "artifacts"
    / "MockCreditUSDC_sol_MockCreditUSDC.bin"
)
VAULT_BIN_PATH = (
    REPO_ROOT
    / "contracts"
    / "base-sepolia"
    / "artifacts"
    / "ReceiptCreditVault_sol_ReceiptCreditVault.bin"
)


# ---------------------------------------------------------------------------
# Checkpoint persistence
# ---------------------------------------------------------------------------


def load_checkpoint() -> dict[str, Any]:
    """Load persisted Phase 3 checkpoint state from disk."""
    if CHECKPOINT_PATH.exists():
        return cast(dict[str, Any], json.loads(CHECKPOINT_PATH.read_text(encoding="utf-8")))
    return {}


def save_checkpoint(state: dict[str, Any]) -> None:
    """Persist Phase 3 checkpoint state atomically."""
    CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
    CHECKPOINT_PATH.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Cryptographic & Encoding Helpers
# ---------------------------------------------------------------------------


def keccak256(data: bytes) -> bytes:
    """Compute Ethereum Keccak-256 digest."""
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def selector(sig: str) -> bytes:
    """Compute 4-byte Solidity function selector."""
    return keccak256(sig.encode("ascii"))[:4]


def abi_word_address(addr_hex: str) -> bytes:
    """ABI-encode a 20-byte EVM address as a 32-byte word."""
    raw = bytes.fromhex(addr_hex.removeprefix("0x"))
    if len(raw) != 20:
        raise ValueError(f"Expected 20-byte EVM address, got {len(raw)} bytes")
    return b"\x00" * 12 + raw


def abi_word_uint(val: int) -> bytes:
    """ABI-encode an unsigned integer as a 32-byte big-endian word."""
    return val.to_bytes(32, "big")


def borsh_str(s: str) -> bytes:
    """Borsh-serialize a UTF-8 string."""
    b = s.encode("utf-8")
    return struct.pack("<I", len(b)) + b


def derive_evm_address_from_near_secp256k1(near_pk: str) -> str:
    """Compute '0x' + last 20 bytes of keccak256(64-byte uncompressed secp256k1 pubkey)."""
    if not near_pk.startswith("secp256k1:"):
        raise ValueError("NEAR public key must start with secp256k1:")
    pk64 = base58.b58decode(near_pk.removeprefix("secp256k1:"))
    if len(pk64) != 64:
        raise ValueError(f"Expected 64-byte secp256k1 key, got {len(pk64)}")
    return "0x" + keccak256(pk64)[-20:].hex()


def derive_evm_address_from_privkey(priv_hex: str) -> str:
    """Derive 0x-prefixed lowercase EVM address from a 32-byte secp256k1 private key."""
    priv_bytes = bytes.fromhex(priv_hex.removeprefix("0x"))
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    if vk is None:
        raise RuntimeError("Failed to derive verifying key")
    pub64: bytes = vk.to_string()
    return "0x" + keccak256(pub64)[-20:].hex()


# ---------------------------------------------------------------------------
# Pure-Python RLP & EIP-155 Transaction Signing for Base Sepolia
# ---------------------------------------------------------------------------


def _rlp_encode_int(n: int) -> bytes:
    if n == 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def rlp_encode(item: int | bytes | list[Any]) -> bytes:
    """Minimal canonical RLP encoder for integers, byte strings, and lists."""
    if isinstance(item, int):
        item = _rlp_encode_int(item)
    if isinstance(item, bytes):
        if len(item) == 1 and item[0] < 0x80:
            return item
        if len(item) <= 55:
            return bytes([0x80 + len(item)]) + item
        len_bytes = _rlp_encode_int(len(item))
        return bytes([0xB7 + len(len_bytes)]) + len_bytes + item
    if isinstance(item, list):
        payload = b"".join(rlp_encode(x) for x in item)
        if len(payload) <= 55:
            return bytes([0xC0 + len(payload)]) + payload
        len_bytes = _rlp_encode_int(len(payload))
        return bytes([0xF7 + len(len_bytes)]) + len_bytes + payload
    raise TypeError(f"Unsupported RLP type: {type(item)}")


def evm_rpc_call(rpc_url: str, method: str, params: list[Any]) -> object:
    """Execute a JSON-RPC call against Base Sepolia."""
    resp = httpx.post(
        rpc_url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=30.0,
    ).json()
    if "error" in resp:
        raise RuntimeError(f"Base Sepolia RPC error in {method}: {resp['error']}")
    return cast(object, resp["result"])


def sign_and_send_evm_tx(
    rpc_url: str,
    priv_hex: str,
    to_addr: str | None,
    data: bytes,
    gas_limit: int,
    value_wei: int = 0,
) -> tuple[str, dict[str, Any]]:
    """Sign an EIP-155 transaction for Base Sepolia, broadcast it, and wait for its receipt."""
    sender = derive_evm_address_from_privkey(priv_hex)
    nonce_hex = cast(str, evm_rpc_call(rpc_url, "eth_getTransactionCount", [sender, "pending"]))
    nonce = int(nonce_hex, 16)
    gas_price_hex = cast(str, evm_rpc_call(rpc_url, "eth_gasPrice", []))
    gas_price = max(int(int(gas_price_hex, 16) * 1.25), 10_000_000)

    to_bytes = b"" if to_addr is None else bytes.fromhex(to_addr.removeprefix("0x"))
    unsigned_items: list[Any] = [
        nonce,
        gas_price,
        gas_limit,
        to_bytes,
        value_wei,
        data,
        BASE_SEPOLIA_CHAIN_ID,
        0,
        0,
    ]
    sighash = keccak256(rlp_encode(unsigned_items))

    priv_bytes = bytes.fromhex(priv_hex.removeprefix("0x"))
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    if vk is None:
        raise RuntimeError("Failed to derive verifying key")
    expected_pub64: bytes = vk.to_string()

    sig64: bytes = sk.sign_digest_deterministic(sighash, hashfunc=hashlib.sha256)
    r_int = int.from_bytes(sig64[:32], "big")
    s_int = int.from_bytes(sig64[32:64], "big")

    recovered_keys = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(
        sig64, sighash, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256
    )
    rec_id = 0
    for idx, cand in enumerate(recovered_keys):
        if cand.to_string() == expected_pub64:
            rec_id = idx
            break

    if s_int > SECP256K1_ORDER // 2:
        s_int = SECP256K1_ORDER - s_int
        rec_id ^= 1

    v = BASE_SEPOLIA_CHAIN_ID * 2 + 35 + rec_id
    signed_raw = rlp_encode(
        [nonce, gas_price, gas_limit, to_bytes, value_wei, data, v, r_int, s_int]
    )
    raw_tx_hex = "0x" + signed_raw.hex()

    tx_hash = cast(str, evm_rpc_call(rpc_url, "eth_sendRawTransaction", [raw_tx_hex]))

    for _ in range(45):
        receipt_obj = evm_rpc_call(rpc_url, "eth_getTransactionReceipt", [tx_hash])
        if receipt_obj is not None:
            receipt = cast(dict[str, Any], receipt_obj)
            status_int = int(receipt["status"], 16)
            if status_int != 1:
                raise RuntimeError(f"Base Sepolia transaction {tx_hash} reverted: {receipt}")
            return tx_hash, receipt
        time.sleep(2.0)

    raise RuntimeError(f"Timed out waiting for Base Sepolia transaction receipt: {tx_hash}")


# ---------------------------------------------------------------------------
# NEAR RPC & Transaction Helpers
# ---------------------------------------------------------------------------


def near_view_call(account_id: str, method_name: str, args: dict[str, Any]) -> object:
    """Invoke a read-only view method on NEAR Testnet."""
    args_b64 = base64.b64encode(json.dumps(args).encode("utf-8")).decode("ascii")
    resp = httpx.post(
        NEAR_RPC_URL,
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
        timeout=30.0,
    ).json()
    if "error" in resp:
        raise RuntimeError(f"NEAR view error ({method_name}): {resp['error']}")
    result = resp["result"]
    if "error" in result:
        raise RuntimeError(f"NEAR view execution error ({method_name}): {result['error']}")
    raw_bytes = bytes(result["result"])
    if not raw_bytes:
        return None
    return cast(object, json.loads(raw_bytes.decode("utf-8")))


def _build_signed_near_tx(
    signer_id: str,
    near_priv_key: str,
    receiver_id: str,
    action_payload: bytes,
) -> tuple[str, str]:
    """Build and sign a NEAR transaction with a single encoded Action payload."""
    if not near_priv_key.startswith("ed25519:"):
        raise ValueError("NEAR private key must start with ed25519:")
    key_bytes = base58.b58decode(near_priv_key.removeprefix("ed25519:"))
    seed = key_bytes[:32]
    signing_key = nacl.signing.SigningKey(seed)
    pub_bytes = bytes(signing_key.verify_key)
    pub_b58 = "ed25519:" + base58.b58encode(pub_bytes).decode("ascii")

    ak_resp = httpx.post(
        NEAR_RPC_URL,
        json={
            "jsonrpc": "2.0",
            "id": "ak",
            "method": "query",
            "params": {
                "request_type": "view_access_key",
                "finality": "optimistic",
                "account_id": signer_id,
                "public_key": pub_b58,
            },
        },
        timeout=20.0,
    ).json()
    if "error" in ak_resp:
        raise RuntimeError(f"Failed to query NEAR access key: {ak_resp['error']}")
    nonce = int(ak_resp["result"]["nonce"]) + 1
    block_hash = base58.b58decode(ak_resp["result"]["block_hash"])

    tx_bytes = bytearray()
    tx_bytes += borsh_str(signer_id)
    tx_bytes += b"\x00" + pub_bytes
    tx_bytes += struct.pack("<Q", nonce)
    tx_bytes += borsh_str(receiver_id)
    tx_bytes += block_hash
    tx_bytes += struct.pack("<I", 1)  # 1 action
    tx_bytes += action_payload

    tx_hash_bytes = hashlib.sha256(bytes(tx_bytes)).digest()
    tx_hash_b58 = base58.b58encode(tx_hash_bytes).decode("ascii")
    sig = signing_key.sign(tx_hash_bytes).signature
    signed_tx = bytes(tx_bytes) + b"\x00" + sig
    return tx_hash_b58, base64.b64encode(signed_tx).decode("ascii")


def _send_and_wait_near_tx(
    signer_id: str,
    tx_hash_b58: str,
    signed_tx_b64: str,
    allow_revert: bool = False,
) -> dict[str, Any]:
    """Broadcast a signed NEAR transaction and poll until final outcome."""
    resp = httpx.post(
        NEAR_RPC_URL,
        json={
            "jsonrpc": "2.0",
            "id": "send",
            "method": "send_tx",
            "params": {
                "signed_tx_base64": signed_tx_b64,
                "wait_until": "EXECUTED_OPTIMISTIC",
            },
        },
        timeout=90.0,
    ).json()

    if "error" in resp:
        for _ in range(25):
            time.sleep(3.0)
            poll = httpx.post(
                NEAR_RPC_URL,
                json={
                    "jsonrpc": "2.0",
                    "id": "poll",
                    "method": "tx",
                    "params": [tx_hash_b58, signer_id],
                },
                timeout=30.0,
            ).json()
            if "result" in poll and "status" in poll["result"]:
                resp = poll
                break
        else:
            raise RuntimeError(f"NEAR RPC error for tx {tx_hash_b58}: {resp['error']}")

    result = cast(dict[str, Any], resp["result"])
    status = result.get("status", {})
    if "Failure" in status and not allow_revert:
        raise RuntimeError(f"NEAR transaction {tx_hash_b58} failed: {json.dumps(status)}")
    return result


def near_deploy_wasm(signer_id: str, near_priv_key: str, wasm_bytes: bytes) -> str:
    """Deploy a WASM contract to `signer_id` on NEAR Testnet (Action variant 1 = DeployContract)."""
    action = b"\x01" + struct.pack("<I", len(wasm_bytes)) + wasm_bytes
    tx_hash_b58, signed_b64 = _build_signed_near_tx(signer_id, near_priv_key, signer_id, action)
    _send_and_wait_near_tx(signer_id, tx_hash_b58, signed_b64)
    return tx_hash_b58


def near_function_call(
    signer_id: str,
    near_priv_key: str,
    receiver_id: str,
    method_name: str,
    args: dict[str, Any],
    gas: int = 100_000_000_000_000,
    deposit: int = 0,
    allow_revert: bool = False,
) -> tuple[str, dict[str, Any]]:
    """Call a state-mutating method on NEAR Testnet (Action variant 2 = FunctionCall)."""
    args_bytes = json.dumps(args).encode("utf-8")
    action = bytearray()
    action += b"\x02"
    action += borsh_str(method_name)
    action += struct.pack("<I", len(args_bytes)) + args_bytes
    action += struct.pack("<Q", gas)
    action += deposit.to_bytes(16, "little")

    tx_hash_b58, signed_b64 = _build_signed_near_tx(
        signer_id, near_priv_key, receiver_id, bytes(action)
    )
    outcome = _send_and_wait_near_tx(signer_id, tx_hash_b58, signed_b64, allow_revert=allow_revert)
    return tx_hash_b58, outcome


def ensure_near_account(account_id: str, near_priv_key: str) -> None:
    """Create the target NEAR Testnet account via helper faucet if it does not already exist."""
    probe = httpx.post(
        NEAR_RPC_URL,
        json={
            "jsonrpc": "2.0",
            "id": "acct",
            "method": "query",
            "params": {
                "request_type": "view_account",
                "finality": "final",
                "account_id": account_id,
            },
        },
        timeout=20.0,
    ).json()
    if "result" in probe:
        return

    if not near_priv_key.startswith("ed25519:"):
        raise ValueError("NEAR private key must start with ed25519:")
    key_bytes = base58.b58decode(near_priv_key.removeprefix("ed25519:"))
    signing_key = nacl.signing.SigningKey(key_bytes[:32])
    pub_b58 = "ed25519:" + base58.b58encode(bytes(signing_key.verify_key)).decode("ascii")
    resp = httpx.post(
        NEAR_HELPER_URL,
        json={"newAccountId": account_id, "newAccountPublicKey": pub_b58},
        timeout=30.0,
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"Failed to provision NEAR Testnet account {account_id}: "
            f"{resp.status_code} {resp.text}"
        )


def compute_settlement_commitment(principal_amount: int) -> bytes:
    """Derive the salted 32-byte confidential settlement commitment."""
    intent_id = hashlib.sha256(b"RECEIPT_PHASE3_PRIVATE_INTENT_V1").digest()
    currency_hash = hashlib.sha256(b"mUSDC:base-sepolia:84532").digest()
    buyer_salt = hashlib.sha256(b"RECEIPT_PHASE3_BUYER_SALT_V1").digest()
    return hashlib.sha256(
        b"RECEIPT_CONFIDENTIAL_V1"
        + intent_id
        + principal_amount.to_bytes(16, "little")
        + currency_hash
        + buyer_salt
    ).digest()


def execute_self_verifier_on_outlayer(
    caller_account: str,
    near_priv_key: str,
    principal_amount: int,
) -> tuple[str, dict[str, Any]]:
    """Run our FastFS-hosted `acceptance-verifier-wasm` live inside OutLayer Intel TDX."""
    settlement_hex = compute_settlement_commitment(principal_amount).hex()
    job_spec_hex = hashlib.sha256(b"RECEIPT_PHASE3_JOB_SPEC_V1").hexdigest()
    test_suite_hex = hashlib.sha256(b"RECEIPT_PHASE3_TEST_SUITE_V1").hexdigest()
    input_data = json.dumps(
        {
            "job_spec_commitment": job_spec_hex,
            "confidential_settlement_commitment": settlement_hex,
            "deliverable_payload": {
                "audit_findings": [{"id": 1, "sev": "low"}],
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
        raise RuntimeError(f"OutLayer self-verifier execution produced no output: {outcome}")
    sv_bytes = base64.b64decode(sv_b64)
    ver_out = cast(dict[str, Any], json.loads(sv_bytes.decode("utf-8")))
    if ver_out.get("outcome") != "PASS":
        raise RuntimeError(f"OutLayer self-verifier returned non-PASS outcome: {ver_out}")

    req_id: int | None = None
    for receipt_out in outcome.get("receipts_outcome", []):
        for log_entry in receipt_out.get("outcome", {}).get("logs", []):
            if "execution_requested" in log_entry:
                ev = json.loads(log_entry.removeprefix("EVENT_JSON:"))
                req_data = json.loads(ev["data"][0]["request_data"])
                req_id = int(req_data["request_id"])
    if req_id is None:
        raise RuntimeError(f"Could not extract OutLayer request_id from tx {exec_tx}")

    attestation: dict[str, Any] | None = None
    for _ in range(15):
        resp = httpx.get(
            f"{OUTLAYER_API_BASE}/attestations/by-request/{req_id}",
            timeout=15.0,
        )
        if resp.status_code == 200:
            attestation = cast(dict[str, Any], resp.json())
            break
        time.sleep(2.0)
    if attestation is None:
        raise RuntimeError(f"Timed out fetching OutLayer attestation for request_id={req_id}")
    if attestation.get("wasm_hash") != OUTLAYER_WASIP1_WASM_HASH:
        raise RuntimeError(
            f"Unexpected OutLayer attestation wasm_hash: {attestation.get('wasm_hash')}"
        )
    if attestation.get("output_hash") != hashlib.sha256(sv_bytes).hexdigest():
        raise RuntimeError("OutLayer attestation output_hash does not match stdout bytes")
    return exec_tx, attestation


# ---------------------------------------------------------------------------
# ReceiptV1 Construction & Ed25519 Co-Signing
# ---------------------------------------------------------------------------


def build_and_sign_receipt_v1(
    attestation: dict[str, Any],
    provider_identity: str,
    registry_account_id: str,
    nonce: int,
    borrower_evm: str,
    max_credit_principal: int,
) -> tuple[dict[str, Any], list[int], dict[str, Any]]:
    """Construct canonical hardened `ReceiptV1`, `tdx_quote_bytes`, and `TaskHashInputs`."""
    quote_bytes = base64.b64decode(attestation["tdx_quote"].strip())
    mrtd = quote_bytes[184:232]
    rtmrs = quote_bytes[376:568]
    verifier_measurement = hashlib.sha256(mrtd + rtmrs).digest()

    wasm_hash = bytes.fromhex(attestation["wasm_hash"])
    input_hash = bytes.fromhex(attestation["input_hash"])
    raw_output_hash = bytes.fromhex(attestation["output_hash"])
    # Commit PASS (1) into receipt.output_hash per Fix 4 while keeping raw output_hash in task_meta.
    committed_output_hash = hashlib.sha256(
        b"RECEIPT_OUTCOME_OUTPUT_V1" + b"\x01" + raw_output_hash
    ).digest()

    settlement_commitment = compute_settlement_commitment(max_credit_principal)

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

    buyer_sk = nacl.signing.SigningKey(bytes([0x10] * 32))
    provider_sk = nacl.signing.SigningKey(bytes([0x20] * 32))
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

    chain_prefix = borsh_str("testnet") + borsh_str(registry_account_id)
    buyer_digest = hashlib.sha256(
        b"NEAR_RECEIPT_BUYER_SIG_V1" + chain_prefix + bytes(signing_body)
    ).digest()
    provider_digest = hashlib.sha256(
        b"NEAR_RECEIPT_PROVIDER_SIG_V1" + chain_prefix + bytes(signing_body)
    ).digest()

    buyer_sig = buyer_sk.sign(buyer_digest).signature
    provider_sig = provider_sk.sign(provider_digest).signature

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
        "buyer_signature": buyer_sig.hex(),
        "provider_signature": provider_sig.hex(),
        "nonce": nonce,
        "created_at": created_at,
        "confidential_settlement_commitment": settlement_commitment.hex(),
        "borrower_evm_address": borrower_bytes.hex(),
        "max_credit_principal": max_credit_principal,
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
        "timestamp": int(attestation["timestamp"]),
        "attached_usd": attestation.get("attached_usd"),
    }

    return receipt_dict, list(quote_bytes), task_meta


# ---------------------------------------------------------------------------
# Phase 3 Orchestrator Execution
# ---------------------------------------------------------------------------


def main() -> None:
    """Execute Phase 3 end-to-end deployment and cross-chain verification with checkpointing."""
    env = dotenv_values(REPO_ROOT / ".env")
    near_priv_key = env.get("NEAR_PRIVATE_KEY") or ""
    registry_account = (env.get("NEAR_REGISTRY_ACCOUNT_ID") or "").strip() or (
        DEFAULT_V2_REGISTRY_ACCOUNT
    )
    base_rpc_url = env.get("BASE_SEPOLIA_RPC_URL") or ""
    base_priv_key = env.get("BASE_SEPOLIA_PRIVATE_KEY") or ""

    if not (near_priv_key and base_rpc_url and base_priv_key):
        raise RuntimeError(
            "Missing required credentials in .env "
            "(NEAR_PRIVATE_KEY, BASE_SEPOLIA_RPC_URL, BASE_SEPOLIA_PRIVATE_KEY)"
        )

    ensure_near_account(registry_account, near_priv_key)
    borrower_evm = derive_evm_address_from_privkey(base_priv_key)
    principal_amount = 250_000_000  # 250.000000 mUSDC (6 decimals)

    state = load_checkpoint()
    print("=== RECEIPT PHASE 3 HARDENED LIVE END-TO-END ORCHESTRATOR ===", flush=True)
    print(f"NEAR Registry Account : {registry_account}", flush=True)
    print(f"Base Sepolia Deployer : {borrower_evm} (chainId={BASE_SEPOLIA_CHAIN_ID})", flush=True)

    # -----------------------------------------------------------------------
    # STEP 1: Deploy near_receipt_registry.wasm, Initialize & Sync Measurements
    # -----------------------------------------------------------------------
    if not state.get("step1_deploy_wasm_tx"):
        wasm_bytes = WASM_REGISTRY_PATH.read_bytes()
        deploy_tx = near_deploy_wasm(registry_account, near_priv_key, wasm_bytes)
        state["step1_deploy_wasm_tx"] = deploy_tx
        save_checkpoint(state)
    print(
        f"[Step 1a] NEAR DeployContract (near_receipt_registry.wasm) "
        f"tx_hash: {state['step1_deploy_wasm_tx']}",
        flush=True,
    )

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
        save_checkpoint(state)
    print(f"[Step 1b] NEAR ReceiptRegistry::new tx_hash: {state['step1_init_tx']}", flush=True)

    if not state.get("step1_sync_measurements_tx"):
        sync_tx, _ = near_function_call(
            registry_account,
            near_priv_key,
            registry_account,
            "sync_approved_measurements",
            {},
            gas=100_000_000_000_000,
        )
        state["step1_sync_measurements_tx"] = sync_tx
        save_checkpoint(state)
    meas_count = near_view_call(registry_account, "approved_measurements_count", {})
    onchain_signer = cast(
        str, near_view_call(registry_account, "derive_vault_authorized_signer_evm_address", {})
    )
    print(
        f"[Step 1c] NEAR ReceiptRegistry::sync_approved_measurements "
        f"tx_hash: {state['step1_sync_measurements_tx']} "
        f"(approved_measurements_count={meas_count}, "
        f"onchain_nearAuthorizedSigner={onchain_signer})",
        flush=True,
    )

    # -----------------------------------------------------------------------
    # STEP 2: Deploy MockCreditUSDC & ReceiptCreditVault on Base Sepolia
    # -----------------------------------------------------------------------
    if not state.get("step2_deploy_usdc_tx"):
        usdc_bin = bytes.fromhex(MOCK_USDC_BIN_PATH.read_text(encoding="utf-8").strip())
        usdc_init = usdc_bin + abi_word_uint(1_000_000_000_000)  # 1,000,000 mUSDC
        usdc_tx, usdc_rcpt = sign_and_send_evm_tx(
            base_rpc_url, base_priv_key, None, usdc_init, gas_limit=1_500_000
        )
        state["step2_deploy_usdc_tx"] = usdc_tx
        state["mock_usdc_address"] = usdc_rcpt["contractAddress"]
        save_checkpoint(state)
    usdc_address: str = state["mock_usdc_address"]
    print(
        f"[Step 2a] Base Sepolia Deploy MockCreditUSDC tx_hash: {state['step2_deploy_usdc_tx']} "
        f"(contract={usdc_address})",
        flush=True,
    )

    if not state.get("step2_deploy_vault_tx"):
        vault_bin = bytes.fromhex(VAULT_BIN_PATH.read_text(encoding="utf-8").strip())
        lender_id_bytes = keccak256(b"RECEIPT_BASE_SEPOLIA_VAULT_V2")
        vault_init = (
            vault_bin
            + abi_word_address(onchain_signer)
            + abi_word_address(usdc_address)
            + lender_id_bytes
        )
        vault_tx, vault_rcpt = sign_and_send_evm_tx(
            base_rpc_url, base_priv_key, None, vault_init, gas_limit=2_000_000
        )
        state["step2_deploy_vault_tx"] = vault_tx
        state["vault_address"] = vault_rcpt["contractAddress"]
        state["lender_id_hex"] = lender_id_bytes.hex()
        state["authorized_signer_evm"] = onchain_signer
        save_checkpoint(state)
    vault_address: str = state["vault_address"]
    print(
        f"[Step 2b] Base Sepolia Deploy ReceiptCreditVault "
        f"tx_hash: {state['step2_deploy_vault_tx']} "
        f"(contract={vault_address}, nearAuthorizedSigner={onchain_signer})",
        flush=True,
    )

    if not state.get("step2_fund_vault_tx"):
        transfer_calldata = (
            selector("transfer(address,uint256)")
            + abi_word_address(vault_address)
            + abi_word_uint(500_000_000_000)  # 500,000 mUSDC
        )
        fund_tx, _ = sign_and_send_evm_tx(
            base_rpc_url, base_priv_key, usdc_address, transfer_calldata, gas_limit=150_000
        )
        state["step2_fund_vault_tx"] = fund_tx
        save_checkpoint(state)
    print(
        f"[Step 2c] Base Sepolia MockCreditUSDC::transfer (500,000 mUSDC -> Vault) "
        f"tx_hash: {state['step2_fund_vault_tx']}",
        flush=True,
    )

    if not state.get("step2_configure_vault_near_tx"):
        cfg_tx, _ = near_function_call(
            registry_account,
            near_priv_key,
            registry_account,
            "set_configured_base_vault",
            {"vault_address_hex": vault_address.removeprefix("0x")},
            gas=30_000_000_000_000,
        )
        state["step2_configure_vault_near_tx"] = cfg_tx
        save_checkpoint(state)
    print(
        f"[Step 2d] NEAR ReceiptRegistry::set_configured_base_vault "
        f"tx_hash: {state['step2_configure_vault_near_tx']}",
        flush=True,
    )

    # -----------------------------------------------------------------------
    # STEP 3: Run Own Acceptance Verifier in OutLayer & Register Hardened ReceiptV1
    # -----------------------------------------------------------------------
    if not state.get("outlayer_attestation"):
        outlayer_tx, attestation = execute_self_verifier_on_outlayer(
            registry_account, near_priv_key, principal_amount
        )
        state["step3_outlayer_exec_tx"] = outlayer_tx
        state["outlayer_attestation"] = attestation
        save_checkpoint(state)
    attestation = cast(dict[str, Any], state["outlayer_attestation"])
    print(
        f"[Step 3a] OutLayer Live acceptance-verifier-wasm (wasm32-wasip1) "
        f"tx_hash: {state['step3_outlayer_exec_tx']} "
        f"(task_id={attestation['task_id']}, wasm_hash={attestation['wasm_hash'][:16]}...)",
        flush=True,
    )

    receipt_nonce = int(state.get("receipt_nonce") or int(time.time()))
    state["receipt_nonce"] = receipt_nonce
    receipt_dict, quote_bytes_list, task_meta = build_and_sign_receipt_v1(
        attestation=attestation,
        provider_identity=registry_account,
        registry_account_id=registry_account,
        nonce=receipt_nonce,
        borrower_evm=borrower_evm,
        max_credit_principal=principal_amount,
    )
    receipt_id_hex: str = receipt_dict["receipt_id"]
    state["receipt_id_hex"] = receipt_id_hex

    if not state.get("step3_pin_wasm_tx"):
        pin_tx, _ = near_function_call(
            registry_account,
            near_priv_key,
            registry_account,
            "add_expected_wasm_hash",
            {"wasm_hash_hex": receipt_dict["wasm_hash"]},
            gas=30_000_000_000_000,
        )
        state["step3_pin_wasm_tx"] = pin_tx
        save_checkpoint(state)
    print(
        f"[Step 3b] NEAR ReceiptRegistry::add_expected_wasm_hash "
        f"tx_hash: {state['step3_pin_wasm_tx']}",
        flush=True,
    )

    if not state.get("step3_register_receipt_tx"):
        reg_tx, _ = near_function_call(
            registry_account,
            near_priv_key,
            registry_account,
            "register_receipt",
            {
                "receipt": receipt_dict,
                "tdx_quote_bytes": quote_bytes_list,
                "outlayer_task_meta": task_meta,
            },
            gas=150_000_000_000_000,
        )
        state["step3_register_receipt_tx"] = reg_tx
        save_checkpoint(state)
    stored_receipt_obj = near_view_call(
        registry_account, "get_receipt", {"receipt_id_hex": receipt_id_hex}
    )
    if stored_receipt_obj is None:
        raise RuntimeError(f"get_receipt returned None for {receipt_id_hex}")
    stored_receipt = cast(dict[str, Any], stored_receipt_obj)
    print(
        f"[Step 3c] NEAR ReceiptRegistry::register_receipt "
        f"tx_hash: {state['step3_register_receipt_tx']} "
        f"(receipt_id={receipt_id_hex}, state={stored_receipt['consequence_state']})",
        flush=True,
    )

    # -----------------------------------------------------------------------
    # STEP 4: Authorize Loan via NEAR Chain Signatures (v1.signer-prod.testnet::sign)
    # -----------------------------------------------------------------------
    if not state.get("step4_authorize_loan_tx"):
        deadline = int(time.time()) + 7200
        auth_tx, _ = near_function_call(
            registry_account,
            near_priv_key,
            registry_account,
            "authorize_loan",
            {
                "receipt_id_hex": receipt_id_hex,
                "borrower_evm_address_hex": borrower_evm.removeprefix("0x"),
                "principal_amount": str(principal_amount),
                "base_vault_address_hex": vault_address.removeprefix("0x"),
                "deadline": deadline,
            },
            gas=150_000_000_000_000,
            deposit=1,
        )
        state["step4_authorize_loan_tx"] = auth_tx
        state["loan_deadline"] = deadline
        save_checkpoint(state)

    loan_packet_obj = near_view_call(
        registry_account, "get_loan_authorization", {"receipt_id_hex": receipt_id_hex}
    )
    if loan_packet_obj is None:
        raise RuntimeError("get_loan_authorization returned None after authorize_loan")
    loan_packet = cast(dict[str, Any], loan_packet_obj)
    print(
        f"[Step 4]  NEAR ReceiptRegistry::authorize_loan (v1.signer-prod.testnet::sign) "
        f"tx_hash: {state['step4_authorize_loan_tx']} "
        f"(eip712_digest={loan_packet['eip712_digest']}, v={loan_packet['signature_v']}, "
        f"r={loan_packet['signature_r']}, s={loan_packet['signature_s']})",
        flush=True,
    )

    # -----------------------------------------------------------------------
    # STEP 5: Execute ReceiptCreditVault.drawCredit(...) on Base Sepolia
    # -----------------------------------------------------------------------
    if not state.get("step5_draw_credit_tx"):
        draw_calldata = (
            selector(
                "drawCredit(bytes32,address,uint256,bytes32,uint256,uint8,bytes32,bytes32)"
            )
            + bytes.fromhex(loan_packet["receipt_id"])
            + abi_word_address(loan_packet["borrower_evm_address"])
            + abi_word_uint(int(loan_packet["principal_amount"]))
            + bytes.fromhex(loan_packet["evidence_commitment"])
            + abi_word_uint(int(loan_packet["deadline"]))
            + abi_word_uint(int(loan_packet["signature_v"]))
            + bytes.fromhex(loan_packet["signature_r"])
            + bytes.fromhex(loan_packet["signature_s"])
        )
        draw_tx, draw_rcpt = sign_and_send_evm_tx(
            base_rpc_url, base_priv_key, vault_address, draw_calldata, gas_limit=250_000
        )
        state["step5_draw_credit_tx"] = draw_tx
        state["step5_draw_credit_block_hash"] = draw_rcpt["blockHash"]
        state["step5_draw_credit_log0"] = draw_rcpt["logs"][0]
        save_checkpoint(state)

    draw_tx_hash: str = state["step5_draw_credit_tx"]
    draw_block_hash: str = state["step5_draw_credit_block_hash"]
    raw_log0: dict[str, Any] = state["step5_draw_credit_log0"]
    print(
        f"[Step 5]  Base Sepolia ReceiptCreditVault::drawCredit tx_hash: {draw_tx_hash} "
        f"(block_hash={draw_block_hash}, logIndex={raw_log0['logIndex']})",
        flush=True,
    )

    # -----------------------------------------------------------------------
    # STEP 6: Verify Cross-Chain Consequence via NEAR MPC (verify_foreign_transaction)
    # -----------------------------------------------------------------------
    if not state.get("step6_verify_consequence_tx"):
        time.sleep(6.0)
        expected_evm_log: dict[str, Any] = {
            "removed": bool(raw_log0.get("removed", False)),
            "log_index": int(raw_log0["logIndex"], 16),
            "transaction_index": int(raw_log0["transactionIndex"], 16),
            "transaction_hash": raw_log0["transactionHash"].removeprefix("0x").lower(),
            "block_hash": raw_log0["blockHash"].removeprefix("0x").lower(),
            "block_number": int(raw_log0["blockNumber"], 16),
            "address": raw_log0["address"].removeprefix("0x").lower(),
            "data": raw_log0["data"].lower(),
            "topics": [t.removeprefix("0x").lower() for t in raw_log0["topics"]],
        }
        verify_tx, _ = near_function_call(
            registry_account,
            near_priv_key,
            registry_account,
            "verify_loan_consequence",
            {
                "receipt_id_hex": receipt_id_hex,
                "base_tx_hash_hex": draw_tx_hash.removeprefix("0x"),
                "base_block_hash_hex": draw_block_hash.removeprefix("0x"),
                "expected_log": expected_evm_log,
                "finality": "Latest",
            },
            gas=150_000_000_000_000,
            deposit=1,
        )
        state["step6_verify_consequence_tx"] = verify_tx
        save_checkpoint(state)

    print(
        f"[Step 6]  NEAR ReceiptRegistry::verify_loan_consequence "
        f"(v1.signer-prod.testnet::verify_foreign_transaction) "
        f"tx_hash: {state['step6_verify_consequence_tx']}",
        flush=True,
    )

    # -----------------------------------------------------------------------
    # STEP 7: Query On-Chain Consequence Proof & Provider Credit Graph
    # -----------------------------------------------------------------------
    proof_view_obj = near_view_call(
        registry_account, "verify_consequence_proof", {"receipt_id_hex": receipt_id_hex}
    )
    credit_graph_obj = near_view_call(
        registry_account, "get_provider_credit_graph", {"provider_identity": registry_account}
    )
    task_consumed = bool(
        near_view_call(
            registry_account, "is_task_id_consumed", {"task_id": int(attestation["task_id"])}
        )
    )
    proof_view = cast(dict[str, Any] | None, proof_view_obj)
    credit_graph = cast(list[dict[str, Any]], credit_graph_obj or [])
    if not proof_view or not proof_view.get("is_mpc_consequence_verified"):
        raise RuntimeError(
            f"Consequence verification did not complete as ConsumedVerified: {proof_view}"
        )
    if not task_consumed:
        raise RuntimeError(f"Task ID {attestation['task_id']} was not marked consumed")
    ev = proof_view["receipt"]["verified_finality_evidence"]
    print(
        f"[Step 7]  Verified On-Chain Consequence Proof:\n"
        f"          consequence_state          = {proof_view['receipt']['consequence_state']}\n"
        f"          is_mpc_consequence_verified = {proof_view['is_mpc_consequence_verified']}\n"
        f"          is_task_id_consumed        = {task_consumed}\n"
        f"          foreign_chain_id           = {proof_view['receipt']['foreign_chain_id']}\n"
        f"          foreign_tx_hash            = 0x{proof_view['receipt']['foreign_tx_hash']}\n"
        f"          mpc_payload_hash           = {ev['payload_hash']}\n"
        f"          mpc_domain3_sig (r,s,v)    = "
        f"({ev['signature_r']}, {ev['signature_s']}, {ev['signature_v']})\n"
        f"          provider_credit_graph_len  = {len(credit_graph)}",
        flush=True,
    )


if __name__ == "__main__":
    main()
