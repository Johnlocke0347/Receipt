"""Live testnet probe for NEAR MPC Chain Signatures (`sign`, domain 0) and Foreign-Tx
verification (`verify_foreign_transaction`, domain 3, `ForeignChainRpcRequest::Base`).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import time
from pathlib import Path

import base58
import ecdsa  # type: ignore[import-untyped]
import httpx
from Crypto.Hash import keccak
from dotenv import load_dotenv
from nacl.signing import SigningKey as Ed25519SigningKey

NEAR_RPC_URL = "https://test.rpc.fastnear.com"
MPC_CONTRACT_ID = "v1.signer-prod.testnet"
DERIVATION_PATH = "receipt-credit-vault-v1"
EXPECTED_DERIVED_PUBKEY = (
    "secp256k1:4BUaArkKFhhnaUmFaxQ3ZDFJKScvpShfeQSo2rsDgLMj3SvfFCuVvZgtDbsntZYmg"
    "ShfPynEJhYm6GiuEShHvzMS"
)
EXPECTED_DOMAIN_3_PUBKEY = (
    "secp256k1:2KGCoy2pZt7n85QfJnQzCT1eHySuNpquUfNc8ySpRbr15F5kqU7agJYjfo5RkrzNd"
    "4tZimDFv2wAZri7RRZ32qj1"
)
BASE_SEPOLIA_CHAIN_ID = 84532


def keccak256(data: bytes) -> bytes:
    """Compute Keccak-256 digest (32 bytes)."""
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def compute_dummy_eip712_loan_digest() -> dict[str, object]:
    """Compute a deterministic dummy EIP-712 LoanAuthorization digest matching receipt-core."""
    domain_typehash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    )
    loan_typehash = keccak256(
        b"LoanAuthorization(bytes32 receiptId,address borrower,uint256 principal,"
        b"bytes32 evidenceCommitment,uint256 deadline)"
    )
    name_hash = keccak256(b"ReceiptCreditVault")
    version_hash = keccak256(b"1")

    vault_address = bytes.fromhex("55" * 20)
    receipt_id = bytes.fromhex("11" * 32)
    borrower = bytes.fromhex("22" * 20)
    principal = 250_000_000
    evidence_commitment = bytes.fromhex("33" * 32)
    deadline = 1_900_000_000

    domain_encoded = (
        domain_typehash
        + name_hash
        + version_hash
        + BASE_SEPOLIA_CHAIN_ID.to_bytes(32, "big")
        + (b"\x00" * 12 + vault_address)
    )
    domain_separator = keccak256(domain_encoded)

    struct_encoded = (
        loan_typehash
        + receipt_id
        + (b"\x00" * 12 + borrower)
        + principal.to_bytes(32, "big")
        + evidence_commitment
        + deadline.to_bytes(32, "big")
    )
    struct_hash = keccak256(struct_encoded)

    digest = keccak256(b"\x19\x01" + domain_separator + struct_hash)
    return {
        "receipt_id": receipt_id.hex(),
        "borrower": "0x" + borrower.hex(),
        "principal": principal,
        "evidence_commitment": evidence_commitment.hex(),
        "vault_address": "0x" + vault_address.hex(),
        "chain_id": BASE_SEPOLIA_CHAIN_ID,
        "deadline": deadline,
        "domain_separator": domain_separator.hex(),
        "struct_hash": struct_hash.hex(),
        "eip712_digest": digest.hex(),
    }


def borsh_string(s: str) -> bytes:
    """Encode a UTF-8 string in Borsh format (u32 LE length + UTF-8 bytes)."""
    raw = s.encode("utf-8")
    return struct.pack("<I", len(raw)) + raw


def serialize_base_foreign_tx_payload_v1(
    tx_hash_hex: str,
    finality: str,
    block_hash_hex: str,
    log: dict[str, object],
    extractor_log_index: int,
) -> bytes:
    """Serialize `ForeignTxSignPayload::V1` for `ForeignChainRpcRequest::Base` in Borsh."""
    tx_hash_bytes = bytes.fromhex(tx_hash_hex.removeprefix("0x"))
    block_hash_bytes = bytes.fromhex(block_hash_hex.removeprefix("0x"))
    if len(tx_hash_bytes) != 32 or len(block_hash_bytes) != 32:
        msg = "tx_hash and block_hash must be 32 bytes"
        raise ValueError(msg)

    finality_discriminant = {"Optimistic": 0, "Safe": 1, "Finalized": 2}[finality]

    buf = bytearray()
    # ForeignTxSignPayload::V1 discriminant = 0
    buf.append(0)
    # ForeignChainRpcRequest::Base discriminant = 6
    buf.append(6)
    # EvmRpcRequest.tx_id ([u8; 32])
    buf.extend(tx_hash_bytes)
    # EvmRpcRequest.extractors: Vec<EvmExtractor> of len 2: [BlockHash, Log { log_index }]
    buf.extend(struct.pack("<I", 2))
    # EvmExtractor::BlockHash discriminant = 0
    buf.append(0)
    # EvmExtractor::Log discriminant = 1 + u64 LE log_index
    buf.append(1)
    buf.extend(struct.pack("<Q", extractor_log_index))
    # EvmFinality discriminant
    buf.append(finality_discriminant)

    # values: Vec<ForeignChainValue> of len 2
    buf.extend(struct.pack("<I", 2))
    # Value 0: ForeignChainValue::Evm (1) -> EvmExtractedValue::BlockHash (0) -> [u8; 32]
    buf.append(1)
    buf.append(0)
    buf.extend(block_hash_bytes)

    # Value 1: ForeignChainValue::Evm (1) -> EvmExtractedValue::Log (1) -> EvmLog
    buf.append(1)
    buf.append(1)
    # EvmLog fields:
    # removed: bool
    buf.append(1 if bool(log.get("removed", False)) else 0)
    # log_index: u64
    raw_log_idx = log["logIndex"]
    log_idx = int(str(raw_log_idx), 16) if isinstance(raw_log_idx, str) else int(str(raw_log_idx))
    buf.extend(struct.pack("<Q", log_idx))
    # transaction_index: u64
    raw_tx_idx = log["transactionIndex"]
    tx_idx = int(str(raw_tx_idx), 16) if isinstance(raw_tx_idx, str) else int(str(raw_tx_idx))
    buf.extend(struct.pack("<Q", tx_idx))
    # transaction_hash: [u8; 32]
    log_tx_hash = bytes.fromhex(str(log["transactionHash"]).removeprefix("0x"))
    buf.extend(log_tx_hash)
    # block_hash: [u8; 32]
    log_block_hash = bytes.fromhex(str(log["blockHash"]).removeprefix("0x"))
    buf.extend(log_block_hash)
    # block_number: u64
    raw_blk_num = log["blockNumber"]
    blk_num = int(str(raw_blk_num), 16) if isinstance(raw_blk_num, str) else int(str(raw_blk_num))
    buf.extend(struct.pack("<Q", blk_num))
    # address: [u8; 20]
    addr_bytes = bytes.fromhex(str(log["address"]).removeprefix("0x"))
    if len(addr_bytes) != 20:
        msg = "EvmLog.address must be 20 bytes"
        raise ValueError(msg)
    buf.extend(addr_bytes)
    # data: String ("0x"-prefixed lowercase hex, matching upstream NEAR MPC EvmLog.data)
    data_str = "0x" + str(log["data"]).removeprefix("0x").removeprefix("0X").lower()
    buf.extend(borsh_string(data_str))
    # topics: Vec<[u8; 32]>
    topics_obj = log["topics"]
    if not isinstance(topics_obj, list):
        msg = "EvmLog.topics must be a list"
        raise TypeError(msg)
    buf.extend(struct.pack("<I", len(topics_obj)))
    for t in topics_obj:
        t_bytes = bytes.fromhex(str(t).removeprefix("0x"))
        if len(t_bytes) != 32:
            msg = "EvmLog topic must be 32 bytes"
            raise ValueError(msg)
        buf.extend(t_bytes)

    return bytes(buf)


def parse_near_ed25519_secret_key(secret_str: str) -> Ed25519SigningKey:
    """Parse an `ed25519:...` NEAR private key into a PyNaCl SigningKey (32-byte seed)."""
    raw = base58.b58decode(secret_str.removeprefix("ed25519:"))
    if len(raw) == 64:
        return Ed25519SigningKey(raw[:32])
    if len(raw) == 32:
        return Ed25519SigningKey(raw)
    msg = f"Unexpected ed25519 secret key length: {len(raw)}"
    raise ValueError(msg)


def build_signed_near_function_call_tx(
    signer_id: str,
    signing_key: Ed25519SigningKey,
    nonce: int,
    block_hash_b58: str,
    receiver_id: str,
    method_name: str,
    args_json: dict[str, object],
    gas: int,
    deposit: int,
) -> tuple[str, str]:
    """Build and sign a Borsh-encoded NEAR SignedTransaction for a single FunctionCall action.
    Returns `(tx_hash_b58, signed_tx_base64)`.
    """
    pubkey_bytes = bytes(signing_key.verify_key)
    block_hash = base58.b58decode(block_hash_b58)
    if len(block_hash) != 32:
        msg = "block_hash must be 32 bytes"
        raise ValueError(msg)

    args_bytes = json.dumps(args_json, separators=(",", ":")).encode("utf-8")

    tx = bytearray()
    tx.extend(borsh_string(signer_id))
    tx.append(0)
    tx.extend(pubkey_bytes)
    tx.extend(struct.pack("<Q", nonce))
    tx.extend(borsh_string(receiver_id))
    tx.extend(block_hash)
    tx.extend(struct.pack("<I", 1))
    tx.append(2)
    tx.extend(borsh_string(method_name))
    tx.extend(struct.pack("<I", len(args_bytes)))
    tx.extend(args_bytes)
    tx.extend(struct.pack("<Q", gas))
    tx.extend(deposit.to_bytes(16, "little"))

    tx_bytes = bytes(tx)
    tx_hash = hashlib.sha256(tx_bytes).digest()
    signature = signing_key.sign(tx_hash).signature

    signed_tx = bytearray(tx_bytes)
    signed_tx.append(0)
    signed_tx.extend(signature)

    return base58.b58encode(tx_hash).decode("ascii"), base64.b64encode(bytes(signed_tx)).decode(
        "ascii"
    )


def near_rpc_call(
    client: httpx.Client, method: str, params: dict[str, object]
) -> dict[str, object]:
    """Execute a JSON-RPC call against NEAR Testnet RPC."""
    resp = client.post(
        NEAR_RPC_URL,
        json={"jsonrpc": "2.0", "id": "probe", "method": method, "params": params},
        timeout=60.0,
    )
    resp.raise_for_status()
    body: dict[str, object] = resp.json()
    if "error" in body:
        msg = f"NEAR RPC error in {method}: {json.dumps(body['error'])}"
        raise RuntimeError(msg)
    result = body["result"]
    if not isinstance(result, dict):
        msg = f"Unexpected NEAR RPC result type in {method}"
        raise TypeError(msg)
    return result


def submit_and_wait_near_call(
    client: httpx.Client,
    signer_id: str,
    signing_key: Ed25519SigningKey,
    receiver_id: str,
    method_name: str,
    args_json: dict[str, object],
    gas: int = 100_000_000_000_000,
    deposit: int = 1,
) -> tuple[str, dict[str, object]]:
    """Submit a FunctionCall transaction and wait for final execution outcome."""
    pubkey_b58 = "ed25519:" + base58.b58encode(bytes(signing_key.verify_key)).decode("ascii")
    ak = near_rpc_call(
        client,
        "query",
        {
            "request_type": "view_access_key",
            "finality": "final",
            "account_id": signer_id,
            "public_key": pubkey_b58,
        },
    )
    nonce = int(str(ak["nonce"])) + 1
    block_hash_b58 = str(ak["block_hash"])

    tx_hash_b58, signed_tx_b64 = build_signed_near_function_call_tx(
        signer_id=signer_id,
        signing_key=signing_key,
        nonce=nonce,
        block_hash_b58=block_hash_b58,
        receiver_id=receiver_id,
        method_name=method_name,
        args_json=args_json,
        gas=gas,
        deposit=deposit,
    )

    try:
        res = near_rpc_call(
            client,
            "send_tx",
            {"signed_tx_base64": signed_tx_b64, "wait_until": "FINAL"},
        )
        return tx_hash_b58, res
    except Exception:
        for _ in range(25):
            time.sleep(2.0)
            try:
                res = near_rpc_call(
                    client,
                    "EXPERIMENTAL_tx_status",
                    {
                        "tx_hash": tx_hash_b58,
                        "sender_account_id": signer_id,
                        "wait_until": "FINAL",
                    },
                )
                status_obj = res.get("status")
                if isinstance(status_obj, dict) and (
                    "SuccessValue" in status_obj or "Failure" in status_obj
                ):
                    return tx_hash_b58, res
            except Exception as poll_err:
                _ = poll_err
        raise


def recover_secp256k1_pubkey_from_mpc_sig(
    digest_32: bytes, mpc_sig: dict[str, object]
) -> tuple[str, str, bytes]:
    """Recover the uncompressed 64-byte secp256k1 public key and EVM address from an MPC
    Secp256k1 signature response (`big_r.affine_point`, `s.scalar`, `recovery_id`).
    Returns `(near_secp256k1_pubkey_str, evm_address_hex, r_32_bytes)`.
    """
    big_r_obj = mpc_sig["big_r"]
    s_obj = mpc_sig["s"]
    if not isinstance(big_r_obj, dict) or not isinstance(s_obj, dict):
        msg = "Malformed MPC signature JSON"
        raise TypeError(msg)

    affine_hex = str(big_r_obj["affine_point"])
    s_hex = str(s_obj["scalar"])
    rec_id = int(str(mpc_sig["recovery_id"]))

    affine_bytes = bytes.fromhex(affine_hex)
    if len(affine_bytes) != 33 or affine_bytes[0] not in (2, 3):
        msg = f"Invalid compressed SEC1 point in big_r: {affine_hex}"
        raise ValueError(msg)

    r_bytes = affine_bytes[1:33]
    s_bytes = bytes.fromhex(s_hex)
    sig_64 = r_bytes + s_bytes

    vk_list = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(
        sig_64,
        digest_32,
        curve=ecdsa.SECP256k1,
        hashfunc=hashlib.sha256,
    )
    # Reconstruct the normalized R point using recovery_id's Y parity (0x02 + (rec_id & 1)),
    # because near/mpc normalizes s -> n - s and flips recovery_id ^= 1 without mutating big_r's tag
    normalized_r_sec1 = bytes([0x02 + (rec_id & 1)]) + r_bytes
    point_r = ecdsa.ellipticcurve.PointJacobi.from_bytes(
        ecdsa.SECP256k1.curve,
        normalized_r_sec1,
    )
    n = int(ecdsa.SECP256k1.order)
    inv_r = pow(int.from_bytes(r_bytes, "big"), -1, n)
    z = int.from_bytes(digest_32, "big")
    s_int = int.from_bytes(s_bytes, "big")
    q_point = inv_r * (s_int * point_r + (-z % n) * ecdsa.SECP256k1.generator)
    vk = ecdsa.VerifyingKey.from_public_point(q_point, curve=ecdsa.SECP256k1)
    pk64: bytes = vk.to_string()

    if not any(candidate.to_string() == pk64 for candidate in vk_list):
        msg = "Recovered public key not in candidate recovery set"
        raise RuntimeError(msg)

    near_pk = "secp256k1:" + base58.b58encode(pk64).decode("ascii")
    evm_addr = "0x" + keccak256(pk64)[12:32].hex()
    return near_pk, evm_addr, r_bytes


def find_recent_finalized_base_sepolia_tx_with_log(
    client: httpx.Client, rpc_url: str
) -> tuple[str, str, int, dict[str, object]]:
    """Find a recent finalized Base Sepolia transaction with at least one non-removed log."""
    blk_resp = client.post(
        rpc_url,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getBlockByNumber",
            "params": ["finalized", False],
        },
        timeout=30.0,
    ).json()
    finalized_block = blk_resp["result"]
    finalized_num = int(finalized_block["number"], 16)

    for offset in range(15):
        blk_num_hex = hex(finalized_num - offset)
        rec_resp = client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "eth_getBlockReceipts",
                "params": [blk_num_hex],
            },
            timeout=30.0,
        ).json()
        receipts = rec_resp.get("result") or []
        for receipt in receipts:
            logs = receipt.get("logs") or []
            for log in logs:
                if not log.get("removed", False):
                    tx_hash = str(receipt["transactionHash"])
                    block_hash = str(receipt["blockHash"])
                    log_index = int(str(log["logIndex"]), 16)
                    return tx_hash, block_hash, log_index, log

    msg = "Could not find a finalized Base Sepolia transaction with logs in last 15 blocks"
    raise RuntimeError(msg)


def run_probe() -> None:
    """Execute both live MPC probes and print structured verification output."""
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    near_account_id = os.environ["NEAR_ACCOUNT_ID"].strip()
    near_private_key = os.environ["NEAR_PRIVATE_KEY"].strip()
    base_rpc_url = os.environ.get("BASE_SEPOLIA_RPC_URL", "https://sepolia.base.org").strip()

    signing_key = parse_near_ed25519_secret_key(near_private_key)

    with httpx.Client() as client:
        print("=== PROBE 1: v1.signer-prod.testnet::sign (domain_id=0) ===")
        dummy = compute_dummy_eip712_loan_digest()
        digest_hex = str(dummy["eip712_digest"])
        digest_bytes = bytes.fromhex(digest_hex)
        sign_args: dict[str, object] = {
            "request": {
                "payload_v2": {"Ecdsa": digest_hex},
                "path": DERIVATION_PATH,
                "domain_id": 0,
            }
        }
        print(f"Caller Account      : {near_account_id}")
        print(f"Target Contract     : {MPC_CONTRACT_ID}::sign")
        print(f"Derivation Path     : {DERIVATION_PATH}")
        print(f"EIP-712 Digest (hex): {digest_hex}")

        sign_tx_hash, sign_outcome = submit_and_wait_near_call(
            client=client,
            signer_id=near_account_id,
            signing_key=signing_key,
            receiver_id=MPC_CONTRACT_ID,
            method_name="sign",
            args_json=sign_args,
            gas=100_000_000_000_000,
            deposit=1,
        )
        print(f"NEAR Tx Hash        : {sign_tx_hash}")
        status = sign_outcome.get("status")
        if not isinstance(status, dict) or "SuccessValue" not in status:
            msg = f"v1.signer-prod.testnet::sign failed: {json.dumps(status)}"
            raise RuntimeError(msg)

        sig_raw = base64.b64decode(str(status["SuccessValue"])).decode("utf-8")
        sig_json: dict[str, object] = json.loads(sig_raw)
        print(f"MPC Sign Response   : {json.dumps(sig_json)}")

        recovered_near_pk, recovered_evm_addr, _ = recover_secp256k1_pubkey_from_mpc_sig(
            digest_bytes, sig_json
        )
        print(f"Recovered NEAR PubKey: {recovered_near_pk}")
        print(f"Expected NEAR PubKey : {EXPECTED_DERIVED_PUBKEY}")
        print(f"Recovered EVM Signer : {recovered_evm_addr}")
        if recovered_near_pk != EXPECTED_DERIVED_PUBKEY:
            msg = (
                f"Public key recovery mismatch! Got {recovered_near_pk}, "
                f"expected {EXPECTED_DERIVED_PUBKEY}"
            )
            raise RuntimeError(msg)
        print("Result              : VERIFIED (Exact match with expected derived key)\n")

        print(
            "=== PROBE 2: v1.signer-prod.testnet::verify_foreign_transaction "
            "(Base, domain_id=3) ==="
        )
        base_tx_hash, base_block_hash, log_index, log_obj = (
            find_recent_finalized_base_sepolia_tx_with_log(client, base_rpc_url)
        )
        print(f"Base Sepolia Tx Hash   : {base_tx_hash}")
        print(f"Base Sepolia Block Hash: {base_block_hash}")
        print(f"Base Sepolia Block Num : {int(str(log_obj['blockNumber']), 16)}")
        print(f"Extracted Log Index    : {log_index}")
        print(f"Log Emitter Address    : {log_obj['address']}")

        borsh_payload = serialize_base_foreign_tx_payload_v1(
            tx_hash_hex=base_tx_hash,
            finality="Finalized",
            block_hash_hex=base_block_hash,
            log=log_obj,
            extractor_log_index=log_index,
        )
        local_payload_hash = hashlib.sha256(borsh_payload).hexdigest()
        print(f"Local Borsh Payload SHA256 : {local_payload_hash}")

        verify_args: dict[str, object] = {
            "request": {
                "request": {
                    "Base": {
                        "tx_id": base_tx_hash.removeprefix("0x").lower(),
                        "extractors": [
                            "BlockHash",
                            {"Log": {"log_index": log_index}},
                        ],
                        "finality": "Finalized",
                    }
                },
                "domain_id": 3,
                "payload_version": 1,
            }
        }
        print(f"Request Args JSON          : {json.dumps(verify_args)}")

        verify_tx_hash, verify_outcome = submit_and_wait_near_call(
            client=client,
            signer_id=near_account_id,
            signing_key=signing_key,
            receiver_id=MPC_CONTRACT_ID,
            method_name="verify_foreign_transaction",
            args_json=verify_args,
            gas=250_000_000_000_000,
            deposit=1,
        )
        print(f"NEAR Tx Hash               : {verify_tx_hash}")
        v_status = verify_outcome.get("status")
        if not isinstance(v_status, dict) or "SuccessValue" not in v_status:
            err_json = json.dumps(v_status)
            msg = f"v1.signer-prod.testnet::verify_foreign_transaction failed: {err_json}"
            raise RuntimeError(msg)

        v_raw = base64.b64decode(str(v_status["SuccessValue"])).decode("utf-8")
        v_json: dict[str, object] = json.loads(v_raw)
        print(f"MPC Verify Response        : {json.dumps(v_json)}")

        mpc_payload_hash = str(v_json["payload_hash"]).removeprefix("0x").lower()
        print(f"MPC Returned Payload Hash  : {mpc_payload_hash}")
        print(f"Payload Hash Match         : {mpc_payload_hash == local_payload_hash}")
        if mpc_payload_hash != local_payload_hash:
            msg = (
                f"ForeignTx payload_hash mismatch! Local={local_payload_hash}, "
                f"MPC={mpc_payload_hash}"
            )
            raise RuntimeError(msg)

        v_sig = v_json["signature"]
        if not isinstance(v_sig, dict):
            msg = "Missing signature object in verify_foreign_transaction response"
            raise TypeError(msg)

        domain3_recovered_pk, domain3_evm_addr, _ = recover_secp256k1_pubkey_from_mpc_sig(
            bytes.fromhex(mpc_payload_hash), v_sig
        )
        print(f"Recovered Domain 3 PubKey  : {domain3_recovered_pk}")
        print(f"Expected Domain 3 PubKey   : {EXPECTED_DOMAIN_3_PUBKEY}")
        print(f"Recovered Domain 3 EVM Addr: {domain3_evm_addr}")
        if domain3_recovered_pk != EXPECTED_DOMAIN_3_PUBKEY:
            msg = (
                f"Domain 3 public key mismatch! Got {domain3_recovered_pk}, "
                f"expected {EXPECTED_DOMAIN_3_PUBKEY}"
            )
            raise RuntimeError(msg)
        print("Result                     : VERIFIED")


if __name__ == "__main__":
    run_probe()
