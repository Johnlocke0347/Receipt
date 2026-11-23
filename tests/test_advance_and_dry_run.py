"""Unit tests for revenue receipt construction and mainnet dry-run safety guards."""

from __future__ import annotations

import base64
import hashlib

import pytest
from scripts.deploy_mainnet_dry_run import (
    HARD_PER_AGENT_CAP_UNITS,
    DryRunGuardError,
    validate_safety_guards,
)

from receipt_orchestrator.advance_cycle import build_signed_revenue_receipt


def test_dry_run_guard_rejects_missing_flag_and_mainnet_rpc() -> None:
    with pytest.raises(DryRunGuardError, match="--dry-run"):
        validate_safety_guards(
            dry_run=False,
            testnet_rpc_url="https://sepolia.base.org",
            hard_cap_units=HARD_PER_AGENT_CAP_UNITS,
        )

    with pytest.raises(DryRunGuardError, match="non-testnet"):
        validate_safety_guards(
            dry_run=True,
            testnet_rpc_url="https://mainnet.base.org",
            hard_cap_units=HARD_PER_AGENT_CAP_UNITS,
        )

    with pytest.raises(DryRunGuardError, match="Hard per-agent cap"):
        validate_safety_guards(
            dry_run=True,
            testnet_rpc_url="https://sepolia.base.org",
            hard_cap_units=HARD_PER_AGENT_CAP_UNITS + 1,
        )

    validate_safety_guards(
        dry_run=True,
        testnet_rpc_url="https://sepolia.base.org",
        hard_cap_units=HARD_PER_AGENT_CAP_UNITS,
    )


def test_build_signed_revenue_receipt_embeds_attested_revenue() -> None:
    fake_quote = bytearray(600)
    fake_quote[184:232] = b"\x01" * 48
    fake_quote[376:568] = b"\x02" * 192
    attestation = {
        "tdx_quote": base64.b64encode(bytes(fake_quote)).decode("ascii"),
        "wasm_hash": hashlib.sha256(b"wasm").hexdigest(),
        "input_hash": hashlib.sha256(b"in").hexdigest(),
        "output_hash": hashlib.sha256(b"out").hexdigest(),
        "task_type": "WasmUrl",
        "task_id": 42,
        "timestamp": 1_771_590_000,
    }
    receipt, quote_list, task_meta = build_signed_revenue_receipt(
        attestation=attestation,
        provider_identity="receipt-advance-20261123.testnet",
        registry_account_id="receipt-advance-20261123.testnet",
        nonce=99,
        borrower_evm="0x2222222222222222222222222222222222222222",
        max_credit_principal=4_000_000,
        attested_revenue=2_000_000,
        buyer_seed=bytes([0x11] * 32),
        provider_seed=bytes([0x20] * 32),
        job_label="job1",
    )
    assert len(quote_list) == 600
    assert receipt["attested_revenue"] == 2_000_000
    assert receipt["max_credit_principal"] == 4_000_000
    assert task_meta["task_id"] == 42
