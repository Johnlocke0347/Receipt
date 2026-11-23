"""Unit tests for partner quickstart replay log decoding and safety guards."""

from __future__ import annotations

import pytest

from receipt_orchestrator.partner_quickstart import (
    TOPIC_ERC20_TRANSFER,
    TOPIC_LOAN_DRAWN,
    TOPIC_LOAN_REPAID,
    PartnerQuickstartError,
    decode_loan_drawn_log,
    decode_loan_repaid_log,
    find_erc20_transfers,
    validate_testnet_rpc,
)


def test_validate_testnet_rpc_rejects_mainnet() -> None:
    assert validate_testnet_rpc("https://sepolia.base.org", "Base") == "https://sepolia.base.org"
    with pytest.raises(PartnerQuickstartError, match="non-testnet"):
        validate_testnet_rpc("https://mainnet.base.org", "Base")
    with pytest.raises(PartnerQuickstartError, match="non-testnet"):
        validate_testnet_rpc("https://rpc.mainnet.near.org", "NEAR")


def test_decode_vault_and_erc20_logs() -> None:
    receipt_topic = "0x" + ("aa" * 32)
    borrower_topic = "0x" + ("00" * 12) + ("11" * 20)
    lender_topic = "0x" + ("bb" * 32)
    vault = "0xeeb53bf1a753ecc9cfc82c00fa7f61f7df57dbda"
    usdc_addr = "0x86727613c06aa4e2ea9da0e60870c9707f661284"

    drawn = decode_loan_drawn_log(
        {
            "topics": [TOPIC_LOAN_DRAWN, receipt_topic, borrower_topic, lender_topic],
            "data": "0x" + f"{4_000_000:064x}" + ("cc" * 32),
        }
    )
    assert drawn["principal"] == 4_000_000
    assert drawn["borrower"] == "0x" + ("11" * 20)

    repaid = decode_loan_repaid_log(
        {
            "topics": [TOPIC_LOAN_REPAID, receipt_topic, borrower_topic, lender_topic],
            "data": "0x" + f"{4_080_000:064x}" + f"{0:064x}" + ("cc" * 32),
        }
    )
    assert repaid["amount_paid"] == 4_080_000
    assert repaid["remaining_balance"] == 0

    xfers = find_erc20_transfers(
        [
            {
                "address": usdc_addr,
                "topics": [
                    TOPIC_ERC20_TRANSFER,
                    "0x" + ("00" * 12) + vault.removeprefix("0x"),
                    borrower_topic,
                ],
                "data": "0x" + f"{2_120_000:064x}",
            }
        ],
        usdc_addr,
    )
    assert len(xfers) == 1
    assert xfers[0]["amount"] == 2_120_000
