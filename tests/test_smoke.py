"""Smoke test so the Python toolchain (pytest, ruff, mypy) is exercised in Phase 1."""

import receipt_orchestrator


def test_version() -> None:
    assert receipt_orchestrator.__version__ == "0.1.0"

