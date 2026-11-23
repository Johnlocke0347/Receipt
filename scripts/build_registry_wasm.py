"""Build and size-optimize `near_receipt_registry.wasm` without changing contract behavior."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from receipt_orchestrator.demo_e2e import REPO_ROOT, WASM_REGISTRY_PATH

REQUIRED_EXPORTS = (
    "new",
    "register_receipt",
    "authorize_loan",
    "verify_loan_consequence",
    "verify_loan_repayment",
    "verify_loan_default",
    "set_paused",
    "set_underwriting_policy",
    "get_trailing_14d_revenue",
    "compute_advance_cap",
    "get_erc8004_reputation_summary",
)


def _read_leb128(buf: bytes, offset: int) -> tuple[int, int]:
    val = 0
    shift = 0
    while True:
        byte = buf[offset]
        offset += 1
        val |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return val, offset
        shift += 7


def read_wasm_function_exports(wasm_path: Path) -> list[str]:
    """Parse exported function names directly from the WASM export section."""
    buf = wasm_path.read_bytes()
    if buf[:4] != b"\x00asm":
        raise ValueError(f"Not a valid WASM binary: {wasm_path}")
    pos = 8
    while pos < len(buf):
        sec_id = buf[pos]
        pos += 1
        sec_size, pos = _read_leb128(buf, pos)
        sec_end = pos + sec_size
        if sec_id == 7:
            count, cursor = _read_leb128(buf, pos)
            exports: list[str] = []
            for _ in range(count):
                name_len, cursor = _read_leb128(buf, cursor)
                name = buf[cursor : cursor + name_len].decode("utf-8")
                cursor += name_len
                kind = buf[cursor]
                cursor += 1
                _, cursor = _read_leb128(buf, cursor)
                if kind == 0:
                    exports.append(name)
            return sorted(exports)
        pos = sec_end
    return []


def build_and_optimize_wasm() -> Path:
    """Compile release WASM and run `wasm-opt -Oz` if `wasm-opt` / `npx` is installed."""
    cargo_exe = shutil.which("cargo") or "cargo"
    subprocess.run(  # noqa: S603
        [
            cargo_exe,
            "build",
            "--release",
            "-p",
            "near-receipt-registry",
            "--target",
            "wasm32-unknown-unknown",
        ],
        cwd=REPO_ROOT,
        check=True,
    )
    raw_bytes = WASM_REGISTRY_PATH.stat().st_size
    raw_exports = read_wasm_function_exports(WASM_REGISTRY_PATH)
    missing = [name for name in REQUIRED_EXPORTS if name not in raw_exports]
    if missing:
        raise RuntimeError(f"Missing expected WASM exports in raw build: {missing}")

    opt_path = WASM_REGISTRY_PATH.with_name("near_receipt_registry_opt.wasm")
    wasm_opt = shutil.which("wasm-opt")
    npx_exe = shutil.which("npx")
    cmd_prefix: list[str] | None = None
    if wasm_opt:
        cmd_prefix = [wasm_opt]
    elif npx_exe:
        cmd_prefix = [npx_exe, "--yes", "wasm-opt"]

    if cmd_prefix is not None:
        subprocess.run(  # noqa: S603
            [
                *cmd_prefix,
                "-Oz",
                "--strip-debug",
                "--strip-producers",
                "--enable-sign-ext",
                "--enable-bulk-memory",
                "--enable-mutable-globals",
                "--enable-nontrapping-float-to-int",
                str(WASM_REGISTRY_PATH),
                "-o",
                str(opt_path),
            ],
            cwd=REPO_ROOT,
            check=True,
        )
        opt_exports = read_wasm_function_exports(opt_path)
        if opt_exports != raw_exports:
            raise RuntimeError("wasm-opt changed exported NEAR contract functions")
        opt_bytes = opt_path.stat().st_size
        print(
            f"Raw WASM : {raw_bytes} bytes (~{raw_bytes / 100_000:.4f} NEAR storage stake)\n"
            f"Opt WASM : {opt_bytes} bytes (~{opt_bytes / 100_000:.4f} NEAR storage stake) "
            f"[{len(opt_exports)} exports verified] -> {opt_path}",
            flush=True,
        )
        return opt_path

    print(
        f"Raw WASM : {raw_bytes} bytes (~{raw_bytes / 100_000:.4f} NEAR storage stake) "
        "(wasm-opt / npx not found; skipping binaryen -Oz pass)",
        flush=True,
    )
    return WASM_REGISTRY_PATH


if __name__ == "__main__":
    build_and_optimize_wasm()
    sys.exit(0)
