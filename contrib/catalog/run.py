#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
"""Regenerate and check the catalog cross-language evidence.

Runs the Go catalog test with CAT_CROSSLANG_OUT pointed at this directory,
which materialises the corpus bundle, runs probe.py and probe.ts, asserts that
all three agree, and rewrites out-python.txt / out-typescript.txt.

The Go test is the authority: this script only drives it and then reports the
checked-in evidence.  With --check it does not rewrite anything and fails if the
checked-in files are missing or their vector lines differ.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REGISTER_DIR = Path(os.environ.get("REGISTER_DIR") or HERE.parents[2] / "register")


def run_go(out_dir: Path | None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if out_dir is not None:
        env["CAT_CROSSLANG_OUT"] = str(out_dir)
    return subprocess.run(
        ["go", "test", "./catalog/", "-run", "TestCrossLanguageVectors", "-v", "-count=1"],
        cwd=REGISTER_DIR,
        env=env,
        capture_output=True,
        text=True,
    )


def body(path: Path) -> list[str]:
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]


def main(argv: list[str]) -> int:
    check = "--check" in argv[1:]
    python_out = HERE / "out-python.txt"
    typescript_out = HERE / "out-typescript.txt"

    if check and (not python_out.exists() or not typescript_out.exists()):
        print("catalog evidence: checked-in output missing; run without --check")
        return 1

    with tempfile.TemporaryDirectory(prefix="catalog-evidence-") as tmp:
        live_dir = Path(tmp) if check else HERE
        result = run_go(out_dir=live_dir)
        if result.returncode != 0:
            sys.stderr.write(result.stdout)
            sys.stderr.write(result.stderr)
            return result.returncode
        if "catalog cross-language:" not in result.stdout:
            print(
                "catalog evidence: cross-language agreement did not run; "
                "a missing probe or interpreter must not pass",
                file=sys.stderr,
            )
            return 1

        if check:
            live_python = live_dir / "out-python.txt"
            live_typescript = live_dir / "out-typescript.txt"
            if not live_python.exists() or not live_typescript.exists():
                print("catalog evidence: live probe output was not produced", file=sys.stderr)
                return 1
            if body(live_python) != body(python_out):
                print("catalog evidence: checked-in Python output is stale", file=sys.stderr)
                return 1
            if body(live_typescript) != body(typescript_out):
                print("catalog evidence: checked-in TypeScript output is stale", file=sys.stderr)
                return 1

    if check:
        print(
            f"catalog evidence OK: {len(body(python_out))} vectors, "
            f"checked-in Python and TypeScript outputs match live Go/probe runs"
        )
        return 0

    print(f"catalog evidence regenerated: {len(body(python_out))} vectors")
    print(f"  {python_out}")
    print(f"  {typescript_out}")
    for line in result.stdout.splitlines():
        if "cross-language:" in line:
            print("  " + line.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
