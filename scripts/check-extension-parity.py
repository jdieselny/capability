#!/usr/bin/env python3
"""Validate the shared CLC extension parity fixture."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    schema_path = root / "data/_vectors/clc-v1/extension-parity-vectors.schema.json"
    fixture_path = root / "data/_vectors/clc-v1/extension-parity-vectors.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    jsonschema.validate(fixture, schema)
    if fixture.get("@version") != "CLC-PARITY-v1":
        raise SystemExit("extension parity fixture: wrong @version")
    if len(fixture["expect"]) != 11:
        raise SystemExit("extension parity fixture: expected output set drifted")
    if len(fixture["expect"]["negative_errors"]) != 8:
        raise SystemExit("extension parity fixture: negative error set drifted")
    print("extension parity fixture OK: 1 fixture, 10 canonical outputs, 8 negative errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
