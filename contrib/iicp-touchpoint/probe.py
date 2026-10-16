#!/usr/bin/env python3
"""IICP §12.3 touchpoint 探针 —— 固定的 CLC operation/grant 对 + 四个 adverse case。

用途：回 Roble（IICP v0.3.1 §12.3 的 "Review touchpoint for Jijie"）时，
给出**可运行**的判定与 reason，而不是叙述。

四个 adverse case（他点名的）：widened destination set / unit ambiguity /
unknown required constraint / retry to another provider。
外加一条：**recognized-but-not-evaluated 约束 → allow_unresolved**（第三态）。

**标识与参数取自本仓已发布的 scheme** `data/std/payments-v1/v1.json`
（action `transfer`；params `amount` number、`currency` 大写 ISO 枚举、
`counterparty` 数组），而不是自造名字。

运行：
  PYTHONPATH=/home/varwof/src/github.com/clc-python python3 probe.py
"""
import json
import os
import sys

# 实现路径可配：本机默认 /home/varwof/src/github.com/clc-python（包名 clc）；
# CI 里指向 varwof/aic-capability-demo（顶层模块 clc_semantics）。
_PY_DIR = os.environ.get("CLC_PY_DIR", "/home/varwof/src/github.com/clc-python")
sys.path.insert(0, _PY_DIR)
try:
    from clc import CLC_REVISION, authorize, contains
except ImportError:  # 顶层模块形态
    from clc_semantics import CLC_REVISION, authorize, contains

CID = "std/payments-v1:transfer"
WINDOW = (
    "varwof/constraint-v1:time:window:"
    '[{"start":"09:00","end":"17:00"}]'
)


def grant(amount, currency, counterparty, constraints=None):
    g = {
        "id": CID,
        "params": {
            "amount": amount,
            "currency": list(currency),
            "counterparty": list(counterparty),
        },
    }
    if constraints is not None:
        g["constraints"] = list(constraints)
    return g


def op(amount, currency, counterparty):
    return {
        "id": CID,
        "params": {
            "amount": amount,
            "currency": currency if isinstance(currency, list) else [currency],
            "counterparty": (
                counterparty if isinstance(counterparty, list) else [counterparty]
            ),
        },
    }


BASE = grant(5000, ["CNY"], ["vendor.example"])

CASES = [
    ("A0 base: inside grant", lambda: authorize(BASE, op(3000, "CNY", "vendor.example"))),
    ("A1 widened destination", lambda: authorize(BASE, op(3000, "CNY", "other.example"))),
    ("A2 unit ambiguity (USD)", lambda: authorize(BASE, op(3000, "USD", "vendor.example"))),
    ("A2b unit case (cny)", lambda: authorize(BASE, op(3000, "cny", "vendor.example"))),
    ("A2c amount above bound", lambda: authorize(BASE, op(6000, "CNY", "vendor.example"))),
    (
        "A3 unknown required constraint",
        lambda: authorize(
            grant(5000, ["CNY"], ["vendor.example"], ["acme/policy-v1:geo:eu"]),
            op(3000, "CNY", "vendor.example"),
        ),
    ),
    (
        "A4 recognized-not-evaluated (time)",
        lambda: authorize(
            grant(5000, ["CNY"], ["vendor.example"], [WINDOW]),
            op(3000, "CNY", "vendor.example"),
        ),
    ),
    (
        "A5 retry to another provider (same verdict)",
        lambda: authorize(BASE, op(3000, "CNY", "vendor.example")),
    ),
]

CONTAIN_CASES = [
    ("C0 child narrows amount", lambda: contains(BASE, grant(1000, ["CNY"], ["vendor.example"]))),
    ("C0b child narrows counterparty set", lambda: contains(BASE, grant(5000, ["CNY"], ["vendor.example"]))),
    ("C1 child widens destination set", lambda: contains(BASE, grant(5000, ["CNY"], ["vendor.example", "other.example"]))),
    ("C2 child changes currency", lambda: contains(BASE, grant(1000, ["USD"], ["vendor.example"]))),
]


def main():
    print("CLC_REVISION =", CLC_REVISION)
    for name, fn in CASES + CONTAIN_CASES:
        try:
            print(f"{name:42s} -> {json.dumps(fn(), ensure_ascii=False, separators=(',', ':'))}")
        except Exception as exc:  # noqa: BLE001
            print(f"{name:42s} -> EXC {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
