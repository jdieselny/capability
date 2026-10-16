#!/usr/bin/env python3
"""CLC {value, unit} 量编码探针 —— Python 侧。

用途：验证"货币/量 -> 以 object 参数 {value, unit} 建模"在 CLC-v1 里
是否可直接表达，并产出可与 TypeScript 侧逐字比对的判定与 reason。

依赖：clc-python（本机 /home/varwof/src/github.com/clc-python）。
运行（实现路径可配）：
  export CLC_PY_DIR=/path/to/an/implementation   # 默认 /home/varwof/src/github.com/clc-python
  python3 probe.py
"""
import json

import os
import sys

# 实现路径可配：本机默认 clc-python（包名 clc）；CI 里指向 aic-capability-demo。
_PY_DIR = os.environ.get("CLC_PY_DIR", "/home/varwof/src/github.com/clc-python")
sys.path.insert(0, _PY_DIR)
try:
    from clc import CLC_REVISION, authorize, contains, entails
except ImportError:
    from clc_semantics import CLC_REVISION, authorize, contains, entails

CID = "example/quantity-v1:charge"  # 示例性标识：本探针演示编码机制，不代表某个已发布 scheme


def grant(value, unit, extra=None):
    params = {"amount": {"value": value, "unit": unit}}
    if extra:
        params.update(extra)
    return {"id": CID, "params": params}


def op(value, unit, extra=None):
    params = {"amount": {"value": value, "unit": unit}}
    if extra:
        params.update(extra)
    return {"id": CID, "params": params}


CASES = [
    ("authorize 30<=50 CNY", lambda: authorize(grant(50, "CNY"), op(30, "CNY"))),
    ("authorize 60<=50 CNY", lambda: authorize(grant(50, "CNY"), op(60, "CNY"))),
    ("authorize 30 CNY vs USD", lambda: authorize(grant(50, "CNY"), op(30, "USD"))),
    ("authorize 50.0 vs 50", lambda: authorize(grant(50.0, "CNY"), op(50, "CNY"))),
    ("authorize cny vs CNY (lowercase)", lambda: authorize(grant(50, "CNY"), op(50, "cny"))),
    ("entails 30<=50", lambda: entails(grant(50, "CNY"), op(30, "CNY"))),
    ("contains child 30<=50", lambda: contains(grant(50, "CNY"), grant(30, "CNY"))),
    ("contains child 60>50", lambda: contains(grant(50, "CNY"), grant(60, "CNY"))),
    ("contains child USD", lambda: contains(grant(50, "CNY"), grant(30, "USD"))),
    (
        "contains child adds key",
        lambda: contains(grant(50, "CNY"), grant(30, "CNY", {"as_of": "2026-10-15"})),
    ),
]


def nested_cases():
    """富写法：param_bounds.nested 给 value 上限、给 unit 一个枚举。"""
    g = {
        "id": CID,
        "param_bounds": {
            "amount": {
                "nested": {
                    "value": {"max": 5000},
                    "unit": {"enum": ["CNY", "USD"]},
                }
            }
        },
    }

    def o(v, u):
        return {"id": CID, "params": {"amount": {"value": v, "unit": u}}}

    narrow = {
        "id": CID,
        "param_bounds": {
            "amount": {"nested": {"value": {"max": 1000}, "unit": {"enum": ["CNY"]}}}
        },
    }
    bad = {
        "id": CID,
        "param_bounds": {
            "amount": {"nested": {"value": {"max": 1000}, "unit": {"enum": ["EUR"]}}}
        },
    }
    return [
        ("param_bounds value 3000 CNY", lambda: authorize(g, o(3000, "CNY"))),
        ("param_bounds value 6000 CNY", lambda: authorize(g, o(6000, "CNY"))),
        ("param_bounds value 3000 EUR", lambda: authorize(g, o(3000, "EUR"))),
        ("param_bounds contains narrow", lambda: contains(g, narrow)),
        ("param_bounds contains EUR", lambda: contains(g, bad)),
    ]


def main():
    print("CLC_REVISION =", CLC_REVISION)
    for name, fn in CASES + nested_cases():
        try:
            result = json.dumps(fn(), ensure_ascii=False, separators=(",", ":"))
            print(f"{name:38s} -> {result}")
        except Exception as exc:  # noqa: BLE001
            print(f"{name:38s} -> EXC {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
