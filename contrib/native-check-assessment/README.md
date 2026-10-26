# Native-check assessment — 跨语言语料（2026-10-25）

`NativeCheckExpectation` / `NativeCheckAssessment` 的语言中立回归语料。三个
runner（Go / Python / TypeScript）消费同一份 `cases-v1.json`，输出必须逐字
节一致。

范围只有"期望清单与实际结果的比对"：不评估 CLC requirement、不实现 OASNT
JWT、不做签名或信任判断。它是 M5 的跨语言一致性证据，不是 CLC-E conformance
声明。

## 语料

`cases-v1.json` 每个 case：

| 字段 | 含义 |
|---|---|
| `id` | 稳定 case ID（`NCA-001`…） |
| `name` | 说明 |
| `expected` | `checkId` / `componentType` / `evidenceDigest` 的期望清单 |
| `results` | 实际报告的结果（`checkId` / `componentType` / `evidenceDigest` / `outcome`） |
| `want` | `complete=…,missing=…,unexpected=…,conflicting=…` |

判定规则（三实现一致）：

1. 空清单永远不是 complete；
2. `missing` = 声明了但没有任何结果的 component；
3. `unexpected` = 未在清单中声明的结果（仅在清单非空时统计）；
4. `conflicting` = 同一 component 出现多个不同 outcome；
5. `complete = 清单非空 && missing == 0 && unexpected == 0 && conflicting == 0`。

`failed` / `unavailable` / `not_applicable` 都是显式结果，仍算 complete；
complete 描述"报告完整"，不描述"检查通过"。

## 运行

```sh
# 从 capability 仓库根目录
export CLC_NATIVE_CHECK_CASES="$PWD/contrib/native-check-assessment/cases-v1.json"

python3 contrib/native-check-assessment/probe.py
node contrib/native-check-assessment/probe.mjs
(cd ../register && go run ./cmd/native-check-vectors-run)
```

三个命令都输出同样的 9 行：

```
PASS NCA-001 ... want=complete=true,missing=0,unexpected=0,conflicting=0 got=...
```

`tools/check_projection_cases.py` 会在 `--register-dir` 模式下重跑三者并比对
逐字节输出；没有该参数时只校验签入的 `out-*.txt`。

## 这证明了什么

- 同一份期望/结果语料在 Go、Python、TypeScript 下得到相同的
  complete/missing/unexpected/conflicting；
- 同类型多构件漏报、未声明结果、冲突结果、空清单这些容易实现不一致的边界，
  三语言行为一致。

不证明：CLC requirement 求值、四值 outcome 的 eligibility 规则、OASNT 或
EMILIA 的完整状态模型、签名与信任——这些仍分别由 Go 探针/测试和 M3/M4 机制
覆盖。
