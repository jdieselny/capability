# Gilda audit record → CLC result vocabulary（2026-10-17）

第二个投影探针。第一个（`contrib/emilia-projection`）测的是 **Requirement 侧**：
把 AEC 的证据要求映射成 `CLC-REQUIREMENT-v1` 并求值。这一个测 **Result 侧**：
一条审计记录里的决定、评估状态与派生出的 agreement，能不能被诚实地读成 CLC 的裁决。

输入字段核对自 `draft-gilda-wimse-agent-audit-record-02`：
§5.3（`decision.reported`、`agreement` 的取值）、§6.5（not-evaluated 与
`unavailableInput`），检查日期 2026-10-17。该草案后来改名为
`draft-gilda-audit-agent-audit-record`，现行 `-00` 仍保留 §5.4 Evaluation
（`evaluation.status`、`unavailableInput`、`decision.reported`），所以
spec 的 `[GILDA]` 引用用新名 `-00`，本探针的核对对象是改名前的 `-02`。

## 映射

| Gilda 成员 | CLC | 说明 |
|---|---|---|
| `decision.reported = permit`（evaluated） | `allow` | 直接对应 |
| `decision.reported = deny`（evaluated） | `deny` | 直接对应 |
| `decision.reported = permit-with-conditions` | `allow_unresolved` | 条件作为残留义务 |
| `evaluation.status = not-evaluated` + permit | `allow_unresolved` + `unavailableInput` | **绝不读成 allow**（该记录是 fail-open 的） |
| `evaluation.status = not-evaluated` + deny | `deny` | fail-closed |
| `agreement`（agree/disagree/not-exercised/indeterminate/one-sided） | — | **无 CLC 轴**：它是"决定 × 观测效果"之间的关系 |
| `effect.observed` | — | 效果侧事实；CLC 的裁决不表达效果是否发生 |

## 实跑（`out-probe.txt`，6/6 PASS）

| id | 记录 | CLC | 残留 |
|---|---|---|---|
| g-1 | permit / evaluated / agree | allow | — |
| g-2 | permit-with-conditions | allow_unresolved | conditions |
| g-3 | deny / disagree | deny | agreement=disagree |
| g-4 | not-evaluated / permit | allow_unresolved | unavailableInput: standing source |
| g-5 | not-evaluated / deny | deny | unavailableInput: consumption state |
| g-6 | permit / one-sided / effect not-observed | allow | agreement=one-sided |

## 结论

1. **决定与评估状态投影得很干净**：`decision.reported` × `evaluation.status`
   四个组合都有确定归属，且 not-evaluated + permit 不会被误读成 allow。
2. **`agreement` 是第二个"关系型"缺口**，与 AEC 的 `required_bindings` 同类：
   它比较的是两个 artifact（决定 vs 效果），而 CLC 的 Result 是一个裁决，
   没有"两者是否一致"这个轴。
3. 由此可以给 binding profile 一条通用规则，而不是逐案处理：
   **事实之间、artifact 之间的关系一律不在投影内**——载体必须把它归一化成一个
   事实/成员，或在投影之外执行；CLC 不得把未检查的关系当作满足。

运行：

```sh
(cd ../register && go run ./cmd/gilda-projection-probe)
```
