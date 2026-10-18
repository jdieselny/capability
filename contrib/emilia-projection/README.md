# EMILIA → CLC evidence projection probe（2026-10-17）

把 EMILIA 的证据侧对象按"投影"方式映射进 CLC，并**实际求值**，用来检验
投影模型（Observation / Fact / Requirement / Result）是否够用。

不是 conformance 套件，是一个探针：输入取自已发布草案的公开示例，输出见
`out-probe.txt`。

## 输入及其出处

| 对象 | 出处 | 检查日期 |
|---|---|---|
| `EP-AEC-REQUIREMENT-v1` 示例（`treasury-wire-evidence@7`） | `draft-schrock-ep-authorization-evidence-chain-08` §4 | 2026-10-17 |
| 证据事实的形态（verified / subject / issued_at） | `draft-schrock-action-evidence-boundary-07` §5.2、§5.6 | 2026-10-17 |
| 动作身份（`tool.call.1`，`occurrence_id` 可选） | `draft-schrock-canonical-action-identifier-05` §4.7 | 2026-10-17 |

运行：

```sh
cd register && go run ./cmd/emilia-projection-probe
```

## 映射规则（探针实现的）

| AEC 字段 | CLC | 说明 |
|---|---|---|
| `expression` | `expression` | 文法兼容（AND/OR/括号/identifier），直接沿用 |
| `freshness_sec[role]` | `constraints += {role, varwof/evidence-v1:freshness:sec:<n>}` | 每角色一条 |
| `role_constraints[type=distinct-subject-quorum]` | `constraints += {role, quorum:distinct:<threshold>}` | 角色取 `component_type`（见下方残差 1） |
| `requirement_id` | `requirement_id` | 原样 |
| `@version` | `CLC-REQUIREMENT-v1` | 版本改写 |
| `purpose` | — | 描述性，丢弃 |
| `status_required` | — | 载体负责（AEB 的状态查询），CLC 无对应 |
| `required_bindings` | — | **无法表达**：事实之间的"关系"（`permits`）不在 CLC 文法里 |
| `subject_id_source` | — | 载体负责（谁提供主体标识） |

## 实际求值结果（`out-probe.txt`）

| # | 事实 | 期望 | 实际 |
|---|---|---|---|
| 1 | 两名已验证批准 + 一份许可，均在新鲜期内 | SATISFIED | SATISFIED |
| 2 | 其中一名批准 `verified=false` | UNSATISFIED | UNSATISFIED（`quorum:distinct_subjects=1<threshold=2`） |
| 3 | 一条批准的 `issued_at` 超过 300s | UNSATISFIED | UNSATISFIED（`freshness:stale`） |
| 4 | 事实按 `component_type` 字面标注为 `ep-human-authorization` | UNSATISFIED | UNSATISFIED（`requirement:expression_false`） |

动作身份（CAID → CLC §4.2）：

| 场景 | 期望 | 实际 |
|---|---|---|
| 同 tool+args，观测里多一个 `occurrence_id` | MATCH | MATCH（非 material 字段不携带身份） |
| args 的 amount 改成 3001 | NOT_EQUIVALENT | NOT_EQUIVALENT |

## 探针暴露的五个残差（binding profile 必须表态）

1. **角色命名不一致**：表达式用的是 `ep-quorum`，而 `role_constraints.component_type`
   写的是 `ep-human-authorization`。草案没有说明"哪个事实类型填充 `ep-quorum`
   这个表达式角色"；探针把 quorum 约束挂到 `ep-quorum` 上，并把这一假设列出来。
   ⇒ binding profile 必须给出角色映射表，不能留给实现猜。
2. **`status_required`**：要求"新鲜的状态结果"，CLC 没有对应约束类型；只能由
   AEB/载体执行，并作为残差上报。
3. **`required_bindings`**（`policy-permit -permits-> ep-quorum`）：**CLC 表达不了**。
   CLC 的 requirement 是"角色布尔表达式 + 每角色约束"，没有**事实间关系**。
   这是目前发现的第一个真正的表达缺口，不是 profile 能补的——要么 AEC 先做关系
   归一化（把关系结果变成一个事实），要么 CLC 将来加一个受限的关系项。
4. **`subject_id_source`**：主体标识由谁提供属于载体语义，CLC 只消费 `subject`。
5. **`purpose`**：描述性字段，丢弃（不应影响求值，AEC 自己也这么写）。

## 结论

投影模型对 **freshness / quorum / 表达式组合** 是够用的，且结果与 AEC 的语义
一致；**关系型证据绑定（required_bindings）是唯一的硬缺口**。这一点应在
binding profile 的"不能表达什么"一节里明写，而不是悄悄丢掉。
