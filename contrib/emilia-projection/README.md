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
| 动作形态（`tool.call.1`，`occurrence_id` 可选；只测 CLC material projection，不解析 CAID wire identifier） | `draft-schrock-canonical-action-identifier-05` §4.7 | 2026-10-17 |

运行：

```sh
(cd ../register && go run ./cmd/emilia-projection-probe)
```

## 映射规则（探针实现的）

| AEC 字段 | CLC | 说明 |
|---|---|---|
| `expression` | `"(<expression>) AND <binding-role>…"` | 原表达式整体加括号，再与派生 binding 角色合取 |
| `freshness_sec[role]` | `constraints += {role, varwof/evidence-v1:freshness:sec:<n>}` | 每角色一条；角色必须通过 pinned RoleMap |
| `role_constraints[type=distinct-subject-quorum]` | `constraints += {role, quorum:distinct:<threshold>}` | `component_type` 必须通过 pinned RoleMap |
| `requirement_id` | `requirement_id` | 原样 |
| `@version` | `CLC-REQUIREMENT-v1` | 版本改写 |
| `purpose` | `purpose` | 保留为描述性字段，不参与求值 |
| `status_required` | `RequiredNativeChecks` | AEB/载体负责状态查询，不作为证据 Fact |
| `required_bindings` | 新角色 `ep:binding:<relation>:<SHA-256(triple)>` | native verifier 输出派生事实；原 `ep-quorum` 和 `policy-permit` 均保留 |
| `subject_id_source` | `RequiredNativeChecks` | AEC-08 要求值为 `native-verifier`；CLC 不自行推断 |

## 实际求值结果（`out-probe.txt`，13/13 PASS）

| # | 事实 | 期望 | 实际 |
|---|---|---|---|
| 1 | 两名已验证批准 + 一份许可 + 派生 binding 事实 | SATISFIED | SATISFIED |
| 2 | 其中一名批准 `verified=false` | UNSATISFIED | UNSATISFIED（`quorum:distinct_subjects=1<threshold=2`） |
| 3 | binding 事实很新，但一条批准已超过 300s | UNSATISFIED | UNSATISFIED（`freshness:stale`） |
| 4 | 原 quorum/permit 都在，但没有派生 binding 事实 | UNSATISFIED | UNSATISFIED（`requirement:expression_false`） |
| 5 | 事实按 `component_type` 字面标注为 `ep-human-authorization` | UNSATISFIED | UNSATISFIED（`requirement:expression_false`） |

CLC 动作身份（CAID 的 `tool.call.1` 形态 → CLC §4.2；不解析 CAID wire identifier）：

| 场景 | 期望 | 实际 |
|---|---|---|
| 同 tool+args，观测里多一个 `occurrence_id` | MATCH | MATCH（非 material 字段不携带身份） |
| args 的 amount 改成 3001 | NOT_EQUIVALENT | NOT_EQUIVALENT |

## 探针暴露的跨层义务

1. **角色命名不一致**：表达式用的是 `ep-quorum`，而 `role_constraints.component_type`
   写的是 `ep-human-authorization`。草案没有说明"哪个事实类型填充 `ep-quorum`
   这个表达式角色"；探针把 quorum 约束挂到 `ep-quorum` 上，并把这一假设列出来。
   ⇒ binding profile 必须给出角色映射表，不能留给实现猜。
2. **`status_required`**：要求"新鲜的状态结果"，CLC 没有对应约束类型；只能由
   AEB/载体执行，并作为 `RequiredNativeChecks` 返回。该检查不能由证据 Fact
   代替。
3. **`required_bindings`**（`policy-permit -permits-> ep-quorum`）：CLC
   不直接比较事实间关系，因此由 native verifier 把它归一化为
   一个由三元组稳定派生的角色。requirement 改写为
   `(ep-quorum AND policy-permit) AND <binding-role>`；关系事实只补充，
   不替代 quorum。若 verifier 不输出该事实，表达式为假。
   - 派生事实绑定 source/target artifact 摘要、action、verifier/trust 结果、
     distinct subjects、原始证据时间和 status 快照。
   - freshness 取原始证据和状态，而不是关系重算时间；重算关系不能刷新旧批准。
4. **`subject_id_source`**：AEC-08 要求主体标识来自 `native-verifier`；CLC
   只消费受保护事实中的 `subject`，不自行推断。

### binding identity 派生检查

`out-probe.txt` 还检查 canonical relation tuple 的 base64url SHA-256 与固定
subject 一致，并分别修改 source artifact、target artifact、action 和 status
快照，确认四种修改都会改变 subject。

CLC core 把 binding subject 当作不透明值：只要 native verifier 给出
`verified=true` 的 `ep:binding:permits` fact，CLC 就接受该 role。因此
source/target/action/status 的实际绑定由 native verifier 负责，不由 CLC
重新计算。probe 用 `EMI-BIND-006` 明确记录这条边界，避免把 role 在场误写成
CLC 已验证关系内容。

Python 和 TypeScript runner（`probe.py`、`probe.mjs`）读取 register 仓库中的
同一 `emilia-binding-fixture-v1.json`，并输出同样的 13 个 case ID、
`want` 和 `got`。Go 通过 `go:embed` 读取该 fixture。

## 结论

投影模型对 **freshness / quorum / 表达式组合** 是够用的。关系型证据绑定
（`required_bindings`）通过 native-verifier 派生事实处理，且不删除或替代原始
quorum。status、revocation、subject resolution 和关系重算不得刷新旧证据的规则
仍是 binding profile 的显式义务。CLC 验证 role、`verified` 和约束；relation
tuple 的身份及来源由 native verifier 和 binding profile 验证。
