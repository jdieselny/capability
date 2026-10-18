# 对称语料 v1（授权 ⇄ 证据）

`data/_vectors/clc-v1/symmetry-vectors.json` —— 48 个向量，外加两个性质测试。
运行器：`register/internal/symmetryvectors`（`TestSymmetryVectors`、
`TestSymmetryIdempotent`、`TestMultiGrantOrderIndependent`）。

请全新运行——语料在运行时读取，因此语料被改动后 Go 的测试缓存不会失效：

```
cd register && go test -count=1 ./internal/symmetryvectors/
```

每个向量携带**同一个 action 的两侧**：授权关系所裁决的授权/operation，以及执行
之后被观察到的 action（以及在相关处的证据约束或 requirement，以及事实）。
运行器断言的是这一对，而不是两个互不相关的结果。

## 语料钉定了什么

- **权威以集合为界，证据同一性是精确的。** 授权界内的 operation 获得授权；
  同一 operation 以不同的值执行则是不同的 action（`sym-010`、`sym-034`）。
- **多出来的键在两侧表现不同。** 未声明的 operation 参数导致 deny
  （`undeclared_param: <key>`，`sym-009`）；未声明的观察字段不携带同一性
  （`sym-002`）。
- **多授权聚合是“任一覆盖即可”**（`sym-033`），而当另一份授权也覆盖时，
  覆盖授权的约束仍被保留（`sym-035`）。
- **链式包含逐跳进行，随后由交集为 operation 定界**（`sym-037`、`sym-039`）。
  放宽边界是 `params_not_narrower`，而不是 `child_exceeds_parent`（`sym-038`）。
- **约束并集是真正的并集**：链跳（`sym-041`）、仅根部的残留（`sym-042`）、
  多授权（`sym-043`）与跨类型（`sym-044`）都保留每一项残留义务。
- **已求值与残留是封闭的二分**：`max_rows` 被求值（`sym-045`/`sym-046`）；
  `time:window` 与 `network:cidr` 作为残留被携带。`consumption:once` 在核心中
  是 `unknown`（`sym-023`）——由执行点裁决它。
- **§8.1 与 §8.2 之间不作自动转换**：作为证据约束提交的授权侧 `time:window`
  会被拒绝（`invalid_evidence_constraint`，`sym-027`）。
- **关系不可表达。** 端点在场并不是该关系（`sym-047`）；一旦载体把关系归一化为
  事实，该角色即可正常求值（`sym-048`）。见 `docs/evidence-relation-normalization.md`。
- **被拒绝的 action 不产生证据**（`sym-012`、`sym-013`、`sym-036`、`sym-038`、
  `sym-039`、`sym-046`）。

## 向量

### 同一性与 material 投影（§4.2、§4.3、§6.2、§6.4）

| id | 条款 | 授权 | 匹配 | 证据 |
|---|---|---|---|---|
| sym-001 | §4.2/§6.4 + §9 | allow | MATCH |  |
| sym-002 | §4.2 未声明字段不携带同一性 | allow | MATCH |  |
| sym-003 | §4.2 material 内容 | allow | NOT_EQUIVALENT |  |
| sym-004 | §4.2 缺失 material 字段 | allow | action_not_matchable |  |
| sym-005 | §6.2 数字同一性 | allow | MATCH |  |
| sym-006 | §4.2 + RFC 8785 §3.2.2.2（不做 HTML 转义） | allow | MATCH |  |
| sym-007 | §4.2 material 内容 | allow | NOT_EQUIVALENT |  |
| sym-008 | §6.4 第 1 步：不同的 action 类型 | allow | INDETERMINATE |  |
| sym-014 | §6.4 第 1 步：跨类型 | allow | INDETERMINATE |  |
| sym-015 | §6.4 跨 suite | allow | INDETERMINATE |  |

### 两侧不同之处（§9 键封闭 vs §4.2，集合界定的权威 vs 精确同一性）

| id | 条款 | 授权 | 匹配 | 证据 |
|---|---|---|---|---|
| sym-009 | §9.1 第 7 层 vs §4.2 | deny/undeclared_param: note | MATCH |  |
| sym-010 | §4.2 集合界定的权威 vs 精确同一性 | allow | NOT_EQUIVALENT |  |

### 同一个 action 携带的证据义务（§8.2、§10、AEB §5.6、AEC §4）

| id | 条款 | 授权 | 匹配 | 证据 |
|---|---|---|---|---|
| sym-013 | §9 超界 deny；无证据 | deny/params_exceed_grant | NO_EVIDENCE |  |
| sym-016 | §8.4 残留 + §4.2 同一性 | allow_unresolved | MATCH |  |
| sym-017 | §8.4 残留 vs §8.2 显式 freshness | allow_unresolved | MATCH | varwof/evidence-v1:freshness:sec:60 -> satisfied |
| sym-018 | §10 第 4 步：freshness 边界 | allow | MATCH | varwof/evidence-v1:freshness:sec:60 -> violated |
| sym-019 | AEC §4 role_constraints → §8.2 quorum | allow | MATCH | varwof/evidence-v1:quorum:distinct:2 -> satisfied |
| sym-020 | §8.2 quorum 统计不同的 subject | allow | MATCH | varwof/evidence-v1:quorum:distinct:2 -> violated |
| sym-021 | AEB §5.6 exclusion:initiator | allow | MATCH | varwof/evidence-v1:exclusion:initiator -> violated (exclusion:initiator_is_approver) |
| sym-022 | AEB §5.6 exclusion:initiator | allow | MATCH | varwof/evidence-v1:exclusion:initiator -> satisfied |
| sym-023 | §10 边界：consumption 不由核心求值 | allow | MATCH | varwof/evidence-v1:consumption:once -> unknown (evidence_not_core_evaluated) |
| sym-024 | §10 资格：只有已验证的事实计入 | allow | MATCH | varwof/evidence-v1:freshness:sec:60 -> violated |
| sym-025 | §10 第 4 步：缺失的 issued_at 使 freshness 失败 | allow | MATCH | varwof/evidence-v1:freshness:sec:60 -> violated |
| sym-026 | AEB §5.6：exclusion 需要边界身份 | allow | MATCH | varwof/evidence-v1:exclusion:initiator -> unknown (exclusion:identity_not_supplied) |
| sym-027 | §8.2：不得由 §8.1 约束自动转换 | allow_unresolved | MATCH | varwof/constraint-v1:time:window:[{"start":"09:00","end":"17:00"}] |
| sym-028 | §10 第 4 步：没有合格事实即边界失败 | allow | MATCH | varwof/evidence-v1:freshness:sec:60 -> violated (freshness:no_eligible_fact) |
| sym-029 | AEC §4 role_constraints：只有已验证的 subject 计入 | allow | MATCH | varwof/evidence-v1:quorum:distinct:2 -> violated |
| sym-030 | §10 第 4 步：未来的签发时刻不算新鲜 | allow | MATCH | varwof/evidence-v1:freshness:sec:60 -> violated (freshness:future_issued) |
| sym-031 | §8.4 残留 vs §10 证据失败 | allow_unresolved | MATCH | varwof/evidence-v1:freshness:sec:60 -> violated (freshness:stale) |
| sym-032 | AEB §5.6 exclusion:executor | allow | MATCH | varwof/evidence-v1:exclusion:executor -> violated (exclusion:executor_is_approver) |

### 多授权聚合（§9、§7 规则 3）

| id | 条款 | 授权 | 匹配 | 证据 |
|---|---|---|---|---|
| sym-011 | §7 交集，然后 §4.2 | allow | MATCH |  |
| sym-033 | §9 三份授权上的任一覆盖 | allow | MATCH |  |
| sym-034 | §9 任一覆盖 + §4.2 精确同一性 | allow | NOT_EQUIVALENT |  |
| sym-035 | §9 残留并集：即使另一份授权也覆盖，覆盖授权的约束仍被保留 | allow_unresolved | MATCH |  |
| sym-036 | §9 没有覆盖授权；无证据 | deny/params_exceed_grant | NO_EVIDENCE |  |
| sym-043 | §7 规则 3：多授权约束并集两者都保留 | allow_unresolved | MATCH |  |

### 委派链（§13.11、§13.4.3、§7 规则 3）

| id | 条款 | 授权 | 匹配 | 证据 |
|---|---|---|---|---|
| sym-012 | §13.11 链交集定界；deny 后无证据 | deny/params_exceed_grant | NO_EVIDENCE |  |
| sym-037 | §13.11 三跳链：逐跳 Contains，然后交集 | allow | MATCH |  |
| sym-038 | §13.4.3 放宽边界的跳被拒绝；无证据 | deny/params_not_narrower | NO_EVIDENCE |  |
| sym-039 | §13.11 operation 高于链交集 | deny/params_exceed_grant | NO_EVIDENCE |  |
| sym-040 | §13.11 带残留约束的链 | allow_unresolved | MATCH |  |
| sym-041 | §7 规则 3 / §13.11：链约束并集保留两跳 | allow_unresolved | MATCH |  |
| sym-042 | §8.4 从两跳链根部携带的残留 | allow_unresolved | MATCH |  |
| sym-044 | §7 规则 3 / §8.4：跨类型残留并集 | allow_unresolved | MATCH |  |
| sym-045 | §8.1：max_rows 由核心求值，不是残留 | allow | MATCH |  |
| sym-046 | §8.1：超出被求值的 max_rows 边界 | deny/max_rows:violated | NO_EVIDENCE |  |

### 制品之间的关系（§11）

| id | 条款 | 授权 | 匹配 | 证据 |
|---|---|---|---|---|
| sym-047 | §11：制品之间的关系不可表达 | allow | MATCH | requirement -> UNSATISFIED (requirement:expression_false) |
| sym-048 | §11：归一化后的关系是一个事实，随后即可求值 | allow | MATCH | requirement -> SATISFIED |

## 性质

- `TestSymmetryIdempotent` —— 相同的输入求值两次，给出相同的裁决与注记
  （P3、P5）。
- `TestMultiGrantOrderIndependent` —— 对含有两份及以上授权的非链向量，
  反转授权顺序不改变结果（P11）。它目前覆盖六个向量。
