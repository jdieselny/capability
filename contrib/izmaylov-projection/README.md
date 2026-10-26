# Izmaylov permission/receipt/log → CLC evidence projection（签名阶段，2026-10-25）

来源：`draft-izmaylov-agent-permission-receipts-00` §4（签名）、§5（permission）、
§6（action receipt）、§9（log 与 tree head）、§10（三个验证答案）。

探针分两段：

1. **签名/日志阶段**：permission 的 passkey 签名、receipt 的 Ed25519（以及可选的
   ML-DSA-87）签名、log 的签名 tree head 与 inclusion。
2. **权限包含性阶段**：actions / never / with / 有效期 / limits（max、each、
   count、per）——这一步是**真实算术**，按 §10.2 在有序 log 上计算累计与计数。
3. **条件阶段**：`requires` 的 countersignature / approval，以及 cancellation；
   存在性、字段匹配、approval 复用、日期先后与 cancellation 由探针计算，
   签名有效性是 modelled boolean。
4. **log 包含性阶段**：真实的 SHA-256 Merkle 证明校验（叶子 → 路径 → 根），
   不是 modelled outcome。
5. **log append-only 阶段**：从叶子集合重算旧/新两个 Merkle 根，与两个签名
   tree head 比对，验证新树是旧树的扩展。

passkey origin/rpId 绑定、acknowledgement、time-stamped cancellation 与 RFC 6962
wire-format 一致性证明仍未投影，作为 residual 列出。

输入是**合成的 Izmaylov 形态证据**，不是生产字节；探针不实现 WebAuthn、
Ed25519 或 ML-DSA，每个 native check 的 outcome 是"真实 verifier 已经跑完"之后
的结果。

## 为什么选它

§10.1 的“三个答案”和 CLC-E 证据模型（native check 结果）几乎一一对应：

| Izmaylov | 本探针输出 |
|---|---|
| 是否发现问题？ | `problem=none\|found`（任一 `failed`） |
| 是否全部验证？ | `verified=all\|partial`（等于 `NativeChecksComplete` 且无 `unavailable`） |
| 动作是否在 permission 内？ | `eligible` + CLC `Satisfaction`（当前阶段只到签名门槛） |

`unavailable` 与 `failed` 必须分开：verifier 没实现 ML-DSA-87 时不能把 receipt
判成“签名失败”，只能报“这项验证没做”。这正是 `IZM-SIG-003`。

## native checks

| check id | 覆盖 |
|---|---|
| `izmaylov:permission-signature` | principal 对 permission 的 passkey 签名 |
| `izmaylov:receipt-signature` | agent 对 receipt 的签名（Ed25519；ML-DSA-87 未实现时 → unavailable） |
| `izmaylov:log-tree-head` | 签名 tree head + receipt 的 inclusion proof |

三者都绑定各自的 artifact digest；receipt 的签名通过时才产生
`izmaylov-receipt` Fact，CLC requirement（freshness 300s）随之求值。

## 实跑（`out-probe.txt`，40/40 PASS）

| case | 场景 | 结果 |
|---|---|---|
| `IZM-SIG-001` | permission/receipt/log 全部验证通过 | complete，eligible，SATISFIED |
| `IZM-SIG-002` | receipt 签名验证后被拒 | `failed`；problem=found，verified=all，无 Fact |
| `IZM-SIG-003` | 未实现 ML-DSA-87 | receipt `unavailable`；problem=none，verified=partial |
| `IZM-SIG-004` | permission passkey 签名被拒 | `failed`；problem=found |
| `IZM-SIG-005` | tree head key 不可用 | `unavailable`；verified=partial |
| `IZM-SIG-006` | 漏报 log 检查 | incomplete；不推断 |
| `IZM-SIG-007` | permission 签名无法验证 | `unavailable`；problem=none |

## 权限包含性阶段（`IZM-PERM-*`，10/10 PASS）

四条 native check，全部绑定 receipt 的 artifact digest：

| check | 覆盖 | 失败/不可用示例 |
|---|---|---|
| `izmaylov:action-allowed` | action ∈ `actions`，且不被 `never` 禁止 | `action-not-allowed`、`prohibited` |
| `izmaylov:party-allowed` | receipt 的服务在 permission 的 `with` 中 | `party-not-allowed` |
| `izmaylov:validity-window` | `validFrom <= when < validUntil` | `outside-valid-time` |
| `izmaylov:limits` | max / each / count / per，按 log 顺序累计 | `amount-missing`、`over-*-limit` |

语义要点：

- action 不在 permission 中时，limits 对它是 **`not_applicable`**（不是 failed），
  由 profile 的 `notApplicableAuthority` 授权；该结果不产生 Fact；
- log 未读完时 limits 是 **`unavailable`**（总量无法结算），不是 failed；
- `amount-missing` 与 `over-*-limit` 都是 §10.2 的 finding，映射为 `failed` 并保留
  原始 reason（`izmaylov:over-each-limit` 等）；
- 金额与周期计算是 verifier 对已给 log 的算术，**不是** executor 的
  reserve/commit 记账。

| case | 场景 | findings |
|---|---|---|
| `IZM-PERM-001` | action/party/window/limits 全部通过 | none，SATISFIED |
| `IZM-PERM-002` | 周期累计超过 max | `over-period-limit` |
| `IZM-PERM-003` | 单笔超过 each，同时超过周期 max | `over-each-limit+over-period-limit` |
| `IZM-PERM-004` | 周期内笔数超过 count | `over-count-limit` |
| `IZM-PERM-005` | action 不在 permission | `action-not-allowed`（limits = not_applicable） |
| `IZM-PERM-006` | action 被 never 禁止 | `action-not-allowed+prohibited` |
| `IZM-PERM-007` | 服务不在 with | `party-not-allowed` |
| `IZM-PERM-008` | receipt 超出有效期 | `outside-valid-time` |
| `IZM-PERM-009` | 有单位限额但 receipt 没有金额 | `amount-missing` |
| `IZM-PERM-010` | log 未读完 | `limits-unavailable`（limits = unavailable） |

## 条件阶段（`IZM-COND-*`，11/11 PASS）

三条 native check：

approval 的匹配按 §6 比较 `slip`（permission 摘要）、`action`、`amount`、`with`
与 `details`（按文件名索引的 sha256 集合）。

| check | 覆盖 | finding 示例 |
|---|---|---|
| `izmaylov:countersignature` | `requires[need=countersignature]` 是否适用、服务是否有 keys、stub 是否匹配、签名是否有效 | `countersignature-missing`、`-not-possible`、`-wrong-stub`、`-invalid` |
| `izmaylov:approval` | `requires[need=approval]` 是否适用、approval 存在、字段匹配、是否复用、签名方法、日期 | `approval-missing`、`-mismatch`、`-reused`、`-invalid`、`-dated-after-stub`、`-unavailable` |
| `izmaylov:cancellation` | 是否存在 sound cancellation，且 receipt 在其之后 | `after-cancellation` |

语义要点：

- 带 `above` 的条件只在 receipt 金额同单位且高于阈值时才适用（`IZM-COND-003`）；
- 服务没有 keys 时 countersignature 无法执行 → `countersignature-not-possible`，
  按 §10.2 是 finding，映射为 `failed`（这是 permission 缺陷，不是取不到数据）；
- approval 的签名方法未实现 → `approval-unavailable`，对应 `unavailable`，
  与 `approval-invalid`（签名验证后被拒）区分；
- cancellation 按时间代理 log 顺序：`cancellation.when <= receipt.when` 视为
  receipt 在其之后；晚于 receipt 的 cancellation 不产生 finding（`IZM-COND-011`）。

| case | 场景 | findings |
|---|---|---|
| `IZM-COND-001` | countersignature + approval 都存在且匹配 | none，SATISFIED |
| `IZM-COND-002` | 缺少必需的 countersignature | `countersignature-missing` |
| `IZM-COND-003` | 金额低于 countersignature 阈值 | none（条件不适用） |
| `IZM-COND-004` | 服务没有 keys | `countersignature-not-possible` |
| `IZM-COND-005` | 缺少必需的 approval | `approval-missing` |
| `IZM-COND-006` | approval 金额不匹配 | `approval-mismatch` |
| `IZM-COND-007` | approval id 被之前的行复用 | `approval-reused` |
| `IZM-COND-008` | approval 晚于 receipt 超过 300 秒 | `approval-dated-after-stub` |
| `IZM-COND-009` | approval 签名方法未实现 | `approval-unavailable`（unavailable） |
| `IZM-COND-010` | receipt 在 sound cancellation 之后 | `after-cancellation` |
| `IZM-COND-011` | cancellation 晚于 receipt | none，SATISFIED |
| `IZM-COND-012` | approval 的 `slip` 不匹配 permission | `approval-mismatch` |
| `IZM-COND-013` | approval 的 `details` 不匹配 receipt | `approval-mismatch` |

## log 包含性阶段（`IZM-LOG-*`，5/5 PASS）

一条 check：`izmaylov:log-inclusion`。探针真实计算：

```text
node = leaf
for step in proof:
    node = sha256(sibling || node)   # side=left
    node = sha256(node || sibling)   # side=right
valid = (node == signed tree-head root)
```

| case | 场景 | findings |
|---|---|---|
| `IZM-LOG-001` | 证明与签名 tree head 一致 | none，SATISFIED |
| `IZM-LOG-002` | leaf 不属于该树 | `inclusion-mismatch` |
| `IZM-LOG-003` | 证明算出的根与 tree head 不同 | `inclusion-mismatch` |
| `IZM-LOG-004` | 没有提供证明 | `inclusion-unavailable`（unavailable） |
| `IZM-LOG-005` | 路径 side 非法 | `inclusion-invalid` |

缺失证明是 `unavailable`（无法验证包含性），不是 `failed`；side 非法是结构错误
（`failed`）。

## log append-only 阶段（`IZM-APPEND-*`，5/5 PASS）

一条 check：`izmaylov:log-append-only`。探针从叶子集合真实重算：

```text
old_root' = merkleRoot(leaves[:old_size])
new_root' = merkleRoot(leaves[:new_size])
valid     = (old_size <= new_size) && old_root' == signed_old && new_root' == signed_new
```

| case | 场景 | findings |
|---|---|---|
| `IZM-APPEND-001` | 新树是旧树的扩展 | none，SATISFIED |
| `IZM-APPEND-002` | 旧尺寸以下的历史被改写 | `consistency-mismatch` |
| `IZM-APPEND-003` | 新树声称的叶子数少于旧树 | `consistency-truncated` |
| `IZM-APPEND-004` | 没有提供叶子集合 | `consistency-unavailable`（unavailable） |
| `IZM-APPEND-005` | 重算的旧根与签名旧头不同 | `consistency-mismatch` |

注意：这是**按叶子重算根**的检查，不是验证 RFC 6962 一致性证明的 wire format；
后者仍未实现，写在 residual 里。

## 未投影/未验证

- 权限包含性（action 是否在 `actions`、`never`、limits、有效期、party）；
- approval 的 300 秒规则之外的时间语义；
- cancellation acknowledgement 与 time-stamped cancellation 的更严格规则；
- RFC 6962 wire-format 的一致性证明（当前按叶子集合重算，需要全部叶子）；
- passkey 的 origin/rpId 绑定（WebAuthn verifier 义务）；
- `never` 的 Appendix B 共享动作目录（探针只做精确名与 `prefix.*`）；
- executor 的 reserve/commit 记账（enforcement 侧，永远不能写成证据成功）。

这些都不改变“签名/日志验证”这一阶段的结论；下一阶段应就 permission
containment 单独建 probe，而不是把 amount 记账塞进 native check。

## 运行

```sh
(cd ../register && go run ./cmd/izmaylov-projection-probe)
```
