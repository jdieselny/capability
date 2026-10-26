# OASNT approval → CLC evidence projection（2026-10-25 更新）

来自一个与 EMILIA 独立的体系：`draft-thallapelly-oasnt-02`（OASNT，一次性
人工批准令牌）。它把"人类批准了哪个动作"绑定在令牌里，而不是用两个证据
artifact 之间的关系来表达。

字段核对自 OASNT-02：§5.3（claims）、§6.2（canonical action 与 `adg`）、
§7（验证步骤）。检查日期 2026-10-25。

**输入是合成的 OASNT 形态证据，不是生产 JWT 字节。** 探针不实现 JWT 解析或
签名验证，只演示"native verifier 已完成验证之后"如何把结果投影成 CLC 报告。

## 映射

| OASNT | CLC / report | 说明 |
|---|---|---|
| `sub` | `Fact.subject` | 谁的批准 |
| `adg`（canonical action 的 SHA-256） | `Observation.nativeActionDigest` | verifier 用自己呈现的动作重算；**`adg` 不是 CLC `ActionId`** |
| 动作 → CLC 动作 | `Observation.clcActionId` + `mappingProfileDigest` | 只有 pinned action-mapping profile 才能建立关系；action mismatch 时不写 CLC `ActionId` |
| `iat` | `Fact.issuedAt` | 驱动 freshness |
| `exp` | — | 有效期截止，不是年龄界；CLC freshness 按年龄 |
| `int=clean` | `oasnt:device-integrity` = `success` | 设备自述，不是证明 |
| `int=compromised` | `oasnt:device-integrity` = `failed` | 构件不合格，不产生 eligible Fact |
| `int=unknown` | `oasnt:device-integrity` = `unavailable` | 结果不可得，不推断 |
| 令牌结构/签名/期限 + enrolled-key lookup | `oasnt:token-validity` = `success|failed|unavailable` | profile 自有 check ID |
| `dsp` | — | 人类看到的披露内容，CLC 无此轴 |
| `rqf` | — | 绑定到某一次具体请求；CLC 身份是动作，不是请求实例 |
| `asl` | — | 保证等级，载体与 relying-party policy 所有 |
| `jti` | — | 一次性 nonce，消费归执行点（AEB/BCR） |
| 嵌套参数 | — | OASNT 的 canonical action 是扁平表；嵌套需显式映射 |

`not_applicable` 不为 OASNT 虚构：OASNT-02 要求 `int`，正常情况下
device-integrity 检查总是适用。四值中的 `not_applicable` 由 EMILIA/通用
单元测试覆盖。

## 与 EMILIA 共用同一套机制

OASNT 不引入任何 carrier-specific 分支，只填同一组 report 类型：

| 机制 | OASNT 的实例 |
|---|---|
| `NativeCheckExpectation`（期望清单） | `oasnt:token-validity`、`oasnt:device-integrity`，组件类型 `oasnt:approval-token`，组件身份为 artifact digest |
| `NativeCheckResult`（显式结果） | 每条结果绑定 check、component、artifact digest、verifier 与 profile digest、核验时间；`success`/`failed` 另带 trust/status snapshot 与 freshness 决策 |
| `NativeCheckAssessment` | 期望与结果比对：missing / unexpected / conflicting；空清单不算 complete |
| `ProjectedObservation` | 同时记录 `adg` 与 pinned 映射后的 CLC `ActionId` |
| `ProjectedEvidenceRecord` | artifact digest → Observation → Fact 的血缘；未产生 Fact 时 `fact` 为空 |
| `Report.NativeChecksComplete` | 期望清单齐全且所需检查都有显式结果时才为 true |

判定规则：只有 action match、期望清单完整、且每个 required gate 都是
`success` 时才产生 eligible Fact。`jti` 未消费、`rqf` 未比对都不会被写成
"证据检查成功"——它们属于 enforcement point。

## 内部测试（不属于本 profile）

OASNT 探针还会运行参考实现内部的 report/lineage 检查（typed digest、profile
一致性、snapshot/replay、签名路径）。这些是**内部测试件**，不是 CLC-E 的
交付物，也不是本 projection profile 的一部分；这里只用它们验证 native
check 结果在内部表示中一致。签名路径仍由 Go 单元测试覆盖。

## 实跑（`out-probe.txt`，13/13 PASS）

动作绑定：

| 呈现的动作 | 结果 |
|---|---|
| 与批准的 action 完全相同 | MATCH |
| amount 改为 3001 | NOT_EQUIVALENT |
| 多加一个参数 | NOT_EQUIVALENT |

native check 与报告：

| case | 场景 | 结果 |
|---|---|---|
| `OAS-NCHECK-001` | 有效、`int=clean`、action match | 两个 success，报告完整，eligible，`SATISFIED` |
| `OAS-NCHECK-002` | `int=compromised` | integrity `failed`，报告完整，无 eligible Fact |
| `OAS-NCHECK-003` | `int=unknown` | integrity `unavailable`，报告完整，无 eligible Fact |
| `OAS-NCHECK-004` | 令牌过期 | validity `failed`，报告完整，无 eligible Fact |
| `OAS-NCHECK-005` | enrolled-key lookup 不可用 | validity `unavailable`，报告完整，无 eligible Fact |
| `OAS-NCHECK-006` | 缺少 integrity 结果 | 不推断；assessment 报 missing，`complete=false` |
| `OAS-NCHECK-007` | `adg` 与呈现动作不一致 | 两个检查 success、报告完整，但 action mismatch，无 eligible Fact，原因保留 |

批准作为 CLC 事实（requirement：`human-authorization` + `freshness:sec:300`）：

| 场景 | 结果 |
|---|---|
| `int=clean`，30 秒前 | SATISFIED |
| `int=compromised`（不合格） | UNSATISFIED |
| 301 秒前 | UNSATISFIED |

## 这证明了什么、不证明什么

- 证明：同一套 Observation / Expectation / Result / Assessment / Lineage 机制
  可以服务两个互不相关的载体，且没有按载体分支；缺失结果和同类型多构件漏报
  都能被期望清单发现。
- 不证明：CLC-E 一致性。OASNT 探针是回归与互操作证据；没有跨语言 native-check
  语料，没有正式 report schema，没有 report 自身的签名/认证模型，报文的真实
  性和 AEC replay 重放也未实现。CLC-E 仍未声明。
- OASNT 不是 EMILIA 的 profile，本文也不表示 OASNT 得到 IETF 背书。

## 运行

```sh
(cd ../register && go run ./cmd/oasnt-projection-probe)
```
