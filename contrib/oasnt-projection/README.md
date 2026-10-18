# OASNT approval → CLC evidence projection（2026-10-17）

第三个投影探针，来自一个与 EMILIA 无关的体系：
`draft-thallapelly-oasnt-02`（OASNT，一次性人工批准令牌）。
前两个分别测了 Requirement 侧（AEC）与 Result 侧（Gilda）；这一个测
**Fact + 动作绑定**侧。

输入字段核对自 OASNT-02 §5.3（claims）与 §6.2（canonical action），
检查日期 2026-10-17。

## 映射

| OASNT | CLC | 说明 |
|---|---|---|
| `sub` | Fact.subject | 谁的批准 |
| `adg`（canonical action 的 SHA-256） | Observation 的动作绑定 | 验证方用呈现的动作重算 adg 并比对 |
| `iat` / `exp` | Fact.issued_at / — | `iat` 驱动 freshness；`exp` 是有效期截止，与"年龄界"不同类 |
| `int` | Fact.verified 的输入 | 只有它对 eligibility 的影响可表达；`compromised/unknown` → 不合格 |
| `dsp` | — | 人类看到的披露内容，CLC 无此轴 |
| `rqf` | — | 绑定到某一次具体请求；CLC 的身份是动作，不是请求实例 |
| `asl` | — | 保证等级，载体所有 |
| `jti` | — | 一次性 nonce，消费归执行点（AEB/BCR） |
| 嵌套参数 | — | OASNT 的 canonical action 是扁平表；嵌套需映射（其自身已知限制） |

## 实跑（`out-probe.txt`，6/6 PASS）

动作绑定：

| 呈现的动作 | 结果 |
|---|---|
| 与批准的 action 完全相同 | MATCH |
| amount 改为 3001 | NOT_EQUIVALENT |
| 多加一个参数 | NOT_EQUIVALENT |

批准作为 CLC 事实（requirement：`human-authorization` + `freshness:sec:300`）：

| 场景 | 结果 |
|---|---|
| `int=clean`，30 秒前 | SATISFIED |
| `int=compromised`（不合格） | UNSATISFIED |
| 301 秒前 | UNSATISFIED |

## 结论：关系型缺口是**精确**的，不是普遍的

OASNT **没有**出现 `required_bindings` / `agreement` 那类缺口——因为它是用
**身份**（adg）把批准绑到动作，而不是用**关系**连接两个证据 artifact。

这正好校准了通用规则：

> 关系型缺口只在载体包含"artifact 之间关系"时出现（AEC 的 `required_bindings`、
> Gilda 的 `agreement`）；用身份/摘要绑定的载体（OASNT）不需要任何额外机制。
> binding profile 只需在遇到关系型成员时声明"归一化为事实或外部执行"。

三个探针合起来覆盖了投影模型的三个面：**Requirement（AEC）**、
**Result（Gilda）**、**Fact + 身份（OASNT）**。

运行：

```sh
cd register && go run ./cmd/oasnt-projection-probe
```
