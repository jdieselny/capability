# 证据关系：归一化为同一性（投影的草案章节）

状态：设计说明，2026-10-17。拟作为通用**证据投影**文档（而非核心）的一章。
它以一个具体机制落实规范 §11（“两个制品之间的关系不可表达”），使载体绝不会
被迫要么发明语言、要么悄悄丢掉该关系。

## 1. 规则

两个制品之间的关系**不是** CLC 对象。拥有这种关系的载体 MUST 恰好做以下二者之一：

1. **把它归一化为同一性**——在自己的验证器中求值该关系，并发出一个*派生事实*，
   其 subject 是对该关系输入求得的摘要（§2）。CLC 随后把该事实当作普通角色求值；或
2. **在投影之外执行它**，并把它报告为残留义务。CLC MUST NOT 把未检查的关系
   报告为满足（satisfied）。

首选第一种：它把“A 是否与 B 相关？”变成“是否存在一个制品为此作证？”，而这正是
CLC 已经求值的形状。这也是 OASNT 对 action 所做的同一处理（`adg`，
`draft-thallapelly-oasnt-02` §6.2）：按同一性绑定，而不是按关系绑定。

## 2. 派生事实

```
type      = <carrier>:binding:<relation>         e.g. ep:binding:permits
subject   = base64url(SHA-256(JCS(relation tuple)))
verified  = true      (the carrier's verifier decided the relation)
issued_at = 被绑定证据的保守新鲜度时刻（绝不是关系重算时间）
```

该 type 同时也就是 requirement 所指名的**角色标识符**，而 requirement 文法的标识符
字母表不含 `/`（AEC §8.1：字母、数字、`.`、`:`、`-`、`_`），因此分隔符是 `:`。
冒号在 CLC 的别处已经是方案分隔符，所以这个形状读作 `<carrier>:binding:<relation>`。

**关系元组**是一个固定的、由载体声明的对象：

```json
{"requirement_id":"treasury-wire-evidence@7",
 "policy_generation":"policy-7",
 "from":{"type":"policy-permit","artifact_digest":"sha256:..."},
 "relation":"permits",
 "to":{"type":"ep-quorum","artifact_set_digest":"sha256:..."},
 "action_digest":"sha256:...",
 "subjects":["alice","bob"],
 "trust":{"verifier":"native-verifier","result":"verified"},
 "status_digest":"sha256:...",
 "evidence_issued_at":["2026-09-13T11:59:00Z", "..."],
 "status_snapshot":{"outcome":"valid","source":"aeb-status",
                    "checked_at":"2026-09-13T12:00:00Z",
                    "valid_until":"2026-09-13T12:01:00Z",
                    "revocation_generation":"rev-42"}}
```

元组的规则，全部旨在使该机制保持有界且局部：

- 对象是封闭的（没有未声明的成员），并以 JCS（RFC 8785）规范化，与 §4.2/§6.2
  已要求的规范化相同；
- `subjects` 在哈希之前按确定顺序排序（顺序由载体声明，例如 UTF-8 字节序），
  或者改由元组携带集合摘要；
- 元组绑定实际的 source/target 制品、精确动作、native verifier 与 trust 结果、
  distinct subjects、原始证据时间、requirement/policy generation，以及该验证器
  使用的 status/revocation 快照；
- 载体 MUST 说明该关系的语义、元组的成员，以及由谁来验证它——这正是绑定配置
  的四项义务，应用到一个关系上；
- 该事实**不**自认证：只有当它由载体的原生验证产生时才具备资格（与任何事实
  相同的 `verified` 规则）。

重算关系不能刷新它所连接的证据。派生事实的新鲜度和有效期来自原始 source/target
证据及状态快照。今天重算出一个真实关系，如果其中一份批准已经过期，它仍然是过期
证据。

探针使用具体的合成 artifact fixture 来测试该形状，不声称这些 fixture 是 EMILIA
生产系统的原始字节。关系与 artifact 摘要由发出派生事实的 native verifier 负责；
CLC 把 fact subject 当作不透明值。

## 3. 示例 1 —— AEC `required_bindings`

`draft-schrock-ep-authorization-evidence-chain-08` §4 携带
`required_bindings: [{from_type: policy-permit, relation: permits,
to_type: ep-quorum}]`。归一化后：

```
type    = ep:binding:permits
subject = b64url(SHA-256(JCS(relation tuple)))
```

依赖方保留原始项，并增加派生角色：

```json
{"@version":"CLC-REQUIREMENT-v1","requirement_id":"treasury-wire-evidence@7",
 "expression":"ep-quorum AND policy-permit AND ep:binding:permits",
 "constraints":[
   {"role":"ep-quorum","constraint":"varwof/evidence-v1:freshness:sec:300"},
   {"role":"policy-permit","constraint":"varwof/evidence-v1:freshness:sec:600"},
   {"role":"ep-quorum","constraint":"varwof/evidence-v1:quorum:distinct:2"}
 ]}
```

binding 事实补充而不是替代原始 quorum 和 permit。链验证器没有发出该事实时，
表达式为假；端点在场并不等于关系成立（sym-047）。原始批准过期时，新算出的
binding 事实也不能把它重新变成新鲜证据。

## 4. 示例 2 —— Gilda `agreement`

`draft-gilda-wimse-agent-audit-record-02` §5.3 从 `decision.reported` 与
`effect.observed`（其表 2）导出 `agreement`。记录本身已经携带该推导；投影把它
变成一个事实，而不是一个 CLC 本来不得不执行的比较：

```
type    = gilda/agreement-v1:<value>          e.g. gilda/agreement-v1:disagree
subject = b64url(SHA-256(JCS({"request": "<decision.requestDigest>",
                              "effect_root": "<effect.interval.afterRoot>"})))
```

关心分歧的 requirement 指名角色 `gilda/agreement-v1:disagree`；不关心的
requirement 直接省略它。审计记录保留自己的成员；投影不推断任何东西。

## 5. 这不做什么

- 它不允许 CLC 直接比较两个事实；比较在载体中发生一次，并成为一个同一性。
- 它不允许载体省略关系：如果载体拥有关系却不归一化，投影必须携带一个残留
  （§1 选项 2），而无法履行该残留的消费方必须拒绝。
- 它不定义关系词汇表。`permits` 的含义以 AEC 的说法为准；投影只固定归一化制品
  的*形状*。

## 6. 若将来加入语言级操作符

只有当至少两个独立载体需要同一关系、词汇表收敛为一个小集合（例如
`subject-in:<role>`）、并且两个独立实现都能运行它时（P12），才可能加入。
在那之前，派生事实这条路线没有任何成本，并让核心保持最小。
