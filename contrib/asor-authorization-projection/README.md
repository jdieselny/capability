# ASOR delegation chain → CLC authorization projection（2026-10-17）

授权侧的第一个投影探针，与证据侧三个探针（`emilia-projection`、
`gilda-projection`、`oasnt-projection`）同一形态：
把载体的原生结构映射进 CLC，跑判定，再列出映射**带不走**的东西。

输入核对自 `draft-asor-wimse-agent-delegation-chain-02`：§3（`par_hash`、
`del_depth`）、§4.1（scope 语法与通配）、§4.2（constraint 词表），
检查日期 2026-10-17。

## 映射规则（探针实现的）

| ASOR | CLC | 说明 |
|---|---|---|
| `authorization_details.scopes[]` | **每个 scope 一个 Grant**，id = `asor/agent-delegation-v1:<scope>`（`.`→`:`；尾部 `.*`→`:*`） | 一个 ASOR token 会映射成多个 grant |
| `constraints[{key,max}]` | Grant `params[key] = max` | 数值上限 |
| `constraints[{key,enum}]` | Grant `params[key] = enum` | 枚举值集 |
| 其它 constraint 类型 | — | 残差（如 `max_lifetime` 是跨动作累计，不是单动作上限） |
| `par_hash` | — | 链连接，载体所有（ASOR §5） |
| `del_depth` / `del_max_depth` | — | 链形状，载体所有 |
| `delegation_mode` | — | 载体预检（对应 CLC §13.4.5 的位置） |
| `sub` / principal standing | — | 链之外（对应 §9.7 的 standing 讨论） |
| status / revocation | — | 链之外，载体 fail-closed 步骤 |

## 实跑（`out-probe.txt`，7/7 PASS）

映射结果（根 token：`crm.customer.read`、`crm.customer.write`、`crm.*`，
`max_rows=5000`；叶 token：`crm.customer.read`，`max_rows=3000`）：

```
asor/agent-delegation-v1:crm:customer:read   params={max_rows:5000}
asor/agent-delegation-v1:crm:customer:write  params={max_rows:5000}
asor/agent-delegation-v1:crm:*               params={max_rows:5000}
asor/agent-delegation-v1:crm:customer:read   params={max_rows:3000}
```

七条机器可检查 case：

| Case | 场景 | 期望 | 实际 |
|---|---|---|---|
| ASOR-001 | root token 精确映射为三个 grant | mapping-exact | grants=3 |
| ASOR-002 | leaf token 精确映射为一个 grant | mapping-exact | grants=1 |
| ASOR-003 | 每个 leaf grant 被父 grant 包含 | contains=true | contains=true |
| ASOR-004 | read，`max_rows=2000` | allow | allow |
| ASOR-005 | read，`max_rows=3000`（叶的上界） | allow | allow |
| ASOR-006 | read，`max_rows=3001` | deny | deny / `params_exceed_grant` |
| ASOR-007 | write（根有、叶没有） | no-chain | no-chain |

## 结论

1. **CLC 能判定 ASOR 八步验证里的"scope 与 constraint 子集"那几步**；
   `par_hash`、深度、mode、standing、status 全部留在载体。
2. **一个 ASOR token 映射成多个 CLC grant**，所以一条 ASOR 链对应**一族**
   CLC 链，必须按操作 id 选择——这是 binding profile 必须写明的映射规则，
   否则"链"这个词两边指的不是同一个东西。
3. **集合包含要逐 grant 做**（每个叶子 grant 都要被某个父 grant 包含），
   不能只比一对：ASOR 的一跳是一个 scope 集合，CLC 的一个 grant 是一个动作。

## 与证据侧对照

| | 证据侧 | 授权侧 |
|---|---|---|
| 投影目标 | Observation / Fact / Requirement / Result | Grant + Operation |
| 主要残差类别 | **关系**（AEC `required_bindings`、Gilda `agreement`） | **身份维度与元数据**（`par_hash`、深度、mode、status、`locations` 类字段） |
| 已知语义分歧 | — | 子 grant 增加父未声明的参数键：CLC 拒绝（`params_not_narrower`），ASOR/Sweeney 允许 |

运行：

```sh
(cd ../register && go run ./cmd/asor-projection-probe)
```
