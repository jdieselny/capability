# IICP §12.3 touchpoint 探针（2026-10-16）

对 Roble《IICP Overall Architecture and Component Interfaces》**v0.3.1 §12.3**
末所留 **"Review touchpoint for Jijie"** 的可运行回答。

他请求：

> "compare a **fixed CLC operation/grant pair** with the IICP
> selection-to-admission boundary. Document **which checks belong before
> discovery, which belong at the provider, and which remain unresolved after
> containment**. Useful adverse cases include a **widened destination set, unit
> ambiguity, an unknown required constraint and a retry to another provider**."

## 一、固定的 grant / operation 对

标识与参数取自本仓**已发布的 scheme** `data/std/payments-v1/v1.json`
（action `transfer`；params `amount` number、`currency` 大写 ISO 枚举、
`counterparty` 数组）——**不是自造名字**。

```
grant     = { "id": "std/payments-v1:transfer",
              "params": { "amount": 5000, "currency": ["CNY"],
                          "counterparty": ["vendor.example"] } }
operation = { "id": "std/payments-v1:transfer",
              "params": { "amount": 3000, "currency": ["CNY"],
                          "counterparty": ["vendor.example"] } }
```

（单位不是单独类型：scheme 把**货币**声明为 `currency` 枚举参数，`amount` 是裸数值。
若某 scheme 要把量与单位绑成一个值，也可用对象 `{value, unit}`——见
`../clc-unit-encoding/README.md`，那是同一机制的另一种编码。）

## 二、结果（12 例；两实现**逐字节一致**）

`out-python.txt` 与 `out-typescript.txt` 的 sha256 相同：

```
b74ddd73b9844063bd163eb9a565bd82a2863054bdcb9e91f4784f8f193d9e45
```

| 例 | 场景 | CLC 判定 |
|---|---|---|
| A0 | base（授权内） | `allow` |
| **A1** | **widened destination set**（`counterparty` 改为 `other.example`） | `deny` `not_in_enum` |
| **A2** | **unit ambiguity**（`currency` 改 `USD`） | `deny` `not_in_enum` |
| A2b | 单位大小写（`cny`） | `deny` `not_in_enum` |
| A2c | 金额越界（6000 > 5000） | `deny` `params_exceed_grant` |
| **A3** | **unknown required constraint**（`acme/policy-v1:geo:eu`） | `deny` `unknown_constraint` |
| A4 | **recognized-but-not-evaluated**（`varwof/constraint-v1:time:window:[…]`） | **`allow_unresolved`** + `unresolved: [<该约束串>]` |
| **A5** | **retry to another provider** | `allow`（**同一 grant/op 对，判定不随 provider 变**） |
| C0 | 子收窄金额 | `contains: true` |
| C0b | 子收窄 counterparty 集 | `contains: true` |
| C1 | 子放宽 counterparty 集（加 `other.example`） | `contains: false` `params_not_narrower` |
| C2 | 子改货币（`USD`） | `contains: false` `params_not_narrower` |

## 三、三类检查的归属（回答他的三问）

| 归属 | 内容 | 依据 |
|---|---|---|
| **discovery 之前** | ① **grant 必须已存在**（它不是发现的产物）；② **操作的标识与参数名**（`scheme:action` + 参数键集）——因为发现匹配的是"能力"，不是一组参数值 | A0 的 grant 与 operation 形状在发现之前即固定 |
| **provider 处** | ① **具体参数值**（`amount`/`currency`/`counterparty`）；② **CLC 的 grant-vs-operation 判定**（`entailment`）与 **grant-vs-grant 包含**（`Contains`）；③ provider-local admission | A0/A1/A2/A2c/C0–C2 |
| **containment 之后仍未决** | **CLC 不能本地求值的已识别约束** → 以 `allow_unresolved` 保留，需在 binding 下解析；**freshness / revocation 状态不在 CLC 范围**（§11） | A4 |

**A5 单独说一句**：改动 provider **不改变** CLC 的判定（授权与 provider 无关）；
但 **provider-bound admission 制品不可跨 provider 复用**——这一条与 IICP
admission-v2 自己在 failover 上的要求一致。

## 四、四个 adverse case 的逐条回答

1. **widened destination set** → `deny not_in_enum`（A1；收窄侧是 C0b/C1）。
2. **unit ambiguity** → 该 scheme 把货币声明为 `currency` 枚举参数（大写 ISO 码），
   CLC 按**集合成员**比较、**不换算**；跨货币即 `deny not_in_enum`（A2/A2b）。
   因是字符串枚举，**大小写敏感** ⇒ 大写是**必需**（`"cny" ≠ "CNY"`）。
3. **unknown required constraint** → `deny unknown_constraint`（fail-closed，**不是**当作不受约束）。
4. **retry to another provider** → 授权判定不变（A5），但**admission 制品必须重取**。

## 五、复现

```bash
cd contrib/iicp-touchpoint
export CLC_PY_DIR=/path/to/aic-capability-demo
export CLC_TS_FILE=file:///path/to/aic-capability-demo/ts/clc_semantics.ts
python3 probe.py > out-python.txt
node --disable-warning=ExperimentalWarning --experimental-strip-types probe.mjs > out-typescript.txt
cmp out-python.txt out-typescript.txt && echo AGREE
```

## 六、要如实说明的

- **独立实现未达标**：三实现（Go/Python/TS）同作者（CLC-00 Abstract 与 §12 已自述）；
  故"两实现逐字节一致"是**回归证据**，不是独立验证。
- **`allow_unresolved` 的处置属消费者义务**：CLC 只保证它不被折叠成 `allow`；
  谁解析、何时解析由 binding 定义。
