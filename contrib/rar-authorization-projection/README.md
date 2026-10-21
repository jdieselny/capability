# OAuth RAR → CLC authorization projection（2026-10-17）

授权侧的第二个投影探针。RAR（`authorization_details`，RFC 9396）是几乎所有
OAuth 授权 profile 的出发点，所以它投影得干不干净，决定了上面那些 profile
能不能顺着映射进 CLC。

成员核对自 RFC 9396 §2（`type` / `locations` / `actions` / `datatypes` /
`identifier`）与 §3 的 payment 示例，检查日期 2026-10-17。

## 映射

| RAR | CLC | 说明 |
|---|---|---|
| `type` + 每个 `action` | 一个 Grant，id = `oauth-rar/rar-v1:<type>:<action>` | **actions 会乘出多个 grant** |
| 类型特有字段（`amount`、`currency`、`identifier` …） | Grant `params` | 数值 → 上界；枚举/标识 → 枚举 |
| `locations` | — | "能在哪里用"没有 CLC 槽位，载体执行 |
| `datatypes` | — | 约束的是资源的数据类型，不是操作 |

## 实跑（`out-probe.txt`，4/4 PASS）

输入：`{type:"payment", actions:["transfer","refund"], amount:5000,
currency:"CNY", identifier:"acct-1234", locations:["https://api.bank.example"]}`

映射出两个 grant：

```
oauth-rar/rar-v1:payment:transfer  params={amount:5000, currency:[CNY], identifier:[acct-1234]}
oauth-rar/rar-v1:payment:refund    params={amount:5000, currency:[CNY], identifier:[acct-1234]}
residual: locations
```

| 操作 | 结果 |
|---|---|
| transfer 3000 CNY | allow |
| transfer 6000 CNY | deny / `params_exceed_grant` |
| transfer 3000 USD | deny / `not_in_enum` |
| refund 1000 CNY | allow（第二个 action 对应第二个 grant） |

## 结论

1. **RAR 的 actions 与 ASOR 的 scopes 是同一个模式**：一个 detail 映射成多个
   grant，binding profile 必须写明"按操作选 grant"的规则。
2. **`locations` 是授权侧最典型的无槽位成员**——它约束的是使用地点/资源服务器，
   不是动作或参数；只能载体执行并作为残差记录。
3. **实现细节**：用 Go 程序构造 grant 时，枚举必须写成 `[]any{...}`；若写成
   `[]string{...}`，引擎会把它当作普通值而不是枚举，导致 `params_exceed_grant`。
   JSON 语料路径没有这个问题（`[]any` 正是解码结果）。

运行：

```sh
(cd ../register && go run ./cmd/rar-projection-probe)
```
