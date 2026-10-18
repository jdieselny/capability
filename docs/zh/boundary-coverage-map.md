# 边界覆盖地图（审计 V-3 / V-4 / V-6）

状态：说明性。审计要求更多的跨族、I-JSON 与 JCS 边界覆盖。本地图展示每个类别
已被钉定的位置，使新的工作不重复既有的向量。

## V-3 跨族

| 用例 | 钉定于 |
|---|---|
| 数值 × enum，两个顺序 | `param-bounds-meet-vectors.json` `bm-012`/`bm-013`；`bm-026`/`bm-027` |
| 标量 × 嵌套（数值/enum 与对象） | `param-bounds-meet-vectors.json`（`bm-019`），design-notes D12 |
| `Intersect` 中的 string × number | `vectors.json` `intersect-011`…`intersect-013` |
| 授权时的跨族 | 针对 `invalid_params_binding` 路径的 `decide` 向量 |
| 声明域 × 不同的声明域 | §6.7 规则 + `string-domain-vectors.json` s-022…s-024 |

## V-4 I-JSON / 整数边界

| 用例 | 钉定于 |
|---|---|
| 原始路径上整数 > 2^53−1 被拒绝 | `vectors.json` `params-053`…`params-062` |
| 指数 / 尾随 `.0` 无法洗白一个超界整数 | 同一区间 |
| 数字同一性 `-0`≡`0`、`1e3`≡`1000`、`1.5e-3`≡`0.0015` | `params-063`…`params-070` |
| 解码路径上的 int64/uint64 载体 | `semantics/rawparams_sanity_test.go` `TestIJSONIntegerBoundDecoded` |
| `param_bounds` 的数字边角情况 | `param-bounds-vectors.json` `pb-044`…`pb-049` |

## V-6 JCS / 规范化

| 用例 | 钉定于 |
|---|---|
| `&`、`<`、`>` 不做 HTML 转义 | `semantics/canonical_test.go` 的 ampersand 测试；`evidence-vectors.json` `eva-006` |
| 键顺序是 UTF-16 码元顺序 | `TestCanonicalJSONUTF16KeyOrder` |
| 数字规范形式 | `TestCanonicalJSONNumbers` |
| 键插入顺序不改变字节；幂等性 | `TestCanonicalJSONOrderAndIdempotence` |
| 等价文本 → 相同的签名输入 | `TestSigningInputStableAcrossRepresentation` |

## 绘图过程中发现的缺口

1. **深度边界**此前未经测试，且实现比 §6.2 严格一级；已于 2026-10-18 修复
   （`paramsDepth` 只计容器；`TestParamsNestingBoundary` 钉定 32 接受 / 33 拒绝）。
2. 没有向量在词法规则之外钉定 **`decimal-string` 值的规范形式**——
   `string-domain-vectors.json` 的 s-012…s-018 覆盖拒绝以及 `007`≡`7`（后者是比较
   规则）；规范字节没有被单独钉定，因为该值是字符串，而 JCS 不改变字符串。
3. ~~`param_bounds` 内的声明域没有规则。~~ **已于 2026-10-18 关闭**：§6.7 现在规定
   声明域的参数 MUST 位于 `params` 中；同一键上的 `param_bounds` 族是
   `invalid_params_binding`。已在 Go/Python/TypeScript 中实现，并由 `p-001`
   （授权）与配套的包含规则（`params_not_narrower`）钉定。

第 2 项是如实记录而非凭空发明：`decimal-string` 值是字符串，因此 JCS 不改变它；
比较规则由 s-012…s-018 钉定。
