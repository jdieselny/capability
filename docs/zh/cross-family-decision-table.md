# 跨族裁决表（审计 C-5）

状态：截至 CLC-1.19 修订后的 §6.5/§6.6/§13.4.3 说明性摘要。它只回答一个问题：
对一对值族而言，operation 是求交、拒绝，还是根本无法比较？

| 父族 | 子族 | 授权（`Entails`） | 求交（`BoundMeet`） | 包含（`Contains`） |
|---|---|---|---|---|
| numeric | numeric | 比较（`min`=取较大、`max`=取较小、`step` 规则） | 求交 | 子项 ≤ 父项 |
| enum | enum | 带 JSON 类型敏感相等性的成员归属 | 成员取交、收窄基数 | 子项集合 ⊆ 父项集合 |
| numeric | enum | 拒绝 `invalid_params_binding` | 拒绝 `invalid_params_binding` | `params_not_narrower` |
| enum | numeric | 拒绝 `invalid_params_binding` | 拒绝 `invalid_params_binding` | `params_not_narrower` |
| 标量（numeric/enum） | 嵌套（object） | 拒绝 `invalid_params_binding` | 拒绝 `invalid_params_binding` | `params_not_narrower` |
| 嵌套 | 标量 | 拒绝 `invalid_params_binding` | 拒绝 `invalid_params_binding` | `params_not_narrower` |
| 嵌套 | 嵌套 | 在相同的键集合上递归 | 递归 | 递归；键集合必须匹配 |
| 声明域 X | 声明域 X | 按 §6.7 | 按 §6.7 | 按 §6.7 |
| 声明域 X | 声明域 Y（X≠Y） | 拒绝 `invalid_params_binding` | 拒绝 `invalid_params_binding` | `params_not_narrower` |

注：

- *同一族内*的空求交是 `no_overlap`；每个跨族组合在任何值运算之前就是
  `invalid_params_binding`（CLC-1.15）。
- “不同的声明域”即使两侧的值都是字符串也算跨族：`subdomain` 值与
  `path-prefix` 值不可比较。
- 声明中指名的域若实现不受支持，会在本表生效之前更早被拒绝，原因是
  `unsupported_domain`（§6.7）。
