# 输入拒绝分类（审计 C-4）

状态：规范性原因代码的说明性地图（§9.1/§9.2）。它的存在是为了让两个实现能够
说出*为什么*拒绝，而不只是说出拒绝了。孤立的“Denied”并不能与另一个实现的
“denied”互换。

| 类别 | 问题所在 | 规范代码 |
|---|---|---|
| 修订 / 特性门禁 | 所声明的修订或声明不受支持 | `unsupported_language_revision`、`unsupported_domain` |
| 语法 | 标识符文法或通配符形状 | `invalid_capability_id`、`missing_capability_id`、`unsupported_wildcard` |
| 输入边界（表示层） | 重复键、非规范数字、畸形 Unicode、大小/深度 | `invalid_params_duplicate_key`、`invalid_params_number`、`invalid_params_size` |
| 绑定 / 形状 | 值与其声明域或推断域不符；边界格式不合法 | `invalid_params_binding` |
| 键封闭 | 声明的键缺失，或出现了未声明的键 | `params_missing`、`undeclared_param` |
| 枚举 | 值在 enum 集合之外；基数超出其边界 | `not_in_enum`、`params_cardinality` |
| 边界 | 数值或十进制边界被超出；unit 不同；未满足 step | `params_exceed_grant`、`unit_mismatch`、`params_out_of_range`、`params_not_multiple` |
| 命名空间 / 路径 | 方案或 class 不同；字面或通配符深度不匹配 | `different_namespace`、`literal_mismatch`、`wildcard_requires_trailing_segment` |
| 覆盖 | 没有来源覆盖该 operation；交集为空 | `capability_not_authorized`、`no_overlap`、`absent_source` |
| 约束 | 未知类型、无效的值文法，或被违反的约束 | `unknown_constraint`、`invalid_constraint`、`{type}:violated` |
| 证据 | 证据约束或 `Resolve` 输入无效 | `invalid_resolution`、`invalid_timestamp`（约束使用上述类别） |
| 包含 | 子项超出父项，或不可比较 | `child_exceeds_parent`、`params_not_narrower`、`delegation_mode_not_narrower` |

由上表推出的规则：

- 规范代码是第一个 `:` 之前的部分；诊断后缀（例如出错的键）不改变类别。
- 钉定一次拒绝的向量，钉定的是规范代码，而不是消息文本。
- `invalid_params_binding` 刻意覆盖“值与其域形状不符”（包括非对象的 `quantity`
  值和不干净的路径）：这一失败是结构性的，而不是边界比较。
