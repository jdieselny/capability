# 方案声明（CLC-SCHEME-v1）——供评审的草案文本

状态：**已作为规范 §6.7 集成于 CLC-1.19**（2026-10-17）。
本说明给出设计理由与所作出的四项决议；规范文本见
`capability-language-core-v1.md` §6.7。

## 1. 它增加什么，不增加什么

**方案声明**是一个内容寻址的制品，针对某一个能力方案说明**每个参数属于哪个域**。
它是求值的一项*输入*，由载体或依赖方钉定，正如授权或事实被钉定一样。CLC 绝不获取它（P9）。

它不增加任何**语法**：授权的 `params` 与 `param_bounds` 保持不变。
今天域是从值的形状推断出来的（数字 → bound，数组 → enum，标量 → exact）；
有了声明，域被显式给出，并由**声明域**决定。没有声明的参数继续沿用现有的
形状推断，因此每一份既有授权都保持原义。

它不允许某个方案定义约束值**如何**求值——这仍属于声明方案自身的事务（§8.1），
核心不认识的约束类型仍然是 `unknown_constraint`。

## 2. 制品

```json
{
  "@version": "CLC-SCHEME-v1",
  "scheme": "std/payments-v1",
  "declaration_id": "std/payments-v1@2026-10-17",
  "clc_revision": "CLC-1.19",
  "digest": "sha256:<base64url of JCS(this object without the digest member)>",
  "capabilities": {
    "transfer": {
      "params": {
        "amount":      { "domain": "quantity", "unit": "CNY" },
        "currency":    { "domain": "enum" },
        "counterparty":{ "domain": "enum" },
        "path":        { "domain": "path-prefix", "optional": true }
      }
    }
  },
  "constraint_types": ["payments:quota:daily"]
}
```

规则：

- `@version` MUST 为 `CLC-SCHEME-v1`。
- `scheme` MUST 等于它所治理的能力 id 的方案段。
- `digest` 在**去掉 `digest` 成员之后**的对象 JCS（RFC 8785）形式上计算，
  再做无填充的 base64url 编码。钉定该声明的载体钉定的是这个摘要，而不是修订号。
- `clc_revision` 是该声明所要求的语言修订。在其之下求值的输入 MUST 至少声明该修订；
  未实现该修订的实现通过 §12.1 的次版本门禁拒绝。
- 每个成员都是封闭的：出现未声明的成员即声明格式不合法（malformed）。
- 能力的 `params` 指名参数；未被列出的参数保留形状推断出的域。声明 MUST NOT
  列出该方案能力并未定义的参数。

## 3. 域

核心目前按三个域分派（P4）：

| 域 | 值形状 | 授权比较 | 包含（§13.4.3） |
|---|---|---|---|
| `bound` | 数字 | operation 值 ≤ 授权值 | 子项值 ≤ 父项值 |
| `enum` | 标量数组 | operation 值 ∈ 授权集合 | 子项集合 ⊆ 父项集合 |
| `exact` | 标量 | 相等 | 相等 |

CLC-1.19 又增加四个，全部是**类型而非语法**（§6 扩展规则）：

| 域 | 值形状 | 比较 | 包含 |
|---|---|---|---|
| `quantity` | `{ "value": number, "unit": string, "scale"?: integer }` | unit MUST 等于声明的 `unit`（不作换算）；归一化后的 `value × 10^-scale` ≤ 授权的 | 同一 unit；子项 ≤ 父项 |
| `decimal-string` | 字符串，规范十进制 | 值空间比较（`"500"` ≡ `"500.00"`，`"1e3"` ≡ `"1000"`） | 子项 ≤ 父项 |
| `subdomain` | DNS 名称 | 整标签后缀，大小写不敏感 | 子域是父域本身或其下级 |
| `path-prefix` | 路径 | 段边界前缀（`/a/b` 不覆盖 `/a/bc`） | 子路径是父路径本身或其下级 |

每个域都必须在其规范定义中说明：确定性（P5）、终止与线性代价（P10）、
局部可判定性（P9）、自己的原因代码，以及它在 `Intersect`（`BoundMeet`，§6.6）中的行为。

## 4. 求值

1. 解析该授权所属方案的声明（输入，按摘要钉定）。
2. 对授权中存在的每个参数，有声明域则使用声明域；否则与今天一样按值形状推断域。
3. 授权（`Entails`，§6）：按该域的比较规则，将 operation 值与授权值比较。
4. 包含（`Contains`，§13.4.3）：在**父项**的声明域下将子项与父项比较。若同一键
   两侧声明了不同的域，该对不可比较 → `params_not_narrower`。
5. 交集（`BoundMeet`，§6.6）：同域按该域的规则求交；不同域拒绝
   `invalid_params_binding`（CLC-1.15 关于跨族求交的规则原样适用）。

## 5. 默认拒绝（fail-closed）规则

- 声明中出现未知的 `domain` → 输入被拒绝（`unsupported_domain`，见下文第 1 项决议）。
- 未实现 `CLC-SCHEME-v1` 的实现收到声明 `CLC-1.19` 的输入 →
  `unsupported_language_revision`（§12.1）。
- 参数声明了某个域，但其值与该域的形状不符 → `invalid_params_binding`。
- `digest` 与其内容不一致的声明 → 该声明无效；依赖它的输入被拒绝。

## 6. 一致性

- `scheme-declaration.schema.json` 校验该制品。
- 某个域的规则至少需要：一个正例、一个边界例、一个反例、一个包含例，
  以及一个跨域拒绝例。
- 与每条规则一样（P12）：在两个独立实现达成一致之前，不作声明。

## 7. 决议（2026-10-17 定案）

1. **未知或不受支持的域 → `unsupported_domain`。** 新增的 §9.2 代码，由声明校验
   产生，并在 §9.1 第 1 层之前解析；不是 `unknown_constraint`（声明不是约束）。
2. **unit 不匹配 → `unit_mismatch`。** 位于 §9.1 第 9 层的新增 §9.2 代码。
   `"50 CNY does not cover 7 USD"` 既不是超出（exceedance），也不是枚举失败。
3. **声明存放在方案注册表条目上。** 独立制品（`CLC-SCHEME-v1`）是规范性的；
   载体的注册表条目（现有的 `data/std/<scheme>/v1.json` 形状）以
   `clc_declaration` 成员承载它，并按其摘要钉定。
4. **`quantity` 在声明时固定 unit**（`"unit": "CNY"`）。unit 永不换算，
   比较归结为单个数值边界；带其他 unit 的值是 `unit_mismatch`。

## 8. 试点实现（2026-10-17）

`quantity` 域有一个可运行的参考试点，刻意放在核心比较代码之外：

- `register/internal/schemedecl` 加载 `CLC-SCHEME-v1` 声明，校验封闭形状、已知域、
  quantity unit 规则与摘要，并通过语义层 API（`semantics.AuthorizeSetWithDomains`、
  `semantics.ContainsWithDomains`、`semantics.EntailsWithDomains`）应用该域：
  每个声明的 quantity 值都在常规关系运行之前转成其归一化数值；
- 语料为 `data/_vectors/clc-v1/quantity-vectors.json`（8 个向量：界内、超界、
  unit 不匹配、scale 归一化、缺少 scale、非对象值、包含接受、包含拒绝）；
- 两个测试：`TestQuantityVectors` 与 `TestDeclarationValidation`（未知域、
  摘要不匹配、quantity 缺少 unit）。
- **Python 与 TypeScript 镜像**：`aic-capability-demo/scheme_decl.py` 与
  `ts/scheme_decl.ts`，各自在同一语料上运行自己的运行器。三个实现全部 8/8 通过，
  且 Python 与 TypeScript 运行器的输出逐字节一致（`contrib/quantity-domain/`）。

三个字符串形状的域在同一层实现（2026-10-17）：Go 中的 `stringDomainCovers`
（`semantics/domains.go`，`decimal-string` 使用精确的 `big.Rat`）、Python 镜像
（`decimal.Decimal`）与 TypeScript 镜像（`BigInt`）。`*WithDomains` 函数先预检
字符串域、将值规范化，然后运行常规关系；Go 有十个字符串域用例
（`TestStringDomains`）。Python 与 TypeScript 在各自的语义模块中覆盖相同用例。
