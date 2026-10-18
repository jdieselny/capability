# CLC-1.19 `quantity` domain — three-language pilot（2026-10-17）

规范 §6.7 的试点实现，三个语言各一份，跑同一套语料：

| 实现 | 位置 | 入口 |
|---|---|---|
| Go（参考） | `register/internal/schemedecl` | `go test -count=1 ./internal/schemedecl/ -v` |
| Python | `aic-capability-demo/scheme_decl.py` | `python3 quantity-vectors-run.py` |
| TypeScript | `aic-capability-demo/ts/scheme_decl.ts` | `node --experimental-strip-types ts/quantity-vectors-run.ts` |

语料：`data/_vectors/clc-v1/quantity-vectors.json`（8 条）。
声明样例：`data/std/payments-v1/clc-declaration.json`。

## 做法

声明是**归一化层**，不改 `Entails`/`Contains`：

1. 校验声明（封闭形状、已知 domain、quantity 必须有固定 unit、JCS digest）；
2. 对声明为 `quantity` 的参数检查单位（不等于声明单位 → `unit_mismatch`），
   归一化为 `value × 10^-scale`；
3. 归一化后的数值交给原生的授权/包含关系。

## 结果

**三端 20/20 全过**（8 条 quantity + 1 条 `unsupported_domain` 失败关闭用例
+ 11 条字符串域）；
Python 与 TypeScript 的输出**逐字节相同**
（`out-python.txt` 与 `out-typescript.txt` 可直接 `cmp`）。

| id | 场景 | 结果 |
|---|---|---|
| q-001 | 3000×10⁻² ≤ 5000×10⁻² | allow |
| q-002 | 5001×10⁻² > 5000×10⁻² | deny `params_exceed_grant` |
| q-003 | 单位 USD ≠ 声明 CNY | deny `unit_mismatch` |
| q-004 | 50（无 scale）vs 5000×10⁻² | allow（归一等值） |
| q-005 | 裸数字代替 quantity 对象 | deny `invalid_params_binding` |
| q-006 | 子 3000 ⊆ 父 5000 | contains=true |
| q-007 | 子 6000 > 父 5000 | params_not_narrower |
| q-008 | 子单位 USD | params_not_narrower |
| u-001 | 声明了一个引擎不认识的 domain（`money`） | deny `unsupported_domain`（不退回形状推断） |

另有三条声明校验：未知 domain → `unsupported_domain`；digest 不匹配 →
`declaration_digest_mismatch`；quantity 缺 unit → 拒。

## 口径

三个实现仍**同作者**，所以这是"三语言一致"的回归证据，不是 P12 的独立实现；
对外表述按 §12 的诚实范围来。

## 三个字符串域（2026-10-17 补）

`decimal-string`、`subdomain`、`path-prefix` 在同一批里实现：

- **Go**：`semantics/domains.go` 的 `stringDomainCovers`，在 `*WithDomains`
  里先比较再"中性化"（把已判定的值替换成占位符，交给原有关系），
  `decimal-string` 用 `math/big.Rat` 精确比较；
- **Python**：`clc_semantics.py` 同名逻辑，用 `decimal.Decimal`；
- **TypeScript**：`clc_semantics.ts` 同名逻辑，用 `BigInt` 精确比较。

Go 侧 11 条字符串域用例（`TestStringDomains`）全过：decimal 等值/指数/上下界、
subdomain 子域/大小写/兄弟域/畸形尾点（`example.com..` → `invalid_params_binding`）、
path 前缀/段边界/未规范化路径。
