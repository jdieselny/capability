# CLC `{value, unit}` 量编码探针（2026-10-15）

## 问题

"CLC 没有数值单位"是我方记录在案的缺口之一（见
`analysis/2026-10-13-CLC-不足与待补.md` §二；旁证：AIP 用"场外约定"回避、
IICP 用闭集合 `unit` 枚举解决）。

用户提出：**能否用 `{ value = 50.0, unit = "CNY" }` 这样的对象直接解决？单位用
国际通用的大写英文货币码（如 `USD`）。**

## 结论：**可以，且不需要改语言**

CLC §6.2 的 `object` 规则是 "every grant key in op, **values recurse**"——
对象参数逐键递归，递归下去 `value` 走 **number 上界**（`op ≤ grant`）、
`unit` 走 **string 精确相等**。§13.4.3 的 object 行同样递归，并施加
**对称 key closure**。§6.5 的 `param_bounds` 还有 **`nested`** family，可对
对象里的键分别给 min/max/step 与 enum。

⇒ **量 = scheme 定义的对象 `{value, unit}`；语言层无需新类型。**

## 方法（可复现）

同一组 15 个用例，分别跑两个已发布实现，输出规范化为紧凑 JSON 后**逐字节比对**：

| 实现 | 仓库 | 运行 |
|---|---|---|
| Python | `/home/varwof/src/github.com/clc-python` | `PYTHONPATH=... python3 probe.py` |
| TypeScript | `/home/varwof/src/github.com/clc-ts` (Node ≥22) | `node --disable-warning=ExperimentalWarning --experimental-strip-types probe.mjs` |

```bash
cd contrib/clc-unit-encoding
PYTHONPATH=/home/varwof/src/github.com/clc-python python3 probe.py | tee out-python.txt
node --disable-warning=ExperimentalWarning --experimental-strip-types probe.mjs | tee out-typescript.txt
cmp out-python.txt out-typescript.txt && echo AGREE
```

## 结果：两实现**逐字节一致**

`out-python.txt` 与 `out-typescript.txt` 的 sha256 相同：

```
0bd2337de2bfd0fc818f76def13bc04f3348a73373aea15f12b1facccecfda30
```

（两者均声明 `CLC_REVISION = CLC-1.15`。）

| 用例 | 判定 / reason |
|---|---|
| `authorize` 30 ≤ 50 **CNY** | `allow` |
| `authorize` 60 ≤ 50 CNY | `deny` `params_exceed_grant` |
| `authorize` 30 CNY **vs USD** | `deny` `params_exceed_grant`（单位精确不等） |
| `authorize` **50.0 vs 50** | `allow`（JCS 数值相等） |
| `authorize` **"cny" vs "CNY"** | `deny` `params_exceed_grant`（**大小写敏感**） |
| `entails` 30 ≤ 50 | `entails: true` |
| `contains` 子 30 ≤ 50 | `contains: true` |
| `contains` 子 60 > 50 | `false` `params_not_narrower` |
| `contains` 子 USD | `false` `params_not_narrower` |
| `contains` 子**多一个键**（`as_of`） | `false` `params_not_narrower`（key closure） |
| `param_bounds.nested` value 3000 CNY | `allow` |
| 同上 value 6000 | `deny` `params_out_of_range` |
| 同上 value 3000 **EUR** | `deny` `not_in_enum` |
| 同上 `contains` 子 CNY/≤1000 | `contains: true` |
| 同上 `contains` 子 EUR | `false` `params_not_narrower` |

**注意第 5 行**：`"cny"` 与 `"CNY"` 被判为**不同单位**（字符串精确相等）——
这就是为什么单位**必须用统一的大写码**（`USD`/`CNY`/`EUR`…）。

## 三条必须一起声明的限定

1. **键名与形状由 scheme 钉死**：`{value, unit}` 与 `{amount, currency}` 在 CLC
   眼里是**两组不同的键**；语言层不做"这是一个量"的推断（§8.1/§11：
   declaring scheme defines how that value is evaluated）。
2. **不做换算**：`50 CNY` 不覆盖 `7 USD`——单位精确匹配，跨单位**不成立
   （fail-closed）**。这与 Iman 的 BCR `max_amount`（"no conversion is defined"）
   **一致**。
3. **key closure 把对象形状钉死**：有界 grant 下，请求多带一个键即
   `params_not_narrower` / `undeclared_param`。

## 对缺口记录的结论

这不是"缺少单位"，而是"**未命名 quantity 类型**；单位可由 scheme 以对象建模，
由既有 object 递归语义完成比较（值收窄 + 单位精确、不换算）"。BCR §7 要求
profile 给出 numerical units——CLC 把它放在 **scheme/profile 层**，正是 BCR §7
预设的分工。**故该缺口在语言层可判为闭合；剩余只是"CLC-00 未随附 quantity
scheme"。**

## 复现材料

- `probe.py` / `probe.mjs`（同 15 例）
- `out-python.txt` / `out-typescript.txt`（原始输出，sha256 相同）
