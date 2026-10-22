# `varwof/scheme-admin-v1` — three-language evidence（2026-10-22）

§7 交叉语言阶段的落地点：把同一套 26 条 scheme-admin 向量同时交给 Go
确认路径、Python 探针和 TypeScript 探针，三端渲染**同一条证据行**，按字节比较。

| 实现 | 位置 | 入口 |
|---|---|---|
| Go（参考） | `register/schemeadmin` + `register/cmd/scheme-admin` | `go test ./schemeadmin/ -run TestCrossLanguageVectors -v` |
| Python | `contrib/scheme-admin/probe.py` | `python3 probe.py BUNDLE.json` |
| TypeScript | `contrib/scheme-admin/probe.ts` | `node --experimental-strip-types probe.ts BUNDLE.json` |

语料：`data/_vectors/scheme-admin-v1/scheme-admin-vectors.json`（26 条）。
证据：`out-python.txt`、`out-typescript.txt`（两个文件除 `# probe*` 头以外逐字节相同）。

一条命令：

```sh
python3 contrib/scheme-admin/run.py          # 重新跑并刷新 checked-in 证据
python3 contrib/scheme-admin/run.py --check  # 只跑，不改文件
```

`run.py` 驱动 Go 测试（`SA_CROSSLANG_OUT` 指向本目录）。Go 测试负责：

1. 从语料物化确定性 fixture（CA、publisher、AIC、detached PKCS#7）；
2. 只把**输入**写进 bundle：payload 字节、规范化后的 package/transition、
   物化后的 trust policy、本地 registry state、签名；
3. 跑 Go 确认路径，跑两个探针，三方证据行逐字节比较；
4. 缺解释器或探针时 `t.Skip`，不静默通过。

bundle 里**没有**期望判决，也没有 Go 的结果，所以探针不能靠复述参考答案过关。

## 探针做什么

探针不是薄封装，它自己完成：

- 解析 detached PKCS#7：CMS `SignedData` → `SignerInfo` → signed attrs，
  校验 `messageDigest`，用内嵌签名证书验证 ECDSA-SHA256；
- 从证书扩展 `1.3.6.1.4.1.66257.1.1` 解出 AIC，校验 principal、SPKI key hash；
- 封闭解析 package / transition（未知成员即 shape 错误）；
- 复算 JCS 摘要（package、transition、management operation）；
- 校验 CLC revision、major 上界、generation 连续性、fork/rollback、撤销、
  新鲜度、审批阈值；
- 用 CLC 语言包跑 `contains` / `authorize_set`，外加 CLC-1.19 的
  `path-prefix` 声明域（在比较前判定并中和），与 Go 的
  `ContainsWithDomains` / `AuthorizeSetWithDomains` 对齐。

Python 依赖 `cryptography`，并可使用 `clc-python` 的
`clc.clc_semantics` 或 `aic-capability-demo` 根目录导出的
`clc_semantics.py`；TypeScript 依赖 `clc_semantics.ts` 与 Node ≥ 22 的
类型剥离。两者都可用 `CLC_PY_DIR` / `CLC_TS_DIR` 覆盖路径。

## 为什么证据行里没有证书摘要

`publisher_certificate_digest` 是**部署时**值：Go 的 `x509.CreateCertificate`
每次生成随机签名，同一 fixture 两次运行的证书 DER 都不同。把它放进稳定证据
会让 checked-in 输出无法复现。语料能钉住的是确定性的 `publisher_key_id`
（SPKI 的 `sha256:` id），证据行因此只带 `pkg` / `tr` / `op` / `key`。

## 口径

三个实现仍**同作者**，所以这是"同一管治下的跨语言一致"回归证据，
不是独立实现，也不构成 P12 的独立实现主张。能力语义没有新增 CLC 语法或判决：
`scheme:verify` 不存在，撤销是墓碑而不是删除。
