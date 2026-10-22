# Catalog cross-language evidence

Inputs for `register/catalog`'s `TestCrossLanguageVectors`, and the two
independent readings of them.

| File | Role |
|---|---|
| `probe.py` | Python reading of the catalog admission algorithm |
| `probe.ts` | TypeScript reading of the same algorithm |
| `run.py` | regenerates / checks `out-*.txt` by driving the Go test |
| `out-python.txt` | checked-in Python evidence lines |
| `out-typescript.txt` | checked-in TypeScript evidence lines |

The Go test materialises a bundle whose members are **inputs only**: exact
artifact bytes, the deployer policy, the accepted-generation state, the trusted
root and the detached PKCS#7 signature.  It contains no expected verdict and no
Go result.

Each probe prints one line per vector:

```text
<id> <kind> <verdict> <reason|-> [cat=<digest>] [key=<keyid>] [gen=<n>]
```

The Go runner renders the same line, and the test fails unless all three are
byte-identical.  The checked-in `out-*.txt` files are compared in `--check`
mode:

```sh
python3 contrib/catalog/run.py            # regenerate
python3 contrib/catalog/run.py --check    # verify checked-in evidence
```

Environment: Python needs `cryptography` and either the `clc-python` package or
the equivalent `clc_semantics.py` exported by `aic-capability-demo` (override
the directory with `CLC_PY_DIR`); Node ≥ 22 needs
`--experimental-strip-types` and `clc_semantics.ts` from either implementation
(override with `CLC_TS_DIR`).  `REGISTER_DIR` overrides the register checkout
location.

The DER/CMS/AIC reader, the CLC-1.19 declared-domain relation and the canonical
digest helper are carried verbatim from `contrib/scheme-admin`.  The catalog
algorithm is a second reading under the same stewardship, not an independent
implementation.
