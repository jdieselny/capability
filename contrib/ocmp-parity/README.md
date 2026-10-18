# OCMP offline profile: three-port run (2026-10-18)

`data/_vectors/clc-v1/offline-vectors.json` now carries a structured `inputs`
object per vector (the original prose is kept under `description`).

| Port | Implemented in | Result |
|---|---|---|
| Go | `register/ocmp` (`TestOfflineVectors`) | 12/12 |
| Python | `aic-capability-demo/ocmp.py` (`offline-vectors-run.py`) | 12/12 |
| TypeScript | `aic-capability-demo/ts/ocmp.ts` (`ts/offline-vectors-run.ts`) | 12/12 |

The Python and TypeScript runner outputs are byte-identical
(`out-python.txt` vs `out-typescript.txt`).

Rules covered: R2 (missing MUST inputs), R3 (snapshot window and monotonic
version), R4 (lifetime and revocation), R5 (counter replay), R6 (local facts),
R7 (clock offset).  All three implementations deny with the same stable code.

Limit: the three ports share an author, so this is regression evidence for the
profile, not the independent-implementation bar of P12.
