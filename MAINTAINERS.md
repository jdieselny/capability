<!--
SPDX-FileCopyrightText: 2026 Jijie Wei and CLC contributors
SPDX-License-Identifier: Apache-2.0
-->

# Maintainers

## Current

| Maintainer | GitHub | Scope | Since |
|---|---|---|---|
| Jijie Wei | [@varwof](https://github.com/varwof) | CLC core, corpora, releases, initial governance | 2026-09 |

## Open roles

The project is actively seeking maintainers for:

- independent implementations;
- carrier bindings and projection profiles;
- security review;
- conformance review for the CLC-D corpora, once the 64 containment and 15
  authorize-chain vectors pass; the CLC-A core corpus is covered by an
  appointed reviewer (`CONFORMANCE.md`).

Maintainer eligibility and appointment are defined in `GOVERNANCE.md`.

## Conformance reviewers

| Reviewer | Scope | Since |
|---|---|---|
| Justin D. Kintzele ([@jdieselny](https://github.com/jdieselny)) | CLC-A core corpus: 154 core vectors and 1,184 property cases, including verdict, reason code and the unresolved channel. Provisional: extends to the CLC-1.19 corpora and to CLC-D once the reviewer has run those corpora and published the results | 2026-10 |

Appointed 2026-10-27 on the reviewer's written acceptance, which carried a
P12 independence statement and a standing commitment to rerun the corpora on
each revision published here. Not in this appointment: CLC-1.19 minor-gate
semantics, CLC-D, CLC-E, and governance votes. Claims authored by the reviewer
are outside the reviewer's scope in every class: the reviewer authored
`reg-2026-001` and recuses from it. Term 12 months, renewable. The role and
its limits are in `GOVERNANCE.md`; review ownership is recorded in
`.github/CODEOWNERS`, which takes effect only if the reviewer is given write
access.

Reviewer scope, term and recusal rules are in `GOVERNANCE.md`; the procedure
and checklist are in `CONFORMANCE.md`; verified claims are recorded in
`conformance/registry.md`.

## Emeritus

None.
