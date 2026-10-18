# Cross-family decision table (audit C-5)
[中文](zh/cross-family-decision-table.md)

Status: informative summary of §6.5/§6.6/§13.4.3 as revised through CLC-1.19.
It answers one question: for a pair of value families, does the operation meet,
refuse, or compare at all?

| Parent family | Child family | Authorization (`Entails`) | Meet (`BoundMeet`) | Containment (`Contains`) |
|---|---|---|---|---|
| numeric | numeric | compare (`min`=greater, `max`=least, `step` rule) | meet | child ≤ parent |
| enum | enum | membership with JSON type-sensitive equality | intersect members, tighten cardinality | child set ⊆ parent set |
| numeric | enum | refuse `invalid_params_binding` | refuse `invalid_params_binding` | `params_not_narrower` |
| enum | numeric | refuse `invalid_params_binding` | refuse `invalid_params_binding` | `params_not_narrower` |
| scalar (numeric/enum) | nested (object) | refuse `invalid_params_binding` | refuse `invalid_params_binding` | `params_not_narrower` |
| nested | scalar | refuse `invalid_params_binding` | refuse `invalid_params_binding` | `params_not_narrower` |
| nested | nested | recurse over identical key sets | recurse | recurse; key sets must match |
| declared domain X | declared domain X | per §6.7 | per §6.7 | per §6.7 |
| declared domain X | declared domain Y (X≠Y) | refuse `invalid_params_binding` | refuse `invalid_params_binding` | `params_not_narrower` |

Notes:

- Empty meets *within one family* are `no_overlap`; every cross-family pair is
  `invalid_params_binding` before any value math (CLC-1.15).
- "Different declared domain" counts as cross-family even when both values are
  strings: a `subdomain` value is not comparable with a `path-prefix` value.
- A declaration that names a domain the implementation does not support is
  refused earlier, with `unsupported_domain` (§6.7), before this table applies.
