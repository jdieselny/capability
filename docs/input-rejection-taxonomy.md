# Input rejection taxonomy (audit C-4)
[中文](zh/input-rejection-taxonomy.md)

Status: informative map of the normative reason codes (§9.1/§9.2).  It exists
so that two implementations can say *why* they refused, not only that they did.
"Denied" alone is not interchangeable with another implementation's "denied".

| Class | What is wrong | Canonical codes |
|---|---|---|
| Revision / feature gate | the declared revision or declaration is not supported | `unsupported_language_revision`, `unsupported_domain` |
| Syntax | identifier grammar or wildcard shape | `invalid_capability_id`, `missing_capability_id`, `unsupported_wildcard` |
| Input boundary (representation) | duplicate keys, non-canonical numbers, malformed Unicode, size/depth | `invalid_params_duplicate_key`, `invalid_params_number`, `invalid_params_size` |
| Binding / shape | a value does not match its declared or inferred domain; a bound is malformed | `invalid_params_binding` |
| Key closure | a declared key is missing, or an undeclared key is present | `params_missing`, `undeclared_param` |
| Enumeration | a value is outside an enum set; cardinality is outside its bounds | `not_in_enum`, `params_cardinality` |
| Bound | a numeric or decimal bound is exceeded; a unit differs; a step is not met | `params_exceed_grant`, `unit_mismatch`, `params_out_of_range`, `params_not_multiple` |
| Namespace / path | scheme or class differ; literal or wildcard depth fails | `different_namespace`, `literal_mismatch`, `wildcard_requires_trailing_segment` |
| Coverage | no source covers the operation; the intersection is empty | `capability_not_authorized`, `no_overlap`, `absent_source` |
| Constraint | an unknown type, an invalid value grammar, or a violated constraint | `unknown_constraint`, `invalid_constraint`, `{type}:violated` |
| Evidence | an evidence constraint or a `Resolve` input is invalid | `invalid_resolution`, `invalid_timestamp` (constraints use the classes above) |
| Containment | a child is outside its parent, or not comparable | `child_exceeds_parent`, `params_not_narrower`, `delegation_mode_not_narrower` |

Rules that follow from the table:

- The canonical code is everything before the first `:`; a diagnostic suffix
  (for example the offending key) does not change the class.
- A vector that pins a refusal pins the canonical code, not a message.
- `invalid_params_binding` deliberately covers "the value does not match its
  domain shape" (including a non-object `quantity` value and an unclean path):
  the failure is structural, not a bound comparison.
