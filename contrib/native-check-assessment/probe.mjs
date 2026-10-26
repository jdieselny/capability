#!/usr/bin/env node
// Language-neutral NativeCheckExpectation/NativeCheckAssessment probe
// (TypeScript/JavaScript).  Only the inventory comparison is implemented: no
// CLC requirement evaluation and no carrier-specific logic.  The corpus is
// shared with the Go and Python runners.
//
// Corpus path: CLC_NATIVE_CHECK_CASES, else the first argument.

import { readFileSync } from "node:fs";
import process from "node:process";

const key = (entry) =>
  `${entry.checkId ?? ""}\u0000${entry.componentType ?? ""}\u0000${entry.evidenceDigest ?? ""}`;

// Mirror projection.AssessNativeChecks.  An empty inventory is never complete.
// A duplicate expectation is reported as missing.  Unexpected results only
// count when an inventory was declared.
function assess(expected, results) {
  const outcomes = new Map();
  for (const result of results) {
    const k = key(result);
    if (!outcomes.has(k)) outcomes.set(k, new Set());
    outcomes.get(k).add(result.outcome ?? "");
  }

  const expectedKeys = new Set();
  let missing = 0;
  for (const want of expected) {
    const k = key(want);
    if (expectedKeys.has(k)) {
      missing += 1;
      continue;
    }
    expectedKeys.add(k);
    const seen = outcomes.get(k);
    if (!seen || seen.size === 0) missing += 1;
  }

  let unexpected = 0;
  if (expectedKeys.size > 0) {
    for (const result of results) {
      if (!expectedKeys.has(key(result))) unexpected += 1;
    }
  }

  let conflicting = 0;
  for (const seen of outcomes.values()) if (seen.size > 1) conflicting += 1;

  const complete =
    expected.length > 0 && missing === 0 && unexpected === 0 && conflicting === 0;
  return { complete, missing, unexpected, conflicting };
}

function main() {
  const path = process.env.CLC_NATIVE_CHECK_CASES || process.argv[2];
  if (!path) {
    console.error("usage: probe.mjs <cases.json> (or CLC_NATIVE_CHECK_CASES)");
    return 2;
  }
  const corpus = JSON.parse(readFileSync(path, "utf8"));

  let failures = 0;
  for (const item of corpus.cases) {
    const { complete, missing, unexpected, conflicting } = assess(
      item.expected ?? [],
      item.results ?? [],
    );
    const got = `complete=${complete},missing=${missing},unexpected=${unexpected},conflicting=${conflicting}`;
    const status = got === item.want ? "PASS" : "FAIL";
    if (status === "FAIL") failures += 1;
    console.log(`${status} ${item.id} ${item.name.padEnd(52)} want=${item.want} got=${got}`);
  }

  if (failures > 0) {
    console.error(`${failures} case(s) failed`);
    return 1;
  }
  return 0;
}

process.exit(main());
