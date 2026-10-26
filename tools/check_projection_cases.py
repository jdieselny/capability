#!/usr/bin/env python3
"""Check the declared projection cases against checked-in or rerun output."""

import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys

CASE_RE = re.compile(
    r"^(PASS|FAIL) ([A-Z][A-Z0-9-]+)\s+.*?\bwant=(\S+) got=(\S+)$"
)


def parse_cases(text, label):
    cases = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.startswith(("PASS ", "FAIL ")):
            continue
        match = CASE_RE.match(line)
        if not match:
            raise ValueError(
                f"{label}:{line_number}: malformed case line: {line}"
            )
        status, case_id, want, got = match.groups()
        if case_id in cases:
            raise ValueError(f"{label}: duplicate case ID {case_id}")
        cases[case_id] = {
            "status": status,
            "want": want,
            "got": got,
        }
    return cases


def load_outputs(manifest, root, register_dir):
    outputs = {}
    if register_dir is None:
        for probe, spec in manifest["probes"].items():
            path = root / spec["output"]
            raw = path.read_bytes()
            verify_sha256(raw, spec["output_sha256"], spec["output"])
            outputs[probe] = raw.decode("utf-8")
        return outputs

    for relative_path, expected in manifest["probe_source_sha256"].items():
        path = register_dir / relative_path
        verify_sha256(path.read_bytes(), expected, str(path))

    for probe, spec in manifest["probes"].items():
        command = shlex.split(spec["command"])
        run = subprocess.run(
            command,
            cwd=register_dir,
            check=False,
            capture_output=True,
            text=True,
        )
        if run.returncode != 0:
            raise RuntimeError(
                f"{probe}: command failed ({run.returncode}): "
                f"{' '.join(command)}\n{run.stderr}"
            )
        verify_sha256(
            run.stdout.encode("utf-8"),
            spec["output_sha256"],
            f"{probe} fresh output",
        )
        outputs[probe] = run.stdout
    return outputs


def verify_sha256(raw, expected, label):
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise ValueError(
            f"{label}: sha256 mismatch: expected={expected} actual={actual}"
        )


def load_cross_language_outputs(manifest, root, register_dir, demo_dir):
    parity = manifest["cross_language_binding"]
    if demo_dir is not None and register_dir is None:
        raise ValueError("--demo-dir requires --register-dir for the shared fixture")
    if demo_dir is not None:
        for relative_path, expected in parity["demo_source_sha256"].items():
            path = demo_dir / relative_path
            verify_sha256(path.read_bytes(), expected, str(path))

    outputs = {}
    for language in ("python", "typescript"):
        spec = parity[language]
        source = root / spec["source"]
        verify_sha256(source.read_bytes(), spec["source_sha256"], str(source))

        checked = root / spec["output"]
        checked_raw = checked.read_bytes()
        verify_sha256(checked_raw, spec["output_sha256"], str(checked))
        outputs[language] = checked_raw.decode("utf-8")

        if demo_dir is None:
            continue

        fixture = register_dir / parity["fixture"]
        verify_sha256(
            fixture.read_bytes(),
            parity["fixture_sha256"],
            str(fixture),
        )
        env = os.environ.copy()
        env["CLC_EMILIA_BINDING_FIXTURE"] = str(fixture.resolve())
        if language == "python":
            env["CLC_PY_DIR"] = str(demo_dir.resolve())
        else:
            env["CLC_TS_FILE"] = str(
                (demo_dir / "ts" / "clc_semantics.ts").resolve()
            )

        run = subprocess.run(
            shlex.split(spec["command"]),
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        if run.returncode != 0:
            raise RuntimeError(
                f"{language} binding probe failed ({run.returncode}):\n{run.stderr}"
            )
        fresh_raw = run.stdout.encode("utf-8")
        verify_sha256(fresh_raw, spec["output_sha256"], f"{language} fresh output")
        outputs[language] = run.stdout
    return outputs


def check_cross_language(manifest, outputs):
    parity = manifest["cross_language_binding"]
    declared = {
        case["id"]: case
        for case in manifest["probes"][parity["case_set"]]["cases"]
    }
    failures = []
    for language, text in outputs.items():
        actual = parse_cases(text, f"{language} binding probe")
        missing = sorted(set(declared) - set(actual))
        extra = sorted(set(actual) - set(declared))
        if missing:
            failures.append(
                f"{language}: missing binding cases {', '.join(missing)}"
            )
        if extra:
            failures.append(
                f"{language}: undeclared binding cases {', '.join(extra)}"
            )
        for case_id, expected in declared.items():
            result = actual.get(case_id)
            if result is None:
                continue
            if result["status"] != "PASS":
                failures.append(f"{language}: {case_id} did not PASS")
            elif result["want"] != result["got"]:
                failures.append(
                    f"{language}: {case_id} printed PASS but want != got: "
                    f"want={result['want']} got={result['got']}"
                )
            if result["want"] != expected["want"]:
                failures.append(f"{language}: {case_id} want mismatch")
            if result["got"] != expected["got"]:
                failures.append(f"{language}: {case_id} got mismatch")
    return len(declared), failures


def check(manifest, outputs):
    declared_total = manifest["total_cases"]
    checked_total = 0
    failures = []

    for probe, spec in manifest["probes"].items():
        declared = {case["id"]: case for case in spec["cases"]}
        actual = parse_cases(outputs[probe], probe)
        checked_total += len(declared)

        missing = sorted(set(declared) - set(actual))
        extra = sorted(set(actual) - set(declared))
        if missing:
            failures.append(f"{probe}: missing cases {', '.join(missing)}")
        if extra:
            failures.append(f"{probe}: undeclared cases {', '.join(extra)}")

        for case_id, expected in declared.items():
            result = actual.get(case_id)
            if result is None:
                continue
            if result["status"] != "PASS":
                failures.append(f"{probe}: {case_id} did not PASS")
            elif result["want"] != result["got"]:
                failures.append(
                    f"{probe}: {case_id} printed PASS but want != got: "
                    f"want={result['want']} got={result['got']}"
                )
            if result["want"] != expected["want"]:
                failures.append(
                    f"{probe}: {case_id} want mismatch: "
                    f"declared={expected['want']} output={result['want']}"
                )
            if result["got"] != expected["got"]:
                failures.append(
                    f"{probe}: {case_id} got mismatch: "
                    f"declared={expected['got']} output={result['got']}"
                )

    if checked_total != declared_total:
        failures.append(
            f"total_cases mismatch: declared={declared_total} "
            f"checked={checked_total}"
        )
    return checked_total, failures


def load_assessment_outputs(spec, root, register_dir):
    """Load the language-neutral native-check assessment outputs.

    The checked-in output is always verified; when a register checkout is given,
    each runner is re-executed and its fresh output must match byte for byte.
    """
    if not spec:
        return {}

    corpus = root / spec["corpus"]
    verify_sha256(corpus.read_bytes(), spec["corpus_sha256"], spec["corpus"])

    outputs = {}
    for language, runner in spec["runners"].items():
        checked = root / runner["output"]
        checked_raw = checked.read_bytes()
        verify_sha256(checked_raw, runner["output_sha256"], runner["output"])
        outputs[language] = checked_raw.decode("utf-8")

        if register_dir is None:
            continue

        base = register_dir if runner.get("in_register") else root
        for relative_path, expected in runner.get("source_sha256", {}).items():
            path = base / relative_path
            verify_sha256(path.read_bytes(), expected, str(path))

        env = os.environ.copy()
        env["CLC_NATIVE_CHECK_CASES"] = str(corpus.resolve())
        command = shlex.split(runner["command"])
        run = subprocess.run(
            command,
            cwd=base,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        if run.returncode != 0:
            raise RuntimeError(
                f"{language} assessment probe failed ({run.returncode}): "
                f"{' '.join(command)}\n{run.stderr}"
            )
        fresh_raw = run.stdout.encode("utf-8")
        verify_sha256(fresh_raw, runner["output_sha256"], f"{language} fresh output")
        outputs[language] = run.stdout
    return outputs


def check_assessment(spec, outputs):
    if not spec:
        return 0, []

    declared = {case["id"]: case for case in spec["cases"]}
    failures = []
    for language, text in outputs.items():
        actual = parse_cases(text, f"{language} assessment")
        missing = sorted(set(declared) - set(actual))
        extra = sorted(set(actual) - set(declared))
        if missing:
            failures.append(
                f"{language}: missing assessment cases {', '.join(missing)}"
            )
        if extra:
            failures.append(
                f"{language}: undeclared assessment cases {', '.join(extra)}"
            )
        for case_id, expected in declared.items():
            result = actual.get(case_id)
            if result is None:
                continue
            if result["status"] != "PASS":
                failures.append(f"{language}: {case_id} did not PASS")
            elif result["want"] != result["got"]:
                failures.append(
                    f"{language}: {case_id} printed PASS but want != got: "
                    f"want={result['want']} got={result['got']}"
                )
            if result["want"] != expected["want"]:
                failures.append(f"{language}: {case_id} want mismatch")
            if result["got"] != expected["got"]:
                failures.append(f"{language}: {case_id} got mismatch")
    return len(declared), failures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        help="manifest path (default: contrib/projection-cases-v1.json)",
    )
    parser.add_argument(
        "--register-dir",
        type=pathlib.Path,
        help="run probe commands from this register checkout instead of reading checked-in output",
    )
    parser.add_argument(
        "--demo-dir",
        type=pathlib.Path,
        help="run Python/TypeScript binding probes from this aic-capability-demo checkout",
    )
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parents[1]
    manifest_path = args.manifest or root / "contrib/projection-cases-v1.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    outputs = load_outputs(manifest, root, args.register_dir)
    checked_total, failures = check(manifest, outputs)
    cross_outputs = load_cross_language_outputs(
        manifest, root, args.register_dir, args.demo_dir
    )
    cross_total, cross_failures = check_cross_language(manifest, cross_outputs)
    failures.extend(cross_failures)

    assessment_spec = manifest.get("native_check_assessment")
    assessment_outputs = load_assessment_outputs(
        assessment_spec, root, args.register_dir
    )
    assessment_total, assessment_failures = check_assessment(
        assessment_spec, assessment_outputs
    )
    failures.extend(assessment_failures)

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        return 1
    print(f"PASS {checked_total} projection cases")
    print(f"PASS {cross_total} cross-language binding cases x2")
    if assessment_spec:
        print(
            f"PASS {assessment_total} native-check assessment cases "
            f"x{len(assessment_outputs)}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
