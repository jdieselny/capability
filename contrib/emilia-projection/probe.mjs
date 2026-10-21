// Cross-language EMILIA binding projection probe (TypeScript).
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const FIXTURE = process.env.CLC_EMILIA_BINDING_FIXTURE
  || path.resolve(ROOT, '..', 'register', 'cmd', 'emilia-projection-probe',
    'testdata', 'emilia-binding-fixture-v1.json');
const CLC_TS_FILE = process.env.CLC_TS_FILE
  || path.resolve(ROOT, '..', 'aic-capability-demo', 'ts', 'clc_semantics.ts');
const CLC_TS_URL = CLC_TS_FILE.startsWith('file://')
  ? new URL(CLC_TS_FILE) : pathToFileURL(CLC_TS_FILE);
const clc = await import(CLC_TS_URL.href);
const evidence = await import(new URL('./evidence_semantics.ts', CLC_TS_URL).href);

const digestObject = (value) =>
  'sha256:' + createHash('sha256')
    .update(Buffer.from(clc.canonicalJSON(value), 'utf8'))
    .digest('hex');

function relationTuple(binding) {
  const subjects = binding.targets.map((target) => target.subject).sort();
  const issuedAt = [binding.source.issued_at,
    ...binding.targets.map((target) => target.issued_at)].sort();
  return {
    requirement_id: 'treasury-wire-evidence@7',
    policy_generation: binding.source.policy_generation,
    from: {
      type: 'policy-permit',
      artifact_digest: digestObject(binding.source),
    },
    relation: 'permits',
    to: {
      type: 'ep-quorum',
      artifact_set_digest: digestObject(binding.targets),
    },
    action_digest: digestObject(binding.action),
    subjects,
    trust: binding.trust,
    status_digest: digestObject(binding.status),
    status_snapshot: binding.status,
    evidence_issued_at: issuedAt,
  };
}

const bindingSubject = (binding) => createHash('sha256')
  .update(Buffer.from(clc.canonicalJSON(relationTuple(binding)), 'utf8'))
  .digest('base64url');

function mutate(binding, mutation) {
  const value = JSON.parse(JSON.stringify(binding));
  const parts = mutation.path;
  let current = value;
  for (const part of parts.slice(0, -1)) current = current[part];
  current[parts.at(-1)] = mutation.value;
  return value;
}

function evidenceFacts(testCase, now, subject) {
  const facts = [];
  for (const [role, entries] of Object.entries(testCase.facts)) {
    for (const entry of entries) {
      facts.push({
        type: role,
        subject: entry.subject === '$binding' ? subject : entry.subject,
        verified: entry.verified,
        issued_at: new Date(
          Date.parse(now) - entry.age_sec * 1000
        ).toISOString(),
      });
    }
  }
  return facts;
}

const verdictString = (verdict, reason) => verdict + (reason ? `/${reason}` : '');

function printCase(id, name, want, got, expectedGot = want) {
  const status = got === expectedGot ? 'PASS' : 'FAIL';
  console.log(`${status} ${id} ${name.padEnd(55)} want=${want} got=${got}`);
}

const fixture = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
const subject = bindingSubject(fixture.binding);

console.log('EMILIA → CLC evidence projection probe (TypeScript)');
console.log('fixture: register/cmd/emilia-projection-probe/testdata/'
  + 'emilia-binding-fixture-v1.json');
console.log();

printCase('EMI-BIND-001', 'base relation tuple has the pinned subject',
  fixture.expected_subject, subject);

for (const testCase of fixture.evidence_cases) {
  const [verdict, reason] = evidence.evaluateRequirement(
    fixture.mapped_requirement,
    evidenceFacts(testCase, fixture.now, subject),
    { now: fixture.now },
  );
  printCase(testCase.id, testCase.name, testCase.want,
    verdictString(verdict, reason), testCase.expected_got);
}

const caid = fixture.caid;
const operationId = clc.computeActionID(
  caid.type.name, caid.type.material, caid.suite, caid.operation,
);
for (const testCase of caid.cases) {
  const observedId = clc.computeActionID(
    caid.type.name, caid.type.material, caid.suite, testCase.observed,
  );
  const got = operationId === observedId ? 'MATCH' : 'NOT_EQUIVALENT';
  printCase(testCase.id, testCase.name, testCase.want, got);
}

const bindingIds = {
  source: 'EMI-BIND-002',
  target: 'EMI-BIND-003',
  action: 'EMI-BIND-004',
  status: 'EMI-BIND-005',
};
for (const kind of Object.keys(bindingIds)) {
  const changed = bindingSubject(mutate(fixture.binding, fixture.mutations[kind]));
  printCase(bindingIds[kind], `${kind} mutation changes the relation subject`,
    'different', changed === subject ? 'unchanged' : 'different');
}

const opaqueCase = {
  facts: {
    'ep-quorum': [
      { subject: 'alice', verified: true, age_sec: 30 },
      { subject: 'bob', verified: true, age_sec: 20 },
    ],
    'policy-permit': [{ subject: 'policy', verified: true, age_sec: 60 }],
    'ep:binding:permits': [
      { subject: 'arbitrary-unbound-subject', verified: true, age_sec: 60 },
    ],
  },
};
const [opaqueVerdict, opaqueReason] = evidence.evaluateRequirement(
  fixture.mapped_requirement,
  evidenceFacts(opaqueCase, fixture.now, subject),
  { now: fixture.now },
);
printCase('EMI-BIND-006', 'CLC treats the binding subject as opaque',
  'opaque-subject-accepted',
  verdictString(opaqueVerdict, opaqueReason) === 'SATISFIED'
    ? 'opaque-subject-accepted' : 'unexpectedly-rejected');
