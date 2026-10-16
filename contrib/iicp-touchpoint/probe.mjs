// IICP §12.3 touchpoint 探针 —— TypeScript 侧（与 probe.py 逐例对应）。
// 运行：node --disable-warning=ExperimentalWarning --experimental-strip-types probe.mjs
// 实现文件可配：本机默认 clc-ts/clc_semantics.ts；CI 里指向 aic-capability-demo/ts/。
const CLC_TS = process.env.CLC_TS_FILE
  || 'file:///home/varwof/src/github.com/clc-ts/clc_semantics.ts';
const { CLC_REVISION, authorize, contains } = await import(CLC_TS);

// 标识与参数取自本仓已发布的 scheme data/std/payments-v1/v1.json
// （action transfer；params amount(number) / currency(大写 ISO 枚举) / counterparty(数组)）。
const CID = 'std/payments-v1:transfer';
const WINDOW = 'varwof/constraint-v1:time:window:[{"start":"09:00","end":"17:00"}]';

const grant = (amount, currency, counterparty, constraints) => {
  const g = {
    id: CID,
    params: { amount, currency: [...currency], counterparty: [...counterparty] },
  };
  if (constraints !== undefined) g.constraints = [...constraints];
  return g;
};
const op = (amount, currency, counterparty) => ({
  id: CID,
  params: {
    amount,
    currency: Array.isArray(currency) ? currency : [currency],
    counterparty: Array.isArray(counterparty) ? counterparty : [counterparty],
  },
});

const BASE = grant(5000, ['CNY'], ['vendor.example']);

const cases = [
  ['A0 base: inside grant', () => authorize(BASE, op(3000, 'CNY', 'vendor.example'))],
  ['A1 widened destination', () => authorize(BASE, op(3000, 'CNY', 'other.example'))],
  ['A2 unit ambiguity (USD)', () => authorize(BASE, op(3000, 'USD', 'vendor.example'))],
  ['A2b unit case (cny)', () => authorize(BASE, op(3000, 'cny', 'vendor.example'))],
  ['A2c amount above bound', () => authorize(BASE, op(6000, 'CNY', 'vendor.example'))],
  [
    'A3 unknown required constraint',
    () => authorize(grant(5000, ['CNY'], ['vendor.example'], ['acme/policy-v1:geo:eu']), op(3000, 'CNY', 'vendor.example')),
  ],
  [
    'A4 recognized-not-evaluated (time)',
    () => authorize(grant(5000, ['CNY'], ['vendor.example'], [WINDOW]), op(3000, 'CNY', 'vendor.example')),
  ],
  ['A5 retry to another provider (same verdict)', () => authorize(BASE, op(3000, 'CNY', 'vendor.example'))],
];

const containCases = [
  ['C0 child narrows amount', () => contains(BASE, grant(1000, ['CNY'], ['vendor.example']))],
  ['C0b child narrows counterparty set', () => contains(BASE, grant(5000, ['CNY'], ['vendor.example']))],
  ['C1 child widens destination set', () => contains(BASE, grant(5000, ['CNY'], ['vendor.example', 'other.example']))],
  ['C2 child changes currency', () => contains(BASE, grant(1000, ['USD'], ['vendor.example']))],
];

console.log('CLC_REVISION =', CLC_REVISION);
for (const [name, fn] of [...cases, ...containCases]) {
  try {
    console.log(name.padEnd(42), '->', JSON.stringify(fn()));
  } catch (e) {
    console.log(name.padEnd(42), '-> EXC', e.constructor.name, e.message);
  }
}
