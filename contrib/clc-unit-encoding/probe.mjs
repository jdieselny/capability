// CLC {value, unit} 量编码探针 —— TypeScript 侧。
//
// 与 probe.py 逐例对应，用于比对 verdict 与 reason code 是否逐字一致。
// 依赖：clc-ts（本机 /home/varwof/src/github.com/clc-ts），Node >= 22。
// 运行：
//   node --disable-warning=ExperimentalWarning --experimental-strip-types probe.mjs
// 实现文件可配：本机默认 clc-ts/clc_semantics.ts；CI 里指向 aic-capability-demo/ts/。
const CLC_TS = process.env.CLC_TS_FILE
  || 'file:///home/varwof/src/github.com/clc-ts/clc_semantics.ts';
const { authorize, contains, entails, CLC_REVISION } = await import(CLC_TS);

// 示例性标识：本探针演示编码机制，不代表某个已发布 scheme。
const CID = 'example/quantity-v1:charge';

const grant = (value, unit, extra) => ({
  id: CID,
  params: Object.assign({ amount: { value, unit } }, extra || {}),
});
const op = (value, unit, extra) => ({
  id: CID,
  params: Object.assign({ amount: { value, unit } }, extra || {}),
});

const cases = [
  ['authorize 30<=50 CNY', () => authorize(grant(50, 'CNY'), op(30, 'CNY'))],
  ['authorize 60<=50 CNY', () => authorize(grant(50, 'CNY'), op(60, 'CNY'))],
  ['authorize 30 CNY vs USD', () => authorize(grant(50, 'CNY'), op(30, 'USD'))],
  ['authorize 50.0 vs 50', () => authorize(grant(50.0, 'CNY'), op(50, 'CNY'))],
  ['authorize cny vs CNY (lowercase)', () => authorize(grant(50, 'CNY'), op(50, 'cny'))],
  ['entails 30<=50', () => entails(grant(50, 'CNY'), op(30, 'CNY'))],
  ['contains child 30<=50', () => contains(grant(50, 'CNY'), grant(30, 'CNY'))],
  ['contains child 60>50', () => contains(grant(50, 'CNY'), grant(60, 'CNY'))],
  ['contains child USD', () => contains(grant(50, 'CNY'), grant(30, 'USD'))],
  ['contains child adds key', () => contains(grant(50, 'CNY'), grant(30, 'CNY', { as_of: '2026-10-15' }))],
];

// 富写法：param_bounds.nested 给 value 上限、给 unit 一个枚举。
const gNested = {
  id: CID,
  param_bounds: {
    amount: { nested: { value: { max: 5000 }, unit: { enum: ['CNY', 'USD'] } } },
  },
};
const oNested = (v, u) => ({ id: CID, params: { amount: { value: v, unit: u } } });
const narrowNested = {
  id: CID,
  param_bounds: {
    amount: { nested: { value: { max: 1000 }, unit: { enum: ['CNY'] } } },
  },
};
const badNested = {
  id: CID,
  param_bounds: {
    amount: { nested: { value: { max: 1000 }, unit: { enum: ['EUR'] } } },
  },
};

const nestedCases = [
  ['param_bounds value 3000 CNY', () => authorize(gNested, oNested(3000, 'CNY'))],
  ['param_bounds value 6000 CNY', () => authorize(gNested, oNested(6000, 'CNY'))],
  ['param_bounds value 3000 EUR', () => authorize(gNested, oNested(3000, 'EUR'))],
  ['param_bounds contains narrow', () => contains(gNested, narrowNested)],
  ['param_bounds contains EUR', () => contains(gNested, badNested)],
];

console.log('CLC_REVISION =', CLC_REVISION);
for (const [name, fn] of [...cases, ...nestedCases]) {
  try {
    console.log(name.padEnd(38), '->', JSON.stringify(fn()));
  } catch (e) {
    console.log(name.padEnd(38), '-> EXC', e.constructor.name, e.message);
  }
}
