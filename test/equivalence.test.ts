/**
 * The central guarantee (ADR-0008): for every filter the gate accepts, in-memory evaluation and
 * the SQL compiler select exactly the same rows. Ported from spike 02, run on PGlite (real
 * Postgres compiled to WASM, in-process), with property-based tests (fast-check).
 *
 * Mutation checks prove the property test has teeth: each deliberately broken compiler (the bugs
 * the design exists to prevent) must be caught.
 */
import { PGlite } from '@electric-sql/pglite'
import type { Actor, QueryFilter } from '@strutvane/contracts'
import fc from 'fast-check'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { evaluateFilter } from '../src/policy/evaluate.ts'
import { compileToSql } from '../src/sql/index.ts'
import { invoicePolicy, invoiceSchema } from './fixtures.ts'

const UUIDS = [
  '0190f2a0-0000-7000-8000-00000000000a',
  '0190f2a0-0000-7000-8000-00000000000b',
  '0190f2a0-0000-7000-8000-00000000000c',
]
const CUSTOMERS = [
  '0190f2a0-0000-7000-8000-000000000c01',
  '0190f2a0-0000-7000-8000-000000000c02',
  '0190f2a0-0000-7000-8000-000000000c03',
]
const DANGLING = '0190f2a0-0000-7000-8000-000000000dea'
const TEXT_ATOMS = [
  'a',
  'A',
  'b',
  'B',
  'z',
  'Z',
  '%',
  '_',
  '\\',
  "'",
  ' ',
  'é',
  'É',
  'ß',
  'ı',
  'İ',
  '👋',
  '-',
  '0',
]

const text = fc
  .array(fc.constantFrom(...TEXT_ATOMS), { maxLength: 4 })
  .map((parts) => parts.join(''))
const nullable = <T>(arb: fc.Arbitrary<T>) => fc.option(arb, { nil: null, freq: 4 })
const int4 = fc.oneof(
  fc.integer({ min: -5, max: 5 }),
  fc.constantFrom(-2147483648, 2147483647, 500, 10_000),
)
const float8 = fc.oneof(
  fc.constantFrom(0, -0, 0.5, -1.5, 1e-10, 1.5, 2.25),
  fc.double({ min: -10, max: 10, noNaN: true, noDefaultInfinity: true }),
)
const uuid = fc.constantFrom(...UUIDS)

const rowArb = fc.record({
  owner_id: nullable(uuid),
  status: nullable(text),
  title: nullable(text),
  amount: nullable(int4),
  score: nullable(float8),
  archived: nullable(fc.boolean()),
  region: nullable(text),
  internal_notes: nullable(text),
  customer_id: nullable(fc.constantFrom(...CUSTOMERS, DANGLING)),
})

const FIELDS: readonly (readonly [string, 'text' | 'uuid' | 'int4' | 'float8' | 'bool'])[] = [
  ['ownerId', 'uuid'],
  ['status', 'text'],
  ['title', 'text'],
  ['amount', 'int4'],
  ['score', 'float8'],
  ['archived', 'bool'],
  ['region', 'text'],
  ['customer.region', 'text'],
  ['customer.tier', 'int4'],
  ['customer.id', 'uuid'],
]

const valueFor = (type: string): fc.Arbitrary<string | number | boolean> => {
  switch (type) {
    case 'text':
      return text
    case 'uuid':
      // Upper-case variants prove case-insensitive uuid comparison in both paths.
      return fc.oneof(
        uuid,
        uuid.map((u) => u.toUpperCase()),
        fc.constantFrom(...CUSTOMERS),
      )
    case 'int4':
      return int4
    case 'float8':
      return float8
    default:
      return fc.boolean()
  }
}

const leaf: fc.Arbitrary<QueryFilter> = fc.constantFrom(...FIELDS).chain(([field, type]) => {
  const v = valueFor(type)
  const options: fc.Arbitrary<QueryFilter>[] = [
    v.map((value) => ({ op: 'eq', field, value }) as const),
    v.map((value) => ({ op: 'ne', field, value }) as const),
    fc.array(v, { maxLength: 3 }).map((values) => ({ op: 'in', field, values }) as const),
    fc.array(v, { maxLength: 3 }).map((values) => ({ op: 'nin', field, values }) as const),
    fc.constant({ op: 'isNull', field } as const),
    fc.constant({ op: 'isNotNull', field } as const),
  ]
  if (type === 'int4' || type === 'float8') {
    for (const op of ['gt', 'gte', 'lt', 'lte'] as const)
      options.push(v.map((value) => ({ op, field, value })))
    options.push(fc.tuple(v, v).map(([from, to]) => ({ op: 'between', field, from, to }) as const))
  }
  if (type === 'text') {
    for (const op of ['contains', 'startsWith', 'endsWith'] as const) {
      options.push(
        fc
          .tuple(text, fc.option(fc.boolean(), { nil: undefined }))
          .map(([value, cs]) =>
            cs === undefined ? { op, field, value } : { op, field, value, caseSensitive: cs },
          ),
      )
    }
  }
  return fc.oneof(...options)
})

const filterArb: fc.Arbitrary<QueryFilter> = fc.letrec<{ f: QueryFilter }>((tie) => ({
  f: fc.oneof(
    { depthSize: 'small', withCrossShrink: true },
    leaf,
    fc.constantFrom<QueryFilter>({ op: 'true' }, { op: 'false' }),
    fc.array(tie('f'), { maxLength: 3 }).map((filters): QueryFilter => ({ op: 'and', filters })),
    fc.array(tie('f'), { maxLength: 3 }).map((filters): QueryFilter => ({ op: 'or', filters })),
    tie('f').map((filter): QueryFilter => ({ op: 'not', filter })),
  ),
})).f

interface LoadedRow {
  readonly [column: string]: unknown
  id: string
  owner_id: unknown
  tenant_id: unknown
  status: unknown
  title: unknown
  amount: unknown
  score: unknown
  archived: unknown
  region: unknown
  internal_notes: unknown
  c_id: unknown
  c_region: unknown
  c_tier: unknown
}

let db: PGlite
let records: { id: string; record: Record<string, unknown> }[]

beforeAll(async () => {
  db = new PGlite()
  await db.exec(`
    CREATE TABLE customers (id uuid PRIMARY KEY, region text, tier int4);
    CREATE TABLE invoices (
      id uuid PRIMARY KEY, owner_id uuid, tenant_id uuid, status text, title text, amount int4,
      score float8, archived bool, region text, internal_notes text, customer_id uuid);
  `)
  await db.query('INSERT INTO customers VALUES ($1, $2, $3), ($4, $5, $6), ($7, $8, $9)', [
    CUSTOMERS[0],
    'eu',
    1,
    CUSTOMERS[1],
    null,
    null,
    CUSTOMERS[2],
    'EU%_',
    3,
  ])
  const rows = [
    ...fc.sample(rowArb, { numRuns: 80, seed: 2026 }),
    // Hand-written edge rows: all-null, dangling relation, and a fully populated one.
    {
      owner_id: null,
      status: null,
      title: null,
      amount: null,
      score: null,
      archived: null,
      region: null,
      internal_notes: null,
      customer_id: null,
    },
    {
      owner_id: UUIDS[0],
      status: '',
      title: '%_',
      amount: 0,
      score: -0,
      archived: false,
      region: 'EU',
      internal_notes: 'x',
      customer_id: DANGLING,
    },
    {
      owner_id: UUIDS[1],
      status: 'Paid',
      title: 'Ünïcode 👋',
      amount: 10_000,
      score: 0.5,
      archived: true,
      region: 'eu',
      internal_notes: null,
      customer_id: CUSTOMERS[0],
    },
  ]
  let n = 0
  for (const r of rows) {
    n++
    const id = `0190f2a0-0000-7000-8000-${n.toString(16).padStart(12, '0')}`
    await db.query(
      'INSERT INTO invoices (id, owner_id, status, title, amount, score, archived, region, internal_notes, customer_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [
        id,
        r.owner_id,
        r.status,
        r.title,
        r.amount,
        r.score,
        r.archived,
        r.region,
        r.internal_notes,
        r.customer_id,
      ],
    )
  }
  // Load records exactly as stored, with the to-one relation nested (null when absent or dangling).
  const loaded = await db.query<LoadedRow>(
    `SELECT t.*, c.id AS c_id, c.region AS c_region, c.tier AS c_tier FROM invoices t LEFT JOIN customers c ON c.id = t.customer_id ORDER BY t.id`,
  )
  records = loaded.rows.map((r) => ({
    id: r.id,
    record: {
      id: r.id,
      ownerId: r.owner_id,
      tenantId: r.tenant_id,
      status: r.status,
      title: r.title,
      amount: r.amount,
      score: r.score,
      archived: r.archived,
      region: r.region,
      internalNotes: r.internal_notes,
      customer: r.c_id === null ? null : { id: r.c_id, region: r.c_region, tier: r.c_tier },
    },
  }))
}, 60_000)

afterAll(async () => {
  await db.close()
})

type Compiler = (f: QueryFilter) => { sql: string; params: unknown[] }
const correct: Compiler = (f) => compileToSql(f, invoiceSchema)

async function mismatch(filter: QueryFilter, compile: Compiler): Promise<boolean> {
  const { sql, params } = compile(filter)
  const result = await db.query<{ id: string }>(
    `SELECT t.id FROM invoices t WHERE ${sql} ORDER BY t.id`,
    params,
  )
  const viaSql = result.rows.map((r) => r.id)
  const inMemory = records
    .filter((r) => evaluateFilter(filter, r.record, invoiceSchema))
    .map((r) => r.id)
  return JSON.stringify(viaSql) !== JSON.stringify(inMemory)
}

describe('SQL ≡ in-memory evaluation (property-based, PGlite)', () => {
  it('agrees for random filters over every operator, NULLs, relations and tricky text', async () => {
    let compared = 0
    await fc.assert(
      fc.asyncProperty(filterArb, async (filter) => {
        compared++
        expect(await mismatch(filter, correct)).toBe(false)
      }),
      { numRuns: 600, seed: 8008 },
    )
    expect(compared).toBe(600)
  }, 120_000)

  it('agrees for every bound policy filter (filterFor vs can) across actors', async () => {
    const actors: (Actor | null)[] = [
      null,
      { id: UUIDS[0] as string, type: 'user', roles: [], attrs: { region: 'eu' } },
      { id: UUIDS[1] as string, type: 'user', roles: ['regional'], attrs: { region: 'EU%_' } },
      { id: UUIDS[2] as string, type: 'user', roles: ['regional'], attrs: { region: null } },
      { id: UUIDS[0] as string, type: 'user', roles: ['manager'], attrs: { region: 'eu' } },
      {
        id: UUIDS[1] as string,
        type: 'user',
        roles: ['director', 'manager'],
        attrs: { region: 'eu' },
      },
    ]
    for (const a of actors) {
      for (const action of ['view', 'update', 'approve', 'delete', 'read']) {
        const filter = invoicePolicy.filterFor(a, action)
        const { sql, params } = compileToSql(filter, invoiceSchema)
        const viaSql = (
          await db.query<{ id: string }>(
            `SELECT t.id FROM invoices t WHERE ${sql} ORDER BY t.id`,
            params,
          )
        ).rows.map((r) => r.id)
        const viaCan = records
          .filter((r) => invoicePolicy.can(a, action, r.record))
          .map((r) => r.id)
        expect(viaSql).toEqual(viaCan)
      }
    }
  })
})

describe('mutation checks: the property test catches each classic bug', () => {
  const FOLD = /translate\(([^,]+?), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'\)/g
  const mutants: Record<string, Compiler> = {
    'ne compiled to <> (drops NULL rows)': (f) => {
      const r = correct(f)
      return { ...r, sql: r.sql.replaceAll(' IS DISTINCT FROM ', ' <> ') }
    },
    'eq compiled to = (NULL under NOT)': (f) => {
      const r = correct(f)
      return { ...r, sql: r.sql.replaceAll(' IS NOT DISTINCT FROM ', ' = ') }
    },
    'COALESCE removed (three-valued logic leaks)': (f) => {
      const r = correct(f)
      return { ...r, sql: r.sql.replaceAll('COALESCE(', '(').replaceAll(', FALSE)', ')') }
    },
    'case folding forgotten in SQL': (f) => {
      const r = correct(f)
      return { ...r, sql: r.sql.replace(FOLD, '$1') }
    },
    'contains compiled to LIKE (wildcards)': (f) => {
      const r = correct(f)
      return {
        ...r,
        sql: r.sql.replace(/strpos\((.+?), (\$\d+::text)\) > 0/g, "$1 LIKE '%' || $2 || '%'"),
      }
    },
  }

  it.each(Object.entries(mutants))(
    'catches: %s',
    async (_name, compile) => {
      const result = await fc.check(
        fc.asyncProperty(filterArb, async (filter) => !(await mismatch(filter, compile))),
        { numRuns: 2000, seed: 4242 },
      )
      expect(result.failed).toBe(true)
    },
    120_000,
  )
})
