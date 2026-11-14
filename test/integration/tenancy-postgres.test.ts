/**
 * Tenancy on real PostgreSQL 18 (ported from spike 03): isolation through a real pg.Pool, zero
 * leaks under concurrency, session-SET leak (the anti-pattern the lint exists for), broken
 * connections destroyed, and every bypass ADR-0007 rule 4 forbids.
 *
 * PgBouncer tests from spike 03 are NOT run here (they need a second container); the pg.Pool
 * tests cover the same transaction-local guarantee.
 */
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { evaluateFilter } from '../../src/policy/evaluate.ts'
import { defineSchema } from '../../src/policy/schema.ts'
import {
  findSessionSet,
  TransactionAbortedError,
  tenancyAudit,
  withTenant,
} from '../../src/postgres/index.ts'
import { compileToSql } from '../../src/sql/index.ts'
import {
  count,
  createDatabase,
  PER_TENANT,
  TENANT_A,
  TENANT_B,
  type TestDatabase,
  tenancyFixture,
} from './helpers.ts'

let db: TestDatabase
let fx: Awaited<ReturnType<typeof tenancyFixture>>
const pools: pg.Pool[] = []
const track = (p: pg.Pool) => {
  pools.push(p)
  return p
}

beforeAll(async () => {
  db = await createDatabase()
  fx = await tenancyFixture(db)
})
afterAll(async () => {
  for (const p of pools) await p.end().catch(() => undefined)
  await db.admin.query(
    `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
    [db.name],
  )
  for (const role of [fx.runtime, fx.owner, fx.bypass]) {
    await db.admin.query(`DROP OWNED BY ${role} CASCADE`).catch(() => undefined)
  }
  await db.drop()
  const admin = new pg.Client({ connectionString: inject_admin() })
  await admin.connect()
  for (const role of [fx.runtime, fx.owner, fx.bypass])
    await admin.query(`DROP ROLE IF EXISTS ${role}`)
  await admin.end()
})

function inject_admin(): string {
  return db.url().replace(`/${db.name}`, '/postgres')
}

describe('isolation through a real pg.Pool', () => {
  it('unscoped queries see nothing; withTenant sees exactly its tenant', async () => {
    const pool = track(fx.pool(fx.runtime))
    expect(await count(pool)).toBe(0)
    expect(await withTenant(pool, TENANT_A, (c) => count(c))).toBe(PER_TENANT)
    expect(await withTenant(pool, TENANT_B, (c) => count(c))).toBe(PER_TENANT)
  })

  it('cross-tenant read by key, update, delete and insert are all blocked', async () => {
    const pool = track(fx.pool(fx.runtime))
    const bRow = (
      await db.admin.query<{ id: number }>(
        'SELECT id FROM app.invoices WHERE tenant_id = $1 LIMIT 1',
        [TENANT_B],
      )
    ).rows[0]?.id
    await withTenant(pool, TENANT_A, async (c) => {
      expect((await c.query('SELECT * FROM app.invoices WHERE id = $1', [bRow])).rowCount).toBe(0)
      expect(
        (await c.query("UPDATE app.invoices SET number = 'x' WHERE id = $1", [bRow])).rowCount,
      ).toBe(0)
      expect((await c.query('DELETE FROM app.invoices WHERE id = $1', [bRow])).rowCount).toBe(0)
    })
    await expect(
      withTenant(pool, TENANT_A, (c) =>
        c.query("INSERT INTO app.invoices (tenant_id, number) VALUES ($1, 'evil')", [TENANT_B]),
      ),
    ).rejects.toMatchObject({
      code: '42501',
    })
    await expect(
      withTenant(pool, TENANT_A, (c) =>
        c.query('UPDATE app.invoices SET tenant_id = $1', [TENANT_B]),
      ),
    ).rejects.toMatchObject({ code: '42501' })
    expect(await withTenant(pool, TENANT_B, (c) => count(c))).toBe(PER_TENANT)
  })

  it('400 concurrent transactions across two tenants on 8 connections: zero leaks', async () => {
    const pool = track(fx.pool(fx.runtime, 8))
    let leaks = 0
    await Promise.all(
      Array.from({ length: 400 }, async (_, i) => {
        const tenant = i % 2 === 0 ? TENANT_A : TENANT_B
        const seen = await withTenant(pool, tenant, async (c) => {
          const r = await c.query<{ tenant_id: string }>(
            'SELECT DISTINCT tenant_id FROM app.invoices',
          )
          return r.rows.map((x) => x.tenant_id)
        })
        if (seen.length !== 1 || seen[0] !== tenant) leaks++
        // A plain, unscoped query on the same pool right after must see nothing.
        if ((await count(pool)) !== 0) leaks++
      }),
    )
    expect(leaks).toBe(0)
  })

  it('anti-pattern: a session-level SET leaks into the next request on a pooled connection (and the lint catches it)', async () => {
    const pool = track(fx.pool(fx.runtime, 1))
    const badSql = `SET app.tenant_id = '${TENANT_A}'`
    await pool.query(badSql)
    expect(await count(pool)).toBe(PER_TENANT) // the next, unrelated "request" sees tenant A
    await pool.query('SELECT set_config($1, $2, false)', ['app.tenant_id', TENANT_B])
    expect(await count(pool)).toBe(PER_TENANT)
    expect(
      findSessionSet(`${badSql};\nSELECT set_config('app.tenant_id', $1, false)`).map(
        (f) => f.code,
      ),
    ).toEqual(['SESSION_SET', 'SESSION_SET_CONFIG'])
  })

  it('a backend killed mid-transaction rejects, is destroyed (not re-pooled) and never crashes the process', async () => {
    const pool = track(fx.pool(fx.runtime, 1))
    const pids = new Set<number>()
    await expect(
      withTenant(pool, TENANT_A, async (c) => {
        const pid =
          (await c.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid ?? 0
        pids.add(pid)
        await db.admin.query('SELECT pg_terminate_backend($1)', [pid])
        await c.query('SELECT 1')
      }),
    ).rejects.toThrow()
    // The next transaction gets a NEW backend with no tenant state.
    const pid2 = await withTenant(
      pool,
      TENANT_B,
      async (c) => (await c.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid,
    )
    expect(pids.has(pid2 ?? 0)).toBe(false)
    expect(await count(pool)).toBe(0)
  })
})

describe('bypasses ADR-0007 rule 4 forbids (and the audit flags)', () => {
  it('a superuser always bypasses RLS, even with FORCE; the audit reports it', async () => {
    expect(await count(db.admin)).toBe(PER_TENANT * 2)
    expect((await tenancyAudit(db.admin)).map((f) => f.code)).toContain('RUNTIME_ROLE_BYPASSES_RLS')
  })

  it('a BYPASSRLS role sees every tenant; the audit reports it', async () => {
    const pool = track(fx.pool(fx.bypass, 1))
    expect(await count(pool)).toBe(PER_TENANT * 2)
    expect((await tenancyAudit(pool)).map((f) => f.code)).toContain('RUNTIME_ROLE_BYPASSES_RLS')
  })

  it('FORCE locks out the owner, but the owner can switch it off: never run the app as the owner', async () => {
    const pool = track(fx.pool(fx.owner, 1))
    expect(await count(pool)).toBe(0)
    expect((await tenancyAudit(pool)).map((f) => f.code)).toContain('RUNTIME_ROLE_OWNS_TABLE')
    const client = await pool.connect()
    try {
      await client.query('BEGIN')
      await client.query('ALTER TABLE app.invoices NO FORCE ROW LEVEL SECURITY')
      expect(await count(client)).toBe(PER_TENANT * 2)
      await client.query('ROLLBACK')
    } finally {
      client.release()
    }
  })

  it('a superuser-owned view leaks every tenant; security_invoker views do not; the audit flags the leak', async () => {
    await db.admin.query('CREATE VIEW public.leak AS SELECT * FROM app.invoices')
    await db.admin.query(
      'CREATE VIEW public.safe WITH (security_invoker = true) AS SELECT * FROM app.invoices',
    )
    await db.admin.query(`GRANT SELECT ON public.leak, public.safe TO ${fx.runtime}`)
    const pool = track(fx.pool(fx.runtime, 1))
    try {
      expect(Number((await pool.query('SELECT count(*) AS n FROM public.leak')).rows[0]?.n)).toBe(
        PER_TENANT * 2,
      )
      expect(Number((await pool.query('SELECT count(*) AS n FROM public.safe')).rows[0]?.n)).toBe(0)
      const findings = (await tenancyAudit(pool)).map((f) => `${f.code}:${f.object}`)
      expect(findings).toContain('DEFINER_VIEW:public.leak')
      expect(findings).not.toContain('DEFINER_VIEW:public.safe')
    } finally {
      await db.admin.query('DROP VIEW public.leak, public.safe')
    }
  })

  it('the runtime role cannot disable RLS or change policies itself; a clean setup audits empty', async () => {
    const pool = track(fx.pool(fx.runtime, 1))
    await expect(
      pool.query('ALTER TABLE app.invoices DISABLE ROW LEVEL SECURITY'),
    ).rejects.toMatchObject({ code: '42501' })
    await expect(
      pool.query('DROP POLICY invoices_tenant_isolation ON app.invoices'),
    ).rejects.toMatchObject({ code: '42501' })
    expect(await tenancyAudit(pool)).toEqual([])
  })
})

describe('withTenant on a real server: swallowed statement errors', () => {
  it('a caught failure inside work makes withTenant reject instead of reporting a commit', async () => {
    const pool = track(fx.pool(fx.runtime, 1))
    await expect(
      withTenant(pool, TENANT_A, async (c) => {
        await c.query('SELECT 1/0').catch(() => undefined)
        return 'looks fine'
      }),
    ).rejects.toBeInstanceOf(TransactionAbortedError)
    // The connection is clean afterwards.
    expect(await withTenant(pool, TENANT_A, (c) => count(c))).toBe(PER_TENANT)
  })
})

describe('text comparisons under a nondeterministic column collation', () => {
  const schema = defineSchema({
    table: 'coll_t',
    columns: { id: { column: 'id', type: 'int4' }, status: { column: 'status', type: 'text' } },
  })
  const rows = [
    { id: 1, status: 'Paid' },
    { id: 2, status: 'paid' },
  ]

  beforeAll(async () => {
    await db.admin.query(
      "CREATE COLLATION IF NOT EXISTS sv_ci (provider = icu, locale = 'und-u-ks-level2', deterministic = false)",
    )
    await db.admin.query('CREATE TABLE coll_t (id int PRIMARY KEY, status text COLLATE sv_ci)')
    await db.admin.query("INSERT INTO coll_t VALUES (1, 'Paid'), (2, 'paid')")
  })

  const select = async (filter: Parameters<typeof compileToSql>[0], database = false) => {
    const { sql, params } = compileToSql(
      filter,
      schema,
      database ? { textCollation: 'database' } : {},
    )
    const result = await db.admin.query(
      `SELECT id FROM coll_t AS t WHERE ${sql} ORDER BY id`,
      params,
    )
    return result.rows.map((r: { id: number }) => r.id)
  }
  const inMemory = (filter: Parameters<typeof compileToSql>[0]) =>
    rows.filter((r) => evaluateFilter(filter, r, schema)).map((r) => r.id)

  it('SQL agrees with in-memory evaluation (COLLATE "C"); the column collation alone would not', async () => {
    for (const filter of [
      { op: 'eq', field: 'status', value: 'paid' },
      { op: 'ne', field: 'status', value: 'paid' },
      { op: 'in', field: 'status', values: ['paid'] },
      { op: 'contains', field: 'status', value: 'Pa', caseSensitive: true },
      { op: 'startsWith', field: 'status', value: 'p', caseSensitive: true },
      { op: 'endsWith', field: 'status', value: 'aid' },
    ] as const) {
      expect(await select(filter)).toEqual(inMemory(filter))
    }
    expect(await select({ op: 'eq', field: 'status', value: 'paid' }, true)).toEqual([1, 2])
  })
})
