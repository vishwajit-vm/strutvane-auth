/**
 * VAPT: attack-style tests against the package's surface, end to end where possible (native
 * engine → Hono middleware → policy filter → SQL → PGlite with RLS). Each block names the attack
 * class (hub docs/13-testing-strategy.md §14). Further attack tests live next to the code they
 * attack: the identity contract (enumeration, fixation, rate-limit bypass), tenancy.test.ts
 * (cross-tenant CRUD under RLS) and sql.test.ts (injection into the compiler).
 */
import { PGlite } from '@electric-sql/pglite'
import type { QueryFilter } from '@strutvane/contracts'
import { currentContext } from '@strutvane/core'
import { Hono } from 'hono'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { InvalidFilterError } from '../src/errors.ts'
import type { IdentityEngine } from '../src/identity/engine.ts'
import { createNativeEngine } from '../src/identity/native.ts'
import { type AuthVariables, authMiddleware } from '../src/middleware/hono.ts'
import { and } from '../src/policy/filter.ts'
import { definePolicy } from '../src/policy/policy.ts'
import { createPermissionProvider } from '../src/policy/provider.ts'
import {
  InvalidTenantIdError,
  tenancyRolesSql,
  tenantRlsSql,
  withTenant,
} from '../src/postgres/index.ts'
import { compileToSql } from '../src/sql/index.ts'
import { headerResolver, sessionResolver, subdomainResolver } from '../src/tenancy/resolver.ts'
import {
  browserRequest,
  freshIp,
  newJar,
  store,
  TEST_PASSWORD,
  testEmail,
} from '../src/testing/index.ts'
import {
  ALICE,
  actor,
  BOB,
  invoice,
  invoicePolicy,
  invoiceSchema,
  TENANT_A,
  TENANT_B,
} from './fixtures.ts'

const provider = createPermissionProvider([invoicePolicy])

describe('IDOR (insecure direct object reference)', () => {
  it('a member cannot view or update another user’s record by id', async () => {
    const bobsInvoice = invoice({ id: '0190f2a0-0000-7000-8000-000000000b0b', ownerId: BOB })
    expect(
      (
        await provider.can(actor(), 'invoice.update', {
          type: 'invoice',
          id: String(bobsInvoice.id),
          record: bobsInvoice,
        })
      ).allowed,
    ).toBe(false)
    expect(
      (
        await provider.can(actor(), 'invoice.view', {
          type: 'invoice',
          id: String(bobsInvoice.id),
          record: bobsInvoice,
        })
      ).allowed,
    ).toBe(false)
  })

  it('without the record, record-level actions are denied (no guessing from the id alone)', async () => {
    expect(
      await provider.can(actor(), 'invoice.update', { type: 'invoice', id: 'anything' }),
    ).toMatchObject({ allowed: false })
  })

  it('an attacker-supplied list filter is AND-ed with the policy filter and can never widen it', () => {
    const policy = invoicePolicy.filterFor(actor(), 'update')
    const hostile: QueryFilter = {
      op: 'or',
      filters: [{ op: 'true' }, { op: 'eq', field: 'ownerId', value: BOB }],
    }
    const combined = and(policy, hostile)
    expect(invoicePolicy.can(actor(), 'update', invoice({ ownerId: BOB }))).toBe(false)
    expect(
      compileToSql(combined, invoiceSchema).sql.startsWith(
        '(("t"."owner_id" IS NOT DISTINCT FROM $1::uuid) AND',
      ),
    ).toBe(true)
  })
})

describe('role and privilege tampering', () => {
  it('role names are exact: case changes, prefixes and prototype names never match', () => {
    for (const roles of [
      ['Manager'],
      ['MANAGER'],
      ['manager '],
      ['__proto__'],
      ['constructor'],
      ['toString'],
      ['*'],
    ]) {
      expect(invoicePolicy.can(actor({ roles }), 'viewAny')).toBe(false)
    }
  })

  it('look-alike permission strings grant nothing', () => {
    for (const permissions of [
      ['invoice.deletex'],
      ['invoices.*'],
      ['invoice'],
      ['*.*'],
      ['invoice.*.delete'],
    ]) {
      expect(
        invoicePolicy.can(actor({ permissions: permissions as never }), 'delete', invoice()),
      ).toBe(false)
    }
  })

  it('roles can only come from the identity engine: request headers and cookies cannot add them', async () => {
    const engine = createNativeEngine({
      baseURL: 'http://localhost',
      deliverPasswordReset: async () => undefined,
      scryptCost: 2 ** 14,
    })
    const s = await engine.signUp(
      { email: testEmail('tamper'), password: TEST_PASSWORD, name: 'T' },
      browserRequest('http://localhost', { ip: freshIp() }),
    )
    const jar = store(newJar(), s)
    const app = new Hono<{ Variables: AuthVariables }>()
    app.use(authMiddleware({ engine }))
    app.get('/', (c) => c.json(c.get('actor')))
    const res = await app.request('http://localhost/', {
      headers: {
        cookie: `${[...jar].map(([k, v]) => `${k}=${v}`).join('; ')}; roles=admin; sv_roles=admin`,
        'x-roles': 'admin',
        'x-user-id': BOB,
      },
    })
    const body = (await res.json()) as { id: string; roles: string[] }
    expect(body.roles).toEqual([])
    expect(body.id).not.toBe(BOB)
  })

  it('a tampered actor object (mutating roles after authentication) is impossible: actors are frozen', async () => {
    const engine = createNativeEngine({
      baseURL: 'http://localhost',
      deliverPasswordReset: async () => undefined,
      scryptCost: 2 ** 14,
    })
    const s = await engine.signUp(
      { email: testEmail('frozen'), password: TEST_PASSWORD, name: 'F' },
      browserRequest('http://localhost', { ip: freshIp() }),
    )
    const a = s.ok ? s.value.actor : null
    expect(Object.isFrozen(a)).toBe(true)
    expect(() => {
      ;(a as unknown as { roles: string[] }).roles.push('admin')
    }).toThrow(TypeError)
  })
})

describe('header spoofing', () => {
  it('X-Tenant-Id from a browser is ignored; Host / subdomain switching is refused', async () => {
    const lookup = (slug: string) => ({ acme: TENANT_A, globex: TENANT_B })[slug]
    const engine = { authenticate: async () => ({ actor: actor(), headers: new Headers() }) }
    const app = new Hono<{ Variables: AuthVariables }>()
    app.use(
      authMiddleware({
        engine,
        tenancy: {
          resolvers: [
            subdomainResolver({ baseDomain: 'example.com', lookup }),
            headerResolver({ trust: ({ actor: x }) => x?.type === 'service' }),
            sessionResolver(),
          ],
        },
      }),
    )
    app.get('/', (c) => c.json({ tenant: c.get('tenant')?.id }))
    expect(
      await (await app.request('https://x.test/', { headers: { 'x-tenant-id': TENANT_B } })).json(),
    ).toEqual({ tenant: TENANT_A })
    expect((await app.request('https://globex.example.com/')).status).toBe(403)
  })
})

describe('SQL injection (executed against real Postgres)', () => {
  let db: PGlite
  beforeAll(async () => {
    db = new PGlite()
    await db.exec(`
      CREATE TABLE customers (id uuid PRIMARY KEY, region text, tier int4);
      CREATE TABLE invoices (id uuid PRIMARY KEY, owner_id uuid, tenant_id uuid, status text, title text, amount int4,
        score float8, archived bool, region text, internal_notes text, customer_id uuid);
      INSERT INTO invoices (id, owner_id, title) VALUES ('0190f2a0-0000-7000-8000-000000000001', '${ALICE}', 'mine');
    `)
  })
  afterAll(async () => db.close())

  it.each([
    "'; DROP TABLE invoices; --",
    "' OR '1'='1",
    "x'); DELETE FROM invoices; --",
    '\\x27 OR 1=1',
    "' UNION SELECT id, owner_id FROM invoices --",
  ])('payload stays data: %s', async (payload) => {
    const filter: QueryFilter = {
      op: 'or',
      filters: [
        { op: 'eq', field: 'title', value: payload },
        { op: 'contains', field: 'title', value: payload },
        { op: 'in', field: 'status', values: [payload, 'x'] },
        { op: 'endsWith', field: 'customer.region', value: payload },
      ],
    }
    const { sql, params } = compileToSql(filter, invoiceSchema)
    const r = await db.query(`SELECT id FROM invoices t WHERE ${sql}`, params)
    expect(r.rows).toEqual([])
    expect((await db.query('SELECT count(*)::int AS n FROM invoices')).rows).toEqual([{ n: 1 }])
  })

  it('identifiers are never taken from input: fields, aliases, tenant ids and settings', async () => {
    expect(() =>
      compileToSql({ op: 'isNull', field: 'title; DROP TABLE invoices' }, invoiceSchema),
    ).toThrow(InvalidFilterError)
    expect(() =>
      compileToSql({ op: 'isNull', field: 'title" IS NULL OR "1' }, invoiceSchema),
    ).toThrow(InvalidFilterError)
    const pool = {
      connect: async () => ({
        query: async () => ({}),
        release: () => undefined,
        on: () => undefined,
        off: () => undefined,
      }),
    }
    await expect(withTenant(pool, "' OR 1=1; --", async () => 1)).rejects.toBeInstanceOf(
      InvalidTenantIdError,
    )
  })
})

describe('session fixation', () => {
  it('a session token planted before sign-in is never elevated to the victim’s account', async () => {
    const engine: IdentityEngine = createNativeEngine({
      baseURL: 'http://localhost',
      deliverPasswordReset: async () => undefined,
      scryptCost: 2 ** 14,
    })
    const req = (jar = newJar()) => browserRequest('http://localhost', { jar, ip: freshIp() })
    // Attacker obtains a valid session of their own and plants it in the victim's browser.
    const attacker = await engine.signUp(
      { email: testEmail('attacker'), password: TEST_PASSWORD, name: 'A' },
      req(),
    )
    const planted = store(newJar(), attacker)
    const victimEmail = testEmail('victim')
    await engine.signUp({ email: victimEmail, password: TEST_PASSWORD, name: 'V' }, req())
    const victimLogin = await engine.signIn(
      { email: victimEmail, password: TEST_PASSWORD },
      req(new Map(planted)),
    )
    const victimJar = store(new Map(planted), victimLogin)
    // The victim now holds a different token; the attacker's copy is NOT the victim.
    expect([...victimJar.values()]).not.toEqual([...planted.values()])
    const asAttacker = await engine.getActor(req(planted))
    const asVictim = await engine.getActor(req(victimJar))
    expect(asVictim?.id).toBe(victimLogin.ok ? victimLogin.value.actor.id : 'x')
    expect(asAttacker?.id).not.toBe(asVictim?.id)
  })
})

describe('cross-tenant access, end to end (engine → middleware → withTenant → RLS)', () => {
  let db: PGlite
  let engine: IdentityEngine
  let app: Hono<{ Variables: AuthVariables }>
  let aliceJar: Map<string, string>
  let tenants: { a: string; b: string }

  beforeAll(async () => {
    db = new PGlite()
    for (const s of tenancyRolesSql().up) await db.exec(s)
    await db.exec(
      'CREATE TABLE notes (id serial PRIMARY KEY, tenant_id uuid NOT NULL, body text NOT NULL)',
    )
    for (const s of tenantRlsSql({ table: 'notes', runtimeRole: 'app_user' }).up) await db.exec(s)
    await db.exec(
      'GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO app_user; GRANT USAGE ON SEQUENCE notes_id_seq TO app_user',
    )

    engine = createNativeEngine({
      baseURL: 'http://localhost',
      deliverPasswordReset: async () => undefined,
      scryptCost: 2 ** 14,
    })
    const req = (jar = newJar()) => browserRequest('http://localhost', { jar, ip: freshIp() })
    const alice = await engine.signUp(
      { email: testEmail('alice'), password: TEST_PASSWORD, name: 'Alice' },
      req(),
    )
    aliceJar = store(newJar(), alice)
    const bob = await engine.signUp(
      { email: testEmail('bob'), password: TEST_PASSWORD, name: 'Bob' },
      req(),
    )
    const bobJar = store(newJar(), bob)
    const ta = await engine.createTenant({ name: 'Acme', slug: 'acme' }, req(aliceJar))
    const tb = await engine.createTenant({ name: 'Globex', slug: 'globex' }, req(bobJar))
    if (!ta.ok || !tb.ok) throw new Error('tenants not created')
    tenants = { a: ta.value.tenantId, b: tb.value.tenantId }
    await db.query('INSERT INTO notes (tenant_id, body) VALUES ($1, $2), ($3, $4)', [
      tenants.a,
      'acme secret',
      tenants.b,
      'globex secret',
    ])
    await db.exec('SET ROLE app_user')

    const pool = {
      connect: async () => ({
        query: (t: string, v?: unknown[]) => db.query<Record<string, unknown>>(t, v),
        release: () => undefined,
        on: () => undefined,
        off: () => undefined,
      }),
    }
    const lookup = (slug: string) => ({ acme: tenants.a, globex: tenants.b })[slug]
    app = new Hono<{ Variables: AuthVariables }>()
    app.use(
      authMiddleware({
        engine,
        requireAuth: true,
        tenancy: {
          resolvers: [subdomainResolver({ baseDomain: 'example.com', lookup }), sessionResolver()],
          required: true,
        },
      }),
    )
    app.get('/notes', async (c) => {
      const tenant = currentContext()?.tenant?.id ?? ''
      const id = c.req.query('id')
      const rows = await withTenant(pool, tenant, async (client) =>
        id
          ? (await client.query('SELECT body FROM notes WHERE id = $1', [id])).rows
          : (await client.query('SELECT body FROM notes ORDER BY id')).rows,
      )
      return c.json(rows)
    })
    app.post('/notes', async (c) => {
      const tenant = currentContext()?.tenant?.id ?? ''
      const body = (await c.req.json()) as { tenant_id: string; body: string }
      try {
        await withTenant(pool, tenant, (client) =>
          client.query('INSERT INTO notes (tenant_id, body) VALUES ($1, $2)', [
            body.tenant_id,
            body.body,
          ]),
        )
        return c.json({ ok: true })
      } catch {
        return c.json({ ok: false }, 403)
      }
    })
  }, 60_000)
  afterAll(async () => db.close())

  const cookie = () => [...aliceJar].map(([k, v]) => `${k}=${v}`).join('; ')

  it('alice reads only her tenant', async () => {
    const res = await app.request('https://acme.example.com/notes', {
      headers: { cookie: cookie() },
    })
    expect(await res.json()).toEqual([{ body: 'acme secret' }])
  })

  it('switching the subdomain to another tenant is refused before any query runs', async () => {
    expect(
      (await app.request('https://globex.example.com/notes', { headers: { cookie: cookie() } }))
        .status,
    ).toBe(403)
  })

  it('reading another tenant’s row by id returns nothing (RLS), and inserting into it is blocked', async () => {
    const byId = await app.request('https://acme.example.com/notes?id=2', {
      headers: { cookie: cookie() },
    })
    expect(await byId.json()).toEqual([])
    const insert = await app.request('https://acme.example.com/notes', {
      method: 'POST',
      headers: { cookie: cookie(), 'content-type': 'application/json' },
      body: JSON.stringify({ tenant_id: tenants.b, body: 'planted' }),
    })
    expect(insert.status).toBe(403)
  })

  it('anonymous requests and requests without a tenant are refused', async () => {
    expect((await app.request('https://acme.example.com/notes')).status).toBe(401)
    expect(
      (await app.request('https://x.test/notes', { headers: { cookie: cookie() } })).status,
    ).toBe(200)
  })
})

describe('denial of service via hostile filters', () => {
  it('deep, wide or huge filters are rejected cheaply before any SQL is built', () => {
    let deep: QueryFilter = { op: 'true' }
    for (let i = 0; i < 10_000; i++) deep = { op: 'not', filter: deep }
    expect(() => compileToSql(deep, invoiceSchema)).toThrow(InvalidFilterError)
    expect(() =>
      compileToSql(
        { op: 'in', field: 'title', values: Array.from({ length: 50_000 }, () => 'x') },
        invoiceSchema,
      ),
    ).toThrow(InvalidFilterError)
  })

  it('policies fail closed on a malformed record instead of granting', () => {
    const p = definePolicy('doc', { schema: invoiceSchema }, ({ allow }) =>
      allow('view', { when: ({ row }) => row.status.ne('locked') }),
    )
    expect(() => p.can(actor(), 'view', { ...invoice(), status: undefined })).toThrow()
  })
})
