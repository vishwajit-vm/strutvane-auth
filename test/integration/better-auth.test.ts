/**
 * The hardened Better Auth adapter on real PostgreSQL 18: the shared identity contract (the same
 * suite the native engine passes), plus Better Auth specifics and TRIPWIRES. A tripwire pins
 * current Better Auth behaviour that the adapter documents as a risk or works around; if one fails
 * after an upgrade, Better Auth changed: re-read ADR-0013 and the adapter docs, then update both.
 */
import { randomBytes } from 'node:crypto'
import { afterAll, beforeAll, describe, expect, test, vi } from 'vitest'
import { createBetterAuthEngine } from '../../src/identity/better-auth.ts'
import { memoryRateLimitStore } from '../../src/identity/rate-limit.ts'
import { postgresRateLimitStore, rateLimitTableSql } from '../../src/postgres/index.ts'
import {
  browserRequest,
  freshIp,
  newJar,
  runIdentityContract,
  store,
  TEST_PASSWORD,
  testEmail,
} from '../../src/testing/index.ts'
import { createDatabase, type TestDatabase } from './helpers.ts'

const secret = randomBytes(32).toString('base64')
const DEV = 'http://localhost:3000'
const noop = async (): Promise<void> => undefined

runIdentityContract('better-auth', async (options) => {
  const db = await createDatabase()
  await db.admin.query(rateLimitTableSql())
  const engine = createBetterAuthEngine({
    pool: db.admin,
    secret,
    rateLimitStore: postgresRateLimitStore(db.admin), // shared storage, as ADR-0013 requires
    ...options,
  })
  await engine.migrate()
  return { engine, cleanup: () => db.drop() }
})

describe('Better Auth specifics', () => {
  let db: TestDatabase
  const reported: string[] = []
  let engine: ReturnType<typeof createBetterAuthEngine>
  const req = (jar = newJar()) => browserRequest(DEV, { jar, ip: freshIp() })

  beforeAll(async () => {
    db = await createDatabase()
    engine = createBetterAuthEngine({
      pool: db.admin,
      baseURL: DEV,
      secret,
      rateLimitStore: memoryRateLimitStore(),
      deliverPasswordReset: () => new Promise((resolve) => setTimeout(resolve, 300)), // a slow mailer
      onUnexpectedError: (context) => {
        reported.push(context)
      },
    })
    await engine.migrate()
  })
  afterAll(async () => db.drop())

  test('schema() describes every table for the Strutvane migration stream; compileMigrations agrees (CI cross-check)', async () => {
    expect(Object.keys(engine.schema()).sort()).toEqual([
      'account',
      'invitation',
      'member',
      'organization',
      'session',
      'user',
      'verification',
    ])
    const fresh = await createDatabase()
    try {
      const other = createBetterAuthEngine({
        pool: fresh.admin,
        baseURL: DEV,
        secret,
        rateLimitStore: memoryRateLimitStore(),
        deliverPasswordReset: noop,
      })
      const sql = await other.compileMigrations()
      expect((sql.match(/create table/gi) ?? []).length).toBe(7)
      expect(sql).toContain('"activeOrganizationId" text')
      await other.migrate()
      // Once migrated, Better Auth has nothing left to run (it emits at most a bare ";").
      expect((await other.compileMigrations()).replace(/[\s;]/g, '')).toBe('')
    } finally {
      await fresh.drop()
    }
  })

  test('user and tenant ids are UUIDs that survive the RLS policy cast (ADR-0007)', async () => {
    const s = await engine.signUp(
      { email: testEmail('uuid'), password: TEST_PASSWORD, name: 'U' },
      req(),
    )
    if (!s.ok) throw new Error('sign-up failed')
    const jar = store(newJar(), s)
    const t = await engine.createTenant(
      { name: 'Uuid', slug: `uuid-${randomBytes(3).toString('hex')}` },
      req(jar),
    )
    if (!t.ok) throw new Error('tenant not created')
    const cast = await db.admin.query<{ id: string }>("SELECT NULLIF($1, '')::uuid AS id", [
      t.value.tenantId,
    ])
    expect(cast.rows[0]?.id).toBe(t.value.tenantId)
  })

  test('password reset takes the same time for known and unknown emails, even with a slow mailer', async () => {
    const known = testEmail('timing')
    await engine.signUp({ email: known, password: TEST_PASSWORD, name: 'T' }, req())
    const time = async (address: string): Promise<number> => {
      const start = performance.now()
      expect((await engine.startPasswordReset({ email: address }, req())).ok).toBe(true)
      return performance.now() - start
    }
    await time(testEmail('warmup'))
    const knownMs = await time(known)
    const unknownMs = await time(testEmail('nobody'))
    expect(knownMs).toBeLessThan(250)
    expect(Math.abs(knownMs - unknownMs)).toBeLessThan(200)
  })

  test('TRIPWIRE: switching tenant does NOT rotate the Better Auth session token (why tenant is re-resolved per request)', async () => {
    const s = await engine.signUp(
      { email: testEmail('rot'), password: TEST_PASSWORD, name: 'R' },
      req(),
    )
    const jar = store(newJar(), s)
    const before = jar.get('better-auth.session_token')
    const t = await engine.createTenant(
      { name: 'Rot', slug: `rot-${randomBytes(3).toString('hex')}` },
      req(jar),
    )
    if (!t.ok) throw new Error('tenant not created')
    store(jar, await engine.switchTenant({ tenantId: t.value.tenantId }, req(jar)))
    expect(jar.get('better-auth.session_token')).toBe(before)
  })

  test('TRIPWIRE: the session keeps activeOrganizationId after membership removal (no FK); the adapter drops it', async () => {
    const owner = await engine.signUp(
      { email: testEmail('own'), password: TEST_PASSWORD, name: 'O' },
      req(),
    )
    const ownerJar = store(newJar(), owner)
    const t = await engine.createTenant(
      { name: 'Stale', slug: `stale-${randomBytes(3).toString('hex')}` },
      req(ownerJar),
    )
    if (!t.ok || !owner.ok) throw new Error('setup failed')
    store(ownerJar, await engine.switchTenant({ tenantId: t.value.tenantId }, req(ownerJar)))
    await engine.removeMemberAsSystem({ tenantId: t.value.tenantId, userId: owner.value.actor.id })
    const raw = await db.admin.query<{ active: string | null }>(
      'SELECT "activeOrganizationId" AS active FROM session WHERE "userId" = $1',
      [owner.value.actor.id],
    )
    expect(raw.rows.some((r) => r.active === t.value.tenantId)).toBe(true)
    const actor = await engine.getActor(req(ownerJar))
    expect(actor?.tenantId).toBeUndefined()
    expect(actor?.roles).toEqual([])
  })

  test('a client-sent x-strutvane-client-ip header is never forwarded (cannot poison the stored session IP)', async () => {
    const r = browserRequest(DEV, { ip: '198.51.100.77' })
    r.headers.set('x-strutvane-client-ip', '6.6.6.6')
    const s = await engine.signUp(
      { email: testEmail('ipspoof'), password: TEST_PASSWORD, name: 'I' },
      r,
    )
    if (!s.ok) throw new Error('sign-up failed')
    const row = await db.admin.query<{ ip: string }>(
      'SELECT "ipAddress" AS ip FROM session WHERE "userId" = $1',
      [s.value.actor.id],
    )
    expect(row.rows[0]?.ip).not.toBe('6.6.6.6')
  })

  test('a database outage becomes INTERNAL_ERROR / anonymous, is reported, and never hits stderr', async () => {
    const outage = await createDatabase()
    const contexts: string[] = []
    const fragile = createBetterAuthEngine({
      pool: outage.admin,
      baseURL: DEV,
      secret,
      rateLimitStore: memoryRateLimitStore(),
      deliverPasswordReset: noop,
      onUnexpectedError: (context) => {
        contexts.push(context)
      },
    })
    await fragile.migrate()
    const s = await fragile.signUp(
      { email: testEmail('down'), password: TEST_PASSWORD, name: 'O' },
      req(),
    )
    const jar = store(newJar(), s)
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    await outage.admin.end()
    const signIn = await fragile.signIn(
      { email: testEmail('down2'), password: TEST_PASSWORD },
      req(),
    )
    expect(signIn.ok ? null : signIn.error).toEqual({ code: 'INTERNAL_ERROR', status: 500 })
    expect(await fragile.getActor(req(jar))).toBeNull()
    expect(consoleError).not.toHaveBeenCalled()
    expect(contexts).toContain('signIn')
    consoleError.mockRestore()
    await outage.drop().catch(() => undefined)
  })

  test('refuses weak configuration at boot', () => {
    const base = {
      pool: db.admin,
      baseURL: DEV,
      deliverPasswordReset: noop,
      rateLimitStore: memoryRateLimitStore(),
    }
    expect(() => createBetterAuthEngine({ ...base, secret: 'short' })).toThrow(TypeError)
    expect(() =>
      createBetterAuthEngine({ ...base, secret, rateLimitStore: undefined as never }),
    ).toThrow(TypeError)
    expect(() => createBetterAuthEngine({ ...base, secret, trustedProxies: ['nope'] })).toThrow(
      TypeError,
    )
  })

  test('no unexpected errors were reported by the specifics engine', () => {
    expect(reported).toEqual([])
  })
})
