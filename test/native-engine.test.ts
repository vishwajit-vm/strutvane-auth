/**
 * The native engine: the identity contract suite (shared with the Better Auth adapter, which runs
 * it in test/integration), plus native-specific behaviour.
 */
import { describe, expect, it, vi } from 'vitest'
import { createNativeEngine } from '../src/identity/native.ts'
import {
  accountKey,
  checkRateLimits,
  memoryRateLimitStore,
  normalizeEmail,
} from '../src/identity/rate-limit.ts'
import {
  browserRequest,
  freshIp,
  Mailbox,
  newJar,
  runIdentityContract,
  store,
  TEST_PASSWORD,
  TEST_PROXY,
  testEmail,
} from '../src/testing/index.ts'

const FAST = 2 ** 14 // lower scrypt cost for tests (the minimum the engine accepts)

runIdentityContract('native', async (options) => ({
  engine: createNativeEngine({ ...options, scryptCost: FAST }),
  cleanup: async () => undefined,
}))

const URL_ = 'http://localhost:3000'
const req = (jar = newJar(), ip = freshIp()) => browserRequest(URL_, { jar, ip })

describe('native engine specifics', () => {
  it('rotates the session token on tenant switch (the old token stops working)', async () => {
    const engine = createNativeEngine({
      baseURL: URL_,
      deliverPasswordReset: async () => undefined,
      scryptCost: FAST,
    })
    const s = await engine.signUp(
      { email: testEmail('rot'), password: TEST_PASSWORD, name: 'R' },
      req(),
    )
    const jar = store(newJar(), s)
    const beforeCreate = new Map(jar)
    const t = await engine.createTenant({ name: 'Rot', slug: 'rot' }, req(jar))
    if (!t.ok) throw new Error('no tenant')
    store(jar, t)
    // Creating a tenant rotates too: the pre-creation token no longer works.
    expect([...jar.values()]).not.toEqual([...beforeCreate.values()])
    expect(await engine.getActor(req(beforeCreate))).toBeNull()
    const before = new Map(jar)
    const sw = await engine.switchTenant({ tenantId: t.value.tenantId.toUpperCase() }, req(jar))
    store(jar, sw)
    expect([...jar.values()]).not.toEqual([...before.values()])
    expect(await engine.getActor(req(before))).toBeNull()
    expect((await engine.getActor(req(jar)))?.tenantId).toBe(t.value.tenantId)
  })

  it('expires sessions and reset tokens', async () => {
    let now = Date.now()
    const mailbox = new Mailbox()
    const engine = createNativeEngine({
      baseURL: URL_,
      deliverPasswordReset: mailbox.deliver,
      scryptCost: FAST,
      sessionTtlSeconds: 60,
      now: () => now,
    })
    const email = testEmail('exp')
    const s = await engine.signUp({ email, password: TEST_PASSWORD, name: 'E' }, req())
    const jar = store(newJar(), s)
    expect(await engine.getActor(req(jar))).not.toBeNull()
    await engine.startPasswordReset({ email }, req())
    const token = await mailbox.waitForToken(email)
    now += 61_000
    expect(await engine.getActor(req(jar))).toBeNull()
    now += 30 * 60_000
    const late = await engine.completePasswordReset(
      { token, newPassword: 'another long password' },
      req(),
    )
    expect(late.ok ? 'ok' : late.error.code).toBe('INVALID_TOKEN')
  })

  it('a weak new password keeps the reset token usable; the cookie is __Host- prefixed on https', async () => {
    const mailbox = new Mailbox()
    const engine = createNativeEngine({
      baseURL: 'https://app.example.com',
      deliverPasswordReset: mailbox.deliver,
      scryptCost: FAST,
    })
    const email = testEmail('weak-reset')
    const s = await engine.signUp(
      { email, password: TEST_PASSWORD, name: 'W' },
      browserRequest('https://app.example.com', { ip: freshIp() }),
    )
    expect(s.headers.getSetCookie()[0]).toMatch(/^__Host-sv_session=.*; Secure$/)
    await engine.startPasswordReset({ email }, req())
    const token = await mailbox.waitForToken(email)
    const weak = await engine.completePasswordReset({ token, newPassword: 'short' }, req())
    expect(weak.ok ? 'ok' : weak.error.code).toBe('VALIDATION_FAILED')
    expect(
      (await engine.completePasswordReset({ token, newPassword: 'a much longer password' }, req()))
        .ok,
    ).toBe(true)
  })

  it('reports engine failures and returns INTERNAL_ERROR / anonymous instead of throwing', async () => {
    const reported: string[] = []
    const failing = {
      hit: async () => {
        throw new Error('store down')
      },
    }
    const engine = createNativeEngine({
      baseURL: URL_,
      deliverPasswordReset: async () => {
        throw new Error('mailer down')
      },
      scryptCost: FAST,
      rateLimitStore: failing,
      onUnexpectedError: (context) => {
        reported.push(context)
        throw new Error('a broken reporter must not break auth')
      },
      actorAttributes: () => {
        throw new Error('attrs down')
      },
    })
    const r = await engine.signIn({ email: testEmail('x'), password: TEST_PASSWORD }, req())
    expect(r.ok ? null : r.error).toEqual({ code: 'INTERNAL_ERROR', status: 500 })
    expect(reported).toContain('signIn')
    expect((await engine.authenticate(req())).actor).toBeNull()
  })

  it('reports background delivery failures and an attribute resolver error during authenticate', async () => {
    const reported: string[] = []
    let failAttrs = false
    const engine = createNativeEngine({
      baseURL: URL_,
      deliverPasswordReset: async () => {
        throw new Error('mailer down')
      },
      scryptCost: FAST,
      onUnexpectedError: (context) => {
        reported.push(context)
      },
      actorAttributes: ({ tenantId }) => {
        if (failAttrs) throw new Error('attrs down')
        return { department: 'ops', tenant: tenantId ?? null }
      },
    })
    const email = testEmail('bg')
    const s = await engine.signUp({ email, password: TEST_PASSWORD, name: 'B' }, req())
    expect(s.ok ? s.value.actor.attrs : null).toEqual({
      department: 'ops',
      tenant: null,
      emailVerified: false,
    })
    await engine.startPasswordReset({ email }, req())
    await vi.waitFor(() => expect(reported).toContain('deliverPasswordReset'))
    failAttrs = true
    expect((await engine.authenticate(req(store(newJar(), s)))).actor).toBeNull()
    expect(reported).toContain('authenticate')
  })

  it('validates options at boot', () => {
    const base = { baseURL: URL_, deliverPasswordReset: async () => undefined }
    expect(() => createNativeEngine({ ...base, scryptCost: 1000 })).toThrow(RangeError)
    expect(() => createNativeEngine({ ...base, scryptCost: 2 ** 10 })).toThrow(RangeError)
    expect(() =>
      createNativeEngine({ ...base, rateLimits: { signInPerIp: { windowSeconds: 0, max: 1 } } }),
    ).toThrow(RangeError)
    expect(() => createNativeEngine({ ...base, trustedProxies: ['bogus'] })).toThrow(TypeError)
  })

  it('rejects duplicate slugs, bad tenant input and bad roles', async () => {
    const engine = createNativeEngine({
      baseURL: URL_,
      deliverPasswordReset: async () => undefined,
      scryptCost: FAST,
    })
    const s = await engine.signUp(
      { email: testEmail('t'), password: TEST_PASSWORD, name: 'T' },
      req(),
    )
    const jar = store(newJar(), s)
    const first = await engine.createTenant({ name: 'A', slug: 'dup' }, req(jar))
    expect(first.ok).toBe(true)
    store(jar, first)
    const dup = await engine.createTenant({ name: 'B', slug: 'dup' }, req(jar))
    expect(dup.ok ? 'ok' : dup.error.code).toBe('VALIDATION_FAILED')
    const bad = await engine.createTenant({ name: 'C', slug: 'Not A Slug' }, req(jar))
    expect(bad.ok ? 'ok' : bad.error.code).toBe('VALIDATION_FAILED')
    const list = await engine.listTenants(req(jar))
    const tenantId = list.ok ? (list.value[0]?.tenantId ?? '') : ''
    const userId = s.ok ? s.value.actor.id : ''
    const role = await engine.addMemberAsSystem({ tenantId, userId, role: 'Admin; DROP' })
    expect(role.ok ? 'ok' : role.error.code).toBe('VALIDATION_FAILED')
  })

  it('counts both IP and account keys, keyed by a hash of the normalised email', async () => {
    expect(normalizeEmail('  Ann@Example.COM ')).toBe('ann@example.com')
    expect(accountKey('signin', 'Ann@Example.com')).toBe(accountKey('signin', ' ann@example.com'))
    expect(accountKey('signin', 'ann@example.com')).not.toContain('ann')
    let now = 0
    const store_ = memoryRateLimitStore({ now: () => now, maxKeys: 2 })
    const rule = { windowSeconds: 10, max: 1 }
    expect(await checkRateLimits(store_, [['a', rule]])).toEqual({ limited: false })
    expect(await checkRateLimits(store_, [['a', rule]])).toEqual({
      limited: true,
      retryAfterSeconds: 10,
    })
    now = 10_000
    expect(await checkRateLimits(store_, [['a', rule]])).toEqual({ limited: false })
    // Bounded memory: the oldest keys are evicted.
    await store_.hit('b', 1000)
    await store_.hit('c', 1000)
    expect((await store_.hit('a', 10_000)).count).toBe(1)
  })

  it('a proxy chain resolves the real client for rate limiting', async () => {
    const engine = createNativeEngine({
      baseURL: URL_,
      deliverPasswordReset: async () => undefined,
      scryptCost: FAST,
      trustedProxies: [TEST_PROXY],
      rateLimits: { signInPerIp: { windowSeconds: 60, max: 1 } },
    })
    const ip = freshIp()
    await engine.signIn(
      { email: testEmail('a'), password: 'x'.repeat(12) },
      browserRequest(URL_, { ip }),
    )
    const second = await engine.signIn(
      { email: testEmail('b'), password: 'x'.repeat(12) },
      browserRequest(URL_, { ip }),
    )
    expect(second.ok ? 'ok' : second.error.code).toBe('RATE_LIMITED')
    const other = await engine.signIn(
      { email: testEmail('c'), password: 'x'.repeat(12) },
      browserRequest(URL_, { ip: freshIp() }),
    )
    expect(other.ok ? 'ok' : other.error.code).toBe('INVALID_CREDENTIALS')
  })
})
