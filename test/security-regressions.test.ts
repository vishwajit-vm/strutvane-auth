/**
 * Attack-style regression tests, one block per vulnerability CLASS (not per instance): tenant
 * selection by anonymous callers, rate-limit evasion, policy fail-open paths (mistyped values,
 * hidden-field oracles, empty role lists, null actor values under negation, role-namespace
 * confusion), record masking, audit redaction and log-safe error reasons.
 */
import type { Actor, QueryFilter } from '@strutvane/contracts'
import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { diffChanges } from '../src/audit/audit.ts'
import { FieldNotLoadedError, InvalidFilterError, PolicyDefinitionError } from '../src/errors.ts'
import { rateLimitSubject, trustedProxies } from '../src/http/client-ip.ts'
import { attachRequestMeta } from '../src/http/request-meta.ts'
import { createIdentityLimiter, UNKNOWN_PEER } from '../src/identity/limiter.ts'
import { createNativeEngine } from '../src/identity/native.ts'
import { memoryRateLimitStore, type RateLimitStore } from '../src/identity/rate-limit.ts'
import { authenticateRequest } from '../src/middleware/core.ts'
import { bindActor } from '../src/policy/bind.ts'
import { definePolicy } from '../src/policy/policy.ts'
import { safeLabel, validateFilter } from '../src/policy/validate.ts'
import { headerResolver, pathResolver, sessionResolver } from '../src/tenancy/resolver.ts'
import {
  browserRequest,
  Mailbox,
  TEST_NEW_PASSWORD,
  TEST_PASSWORD,
  testEmail,
} from '../src/testing/helpers.ts'
import { ALICE, actor, BOB, invoice, invoicePolicy, invoiceSchema, TENANT_A } from './fixtures.ts'

const NO_PROXIES = trustedProxies()

describe('tenant selection by anonymous callers', () => {
  const anonEngine = { authenticate: async () => ({ actor: null, headers: new Headers() }) }
  const trustingEveryone = headerResolver({ trust: () => true })
  const lookup = (slug: string) => (slug === 'acme' ? TENANT_A : undefined)
  const req = (url: string, headers: Record<string, string> = {}) => new Request(url, { headers })

  it('anonymous request cannot select a tenant by header (even with a resolver that trusts everyone)', async () => {
    const out = await authenticateRequest(req('https://x.test/', { 'x-tenant-id': TENANT_A }), {
      engine: anonEngine,
      tenancy: { resolvers: [trustingEveryone] },
    })
    expect(out.ok && out.state).toMatchObject({ actor: null, tenant: undefined })
  })

  it('allowAnonymousTenant: true admits only subdomain/path, never header or custom resolvers', async () => {
    const tenancy = {
      resolvers: [trustingEveryone, { name: 'custom', resolve: () => TENANT_A }],
      allowAnonymousTenant: true,
    }
    const viaHeader = await authenticateRequest(
      req('https://x.test/', { 'x-tenant-id': TENANT_A }),
      { engine: anonEngine, tenancy },
    )
    expect(viaHeader.ok && viaHeader.state.tenant).toBeUndefined()
    const viaPath = await authenticateRequest(req('https://x.test/t/acme/x'), {
      engine: anonEngine,
      tenancy: { resolvers: [pathResolver({ lookup })], allowAnonymousTenant: true },
    })
    expect(viaPath.ok && viaPath.state.tenant?.id).toBe(TENANT_A)
  })

  it('an explicit resolver list is an opt-in (e.g. a network-trusted internal caller by header)', async () => {
    const out = await authenticateRequest(req('https://x.test/', { 'x-tenant-id': TENANT_A }), {
      engine: anonEngine,
      tenancy: { resolvers: [trustingEveryone], allowAnonymousTenant: ['header'] },
    })
    expect(out.ok && out.state.tenant?.id).toBe(TENANT_A)
  })

  it('requireAuth answers 401 before any tenant is resolved (no tenant probing)', async () => {
    let resolved = false
    const out = await authenticateRequest(req('https://x.test/'), {
      engine: anonEngine,
      requireAuth: true,
      tenancy: {
        resolvers: [
          {
            name: 'spy',
            resolve: () => {
              resolved = true
              return undefined
            },
          },
          sessionResolver(),
        ],
        required: true,
      },
    })
    expect(out.ok ? 200 : out.response.status).toBe(401)
    expect(resolved).toBe(false)
  })
})

describe('rate-limit evasion', () => {
  const rule = { windowSeconds: 60, max: 2 }
  const peerless = () => new Request('http://x.test/')
  const withPeer = (ip: string) =>
    attachRequestMeta(new Request('http://x.test/'), { remoteAddress: ip })

  it('requests without a peer address share one fallback bucket and warn exactly once', async () => {
    const warnings: string[] = []
    const store_ = memoryRateLimitStore()
    const limited = createIdentityLimiter({
      store: store_,
      proxies: NO_PROXIES,
      engine: 'test',
      logger: { warn: (msg) => warnings.push(msg) },
    })
    expect(await limited(peerless(), 'signin', rule)).toBeUndefined()
    expect(await limited(peerless(), 'signin', rule)).toBeUndefined()
    expect(await limited(peerless(), 'signin', rule)).toBeGreaterThan(0)
    expect(warnings).toHaveLength(1)
    expect((await store_.hit(`signin:ip:${UNKNOWN_PEER}`, 60_000)).count).toBe(4)
    // A broken logger never breaks the limiter.
    const noisy = createIdentityLimiter({
      store: memoryRateLimitStore(),
      proxies: NO_PROXIES,
      engine: 'test',
      logger: {
        warn: () => {
          throw new Error('logger down')
        },
      },
    })
    expect(await noisy(peerless(), 'signup', rule)).toBeUndefined()
  })

  it('allowMissingPeer skips only the per-IP limit; the per-account limit still applies', async () => {
    const limited = createIdentityLimiter({
      store: memoryRateLimitStore(),
      proxies: NO_PROXIES,
      engine: 'test',
      allowMissingPeer: true,
    })
    for (let i = 0; i < 5; i++) expect(await limited(peerless(), 'signup', rule)).toBeUndefined()
    await limited(peerless(), 'signin', rule, 'a@x.test', rule)
    await limited(peerless(), 'signin', rule, 'a@x.test', rule)
    expect(await limited(peerless(), 'signin', rule, 'A@x.test', rule)).toBeGreaterThan(0)
  })

  it('an IPv6 client cannot rotate addresses inside its /64 to dodge the per-IP limit', async () => {
    const limited = createIdentityLimiter({
      store: memoryRateLimitStore(),
      proxies: NO_PROXIES,
      engine: 'test',
    })
    expect(await limited(withPeer('2001:db8:1:2::1'), 'signin', rule)).toBeUndefined()
    expect(await limited(withPeer('2001:db8:1:2:ffff::9'), 'signin', rule)).toBeUndefined()
    expect(
      await limited(withPeer('2001:0db8:0001:0002:abcd:0:0:1'), 'signin', rule),
    ).toBeGreaterThan(0)
    // A different /64 is a different client.
    expect(await limited(withPeer('2001:db8:1:3::1'), 'signin', rule)).toBeUndefined()
  })

  it('rateLimitSubject: IPv4 per address, IPv6 per /64, including :: and embedded IPv4 forms', () => {
    expect(rateLimitSubject('203.0.113.7')).toBe('203.0.113.7')
    expect(rateLimitSubject('::ffff:203.0.113.7')).toBe('203.0.113.7')
    expect(rateLimitSubject('::1')).toBe('0:0:0:0::/64')
    expect(rateLimitSubject('::')).toBe('0:0:0:0::/64')
    expect(rateLimitSubject('2001:DB8::')).toBe('2001:db8:0:0::/64')
    expect(rateLimitSubject('64:ff9b:1:2:3:4:192.0.2.1')).toBe('64:ff9b:1:2::/64')
    expect(rateLimitSubject('fe80::1%eth0')).toBe('fe80:0:0:0::/64')
    expect(rateLimitSubject('not-an-ip')).toBe('not-an-ip')
  })

  it('flooding the store with new IP keys cannot evict a per-account counter; expired keys go first', async () => {
    let now = 0
    const s: RateLimitStore = memoryRateLimitStore({ now: () => now, maxKeys: 3 })
    await s.hit('signin:account:victim', 60_000)
    await s.hit('signin:account:victim', 60_000)
    for (let i = 0; i < 20; i++) await s.hit(`signin:ip:198.51.100.${i}`, 60_000)
    expect((await s.hit('signin:account:victim', 60_000)).count).toBe(3)
    // Expired windows are dropped before any live key is evicted.
    const t: RateLimitStore = memoryRateLimitStore({ now: () => now, maxKeys: 2 })
    await t.hit('short', 1000)
    await t.hit('live', 60_000)
    await t.hit('live', 60_000)
    now = 2000
    await t.hit('new', 60_000)
    expect((await t.hit('live', 60_000)).count).toBe(3)
    // Only account keys left: the oldest account key is evicted (memory stays bounded).
    const u: RateLimitStore = memoryRateLimitStore({ now: () => now, maxKeys: 2 })
    await u.hit('x:account:1', 60_000)
    await u.hit('x:account:2', 60_000)
    await u.hit('x:account:3', 60_000)
    expect((await u.hit('x:account:1', 60_000)).count).toBe(1)
  })

  it('the native engine applies the fallback bucket and logs through the Logger once', async () => {
    const warnings: string[] = []
    const engine = createNativeEngine({
      baseURL: 'http://localhost:3000',
      deliverPasswordReset: async () => undefined,
      scryptCost: 2 ** 14,
      rateLimits: { signInPerIp: { windowSeconds: 60, max: 1 } },
      logger: { warn: (m) => warnings.push(m) },
    })
    const noPeer = () => browserRequest('http://localhost:3000', { noPeer: true, viaProxy: false })
    const codes: string[] = []
    for (const email of ['a@x.test', 'b@x.test', 'c@x.test']) {
      const r = await engine.signIn({ email, password: 'x'.repeat(12) }, noPeer())
      codes.push(r.ok ? 'ok' : r.error.code)
    }
    expect(codes).toEqual(['INVALID_CREDENTIALS', 'RATE_LIMITED', 'RATE_LIMITED'])
    expect(warnings).toHaveLength(1)
    const lax = createNativeEngine({
      baseURL: 'http://localhost:3000',
      deliverPasswordReset: async () => undefined,
      scryptCost: 2 ** 14,
      rateLimits: { signInPerIp: { windowSeconds: 60, max: 1 } },
      allowMissingPeer: true,
    })
    for (const email of ['a@x.test', 'b@x.test']) {
      const r = await lax.signIn({ email, password: 'x'.repeat(12) }, noPeer())
      expect(r.ok ? 'ok' : r.error.code).toBe('INVALID_CREDENTIALS')
    }
  })
})

describe('mistyped record values fail closed (can() never diverges from filterFor())', () => {
  // A policy whose DENY rule touches every column type: a value that silently compared false
  // would turn the deny off and the decision into an allow.
  const guarded = definePolicy('invoice', { schema: invoiceSchema }, ({ allow, deny }) => {
    allow('view')
    deny('view', {
      name: 'locked',
      when: ({ row, or }) =>
        or(
          row.amount.gt(1000),
          row.score.gte(9),
          row.archived.eq(true),
          row.ownerId.eq(BOB),
          row.status.eq('locked'),
          row.customer.tier.between(5, 9),
        ),
    })
  })
  // What node-pg (and similar drivers) hand back for bigint / numeric / other columns.
  const mistyped = fc.oneof(
    fc.record({ field: fc.constant('amount'), value: fc.integer().map(String) }),
    fc.record({ field: fc.constant('amount'), value: fc.constant(2 ** 40) }),
    fc.record({ field: fc.constant('score'), value: fc.double({ noNaN: true }).map(String) }),
    fc.record({ field: fc.constant('score'), value: fc.constant(Number.POSITIVE_INFINITY) }),
    fc.record({ field: fc.constant('archived'), value: fc.constantFrom(0, 1, 't', 'f', 'true') }),
    fc.record({
      field: fc.constant('ownerId'),
      value: fc.constantFrom(BOB.replace(/-/g, ''), `{${BOB}}`, BOB.toUpperCase().slice(1)),
    }),
    fc.record({ field: fc.constant('status'), value: fc.constantFrom(1, true, ['locked']) }),
  )

  it('a mistyped value never yields allow: the check throws FieldNotLoadedError', () => {
    fc.assert(
      fc.property(mistyped, ({ field, value }) => {
        const record = invoice({ [field]: value })
        expect(() => guarded.can(actor(), 'view', record)).toThrow(FieldNotLoadedError)
      }),
      { numRuns: 200 },
    )
  })

  it('mistyped relation fields fail closed too; well-typed records still decide normally', () => {
    const rel = invoice({ customer: { id: ALICE, region: 'eu', tier: '7' } })
    expect(() => guarded.can(actor(), 'view', rel)).toThrow(FieldNotLoadedError)
    expect(guarded.can(actor(), 'view', invoice())).toBe(true)
    expect(guarded.can(actor(), 'view', invoice({ amount: 5000 }))).toBe(false)
    // An uppercase canonical uuid is valid (Postgres uuid is case-insensitive).
    expect(guarded.can(actor(), 'view', invoice({ ownerId: BOB.toUpperCase() }))).toBe(false)
  })
})

describe('hidden fields cannot be used as a filter or sort oracle', () => {
  const clerk = actor({ roles: ['accountant'] })
  const manager = actor({ roles: ['manager'] })
  const probe: QueryFilter = {
    op: 'startsWith',
    field: 'internalNotes',
    value: 's',
    caseSensitive: true,
  }

  it('filterableFields excludes fields the actor may not read', () => {
    expect(invoicePolicy.filterableFields(clerk)).not.toContain('internalNotes')
    expect(invoicePolicy.filterableFields(manager)).toContain('internalNotes')
    expect(invoicePolicy.filterableFields(null)).not.toContain('internalNotes')
  })

  it('an untrusted filter on a hidden field is rejected like an unknown field', () => {
    expect(() =>
      validateFilter(probe, invoiceSchema, {
        allowedFields: invoicePolicy.filterableFields(clerk),
      }),
    ).toThrow(InvalidFilterError)
    // Nested inside not/or as well.
    expect(() =>
      validateFilter(
        { op: 'or', filters: [{ op: 'true' }, { op: 'not', filter: probe }] },
        invoiceSchema,
        {
          allowedFields: invoicePolicy.filterableFields(clerk),
        },
      ),
    ).toThrow(InvalidFilterError)
    expect(() =>
      validateFilter(probe, invoiceSchema, {
        allowedFields: invoicePolicy.filterableFields(manager),
      }),
    ).not.toThrow()
    // Relation paths must be listed explicitly.
    expect(() =>
      validateFilter({ op: 'eq', field: 'customer.region', value: 'eu' }, invoiceSchema, {
        allowedFields: ['status'],
      }),
    ).toThrow(InvalidFilterError)
  })
})

describe('empty role lists never mean "everyone"', () => {
  const define = (build: Parameters<typeof definePolicy>[2]) =>
    definePolicy('invoice', { schema: invoiceSchema }, build)

  it('role: [] (or an invalid role value) is a definition error in allow, deny and field rules', () => {
    expect(() => define(({ allow }) => allow('view', { role: [] }))).toThrow(PolicyDefinitionError)
    expect(() => define(({ deny }) => deny('view', { role: [] }))).toThrow(PolicyDefinitionError)
    expect(() => define(({ allow }) => allow('view', { role: [''] }))).toThrow(
      PolicyDefinitionError,
    )
    expect(() => define(({ allow }) => allow('view', { role: 5 as unknown as string }))).toThrow(
      PolicyDefinitionError,
    )
    expect(() => define(({ field }) => field('internalNotes').readable({ role: [] }))).toThrow(
      PolicyDefinitionError,
    )
    expect(() => define(({ field }) => field('internalNotes').writable({ role: ['  '] }))).toThrow(
      PolicyDefinitionError,
    )
  })
})

describe('null actor values never widen an allow rule, even under negation', () => {
  const p = definePolicy(
    'invoice',
    { schema: invoiceSchema, attrs: { region: 'text', limit: 'int4' } },
    ({ allow, deny }) => {
      allow('ne', { when: ({ row, actor }) => row.region.ne(actor.attrs.region) })
      allow('nin', { when: ({ row, actor }) => row.region.nin([actor.attrs.region]) })
      allow('notEq', { when: ({ row, actor, not }) => not(row.region.eq(actor.attrs.region)) })
      allow('notIn', {
        when: ({ row, actor, not }) => not(row.region.in([actor.attrs.region, 'eu'])),
      })
      allow('notGt', { when: ({ row, actor, not }) => not(row.amount.gt(actor.attrs.limit)) })
      allow('notBetween', {
        when: ({ row, actor, not }) => not(row.amount.between(0, actor.attrs.limit)),
      })
      allow('in', { when: ({ row, actor }) => row.region.in([actor.attrs.region, 'eu']) })
      allow('notNin', {
        when: ({ row, actor, not }) => not(row.region.nin([actor.attrs.region, 'eu'])),
      })
      allow('doubleNot', {
        when: ({ row, actor, not }) => not(not(row.region.ne(actor.attrs.region))),
      })
      allow('safeDeny')
      deny('safeDeny', { when: ({ row, actor }) => row.region.eq(actor.attrs.region) })
    },
  )
  const noRegion: Actor = actor({ attrs: { region: null, limit: null } })
  const rows = [invoice({ region: 'us' }), invoice({ region: 'eu' }), invoice({ region: null })]

  it.each(['ne', 'nin', 'notEq', 'notIn', 'notGt', 'notBetween', 'doubleNot'])(
    '%s: matches no rows in memory and in the list filter',
    (action) => {
      expect(p.filterFor(noRegion, action)).toEqual({ op: 'false' })
      for (const r of rows) expect(p.can(noRegion, action, r)).toBe(false)
    },
  )

  it('narrowing forms keep working: positive in / negated nin drop the null value', () => {
    expect(p.can(noRegion, 'in', invoice({ region: 'eu' }))).toBe(true)
    expect(p.can(noRegion, 'in', invoice({ region: 'us' }))).toBe(false)
    expect(p.can(noRegion, 'notNin', invoice({ region: 'eu' }))).toBe(true)
    expect(p.can(noRegion, 'notNin', invoice({ region: 'us' }))).toBe(false)
  })

  it('deny rules and bindActor keep ADR-0008 "null never matches" semantics', () => {
    expect(p.can(noRegion, 'safeDeny', invoice({ region: null }))).toBe(true)
    const ne: QueryFilter = { op: 'ne', field: 'region', value: { $actor: 'attrs.region' } }
    expect(bindActor(ne, noRegion)).toEqual({ op: 'true' })
    expect(bindActor(ne, noRegion, { failClosed: true })).toEqual({ op: 'false' })
    // Actors with a value are unaffected.
    expect(
      p.can(actor({ attrs: { region: 'eu', limit: 1 } }), 'ne', invoice({ region: 'us' })),
    ).toBe(true)
  })
})

describe('platform roles and tenant roles with the same name stay separate', () => {
  const p = definePolicy('invoice', { schema: invoiceSchema }, ({ allow, field }) => {
    allow('purge', { role: 'admin', scope: 'global' })
    allow('manage', { role: 'admin', scope: 'tenant' })
    allow('view', { role: 'admin' })
    field('internalNotes').readable({ role: 'admin', scope: 'global' })
  })
  const tenantAdmin = actor({ roles: ['admin'], tenantId: TENANT_A })
  const { tenantId: _t, ...rest } = actor({ roles: ['admin'] })
  const platformAdmin: Actor = rest

  it("a tenant's own admin never matches scope: 'global' rules (and vice versa)", () => {
    expect(p.can(tenantAdmin, 'purge')).toBe(false)
    expect(p.can(platformAdmin, 'purge')).toBe(true)
    expect(p.can(tenantAdmin, 'manage')).toBe(true)
    expect(p.can(platformAdmin, 'manage')).toBe(false)
    expect(p.can(tenantAdmin, 'view') && p.can(platformAdmin, 'view')).toBe(true)
    expect(p.readableFields(tenantAdmin)).not.toContain('internalNotes')
    expect(p.readableFields(platformAdmin)).toContain('internalNotes')
    expect(p.rules.find((r) => r.actions.includes('purge'))?.scope).toBe('global')
  })

  it('scope is validated and cannot be combined with anonymous', () => {
    expect(() =>
      definePolicy('invoice', { schema: invoiceSchema }, ({ allow }) =>
        allow('x', { scope: 'planet' as 'global' }),
      ),
    ).toThrow(PolicyDefinitionError)
    expect(() =>
      definePolicy('invoice', { schema: invoiceSchema }, ({ allow }) =>
        allow('x', { anonymous: true, scope: 'global' }),
      ),
    ).toThrow(PolicyDefinitionError)
  })
})

describe('combined rule limits are checked at definition time', () => {
  it('a policy whose combined list filter would exceed the limits fails at boot, not in filterFor', () => {
    expect(() =>
      definePolicy('invoice', { schema: invoiceSchema, limits: { maxNodes: 20 } }, ({ allow }) => {
        for (let i = 0; i < 6; i++)
          allow('view', {
            role: `r${i}`,
            when: ({ row, and }) => and(row.amount.gt(i), row.status.eq(`s${i}`)),
          })
      }),
    ).toThrow(/combined rules for action "view"/)
  })
})

describe('masking copies only readable schema fields', () => {
  const clerk = actor({ roles: ['accountant'] })

  it('unknown keys (secrets, nested objects) and __proto__ never pass through maskRecord', () => {
    const loaded = JSON.parse(
      '{"id":"i","status":"draft","internalNotes":"n","passwordHash":"$scrypt$","__proto__":{"admin":true},"customer":{"tier":1}}',
    ) as Record<string, unknown>
    const out = invoicePolicy.maskRecord(clerk, loaded)
    expect(Object.keys(out).sort()).toEqual(['id', 'status'])
    expect((out as { admin?: unknown }).admin).toBeUndefined()
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype)
    expect(Object.keys(invoicePolicy.maskRecord(actor({ roles: ['manager'] }), loaded))).toContain(
      'internalNotes',
    )
  })

  it('a schema field literally named __proto__ stays an own data property', () => {
    const schema = {
      table: 'odd',
      columns: JSON.parse('{"__proto__":{"column":"proto","type":"text"}}') as Record<
        string,
        { column: string; type: 'text' }
      >,
    }
    const odd = definePolicy('odd', { schema: schema as never }, () => undefined)
    const out = odd.maskRecord(null, JSON.parse('{"__proto__":"x"}') as Record<string, unknown>)
    expect(Object.hasOwn(out, '__proto__')).toBe(true)
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype)
  })

  it('unwritableFields reports keys that are not schema columns', () => {
    expect(
      invoicePolicy.unwritableFields(actor({ roles: ['director'] }), {
        status: 'x',
        role: 'admin',
      }),
    ).toEqual(['role'])
    expect(invoicePolicy.unwritableFields(clerk, { status: 'x', internalNotes: 'y' })).toEqual([
      'internalNotes',
    ])
  })
})

describe('audit diffs never store values a policy hides', () => {
  it('maskFor redacts every field with a read rule; restrictedFields lists them', () => {
    expect(invoicePolicy.restrictedFields).toEqual(['internalNotes'])
    const changes = diffChanges(
      { internalNotes: 'old secret', status: 'draft' },
      { internalNotes: 'new secret', status: 'sent' },
      { maskFor: invoicePolicy },
    )
    expect(changes).toEqual([
      { field: 'internalNotes', from: '[REDACTED]', to: '[REDACTED]', redacted: true },
      { field: 'status', from: 'draft', to: 'sent' },
    ])
    expect(JSON.stringify(changes)).not.toContain('secret')
  })
})

describe('error reasons are log-safe', () => {
  it('untrusted fields and operators are escaped and truncated; table names are not disclosed', () => {
    const reason = (f: unknown) => {
      try {
        validateFilter(f as QueryFilter, invoiceSchema)
      } catch (error) {
        return error instanceof InvalidFilterError ? error.reason : 'other'
      }
      return 'accepted'
    }
    const field = reason({ op: 'eq', field: `x\n[ERROR] forged ${'y'.repeat(150)}`, value: 1 })
    expect(field).not.toContain('\n')
    expect(field).not.toContain('invoices')
    expect(field.length).toBeLessThan(120)
    const op = reason({ op: `${'z'.repeat(5000)}\r\n` })
    expect(op).not.toMatch(/[\r\n]/)
    expect(op.length).toBeLessThan(80)
    expect(reason({ op: 'eq', field: 'customer.nope', value: 1 })).not.toContain('customers')
    expect(reason({ op: 'eq', field: 'nope.x', value: 1 })).toContain('unknown relation')
    expect(reason({ op: 'eq', field: 'a.b.c', value: 1 })).toContain('deeper')
    expect(safeLabel({ toJSON: () => undefined })).toBe('"object"')
    const cyclic: Record<string, unknown> = {}
    cyclic['self'] = cyclic
    expect(safeLabel(cyclic)).toBe('"object"')
  })
})

describe('password reset links die with the reset', () => {
  it('completing one reset invalidates every other outstanding reset token of that user', async () => {
    const mailbox = new Mailbox()
    const engine = createNativeEngine({
      baseURL: 'http://localhost:3000',
      deliverPasswordReset: mailbox.deliver,
      scryptCost: 2 ** 14,
    })
    const email = testEmail('reset')
    const req = () => browserRequest('http://localhost:3000')
    expect((await engine.signUp({ email, password: TEST_PASSWORD, name: 'R' }, req())).ok).toBe(
      true,
    )
    await engine.startPasswordReset({ email }, req())
    const first = await mailbox.waitForToken(email)
    await engine.startPasswordReset({ email }, req())
    for (;;) {
      if (mailbox.messages.length >= 2) break
      await new Promise((r) => setTimeout(r, 5))
    }
    const second = mailbox.tokenFor(email) ?? ''
    expect(second).not.toBe(first)
    const done = await engine.completePasswordReset(
      { token: second, newPassword: TEST_NEW_PASSWORD },
      req(),
    )
    expect(done.ok).toBe(true)
    const replay = await engine.completePasswordReset(
      { token: first, newPassword: 'attacker chosen password' },
      req(),
    )
    expect(replay.ok ? 'ok' : replay.error.code).toBe('INVALID_TOKEN')
  })
})
