/**
 * The `IdentityEngine` CONTRACT: behaviour every engine must have, written only against the
 * interface. `@strutvane/auth` runs it against the native engine and the Better Auth adapter; run it
 * against your own adapter the same way:
 *
 * ```ts
 * import { runIdentityContract } from '@strutvane/auth/testing'
 * runIdentityContract('my-engine', async (o) => ({ engine: createMyEngine(o), cleanup: async () => {} }))
 * ```
 *
 * Covered: sign-up validation, no user enumeration (sign-in and reset), no session fixation,
 * cookie attributes, forged/garbage cookies, server-side sign-out, per-IP and per-account rate
 * limits that a forged `X-Forwarded-For` cannot bypass, single-use resets that revoke sessions,
 * tenant membership and roles re-read on every request, and malformed (non-string) input.
 *
 * @module
 */
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import type {
  ErrorReporter,
  IdentityEngine,
  IdentityResult,
  PasswordResetDelivery,
} from '../identity/engine.ts'
import type { IdentityRateLimits } from '../identity/native.ts'
import {
  browserRequest,
  cookieAttributes,
  freshIp,
  type Jar,
  Mailbox,
  newJar,
  store,
  TEST_NEW_PASSWORD,
  TEST_PASSWORD,
  TEST_PROXY,
  testEmail,
} from './helpers.ts'

/** What the contract passes to your factory. Wire every option into your engine. */
export interface EngineFactoryOptions {
  readonly baseURL: string
  readonly deliverPasswordReset: PasswordResetDelivery
  readonly rateLimits: Required<IdentityRateLimits>
  readonly trustedProxies: readonly string[]
  readonly onUnexpectedError: ErrorReporter
}

/** Builds a fresh engine (and its cleanup) for the contract. */
export type EngineFactory = (
  options: EngineFactoryOptions,
) => Promise<{ engine: IdentityEngine; cleanup: () => Promise<void> }>

export const CONTRACT_DEV_URL = 'http://localhost:3000'
export const CONTRACT_PROD_URL = 'https://app.example.com'

/** The limits the contract configures (small, so tests can trip them quickly). */
export const CONTRACT_RATE_LIMITS: Required<IdentityRateLimits> = Object.freeze({
  signInPerIp: { windowSeconds: 60, max: 3 },
  signInPerAccount: { windowSeconds: 60, max: 6 },
  signUpPerIp: { windowSeconds: 60, max: 1000 },
  passwordReset: { windowSeconds: 60, max: 1000 },
})

const err = (r: IdentityResult<unknown>) => (r.ok ? null : r.error)
const code = (r: IdentityResult<unknown>) => (r.ok ? 'ok' : r.error.code)

/** Register the contract suite (Vitest). */
export function runIdentityContract(label: string, factory: EngineFactory): void {
  describe(`IdentityEngine contract: ${label}`, () => {
    const mailbox = new Mailbox()
    const reported: string[] = []
    let engine: IdentityEngine
    let cleanup: () => Promise<void>

    beforeAll(async () => {
      ;({ engine, cleanup } = await factory({
        baseURL: CONTRACT_DEV_URL,
        deliverPasswordReset: mailbox.deliver,
        rateLimits: CONTRACT_RATE_LIMITS,
        trustedProxies: [TEST_PROXY],
        onUnexpectedError: (context) => {
          reported.push(context)
        },
      }))
    })
    afterAll(async () => cleanup())

    const req = (jar: Jar = newJar(), ip = freshIp()) =>
      browserRequest(CONTRACT_DEV_URL, { jar, ip })

    async function signedUpUser(name: string) {
      const address = testEmail(name)
      const result = await engine.signUp({ email: address, password: TEST_PASSWORD, name }, req())
      if (!result.ok) throw new Error(`sign-up failed: ${result.error.code}`)
      return { address, jar: store(newJar(), result), id: result.value.actor.id }
    }

    describe('sign-up', () => {
      test('creates a signed-in user actor without a tenant', async () => {
        const result = await engine.signUp(
          { email: testEmail('signup'), password: TEST_PASSWORD, name: 'Ann' },
          req(),
        )
        expect(result.ok).toBe(true)
        if (!result.ok) return
        expect(result.value.actor).toMatchObject({ type: 'user', roles: [] })
        expect(result.value.actor.tenantId).toBeUndefined()
        expect(result.value.actor.id).toMatch(
          /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
        )
        const auth = await engine.authenticate(req(store(newJar(), result)))
        expect(auth.actor?.id).toBe(result.value.actor.id)
        expect(auth.headers).toBeInstanceOf(Headers)
      })

      test('rejects weak passwords and malformed emails with VALIDATION_FAILED', async () => {
        const weak = await engine.signUp(
          { email: testEmail('weak'), password: 'short', name: 'W' },
          req(),
        )
        expect(err(weak)).toEqual({ code: 'VALIDATION_FAILED', status: 422 })
        const eleven = await engine.signUp(
          { email: testEmail('eleven'), password: '12345678901', name: 'E' },
          req(),
        )
        expect(code(eleven)).toBe('VALIDATION_FAILED')
        const bad = await engine.signUp(
          { email: 'not-an-email', password: TEST_PASSWORD, name: 'B' },
          req(),
        )
        expect(code(bad)).toBe('VALIDATION_FAILED')
      })

      test('a duplicate email (any case) returns EMAIL_UNAVAILABLE', async () => {
        const { address } = await signedUpUser('dup')
        const again = await engine.signUp(
          { email: address.toUpperCase(), password: TEST_PASSWORD, name: 'Dup' },
          req(),
        )
        expect(err(again)).toEqual({ code: 'EMAIL_UNAVAILABLE', status: 422 })
      })

      test('malformed (non-string) input is a validation failure, never an internal error', async () => {
        const result = await engine.signUp({ email: 42, password: null, name: {} } as never, req())
        expect(code(result)).toBe('VALIDATION_FAILED')
        const signIn = await engine.signIn({ email: ['x'], password: 7 } as never, req())
        expect(code(signIn)).toBe('INVALID_CREDENTIALS')
        const reset = await engine.startPasswordReset({ email: { $ne: '' } } as never, req())
        expect(code(reset)).toBe('VALIDATION_FAILED')
      })
    })

    describe('sign-in, sessions and sign-out', () => {
      test('wrong password and unknown email are indistinguishable (no user enumeration)', async () => {
        const { address } = await signedUpUser('enum')
        const wrong = await engine.signIn(
          { email: address, password: 'definitely wrong pw' },
          req(),
        )
        const unknown = await engine.signIn(
          { email: testEmail('ghost'), password: 'definitely wrong pw' },
          req(),
        )
        expect(err(wrong)).toEqual({ code: 'INVALID_CREDENTIALS', status: 401 })
        expect(err(unknown)).toEqual(err(wrong))
        expect(wrong.headers.getSetCookie()).toEqual([])
        expect(unknown.headers.getSetCookie()).toEqual([])
      })

      test('sign-in issues a fresh session every time (no session fixation)', async () => {
        const { address, jar: planted } = await signedUpUser('fixation')
        const first = await engine.signIn({ email: address, password: TEST_PASSWORD }, req())
        // A victim signing in while carrying a session the attacker planted gets a NEW session.
        const second = await engine.signIn(
          { email: address, password: TEST_PASSWORD },
          req(new Map(planted)),
        )
        expect(first.ok && second.ok).toBe(true)
        const a = [...store(newJar(), first).values()]
        const b = [...store(newJar(), second).values()]
        expect(a.length).toBeGreaterThan(0)
        expect(b).not.toEqual(a)
        expect(b).not.toEqual([...planted.values()])
        // The presented (possibly planted) session is revoked, not left alive next to the new one.
        expect(await engine.getActor(req(new Map(planted)))).toBeNull()
        expect(await engine.getActor(req(store(newJar(), second)))).not.toBeNull()
      })

      test('session cookies are HttpOnly, SameSite=Lax, Path=/ and not Secure on http dev URLs', async () => {
        const { address } = await signedUpUser('cookie-dev')
        const result = await engine.signIn({ email: address, password: TEST_PASSWORD }, req())
        const cookies = result.headers.getSetCookie().map(cookieAttributes)
        expect(cookies.length).toBeGreaterThan(0)
        for (const { attrs } of cookies) {
          expect(attrs.has('httponly')).toBe(true)
          expect(attrs.get('samesite')?.toLowerCase()).toBe('lax')
          expect(attrs.get('path')).toBe('/')
          expect(attrs.has('secure')).toBe(false)
        }
      })

      test('authenticate returns null for no, forged and garbage cookies, and never throws', async () => {
        expect((await engine.authenticate(req())).actor).toBeNull()
        const { jar } = await signedUpUser('forged')
        const forged = new Map([...jar].map(([k, v]) => [k, `${v.slice(0, -4)}AAAA`]))
        expect(await engine.getActor(req(forged))).toBeNull()
        const garbage = new Map(
          [...jar].map(([k]) => [k, `${'%00\u0001;'.repeat(50)}"' OR 1=1 --`]),
        )
        expect(await engine.getActor(req(garbage))).toBeNull()
        const huge = new Map([...jar].map(([k]) => [k, 'A'.repeat(8000)]))
        expect(await engine.getActor(req(huge))).toBeNull()
      })

      test('sign-out revokes the session server-side (an old copy of the cookie stops working)', async () => {
        const { jar } = await signedUpUser('signout')
        const stolenCopy = new Map(jar)
        expect(await engine.getActor(req(jar))).not.toBeNull()
        expect((await engine.signOut(req(jar))).ok).toBe(true)
        expect(await engine.getActor(req(stolenCopy))).toBeNull()
        expect(code(await engine.signOut(req(newJar())))).toBe('UNAUTHENTICATED')
      })
    })

    describe('rate limits', () => {
      test('sign-in is limited per client IP, with Retry-After; other IPs are unaffected', async () => {
        const { address } = await signedUpUser('ratelimit')
        const ip = freshIp()
        let last: IdentityResult<unknown> | undefined
        for (let i = 0; i <= CONTRACT_RATE_LIMITS.signInPerIp.max; i++) {
          last = await engine.signIn(
            { email: address, password: 'wrong wrong wrong' },
            req(newJar(), ip),
          )
        }
        expect(last && code(last)).toBe('RATE_LIMITED')
        expect(last && !last.ok ? last.error.retryAfterSeconds : 0).toBeGreaterThan(0)
        expect(Number(last?.headers.get('retry-after'))).toBeGreaterThan(0)
        // Even the correct password is refused while limited…
        expect(
          code(await engine.signIn({ email: address, password: TEST_PASSWORD }, req(newJar(), ip))),
        ).toBe('RATE_LIMITED')
        // …but another client is not affected.
        expect(
          code(
            await engine.signIn(
              { email: address, password: TEST_PASSWORD },
              req(newJar(), freshIp()),
            ),
          ),
        ).toBe('ok')
      })

      test('a rotating forged X-Forwarded-For from an untrusted peer does NOT bypass the IP limit', async () => {
        const { address } = await signedUpUser('xff')
        const attacker = freshIp()
        const codes: string[] = []
        for (let i = 0; i < CONTRACT_RATE_LIMITS.signInPerIp.max + 2; i++) {
          const request = browserRequest(CONTRACT_DEV_URL, {
            ip: attacker,
            viaProxy: false,
            forwardedFor: `100.64.${i}.1`,
          })
          codes.push(
            code(await engine.signIn({ email: address, password: 'wrong wrong wrong' }, request)),
          )
        }
        expect(codes.at(-1)).toBe('RATE_LIMITED')
      })

      test('a per-account limit stops a distributed attack from many IPs', async () => {
        const { address } = await signedUpUser('account-limit')
        const codes: string[] = []
        for (let i = 0; i <= CONTRACT_RATE_LIMITS.signInPerAccount.max; i++) {
          codes.push(
            code(
              await engine.signIn(
                { email: address, password: 'wrong wrong wrong' },
                req(newJar(), freshIp()),
              ),
            ),
          )
        }
        expect(codes.slice(0, -1).every((c) => c === 'INVALID_CREDENTIALS')).toBe(true)
        expect(codes.at(-1)).toBe('RATE_LIMITED')
        // The account key is the normalised email: case changes don't reset it.
        expect(
          code(
            await engine.signIn({ email: address.toUpperCase(), password: TEST_PASSWORD }, req()),
          ),
        ).toBe('RATE_LIMITED')
      })

      test('requests without a known client address share ONE fallback bucket (fail closed)', async () => {
        const a = await signedUpUser('noip-a')
        const b = await signedUpUser('noip-b')
        const noPeer = () => browserRequest(CONTRACT_DEV_URL, { noPeer: true, viaProxy: false })
        for (let i = 0; i < CONTRACT_RATE_LIMITS.signInPerIp.max; i++) {
          expect(
            code(
              await engine.signIn({ email: a.address, password: 'wrong wrong wrong' }, noPeer()),
            ),
          ).toBe('INVALID_CREDENTIALS')
        }
        // The per-IP limit is not skipped: the next peer-less attempt is limited, for any account.
        expect(
          code(await engine.signIn({ email: b.address, password: TEST_PASSWORD }, noPeer())),
        ).toBe('RATE_LIMITED')
        // Requests with a known peer are unaffected.
        expect(
          code(await engine.signIn({ email: b.address, password: TEST_PASSWORD }, req())),
        ).toBe('ok')
      })
    })

    describe('password reset', () => {
      test('start is identical for known and unknown emails; only known emails get a token', async () => {
        const { address } = await signedUpUser('reset-enum')
        const known = await engine.startPasswordReset({ email: address }, req())
        const unknown = await engine.startPasswordReset({ email: testEmail('nobody') }, req())
        expect(known.ok).toBe(true)
        expect(unknown.ok).toBe(true)
        expect(await mailbox.waitForToken(address)).toBeTruthy()
      })

      test('a bad token is INVALID_TOKEN; a good one changes the password, is single-use and revokes sessions', async () => {
        const { address, jar } = await signedUpUser('reset-flow')
        await engine.startPasswordReset({ email: address }, req())
        const token = await mailbox.waitForToken(address)

        const bad = await engine.completePasswordReset(
          { token: 'not-a-real-token', newPassword: TEST_NEW_PASSWORD },
          req(),
        )
        expect(err(bad)).toEqual({ code: 'INVALID_TOKEN', status: 400 })
        const nonString = await engine.completePasswordReset(
          { token: 12 as never, newPassword: TEST_NEW_PASSWORD },
          req(),
        )
        expect(code(nonString)).toBe('INVALID_TOKEN')

        expect(
          (await engine.completePasswordReset({ token, newPassword: TEST_NEW_PASSWORD }, req())).ok,
        ).toBe(true)
        const reused = await engine.completePasswordReset(
          { token, newPassword: 'yet another long password' },
          req(),
        )
        expect(code(reused)).toBe('INVALID_TOKEN')

        expect(await engine.getActor(req(jar))).toBeNull() // old session revoked
        expect(code(await engine.signIn({ email: address, password: TEST_PASSWORD }, req()))).toBe(
          'INVALID_CREDENTIALS',
        )
        expect(
          code(await engine.signIn({ email: address, password: TEST_NEW_PASSWORD }, req())),
        ).toBe('ok')
      })
    })

    describe('tenants and roles', () => {
      test('creating a tenant makes the creator its owner; the actor carries tenantId and roles', async () => {
        const owner = await signedUpUser('owner')
        const created = await engine.createTenant(
          { name: 'Acme', slug: `acme-${owner.id.slice(-8)}` },
          req(owner.jar),
        )
        expect(created.ok).toBe(true)
        if (!created.ok) return
        expect(created.value.tenantId).toMatch(/^[0-9a-f-]{36}$/i)
        store(owner.jar, created)
        const switched = await engine.switchTenant(
          { tenantId: created.value.tenantId },
          req(owner.jar),
        )
        expect(switched.ok ? switched.value.actor : null).toMatchObject({
          tenantId: created.value.tenantId,
          roles: ['owner'],
        })
        const actor = await engine.getActor(req(store(owner.jar, switched)))
        expect(actor).toMatchObject({ tenantId: created.value.tenantId, roles: ['owner'] })
        const list = await engine.listTenants(req(owner.jar))
        expect(list.ok ? list.value : null).toEqual([
          {
            tenantId: created.value.tenantId,
            name: 'Acme',
            slug: created.value.slug,
            roles: ['owner'],
          },
        ])
      })

      test('a refused switch leaves the current tenant active (no silent tenant loss)', async () => {
        const ownerA = await signedUpUser('keep-a')
        const ownerB = await signedUpUser('keep-b')
        const a = await engine.createTenant(
          { name: 'A', slug: `ka-${ownerA.id.slice(-8)}` },
          req(ownerA.jar),
        )
        const b = await engine.createTenant(
          { name: 'B', slug: `kb-${ownerB.id.slice(-8)}` },
          req(ownerB.jar),
        )
        if (!a.ok || !b.ok) throw new Error('tenants not created')
        store(ownerB.jar, b)
        expect((await engine.getActor(req(ownerB.jar)))?.tenantId).toBe(b.value.tenantId)
        for (const tenantId of [
          a.value.tenantId,
          '0190f2a0-0000-7000-8000-00000000dead',
          'garbage',
        ]) {
          const refused = await engine.switchTenant({ tenantId }, req(ownerB.jar))
          expect(code(refused)).toBe('FORBIDDEN')
          store(ownerB.jar, refused)
          const actor = await engine.getActor(req(ownerB.jar))
          expect(actor?.tenantId).toBe(b.value.tenantId)
          expect(actor?.roles).toEqual(['owner'])
        }
      })

      test('a non-member cannot switch into a tenant; unknown and malformed tenants look identical', async () => {
        const owner = await signedUpUser('tenant-a-owner')
        const outsider = await signedUpUser('outsider')
        const a = await engine.createTenant(
          { name: 'A', slug: `a-${owner.id.slice(-8)}` },
          req(owner.jar),
        )
        if (!a.ok) throw new Error('tenant A not created')
        const intoA = await engine.switchTenant({ tenantId: a.value.tenantId }, req(outsider.jar))
        const intoUnknown = await engine.switchTenant(
          { tenantId: '0190f2a0-0000-7000-8000-00000000dead' },
          req(outsider.jar),
        )
        const intoGarbage = await engine.switchTenant(
          { tenantId: "x' OR '1'='1" },
          req(outsider.jar),
        )
        expect(err(intoA)).toEqual({ code: 'FORBIDDEN', status: 403 })
        expect(err(intoUnknown)).toEqual(err(intoA))
        expect(err(intoGarbage)).toEqual(err(intoA))
        expect((await engine.getActor(req(outsider.jar)))?.tenantId).toBeUndefined()
        const list = await engine.listTenants(req(outsider.jar))
        expect(list.ok ? list.value : null).toEqual([])
      })

      test('membership roles map to actor.roles; removing the membership drops the tenant immediately', async () => {
        const owner = await signedUpUser('roles-owner')
        const member = await signedUpUser('roles-member')
        const t = await engine.createTenant(
          { name: 'Roles Inc', slug: `roles-${owner.id.slice(-8)}` },
          req(owner.jar),
        )
        if (!t.ok) throw new Error('tenant not created')
        expect(
          (
            await engine.addMemberAsSystem({
              tenantId: t.value.tenantId,
              userId: member.id,
              role: 'member',
            })
          ).ok,
        ).toBe(true)
        const switched = await engine.switchTenant({ tenantId: t.value.tenantId }, req(member.jar))
        expect(switched.ok ? switched.value.actor : null).toMatchObject({
          tenantId: t.value.tenantId,
          roles: ['member'],
        })
        store(member.jar, switched)

        await engine.removeMemberAsSystem({ tenantId: t.value.tenantId, userId: member.id })
        const after = await engine.getActor(req(member.jar))
        expect(after).not.toBeNull()
        expect(after?.tenantId).toBeUndefined() // fail closed: no stale tenant access
        expect(after?.roles).toEqual([])
      })

      test('system membership operations validate ids before touching storage', async () => {
        expect(
          code(
            await engine.addMemberAsSystem({ tenantId: 'nope', userId: 'nope', role: 'member' }),
          ),
        ).toBe('VALIDATION_FAILED')
        expect(
          code(
            await engine.removeMemberAsSystem({
              tenantId: "1'; DROP TABLE member; --",
              userId: 'x',
            }),
          ),
        ).toBe('VALIDATION_FAILED')
      })

      test('system operations: users, tenants and members (seeders, CLI, membership admin)', async () => {
        const email = testEmail('system')
        const created = await engine.createUserAsSystem({
          email: email.toUpperCase(),
          password: TEST_PASSWORD,
          name: 'System User',
        })
        expect(created.ok).toBe(true)
        if (!created.ok) return
        // Not signed in anywhere: no cookie is issued for a system-created account.
        expect(created.headers.getSetCookie()).toEqual([])
        expect(created.value.email).toBe(email.toLowerCase())
        expect(
          code(await engine.createUserAsSystem({ email, password: TEST_PASSWORD, name: 'Again' })),
        ).toBe('EMAIL_UNAVAILABLE')
        expect(
          code(
            await engine.createUserAsSystem({
              email: testEmail('weak'),
              password: 'short',
              name: 'W',
            }),
          ),
        ).toBe('VALIDATION_FAILED')
        const found = await engine.findUserAsSystem({ email: email.toUpperCase() })
        expect(found.ok ? found.value?.id : null).toBe(created.value.id)
        const missing = await engine.findUserAsSystem({ email: testEmail('nobody') })
        expect(missing.ok ? missing.value : 'error').toBeNull()
        // The account can sign in with the password it was created with.
        const signedIn = await engine.signIn(
          { email, password: TEST_PASSWORD },
          browserRequest(CONTRACT_DEV_URL, { ip: freshIp() }),
        )
        expect(signedIn.ok).toBe(true)

        const slug = `sys-${created.value.id.slice(-8)}`
        const tenant = await engine.createTenantAsSystem({
          name: 'System Tenant',
          slug,
          ownerUserId: created.value.id,
        })
        expect(tenant.ok ? tenant.value.roles : null).toEqual(['owner'])
        if (!tenant.ok) return
        expect(
          code(
            await engine.createTenantAsSystem({ name: 'Dup', slug, ownerUserId: created.value.id }),
          ),
        ).toBe('VALIDATION_FAILED')
        const bySlug = await engine.findTenantAsSystem({ slug })
        expect(bySlug.ok ? bySlug.value?.tenantId : null).toBe(tenant.value.tenantId)

        // Any configured role name works (not just the engine's built-ins), and re-adding a member
        // replaces the role instead of duplicating the membership.
        const viewer = await engine.createUserAsSystem({
          email: testEmail('system-viewer'),
          password: TEST_PASSWORD,
          name: 'Viewer',
        })
        if (!viewer.ok) throw new Error('viewer not created')
        const add = (role: string) =>
          engine.addMemberAsSystem({
            tenantId: tenant.value.tenantId,
            userId: viewer.value.id,
            role,
          })
        expect((await add('viewer')).ok).toBe(true)
        expect((await add('member')).ok).toBe(true)
        const roster = await engine.listMembersAsSystem({ tenantId: tenant.value.tenantId })
        const rows = roster.ok ? [...roster.value].sort((a, b) => a.name.localeCompare(b.name)) : []
        expect(rows.map((m) => [m.name, m.roles])).toEqual([
          ['System User', ['owner']],
          ['Viewer', ['member']],
        ])
        expect(code(await engine.listMembersAsSystem({ tenantId: 'x' }))).toBe('VALIDATION_FAILED')
        expect(
          code(
            await engine.addMemberAsSystem({
              tenantId: tenant.value.tenantId,
              userId: '0190f2a0-0000-7000-8000-00000000dead',
              role: 'member',
            }),
          ),
        ).toBe('VALIDATION_FAILED')
      })

      test('tenant operations require a session', async () => {
        expect(code(await engine.listTenants(req()))).toBe('UNAUTHENTICATED')
        expect(code(await engine.switchTenant({ tenantId: 'x' }, req()))).toBe('UNAUTHENTICATED')
        expect(code(await engine.createTenant({ name: 'X', slug: 'x-nosession' }, req()))).toBe(
          'UNAUTHENTICATED',
        )
      })
    })

    test('no unexpected internal errors were reported during the contract', () => {
      expect(reported).toEqual([])
    })
  })

  describe(`IdentityEngine contract (https): ${label}`, () => {
    test('session cookies are Secure and HttpOnly when the app runs on https', async () => {
      const { engine, cleanup } = await factory({
        baseURL: CONTRACT_PROD_URL,
        deliverPasswordReset: async () => undefined,
        rateLimits: CONTRACT_RATE_LIMITS,
        trustedProxies: [TEST_PROXY],
        onUnexpectedError: () => undefined,
      })
      try {
        const result = await engine.signUp(
          { email: testEmail('secure'), password: TEST_PASSWORD, name: 'S' },
          browserRequest(CONTRACT_PROD_URL, { ip: freshIp() }),
        )
        expect(result.ok).toBe(true)
        const cookies = result.headers.getSetCookie().map(cookieAttributes)
        expect(cookies.length).toBeGreaterThan(0)
        for (const { attrs } of cookies) {
          expect(attrs.has('secure')).toBe(true)
          expect(attrs.has('httponly')).toBe(true)
        }
      } finally {
        await cleanup()
      }
    })
  })
}
