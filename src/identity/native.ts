/**
 * The native identity engine: in-memory, single-process, dependency-free.
 *
 * **Use it for development, tests and demos**, and as the second implementation that keeps the
 * {@link IdentityEngine} seam honest (it passes the same contract suite as the Better Auth
 * adapter). Data lives in process memory and is lost on restart; use the Better Auth adapter for
 * production.
 *
 * It still follows production security rules:
 * - scrypt password hashing with per-user salts; constant-time comparison; a dummy hash for
 *   unknown emails, so timing does not reveal which emails exist;
 * - opaque 256-bit session tokens, stored only as SHA-256 hashes, revocable server-side, expiring;
 *   cookies are `HttpOnly; SameSite=Lax; Path=/`, and `__Host-` prefixed + `Secure` on https;
 * - a NEW session on every sign-in (the presented one is revoked), and token rotation on tenant
 *   switch (no session fixation);
 * - single-use, expiring, hashed reset tokens; delivery runs in the background so known and
 *   unknown emails take the same time; a completed reset revokes every session;
 * - per-IP (trusted proxies only) and per-account rate limits on sign-in, sign-up and reset;
 * - tenant and roles re-read from membership on every request.
 *
 * @module
 */
import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto'
import type { Actor } from '@strutvane/contracts'
import { uuidv7 } from '@strutvane/core'
import { resolveClientIp, type TrustedProxies, trustedProxies } from '../http/client-ip.ts'
import { isUuid } from '../policy/schema.ts'
import {
  type Authentication,
  type ErrorReporter,
  fail,
  type IdentityEngine,
  type IdentityResult,
  ok,
  type PasswordResetDelivery,
  type TenantMembership,
} from './engine.ts'
import {
  accountKey,
  assertRule,
  checkRateLimits,
  memoryRateLimitStore,
  normalizeEmail,
  type RateLimitRule,
  type RateLimitStore,
} from './rate-limit.ts'

/** Rate limits applied by identity engines. */
export interface IdentityRateLimits {
  /** Sign-in attempts per client IP. Default 10 per minute. */
  readonly signInPerIp?: RateLimitRule
  /** Sign-in attempts per account (email). Default 20 per 15 minutes. */
  readonly signInPerAccount?: RateLimitRule
  /** Sign-ups per client IP. Default 10 per hour. */
  readonly signUpPerIp?: RateLimitRule
  /** Password-reset requests per IP and per account. Default 5 per 15 minutes. */
  readonly passwordReset?: RateLimitRule
}

/** Defaults for {@link IdentityRateLimits}. */
export const DEFAULT_RATE_LIMITS: Required<IdentityRateLimits> = Object.freeze({
  signInPerIp: { windowSeconds: 60, max: 10 },
  signInPerAccount: { windowSeconds: 900, max: 20 },
  signUpPerIp: { windowSeconds: 3600, max: 10 },
  passwordReset: { windowSeconds: 900, max: 5 },
})

/** Extra actor attributes for ABAC rules (department, region…), resolved per request. */
export type ActorAttributes = (input: {
  readonly userId: string
  readonly tenantId: string | undefined
}) => Promise<Readonly<Record<string, unknown>>> | Readonly<Record<string, unknown>>

/** Options for {@link createNativeEngine}. */
export interface NativeEngineOptions {
  /** Public base URL, e.g. `https://app.example.com`. `https` makes cookies `Secure` and `__Host-`. */
  readonly baseURL: string
  readonly deliverPasswordReset: PasswordResetDelivery
  readonly rateLimits?: IdentityRateLimits
  /** Where counters live. Default: an in-memory store (fine, since this engine is single-process). */
  readonly rateLimitStore?: RateLimitStore
  /** Proxies whose `X-Forwarded-For` may be trusted (addresses or CIDRs). Default: none. */
  readonly trustedProxies?: readonly string[]
  /** Session lifetime. Default 7 days. */
  readonly sessionTtlSeconds?: number
  /** scrypt cost (a power of two, at least 2^14). Default 2^15. Tests may lower it to 2^14. */
  readonly scryptCost?: number
  /** Unexpected failures go here (wire to the logger). */
  readonly onUnexpectedError?: ErrorReporter
  /** Extra actor attributes. `emailVerified` is always set. */
  readonly actorAttributes?: ActorAttributes
  /** Clock (ms), for tests. */
  readonly now?: () => number
}

interface User {
  readonly id: string
  readonly email: string
  readonly name: string
  salt: Buffer
  hash: Buffer
}

interface Session {
  readonly userId: string
  activeTenantId: string | undefined
  readonly expiresAt: number
}

interface Tenant {
  readonly id: string
  readonly name: string
  readonly slug: string
}

const MIN_PASSWORD = 12
const MAX_PASSWORD = 128
const RESET_TTL_MS = 30 * 60 * 1000
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const ROLE = /^[a-z][a-z0-9_-]{0,63}$/
const TOKEN = /^[A-Za-z0-9_-]{43}$/

const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex')
const token = (): string => randomBytes(32).toString('base64url')
const isText = (value: unknown, max: number): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= max

/** Create the native in-memory engine. */
export function createNativeEngine(options: NativeEngineOptions): IdentityEngine {
  const now = options.now ?? Date.now
  const secure = options.baseURL.startsWith('https://')
  const cookieName = secure ? '__Host-sv_session' : 'sv_session'
  const ttlMs = (options.sessionTtlSeconds ?? 7 * 24 * 3600) * 1000
  const cost = options.scryptCost ?? 2 ** 15
  if (!Number.isInteger(Math.log2(cost)) || cost < 2 ** 14) {
    throw new RangeError('scryptCost must be a power of two of at least 2^14')
  }
  const limits = { ...DEFAULT_RATE_LIMITS, ...options.rateLimits }
  for (const [name, rule] of Object.entries(limits)) assertRule(name, rule)
  const store = options.rateLimitStore ?? memoryRateLimitStore({ now })
  const proxies: TrustedProxies = trustedProxies(options.trustedProxies)
  const report: ErrorReporter = (context, error) => {
    try {
      options.onUnexpectedError?.(context, error)
    } catch {
      // A broken reporter must never break authentication.
    }
  }

  const users = new Map<string, User>()
  const byEmail = new Map<string, string>()
  const sessions = new Map<string, Session>() // sha256(token) → session
  const tenants = new Map<string, Tenant>()
  const members = new Map<string, Map<string, readonly string[]>>() // tenantId → userId → roles
  const resetTokens = new Map<string, { userId: string; expiresAt: number }>() // sha256(token) → entry
  const dummySalt = randomBytes(16)

  const hashPassword = (password: string, salt: Buffer): Promise<Buffer> =>
    new Promise((resolve, reject) => {
      scryptCallback(
        password,
        salt,
        64,
        { N: cost, r: 8, p: 1, maxmem: 256 * cost * 8 },
        (error, key) => (error ? reject(error) : resolve(key)),
      )
    })

  const cookie = (value: string, maxAgeSeconds: number): Headers => {
    const parts = [
      `${cookieName}=${value}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Lax',
      `Max-Age=${maxAgeSeconds}`,
    ]
    if (secure) parts.push('Secure')
    const headers = new Headers()
    headers.append('set-cookie', parts.join('; '))
    return headers
  }

  const presentedToken = (request: Request): string | undefined => {
    for (const pair of (request.headers.get('cookie') ?? '').split(';')) {
      const eq = pair.indexOf('=')
      if (eq > 0 && pair.slice(0, eq).trim() === cookieName) {
        const value = pair.slice(eq + 1).trim()
        return TOKEN.test(value) ? value : undefined
      }
    }
    return undefined
  }

  const current = (request: Request): { key: string; session: Session } | undefined => {
    const t = presentedToken(request)
    if (!t) return undefined
    const key = sha256(t)
    const session = sessions.get(key)
    if (!session) return undefined
    if (session.expiresAt <= now() || !users.has(session.userId)) {
      sessions.delete(key)
      return undefined
    }
    return { key, session }
  }

  const actorFor = async (session: Session): Promise<Actor> => {
    // Re-read membership every time: a removed member loses the tenant immediately.
    const tenantId = session.activeTenantId
    const roles = tenantId ? members.get(tenantId)?.get(session.userId) : undefined
    const activeTenant = tenantId && roles ? tenantId : undefined
    const extra = options.actorAttributes
      ? await options.actorAttributes({ userId: session.userId, tenantId: activeTenant })
      : {}
    const attrs = Object.freeze({ ...extra, emailVerified: false })
    const base = { id: session.userId, type: 'user' as const, attrs }
    return Object.freeze(
      activeTenant && roles
        ? { ...base, tenantId: activeTenant, roles: Object.freeze([...roles]) }
        : { ...base, roles: Object.freeze([]) },
    )
  }

  const newSession = (
    userId: string,
    activeTenantId?: string,
  ): { headers: Headers; session: Session } => {
    const t = token()
    const session: Session = { userId, activeTenantId, expiresAt: now() + ttlMs }
    sessions.set(sha256(t), session)
    return { headers: cookie(t, Math.floor(ttlMs / 1000)), session }
  }

  const limited = async (
    request: Request,
    scope: string,
    ipRule: RateLimitRule,
    email?: string,
    accountRule?: RateLimitRule,
  ) => {
    const ip = resolveClientIp(request, proxies)
    const checks: [string, RateLimitRule][] = []
    // No usable IP (no adapter attached the peer address): skip the IP limit rather than putting
    // every such request into ONE shared bucket (spike 07 finding). The account limit still applies.
    if (ip !== undefined) checks.push([`${scope}:ip:${ip}`, ipRule])
    if (email !== undefined && accountRule) checks.push([accountKey(scope, email), accountRule])
    const result = await checkRateLimits(store, checks)
    return result.limited ? result.retryAfterSeconds : undefined
  }

  const guarded = async <T>(
    context: string,
    run: () => Promise<IdentityResult<T>>,
  ): Promise<IdentityResult<T>> => {
    try {
      return await run()
    } catch (error) {
      report(context, error)
      return fail('INTERNAL_ERROR')
    }
  }

  const passwordOk = (password: unknown): password is string =>
    typeof password === 'string' &&
    password.length >= MIN_PASSWORD &&
    password.length <= MAX_PASSWORD

  const authenticate = async (request: Request): Promise<Authentication> => {
    try {
      const c = current(request)
      return { actor: c ? await actorFor(c.session) : null, headers: new Headers() }
    } catch (error) {
      report('authenticate', error)
      return { actor: null, headers: new Headers() }
    }
  }

  return Object.freeze({
    name: 'native',
    authenticate,
    getActor: async (request: Request) => (await authenticate(request)).actor,

    signUp: (input, request) =>
      guarded('signUp', async () => {
        const retry = await limited(request, 'signup', limits.signUpPerIp)
        if (retry !== undefined) return fail('RATE_LIMITED', new Headers(), retry)
        if (
          !isText(input.email, 254) ||
          !EMAIL.test(input.email) ||
          !passwordOk(input.password) ||
          !isText(input.name, 200)
        ) {
          return fail('VALIDATION_FAILED')
        }
        const key = normalizeEmail(input.email)
        if (byEmail.has(key)) return fail('EMAIL_UNAVAILABLE')
        const salt = randomBytes(16)
        const user: User = {
          id: uuidv7(),
          email: key,
          name: input.name,
          salt,
          hash: await hashPassword(input.password, salt),
        }
        // Re-check after the await: two concurrent sign-ups for one email must not both win.
        if (byEmail.has(key)) return fail('EMAIL_UNAVAILABLE')
        users.set(user.id, user)
        byEmail.set(key, user.id)
        const created = newSession(user.id)
        return ok({ actor: await actorFor(created.session) }, created.headers)
      }),

    signIn: (input, request) =>
      guarded('signIn', async () => {
        const email = typeof input.email === 'string' ? input.email : ''
        const retry = await limited(
          request,
          'signin',
          limits.signInPerIp,
          email,
          limits.signInPerAccount,
        )
        if (retry !== undefined) return fail('RATE_LIMITED', new Headers(), retry)
        if (typeof input.password !== 'string' || input.password.length > MAX_PASSWORD)
          return fail('INVALID_CREDENTIALS')
        const user = users.get(byEmail.get(normalizeEmail(email)) ?? '')
        // Hash even for unknown emails, so response time does not reveal which emails exist.
        const candidate = await hashPassword(input.password, user?.salt ?? dummySalt)
        if (!user || !timingSafeEqual(candidate, user.hash)) return fail('INVALID_CREDENTIALS')
        // Session fixation: never keep a session the client presented; always issue a new one.
        const presented = current(request)
        if (presented) sessions.delete(presented.key)
        const created = newSession(user.id)
        return ok({ actor: await actorFor(created.session) }, created.headers)
      }),

    signOut: (request) =>
      guarded('signOut', async () => {
        const c = current(request)
        if (!c) return fail('UNAUTHENTICATED')
        sessions.delete(c.key)
        return ok(null, cookie('', 0))
      }),

    startPasswordReset: (input, request) =>
      guarded('startPasswordReset', async () => {
        if (!isText(input.email, 254) || !EMAIL.test(input.email)) return fail('VALIDATION_FAILED')
        const retry = await limited(
          request,
          'reset',
          limits.passwordReset,
          input.email,
          limits.passwordReset,
        )
        if (retry !== undefined) return fail('RATE_LIMITED', new Headers(), retry)
        const user = users.get(byEmail.get(normalizeEmail(input.email)) ?? '')
        if (user) {
          const t = token()
          resetTokens.set(sha256(t), { userId: user.id, expiresAt: now() + RESET_TTL_MS })
          // Background delivery: the response must not wait for the mailer (timing enumeration).
          Promise.resolve()
            .then(() => options.deliverPasswordReset({ email: user.email, token: t }))
            .catch((error: unknown) => report('deliverPasswordReset', error))
        }
        return ok(null)
      }),

    completePasswordReset: (input) =>
      guarded('completePasswordReset', async () => {
        if (typeof input.token !== 'string' || input.token.length > 200)
          return fail('INVALID_TOKEN')
        const key = sha256(input.token)
        const entry = resetTokens.get(key)
        if (!entry || entry.expiresAt <= now()) {
          resetTokens.delete(key)
          return fail('INVALID_TOKEN')
        }
        if (!passwordOk(input.newPassword)) return fail('VALIDATION_FAILED')
        resetTokens.delete(key) // single use
        const user = users.get(entry.userId)
        if (!user) return fail('INVALID_TOKEN')
        const salt = randomBytes(16)
        user.hash = await hashPassword(input.newPassword, salt)
        user.salt = salt
        for (const [sid, session] of sessions) if (session.userId === user.id) sessions.delete(sid)
        return ok(null)
      }),

    createTenant: (input, request) =>
      guarded('createTenant', async () => {
        const c = current(request)
        if (!c) return fail('UNAUTHENTICATED')
        if (!isText(input.name, 200) || typeof input.slug !== 'string' || !SLUG.test(input.slug))
          return fail('VALIDATION_FAILED')
        if ([...tenants.values()].some((t) => t.slug === input.slug))
          return fail('VALIDATION_FAILED')
        const tenant: Tenant = { id: uuidv7(), name: input.name, slug: input.slug }
        tenants.set(tenant.id, tenant)
        members.set(tenant.id, new Map([[c.session.userId, ['owner']]]))
        c.session.activeTenantId = tenant.id
        return ok<TenantMembership>({
          tenantId: tenant.id,
          name: tenant.name,
          slug: tenant.slug,
          roles: ['owner'],
        })
      }),

    listTenants: (request) =>
      guarded('listTenants', async () => {
        const c = current(request)
        if (!c) return fail('UNAUTHENTICATED')
        const result: TenantMembership[] = []
        for (const [tenantId, roster] of members) {
          const roles = roster.get(c.session.userId)
          const tenant = tenants.get(tenantId)
          if (roles && tenant)
            result.push({ tenantId, name: tenant.name, slug: tenant.slug, roles: [...roles] })
        }
        return ok<readonly TenantMembership[]>(result)
      }),

    switchTenant: (input, request) =>
      guarded('switchTenant', async () => {
        const c = current(request)
        if (!c) return fail('UNAUTHENTICATED')
        const tenantId = typeof input.tenantId === 'string' ? input.tenantId.toLowerCase() : ''
        if (!isUuid(tenantId) || !members.get(tenantId)?.has(c.session.userId))
          return fail('FORBIDDEN')
        // Rotate the token when privileges change, so a token captured before the switch cannot
        // ride along into the new tenant.
        sessions.delete(c.key)
        const rotated = newSession(c.session.userId, tenantId)
        return ok({ actor: await actorFor(rotated.session) }, rotated.headers)
      }),

    addMemberAsSystem: (input) =>
      guarded('addMemberAsSystem', async () => {
        const roster = isUuid(input.tenantId)
          ? members.get(input.tenantId.toLowerCase())
          : undefined
        if (
          !roster ||
          !isUuid(input.userId) ||
          !users.has(input.userId) ||
          typeof input.role !== 'string' ||
          !ROLE.test(input.role)
        ) {
          return fail('VALIDATION_FAILED')
        }
        roster.set(input.userId, [input.role])
        return ok(null)
      }),

    removeMemberAsSystem: (input) =>
      guarded('removeMemberAsSystem', async () => {
        if (!isUuid(input.tenantId) || !isUuid(input.userId)) return fail('VALIDATION_FAILED')
        members.get(input.tenantId.toLowerCase())?.delete(input.userId)
        return ok(null)
      }),
  } satisfies IdentityEngine)
}
