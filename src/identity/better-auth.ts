/**
 * `@strutvane/auth/better-auth`: Better Auth behind the {@link IdentityEngine} interface, with the
 * hardening of ADR-0013 always applied.
 *
 * Every user-facing call goes through Better Auth's real HTTP handler (`auth.handler`), not its
 * server-API shortcuts, so cookies and origin checks behave exactly as in production; the adapter
 * only translates requests in and results out. No Better Auth type is exported.
 *
 * Hardening (ADR-0013), each pinned by a test:
 * - **Rate limiting with shared storage**, per IP AND per account, in front of sign-in, sign-up and
 *   reset. Better Auth's own limiter is disabled: it keys on headers alone, so a rotating forged
 *   `X-Forwarded-For` bypassed it, and requests without an IP shared one bucket (spike 07).
 * - **Trusted proxies only.** The client IP comes from the socket peer (see `attachRequestMeta`),
 *   and `X-Forwarded-For` is honoured only from configured proxies. Better Auth receives the
 *   resolved IP in a private header that clients cannot inject (only allow-listed headers are
 *   forwarded). IPv6 clients count per /64. A request without a peer address counts against one
 *   shared fallback bucket (fail closed) unless `allowMissingPeer` is set.
 * - Better Auth's origin check for cookie-authenticated writes is pinned on (it otherwise
 *   switches itself off under `NODE_ENV=test`).
 * - A completed password reset also deletes every other outstanding reset token of that user
 *   (Better Auth only consumes the one used), so an older mailed link cannot reset again.
 * - `minPasswordLength: 12`, `revokeSessionsOnPasswordReset`, background tasks (constant-time
 *   reset), `onAPIError.throw` routed to the reporter (never stderr), UUID ids validated at the
 *   boundary before any database call.
 * - **Tenant and roles are re-resolved from membership on every request.** The session's active
 *   organisation is never trusted on its own: it has no foreign key, and switching tenants does not
 *   rotate the token (tripwire-tested).
 *
 * Better Auth's internal `$context.adapter` API is semi-internal: the peer dependency is pinned to
 * an exact version and every upgrade must re-run the integration suite (tripwires included).
 *
 * @module
 */

import type { Actor, Logger } from '@strutvane/framework/contracts'
import { betterAuth } from 'better-auth'
import { getSchema } from 'better-auth/db'
import { getMigrations } from 'better-auth/db/migration'
import { organization } from 'better-auth/plugins/organization'
import type { Pool } from 'pg'
import { resolveClientIp, trustedProxies } from '../http/client-ip.ts'
import { isUuid } from '../policy/schema.ts'
import {
  type Authentication,
  type ErrorReporter,
  fail,
  type IdentityEngine,
  type IdentityErrorCode,
  type IdentityResult,
  type IdentityUser,
  ok,
  type PasswordResetDelivery,
  type TenantInfo,
  type TenantMember,
  type TenantMembership,
} from './engine.ts'
import { createIdentityLimiter } from './limiter.ts'
import {
  type ActorAttributes,
  DEFAULT_RATE_LIMITS,
  type GlobalRoles,
  type IdentityRateLimits,
} from './native.ts'
import { assertRule, normalizeEmail, type RateLimitStore } from './rate-limit.ts'

/** Options for {@link createBetterAuthEngine}. */
export interface BetterAuthEngineOptions {
  /** The app's PostgreSQL pool; Better Auth tables live in the app database. */
  readonly pool: Pool
  /** Public base URL, e.g. `https://app.example.com`. `https` makes cookies `Secure`. */
  readonly baseURL: string
  /** At least 32 characters of random secret. Signs cookies and tokens. Never commit it. */
  readonly secret: string
  readonly deliverPasswordReset: PasswordResetDelivery
  /**
   * REQUIRED: where rate-limit counters live. Use `postgresRateLimitStore` (shared by every
   * process). `memoryRateLimitStore` is only correct for a single process.
   */
  readonly rateLimitStore: RateLimitStore
  readonly rateLimits?: IdentityRateLimits
  /** Proxies whose `X-Forwarded-For` may be trusted (addresses or CIDRs). Default: none. */
  readonly trustedProxies?: readonly string[]
  /**
   * When a request carries no peer address, skip the per-IP limit instead of counting it against
   * the shared fallback bucket. Default `false` (fail closed).
   */
  readonly allowMissingPeer?: boolean
  /** Receives operational warnings (e.g. requests without a peer address), once each. */
  readonly logger?: Pick<Logger, 'warn'>
  /** Unexpected failures go here (wire to the logger). */
  readonly onUnexpectedError?: ErrorReporter
  /** Extra actor attributes for ABAC rules. `emailVerified` is always set. */
  readonly actorAttributes?: ActorAttributes
  /**
   * Roles for a user acting **outside** any tenant (platform admins, apps without tenancy).
   * Default: none (deny-by-default). Tenant roles always come from membership.
   */
  readonly globalRoles?: GlobalRoles
}

/** The engine, plus schema access for Strutvane's migration planner. */
export interface BetterAuthEngine extends IdentityEngine {
  /** Better Auth's table definitions (`getSchema()`), for the Strutvane migration stream. */
  schema(): Readonly<Record<string, unknown>>
  /** Create or upgrade Better Auth's tables directly. For development and tests only. */
  migrate(): Promise<void>
  /** The SQL Better Auth itself would run against the current database (a CI cross-check for the planner). */
  compileMigrations(): Promise<string>
}

/** Request headers forwarded to Better Auth. Everything else (including spoofable IP headers) is dropped. */
const FORWARDED_HEADERS = [
  'cookie',
  'origin',
  'referer',
  'user-agent',
  'sec-fetch-site',
  'sec-fetch-mode',
  'sec-fetch-dest',
] as const

/** The private header carrying the resolved client IP. Incoming copies are never forwarded. */
const CLIENT_IP_HEADER = 'x-strutvane-client-ip'
const BASE_PATH = '/api/auth'
/** Better Auth's `verification.identifier` prefix for password-reset tokens (tripwire-tested). */
const RESET_PREFIX = 'reset-password:'
/** Longest display name accepted (the native engine's bound). */
const MAX_NAME = 200
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/
const ROLE = /^[a-z][a-z0-9_-]{0,63}$/
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/** Better Auth codes → Strutvane codes. Unknown codes fall back to the HTTP status. */
const CODE_MAP: Readonly<Record<string, IdentityErrorCode>> = {
  INVALID_EMAIL_OR_PASSWORD: 'INVALID_CREDENTIALS',
  INVALID_PASSWORD: 'INVALID_CREDENTIALS',
  USER_ALREADY_EXISTS: 'EMAIL_UNAVAILABLE',
  USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL: 'EMAIL_UNAVAILABLE',
  PASSWORD_TOO_SHORT: 'VALIDATION_FAILED',
  PASSWORD_TOO_LONG: 'VALIDATION_FAILED',
  INVALID_EMAIL: 'VALIDATION_FAILED',
  VALIDATION_ERROR: 'VALIDATION_FAILED',
  MISSING_FIELD: 'VALIDATION_FAILED',
  INVALID_TOKEN: 'INVALID_TOKEN',
  TOKEN_EXPIRED: 'INVALID_TOKEN',
  ORGANIZATION_ALREADY_EXISTS: 'VALIDATION_FAILED',
  ORGANIZATION_SLUG_ALREADY_TAKEN: 'VALIDATION_FAILED',
  // "Not a member" and "does not exist" must look identical.
  YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION: 'FORBIDDEN',
  ORGANIZATION_NOT_FOUND: 'FORBIDDEN',
  USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION: 'FORBIDDEN',
}

function codeFromStatus(status: number): IdentityErrorCode {
  if (status === 401) return 'UNAUTHENTICATED'
  if (status === 403) return 'FORBIDDEN'
  if (status === 429) return 'RATE_LIMITED'
  if (status >= 400 && status < 500) return 'VALIDATION_FAILED'
  return 'INTERNAL_ERROR'
}

function build(options: BetterAuthEngineOptions, report: ErrorReporter) {
  return betterAuth({
    database: options.pool,
    baseURL: options.baseURL,
    basePath: BASE_PATH,
    secret: options.secret,
    logger: { disabled: true },
    telemetry: { enabled: false },
    emailAndPassword: {
      enabled: true,
      minPasswordLength: 12,
      maxPasswordLength: 128,
      // Without this, a reset leaves an attacker's existing session alive.
      revokeSessionsOnPasswordReset: true,
      resetPasswordTokenExpiresIn: 60 * 30,
      sendResetPassword: async ({ user, token }) => {
        await options.deliverPasswordReset({ email: user.email, token })
      },
    },
    // Disabled on purpose: the adapter applies its own per-IP + per-account limits with a shared
    // store and trusted-proxy IP resolution (see the module docs).
    rateLimit: { enabled: false },
    advanced: {
      // Better Auth turns its origin (CSRF) check off by itself whenever it detects a test
      // environment (NODE_ENV=test). Pin it on, so security does not depend on an env variable
      // and the integration suite exercises the production behaviour.
      disableOriginCheck: false,
      // Tenant ids flow into `NULLIF(current_setting('app.tenant_id', true), '')::uuid` (ADR-0007).
      database: { generateId: 'uuid' },
      ipAddress: { ipAddressHeaders: [CLIENT_IP_HEADER] },
      // Without a background handler the reset response waits for the mailer: ~419 ms for a known
      // email vs ~12 ms for an unknown one (enumeration by timing, spike 07).
      backgroundTasks: {
        handler: (task) => {
          task.catch((error: unknown) => report('better-auth background task', error))
        },
      },
    },
    // Unexpected errors are thrown out of the handler instead of printed with console.error (which
    // bypasses the logger and redaction); `guarded()` reports them once and returns INTERNAL_ERROR.
    onAPIError: { throw: true },
    plugins: [organization({ allowUserToCreateOrganization: true, creatorRole: 'owner' })],
  })
}

interface HandlerResponse {
  readonly status: number
  readonly body: unknown
  readonly headers: Headers
}

/**
 * The session token in the request's Better Auth cookie (`<token>.<signature>`), or `undefined`.
 * Only used to revoke that exact session; a forged value matches no row.
 */
export function presentedToken(request: Request): string | undefined {
  for (const pair of (request.headers.get('cookie') ?? '').split(';')) {
    const eq = pair.indexOf('=')
    if (eq < 0) continue
    const name = pair.slice(0, eq).trim()
    if (name !== 'better-auth.session_token' && name !== '__Secure-better-auth.session_token')
      continue
    let value: string
    try {
      value = decodeURIComponent(pair.slice(eq + 1).trim())
    } catch {
      return undefined
    }
    const token = value.split('.')[0] ?? ''
    return /^[A-Za-z0-9_-]{16,128}$/.test(token) ? token : undefined
  }
  return undefined
}

/** Create the hardened Better Auth identity engine. */
export function createBetterAuthEngine(options: BetterAuthEngineOptions): BetterAuthEngine {
  if (typeof options.secret !== 'string' || options.secret.length < 32) {
    throw new TypeError(
      'Better Auth secret must be at least 32 characters (use a random value from your secret store)',
    )
  }
  if (!options.rateLimitStore)
    throw new TypeError('rateLimitStore is required (ADR-0013: shared storage)')
  const limits = { ...DEFAULT_RATE_LIMITS, ...options.rateLimits }
  for (const [name, rule] of Object.entries(limits)) assertRule(name, rule)
  const proxies = trustedProxies(options.trustedProxies)
  const report: ErrorReporter = (context, error) => {
    try {
      options.onUnexpectedError?.(context, error)
    } catch {
      // A broken reporter must never break authentication.
    }
  }
  const auth = build(options, report)
  const limited = createIdentityLimiter({
    store: options.rateLimitStore,
    proxies,
    engine: 'better-auth',
    logger: options.logger,
    ...(options.allowMissingPeer !== undefined
      ? { allowMissingPeer: options.allowMissingPeer }
      : {}),
  })

  async function call(
    method: 'GET' | 'POST',
    path: string,
    from: Request,
    body?: Readonly<Record<string, unknown>>,
  ): Promise<HandlerResponse> {
    const headers = new Headers()
    for (const name of FORWARDED_HEADERS) {
      const value = from.headers.get(name)
      if (value !== null) headers.set(name, value)
    }
    const ip = resolveClientIp(from, proxies)
    if (ip !== undefined) headers.set(CLIENT_IP_HEADER, ip)
    const init: RequestInit = { method, headers }
    if (body !== undefined) {
      headers.set('content-type', 'application/json')
      init.body = JSON.stringify(body)
    }
    const response = await auth.handler(new Request(`${options.baseURL}${BASE_PATH}${path}`, init))
    const out = new Headers()
    for (const c of response.headers.getSetCookie()) out.append('set-cookie', c)
    const text = await response.text()
    let parsed: unknown = null
    if (text.length > 0) {
      try {
        parsed = JSON.parse(text)
      } catch {
        parsed = null
      }
    }
    return { status: response.status, body: parsed, headers: out }
  }

  function toFailure<T>(res: HandlerResponse): IdentityResult<T> {
    const engineCode =
      typeof res.body === 'object' && res.body !== null && 'code' in res.body
        ? String((res.body as { code: unknown }).code)
        : ''
    // Own keys only: a body code such as "constructor" or "__proto__" must not reach the prototype.
    const mapped = Object.hasOwn(CODE_MAP, engineCode) ? CODE_MAP[engineCode] : undefined
    const code = mapped ?? codeFromStatus(res.status)
    if (code === 'INTERNAL_ERROR')
      report(`better-auth ${res.status} ${engineCode}`, new Error(`HTTP ${res.status}`))
    return fail(code, res.headers)
  }

  async function guarded<T>(
    context: string,
    run: () => Promise<IdentityResult<T>>,
  ): Promise<IdentityResult<T>> {
    try {
      return await run()
    } catch (error) {
      report(context, error)
      return fail('INTERNAL_ERROR')
    }
  }

  async function rolesIn(userId: string, tenantId: string): Promise<readonly string[] | null> {
    // Validated BEFORE Postgres: a malformed id would fail the uuid cast as a 500 (and be a probe).
    if (!isUuid(userId) || !isUuid(tenantId)) return null
    const ctx = await auth.$context
    const member = await ctx.adapter.findOne<{ role: string }>({
      model: 'member',
      where: [
        { field: 'userId', value: userId },
        { field: 'organizationId', value: tenantId },
      ],
    })
    if (!member) return null
    return member.role
      .split(',')
      .map((r) => r.trim())
      .filter((r) => r.length > 0)
  }

  async function globalRolesFor(userId: string): Promise<readonly string[]> {
    if (!options.globalRoles) return []
    const ctx = await auth.$context
    const user = await ctx.adapter.findOne<{ email: string }>({
      model: 'user',
      where: [{ field: 'id', value: userId }],
    })
    if (!user) return []
    const roles = await options.globalRoles({ userId, email: user.email })
    // Same role-name rule as tenant roles: a bad value fails closed instead of granting access.
    return roles.filter((r) => ROLE.test(r))
  }

  async function actorFrom(
    user: { id: string; emailVerified?: boolean },
    activeTenantId: unknown,
  ): Promise<Actor> {
    const tenantId =
      typeof activeTenantId === 'string' && activeTenantId.length > 0 ? activeTenantId : undefined
    const roles = tenantId ? await rolesIn(user.id, tenantId) : null
    const activeTenant = tenantId && roles ? tenantId : undefined // stale tenant: fail closed
    const extra = options.actorAttributes
      ? await options.actorAttributes({ userId: user.id, tenantId: activeTenant })
      : {}
    const attrs = Object.freeze({ ...extra, emailVerified: user.emailVerified === true })
    const base = { id: user.id, type: 'user' as const, attrs }
    return Object.freeze(
      activeTenant && roles
        ? { ...base, tenantId: activeTenant, roles: Object.freeze([...roles]) }
        : { ...base, roles: Object.freeze([...(await globalRolesFor(user.id))]) },
    )
  }

  async function session(request: Request): Promise<{
    user: { id: string; emailVerified?: boolean }
    activeTenantId: unknown
    headers: Headers
  } | null> {
    const res = await call('GET', '/get-session', request)
    if (res.status !== 200 || typeof res.body !== 'object' || res.body === null) return null
    const body = res.body as {
      user?: { id?: unknown; emailVerified?: boolean }
      session?: { activeOrganizationId?: unknown }
    }
    if (!body.user || !body.session || typeof body.user.id !== 'string' || !isUuid(body.user.id))
      return null
    return {
      user: { id: body.user.id, emailVerified: body.user.emailVerified === true },
      activeTenantId: body.session.activeOrganizationId,
      headers: res.headers,
    }
  }

  /** A request carrying a just-issued session cookie (to read the new session back). */
  function withCookies(request: Request, setCookies: Headers): Request {
    const fresh = setCookies
      .getSetCookie()
      .map((c) => c.split(';')[0] ?? '')
      .filter((c) => c.length > 0)
    const headers = new Headers(request.headers)
    if (fresh.length > 0) headers.set('cookie', fresh.join('; '))
    return new Request(request.url, { method: 'GET', headers })
  }

  const authenticate = async (request: Request): Promise<Authentication> => {
    try {
      const current = await session(request)
      if (!current) return { actor: null, headers: new Headers() }
      return {
        actor: await actorFrom(current.user, current.activeTenantId),
        headers: current.headers,
      }
    } catch (error) {
      report('authenticate', error)
      return { actor: null, headers: new Headers() }
    }
  }

  const signedIn = async (
    request: Request,
    res: HandlerResponse,
  ): Promise<IdentityResult<{ readonly actor: Actor }>> => {
    if (res.status !== 200) return toFailure(res)
    const current = await session(withCookies(request, res.headers))
    if (!current) return fail('INTERNAL_ERROR')
    return ok({ actor: await actorFrom(current.user, current.activeTenantId) }, res.headers)
  }

  const engine: BetterAuthEngine = {
    name: 'better-auth',
    schema: () => getSchema(auth.options),
    async migrate() {
      const { runMigrations } = await getMigrations(auth.options)
      await runMigrations()
    },
    async compileMigrations() {
      const { compileMigrations } = await getMigrations(auth.options)
      return compileMigrations()
    },
    authenticate,
    getActor: async (request) => (await authenticate(request)).actor,

    signUp: (input, request) =>
      guarded('signUp', async () => {
        const retry = await limited(request, 'signup', limits.signUpPerIp)
        if (retry !== undefined) return fail('RATE_LIMITED', new Headers(), retry)
        if (
          typeof input.email !== 'string' ||
          !EMAIL.test(input.email) ||
          typeof input.password !== 'string' ||
          typeof input.name !== 'string' ||
          // Same bounds as the native engine and createUserAsSystem; Better Auth accepts any name.
          input.name.length === 0 ||
          input.name.length > MAX_NAME
        ) {
          return fail('VALIDATION_FAILED')
        }
        return signedIn(
          request,
          await call('POST', '/sign-up/email', request, {
            email: input.email,
            password: input.password,
            name: input.name,
          }),
        )
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
        if (!EMAIL.test(email) || typeof input.password !== 'string')
          return fail('INVALID_CREDENTIALS')
        const result = await signedIn(
          request,
          await call('POST', '/sign-in/email', request, { email, password: input.password }),
        )
        // Session fixation (defence in depth): the session the browser presented, possibly planted
        // by an attacker, is revoked once a NEW one has been issued. Better Auth keeps it alive.
        const presented = presentedToken(request)
        if (result.ok && presented !== undefined) {
          const ctx = await auth.$context
          await ctx.adapter.deleteMany({
            model: 'session',
            where: [{ field: 'token', value: presented }],
          })
        }
        return result
      }),

    signOut: (request) =>
      guarded('signOut', async () => {
        if (!(await session(request))) return fail('UNAUTHENTICATED')
        const res = await call('POST', '/sign-out', request)
        if (res.status !== 200) return toFailure(res)
        return ok(null, res.headers)
      }),

    startPasswordReset: (input, request) =>
      guarded('startPasswordReset', async () => {
        if (typeof input.email !== 'string' || !EMAIL.test(input.email))
          return fail('VALIDATION_FAILED')
        const retry = await limited(
          request,
          'reset',
          limits.passwordReset,
          input.email,
          limits.passwordReset,
        )
        if (retry !== undefined) return fail('RATE_LIMITED', new Headers(), retry)
        const res = await call('POST', '/request-password-reset', request, { email: input.email })
        // Better Auth answers 200 for unknown emails too; only real failures surface.
        if (res.status !== 200) return toFailure(res)
        return ok(null, res.headers)
      }),

    completePasswordReset: (input, request) =>
      guarded('completePasswordReset', async () => {
        if (typeof input.token !== 'string' || input.token.length > 200)
          return fail('INVALID_TOKEN')
        // Better Auth consumes only the token used; every other reset link already mailed to the
        // user stays valid. Read the owner first (the row is gone once the reset succeeds), so the
        // siblings can be deleted afterwards, as the native engine does.
        const ctx = await auth.$context
        const pending = await ctx.adapter.findOne<{ value: string }>({
          model: 'verification',
          where: [{ field: 'identifier', value: `${RESET_PREFIX}${input.token}` }],
        })
        const res = await call('POST', '/reset-password', request, {
          token: input.token,
          newPassword: input.newPassword,
        })
        if (res.status !== 200) return toFailure(res)
        if (pending && typeof pending.value === 'string' && pending.value.length > 0)
          await ctx.adapter.deleteMany({
            model: 'verification',
            where: [
              { field: 'identifier', operator: 'starts_with', value: RESET_PREFIX },
              { field: 'value', value: pending.value },
            ],
          })
        return ok(null, res.headers)
      }),

    createTenant: (input, request) =>
      guarded('createTenant', async () => {
        if (!(await session(request))) return fail('UNAUTHENTICATED')
        if (typeof input.name !== 'string' || typeof input.slug !== 'string')
          return fail('VALIDATION_FAILED')
        const res = await call('POST', '/organization/create', request, {
          name: input.name,
          slug: input.slug,
        })
        if (res.status !== 200) return toFailure(res)
        const org = res.body as { id: string; name: string; slug: string }
        if (!isUuid(org.id)) return fail('INTERNAL_ERROR')
        return ok<TenantMembership>(
          { tenantId: org.id, name: org.name, slug: org.slug, roles: ['owner'] },
          res.headers,
        )
      }),

    listTenants: (request) =>
      guarded('listTenants', async () => {
        const current = await session(request)
        if (!current) return fail('UNAUTHENTICATED')
        const res = await call('GET', '/organization/list', request)
        if (res.status !== 200) return toFailure(res)
        const orgs = (Array.isArray(res.body) ? res.body : []) as {
          id: string
          name: string
          slug: string
        }[]
        const memberships: TenantMembership[] = []
        for (const org of orgs) {
          const roles = await rolesIn(current.user.id, org.id)
          if (roles) memberships.push({ tenantId: org.id, name: org.name, slug: org.slug, roles })
        }
        return ok<readonly TenantMembership[]>(memberships, res.headers)
      }),

    switchTenant: (input, request) =>
      guarded('switchTenant', async () => {
        const current = await session(request)
        if (!current) return fail('UNAUTHENTICATED')
        if (typeof input.tenantId !== 'string' || !isUuid(input.tenantId)) return fail('FORBIDDEN') // same as "unknown"
        // Check membership BEFORE asking Better Auth: a refused set-active can still leave the
        // requested organization in the session, which silently dropped the caller's current
        // tenant (actorFrom then saw a stale tenant and fell back to none).
        if (!(await rolesIn(current.user.id, input.tenantId))) return fail('FORBIDDEN')
        const res = await call('POST', '/organization/set-active', request, {
          organizationId: input.tenantId,
        })
        if (res.status !== 200) {
          // Any refusal (not a member, unknown tenant) is FORBIDDEN, so tenants cannot be probed.
          const failure = toFailure<{ actor: Actor }>(res)
          return !failure.ok && failure.error.code === 'INTERNAL_ERROR'
            ? failure
            : fail('FORBIDDEN', res.headers)
        }
        const after = await session(request)
        if (!after) return fail('UNAUTHENTICATED')
        return ok({ actor: await actorFrom(after.user, after.activeTenantId) }, res.headers)
      }),

    addMemberAsSystem: (input) =>
      guarded('addMemberAsSystem', async () => {
        if (
          !isUuid(input.tenantId) ||
          !isUuid(input.userId) ||
          typeof input.role !== 'string' ||
          !ROLE.test(input.role)
        ) {
          return fail('VALIDATION_FAILED')
        }
        // Written through the adapter, not `api.addMember`: Better Auth only accepts its own role
        // names there, while Strutvane roles come from config/auth.ts (viewer, accountant, …).
        const ctx = await auth.$context
        const [org, user] = await Promise.all([
          ctx.adapter.findOne({
            model: 'organization',
            where: [{ field: 'id', value: input.tenantId }],
          }),
          ctx.adapter.findOne({ model: 'user', where: [{ field: 'id', value: input.userId }] }),
        ])
        if (!org || !user) return fail('VALIDATION_FAILED')
        const where = [
          { field: 'userId', value: input.userId },
          { field: 'organizationId', value: input.tenantId },
        ]
        const existing = await ctx.adapter.findOne({ model: 'member', where })
        if (existing)
          await ctx.adapter.update({ model: 'member', where, update: { role: input.role } })
        else
          await ctx.adapter.create({
            model: 'member',
            data: {
              userId: input.userId,
              organizationId: input.tenantId,
              role: input.role,
              createdAt: new Date(),
            },
          })
        return ok(null)
      }),

    removeMemberAsSystem: (input) =>
      guarded('removeMemberAsSystem', async () => {
        if (!isUuid(input.tenantId) || !isUuid(input.userId)) return fail('VALIDATION_FAILED')
        // No session-less endpoint exists; sessions keep activeOrganizationId, but actorFrom()
        // re-checks membership on every request, so the stale tenant is dropped immediately.
        const ctx = await auth.$context
        await ctx.adapter.deleteMany({
          model: 'member',
          where: [
            { field: 'userId', value: input.userId },
            { field: 'organizationId', value: input.tenantId },
          ],
        })
        return ok(null)
      }),

    findUserAsSystem: (input) =>
      guarded('findUserAsSystem', async () => {
        if (typeof input.email !== 'string' || !EMAIL.test(input.email))
          return ok<IdentityUser | null>(null)
        const ctx = await auth.$context
        const user = await ctx.adapter.findOne<{ id: string; email: string; name: string }>({
          model: 'user',
          where: [{ field: 'email', value: normalizeEmail(input.email) }],
        })
        return ok<IdentityUser | null>(
          user ? { id: user.id, email: user.email, name: user.name } : null,
        )
      }),

    createUserAsSystem: (input) =>
      guarded('createUserAsSystem', async () => {
        if (
          typeof input.email !== 'string' ||
          !EMAIL.test(input.email) ||
          typeof input.password !== 'string' ||
          input.password.length < 12 ||
          input.password.length > 128 ||
          typeof input.name !== 'string' ||
          input.name.length === 0 ||
          input.name.length > MAX_NAME
        ) {
          return fail('VALIDATION_FAILED')
        }
        const ctx = await auth.$context
        const email = normalizeEmail(input.email)
        if (await ctx.adapter.findOne({ model: 'user', where: [{ field: 'email', value: email }] }))
          return fail('EMAIL_UNAVAILABLE')
        // Better Auth's own server-side sign-up (password hashing, credential account), then the
        // session it opens is deleted: a system-created account is not signed in anywhere.
        const result = (await auth.api.signUpEmail({
          body: { email, password: input.password, name: input.name },
        })) as { token?: string | null; user: { id: string; email: string; name: string } }
        if (typeof result.token === 'string')
          await ctx.adapter.deleteMany({
            model: 'session',
            where: [{ field: 'token', value: result.token }],
          })
        if (!isUuid(result.user.id)) return fail('INTERNAL_ERROR')
        return ok<IdentityUser>({
          id: result.user.id,
          email: result.user.email,
          name: result.user.name,
        })
      }),

    createTenantAsSystem: (input) =>
      guarded('createTenantAsSystem', async () => {
        if (
          !isUuid(input.ownerUserId) ||
          typeof input.name !== 'string' ||
          input.name.length === 0 ||
          input.name.length > 200 ||
          typeof input.slug !== 'string' ||
          !SLUG.test(input.slug)
        )
          return fail('VALIDATION_FAILED')
        const ctx = await auth.$context
        if (
          await ctx.adapter.findOne({
            model: 'organization',
            where: [{ field: 'slug', value: input.slug }],
          })
        )
          return fail('VALIDATION_FAILED')
        const org = (await auth.api.createOrganization({
          body: { name: input.name, slug: input.slug, userId: input.ownerUserId },
        })) as { id: string; name: string; slug: string } | null
        if (!org || !isUuid(org.id)) return fail('INTERNAL_ERROR')
        return ok<TenantMembership>({
          tenantId: org.id,
          name: org.name,
          slug: org.slug,
          roles: ['owner'],
        })
      }),

    findTenantAsSystem: (input) =>
      guarded('findTenantAsSystem', async () => {
        if (typeof input.slug !== 'string' || !SLUG.test(input.slug))
          return ok<TenantInfo | null>(null)
        const ctx = await auth.$context
        const org = await ctx.adapter.findOne<{ id: string; name: string; slug: string }>({
          model: 'organization',
          where: [{ field: 'slug', value: input.slug }],
        })
        return ok<TenantInfo | null>(
          org ? { tenantId: org.id, name: org.name, slug: org.slug } : null,
        )
      }),

    listMembersAsSystem: (input) =>
      guarded('listMembersAsSystem', async () => {
        if (!isUuid(input.tenantId)) return fail('VALIDATION_FAILED')
        const ctx = await auth.$context
        const rows = await ctx.adapter.findMany<{ userId: string; role: string }>({
          model: 'member',
          where: [{ field: 'organizationId', value: input.tenantId }],
        })
        const users = rows.length
          ? await ctx.adapter.findMany<{ id: string; email: string; name: string }>({
              model: 'user',
              where: [{ field: 'id', operator: 'in', value: rows.map((r) => r.userId) }],
            })
          : []
        const byId = new Map(users.map((u) => [u.id, u]))
        const out: TenantMember[] = []
        for (const r of rows) {
          const u = byId.get(r.userId)
          if (!u) continue
          const roles = r.role
            .split(',')
            .map((x) => x.trim())
            .filter((x) => x.length > 0)
          out.push({ userId: u.id, email: u.email, name: u.name, roles })
        }
        return ok<readonly TenantMember[]>(out)
      }),
  }
  return Object.freeze(engine)
}

export type { RateLimitStore } from './rate-limit.ts'
