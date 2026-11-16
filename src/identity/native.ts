/**
 * The native identity engine: Strutvane's own engine (ADR-0023), the default for every app.
 *
 * This module adapts the auth core in `src/engine` (ported from spike 20: passwords, verification,
 * reset, email links, TOTP, passkeys, sessions, tokens, teams, impersonation) to the
 * {@link IdentityEngine} contract, so it passes the same contract suite as any other engine and
 * the provider, the middleware and the tenancy layer stay engine-agnostic.
 *
 * - **Tenants are teams.** A tenant's creator is its `admin`; tenant roles come from membership,
 *   re-read on every request, never mixed with global roles.
 * - **Storage is a port.** Pass the store for your database (`postgresAuthStore`,
 *   `sqliteAuthStore`); the default in-memory store is for tests and demos only.
 * - **Secrets are never stored as values.** Session ids, reset tokens and every other secret are
 *   kept as keyed digests (HMAC under `APP_KEY`); cookies are `__Host-` on https.
 * - **Fail closed.** An unexpected error is reported (never with secrets) and answers
 *   `internal_error`; `authenticate` answers "anonymous".
 *
 * The full engine (two-factor, passkeys, tokens…) is on `engine.auth`, for the provider's routes
 * and for apps that call services directly.
 *
 * @module
 */
import { randomBytes } from 'node:crypto'
import type { Actor, Logger } from '@strutvane/framework/contracts'
import { type Auth, createAuth } from '../engine/auth.ts'
import { type AuthConfigInput, defineAuthConfig, type RateLimits } from '../engine/config.ts'
import { AuthError, type AuthErrorCode } from '../engine/errors.ts'
import { fetchCookieJar } from '../engine/http/cookies.ts'
import { createScryptHasher, type PasswordHasher } from '../engine/password/hasher.ts'
import type { Clock } from '../engine/ports/clock.ts'
import type { AuthRequest } from '../engine/ports/cookies.ts'
import type { CounterStore } from '../engine/ports/counter-store.ts'
import type { AuthEventSink } from '../engine/ports/events.ts'
import type { AuthMail, AuthMailer } from '../engine/ports/mailer.ts'
import type { AuthStore } from '../engine/ports/store.ts'
import { memoryAuthStore, memoryCounterStore } from '../engine/store/memory.ts'
import { resolveClientIp, trustedProxies } from '../http/client-ip.ts'
import { requestMeta } from '../http/request-meta.ts'
import {
  type ActorAttributes,
  type Authentication,
  type ErrorReporter,
  fail,
  type GlobalRoles,
  type IdentityEngine,
  type IdentityErrorCode,
  type IdentityRateLimits,
  type IdentityResult,
  type IdentityUser,
  ok,
  type PasswordResetDelivery,
  type TenantMembership,
} from './engine.ts'

/** Options for {@link createNativeEngine}. Only `baseURL` is required. */
export interface NativeEngineOptions {
  /** Public base URL, e.g. `https://app.example.com`. `https` makes every cookie `__Host-` + `Secure`. */
  readonly baseURL: string
  /**
   * `config/auth.ts` engine settings: features, passwords, sessions, links, two-factor, tokens,
   * roles, passkeys, limits, lockout. Defaults suit the identity contract: registration and
   * teams on (the provider decides which routes exist), personal teams off.
   */
  readonly config?: Omit<AuthConfigInput, 'appUrl'>
  /** Where identity data lives. Default: in memory (lost on restart; tests and demos). */
  readonly store?: AuthStore
  /** Shared rate-limit counters (the same database or cache for every instance). Default: memory. */
  readonly counters?: CounterStore
  /**
   * `APP_KEY` (`base64:` + 32 bytes). Every keyed digest and signature derives from it. Required
   * with a persistent store (a random key would sign everyone out and break every link on restart).
   */
  readonly appKey?: string
  /** Sends the engine's mails (queue them). Password-reset mails also go to `deliverPasswordReset`. */
  readonly mailer?: AuthMailer
  /** v1 hook: receives the reset token of every password-reset mail (`{ email, token }`). */
  readonly deliverPasswordReset?: PasswordResetDelivery
  /** Audit events (closed shapes: ids and enums only). The provider forwards them to the event bus. */
  readonly events?: AuthEventSink
  /** The contract's limits, mapped onto the engine's (`config.limits` wins where both are set). */
  readonly rateLimits?: IdentityRateLimits
  /** Proxies whose `X-Forwarded-For` may be trusted (addresses or CIDRs). Default: none. */
  readonly trustedProxies?: readonly string[]
  /** Operational warnings (a request without a peer address), each once. */
  readonly logger?: Pick<Logger, 'warn'>
  /** Unexpected failures (wire to the logger). Receives a context string and the error. */
  readonly onUnexpectedError?: ErrorReporter
  /** Extra actor attributes for ABAC rules. `emailVerified` is always set by the engine. */
  readonly actorAttributes?: ActorAttributes
  /**
   * Roles outside any tenant. Default: the user's stored global roles (`user_roles`), else
   * `defaultRoles`. A function here replaces both (v1 compatibility). Names that are not role
   * names are dropped (fail closed).
   */
  readonly globalRoles?: GlobalRoles
  /** Roles of a user with no stored global roles (`config/auth.ts` `defaultRoles`). Default: none. */
  readonly defaultRoles?: readonly string[]
  /** Password hasher. Default: scrypt `ln=17`; `scryptCost` lowers it for tests. */
  readonly hasher?: PasswordHasher
  /** v1 option: scrypt N (a power of two, at least 2^14). Ignored when `hasher` is given. */
  readonly scryptCost?: number
  /** v1 option: session lifetime in seconds (idle and absolute). Prefer `config.sessions`. */
  readonly sessionTtlSeconds?: number
  readonly clock?: Clock
  /** v1 option: the clock as a function. */
  readonly now?: () => number
}

/** The native engine: the contract, plus the full auth core for routes and services. */
export interface NativeIdentityEngine extends IdentityEngine {
  /** The auth core this engine runs on (two-factor, passkeys, tokens, teams, impersonation…). */
  readonly auth: Auth
  /** The role a tenant's creator gets (`admin`). */
  readonly ownerRole: string
}

const ROLE = /^[a-z][a-z0-9_-]{0,63}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const OWNER_ROLE = 'admin'

/** Engine error → contract code. Anything not listed is unexpected (`internal_error`). */
const CODE_MAP: Partial<Record<AuthErrorCode, IdentityErrorCode>> = {
  validation_failed: 'validation_failed',
  weak_password: 'validation_failed',
  invalid_credentials: 'invalid_credentials',
  email_taken: 'email_unavailable',
  rate_limited: 'rate_limited',
  invalid_token: 'invalid_token',
  invalid_signature: 'invalid_token',
  signature_expired: 'invalid_token',
  unauthenticated: 'unauthenticated',
  email_not_verified: 'email_not_verified',
  forbidden: 'forbidden',
  // Tenants the caller is not in answer not_found in the engine; the contract wants forbidden.
  not_found: 'forbidden',
  last_admin: 'validation_failed',
  conflict: 'validation_failed',
  password_confirmation_required: 'forbidden',
}

/** A correct password for an account with two-factor on: the sign-in waits for the challenge. */
class TwoFactorPending extends Error {
  override readonly name = 'TwoFactorPending'
}

/** Map the contract's limits onto the engine's (v1 used one rule for both sides of reset). */
function engineLimits(limits: IdentityRateLimits | undefined): Partial<RateLimits> {
  if (!limits) return {}
  const out: { -readonly [K in keyof RateLimits]?: RateLimits[K] } = {}
  if (limits.signInPerIp) out.loginPerIp = limits.signInPerIp
  if (limits.signInPerAccount) out.loginPerAccount = limits.signInPerAccount
  if (limits.signUpPerIp) out.registerPerIp = limits.signUpPerIp
  if (limits.passwordReset) {
    out.resetPerIp = limits.passwordReset
    out.resetPerAccount = limits.passwordReset
  }
  return out
}

function hasherFor(options: NativeEngineOptions): PasswordHasher {
  if (options.hasher) return options.hasher
  if (options.scryptCost === undefined) return createScryptHasher()
  const logN = Math.log2(options.scryptCost)
  if (!Number.isInteger(logN) || logN < 14)
    throw new RangeError('scryptCost must be a power of two of at least 2^14')
  return createScryptHasher({ params: { logN, r: 8, p: 1 } })
}

/** The reset token at the end of a password-reset link (`…/reset-password/<token>`). */
function resetToken(mail: AuthMail): string | undefined {
  if (mail.kind !== 'password-reset') return undefined
  return new URL(mail.url).pathname.split('/').at(-1)
}

const toUser = (u: {
  readonly id: string
  readonly email: string
  readonly name: string
}): IdentityUser => Object.freeze({ id: u.id, email: u.email, name: u.name })

const membership = (team: {
  readonly id: string
  readonly name: string
  readonly slug: string | null
  readonly role: string
}): TenantMembership =>
  Object.freeze({ tenantId: team.id, name: team.name, slug: team.slug ?? '', roles: [team.role] })

/** System operations take ids from seeders and admins: refuse anything that is not one. */
function assertIds(...ids: unknown[]): void {
  if (ids.some((id) => typeof id !== 'string' || !UUID.test(id)))
    throw new AuthError('validation_failed')
}

/**
 * Create the native engine.
 *
 * @example
 * ```ts
 * const engine = createNativeEngine({
 *   baseURL: 'https://app.example.com',
 *   appKey: process.env.APP_KEY,
 *   store: postgresAuthStore(pgPoolClient(pool)),
 *   counters: postgresCounterStore(pgPoolClient(pool)),
 *   config: { features: { twoFactor: true, emailVerification: true } },
 * })
 * const { actor } = await engine.authenticate(request)
 * ```
 */
export function createNativeEngine(options: NativeEngineOptions): NativeIdentityEngine {
  if (options.store !== undefined && options.appKey === undefined)
    throw new TypeError(
      'native identity engine: a persistent store needs `appKey` (APP_KEY); a random key would sign everyone out on restart',
    )
  const proxies = trustedProxies(options.trustedProxies)
  const clock: Clock | undefined = options.clock ?? (options.now ? { now: options.now } : undefined)
  const report: ErrorReporter = (context, error) => {
    try {
      options.onUnexpectedError?.(context, error)
    } catch {
      // A broken reporter must never break authentication.
    }
  }
  const input = options.config ?? {}
  const ttl = options.sessionTtlSeconds
  if (ttl !== undefined && (!Number.isFinite(ttl) || ttl <= 0))
    throw new RangeError('sessionTtlSeconds must be a positive number')
  const config = defineAuthConfig({
    ...input,
    appUrl: options.baseURL,
    features: { registration: true, teams: true, ...input.features },
    teams: { personal: false, ...input.teams },
    limits: { ...engineLimits(options.rateLimits), ...input.limits },
    ...(ttl !== undefined
      ? { sessions: { ...input.sessions, idleMinutes: ttl / 60, absoluteHours: ttl / 3600 } }
      : {}),
  })
  const mailer: AuthMailer = {
    async send(mail) {
      const token = resetToken(mail)
      if (token !== undefined && options.deliverPasswordReset)
        await options.deliverPasswordReset({ email: mail.to, token })
      if (options.mailer) await options.mailer.send(mail)
    },
  }
  const auth = createAuth({
    config,
    store: options.store ?? memoryAuthStore(),
    counters: options.counters ?? memoryCounterStore(clock),
    appKey: options.appKey ?? `base64:${randomBytes(32).toString('base64')}`,
    mailer,
    events: options.events ?? { emit: () => undefined },
    hasher: hasherFor(options),
    ...(clock ? { clock } : {}),
    logger: {
      warn: (message, context) => {
        try {
          options.logger?.warn(message, context)
        } catch {
          // A broken logger must not break auth.
        }
      },
    },
  })
  const defaultRoles = Object.freeze((options.defaultRoles ?? []).filter((r) => ROLE.test(r)))

  let warnedNoPeer = false
  /** The engine's view of a request: cookies (collecting Set-Cookie) and the resolved client IP. */
  const context = (request: Request): { readonly req: AuthRequest; headers(): Headers } => {
    const jar = fetchCookieJar(request, { secure: config.secureCookies })
    const ip = resolveClientIp(request, proxies)
    if (ip === undefined && requestMeta(request)?.remoteAddress === undefined && !warnedNoPeer) {
      warnedNoPeer = true
      try {
        options.logger?.warn(
          'auth: a request reached the identity engine without a client address; per-IP rate limits now share one fallback bucket. Attach the socket peer address (attachRequestMeta, or the http.onRequest clientAddress).',
          { engine: 'native' },
        )
      } catch {
        // A broken logger must not break auth.
      }
    }
    const userAgent = request.headers.get('user-agent')
    return {
      req: {
        cookies: jar,
        ip,
        ...(userAgent !== null ? { userAgent: userAgent.slice(0, 512) } : {}),
      },
      headers() {
        const headers = new Headers()
        jar.applyTo(headers)
        return headers
      },
    }
  }

  const globalRolesFor = async (user: {
    readonly id: string
    readonly email: string
    readonly roles: readonly string[]
  }): Promise<readonly string[]> => {
    if (options.globalRoles) {
      const roles = await options.globalRoles({ userId: user.id, email: user.email })
      return roles.filter((r) => ROLE.test(r))
    }
    return user.roles.length > 0 ? user.roles : defaultRoles
  }

  const actorFor = async (req: AuthRequest): Promise<Actor | null> => {
    const state = await auth.state(req)
    if (!state) return null
    const tenantId = state.team?.id
    const extra = options.actorAttributes
      ? await options.actorAttributes({ userId: state.user.id, tenantId })
      : {}
    const attrs = Object.freeze({ ...extra, emailVerified: state.user.emailVerified })
    const roles = state.team
      ? [state.team.role]
      : await globalRolesFor({ id: state.user.id, email: state.user.email, roles: state.roles })
    const base = {
      id: state.user.id,
      type: 'user' as const,
      attrs,
      roles: Object.freeze([...roles]),
    }
    return Object.freeze(tenantId !== undefined ? { ...base, tenantId } : base)
  }

  /** Run one operation: map engine errors to contract codes, report anything else. */
  const guarded = async <T>(
    name: string,
    headers: () => Headers,
    run: () => Promise<T>,
  ): Promise<IdentityResult<T>> => {
    try {
      const value = await run()
      return ok(value, headers())
    } catch (error) {
      if (error instanceof TwoFactorPending) return fail('two_factor_required', headers())
      if (error instanceof AuthError) {
        const code = CODE_MAP[error.code]
        if (code !== undefined) return fail(code, headers(), error.retryAfterSeconds)
      }
      report(name, error)
      return fail('internal_error', headers())
    }
  }

  const signedInActor = async (req: AuthRequest): Promise<{ readonly actor: Actor }> => {
    const actor = await actorFor(req)
    if (!actor) throw new AuthError('unauthenticated')
    return { actor }
  }

  const system = <T>(name: string, run: () => Promise<T>): Promise<IdentityResult<T>> =>
    guarded(name, () => new Headers(), run)

  const engine: NativeIdentityEngine = {
    name: 'native',
    auth,
    ownerRole: OWNER_ROLE,

    async authenticate(request): Promise<Authentication> {
      const ctx = context(request)
      try {
        return { actor: await actorFor(ctx.req), headers: ctx.headers() }
      } catch (error) {
        report('authenticate', error)
        return { actor: null, headers: ctx.headers() }
      }
    },

    async getActor(request) {
      return (await engine.authenticate(request)).actor
    },

    async signUp(input, request) {
      const ctx = context(request)
      return guarded('signUp', ctx.headers, async () => {
        const result = await auth.passwords.register(ctx.req, {
          name: input.name,
          email: input.email,
          password: input.password,
        })
        // With email verification on, sign-up signs nobody in and must not reveal whether the
        // address was taken; the contract has no "check your inbox" outcome, so it is
        // `email_not_verified` for both (the engine's routes answer `verification-sent`).
        if (result.status !== 'signed-in') throw new AuthError('email_not_verified')
        return signedInActor(ctx.req)
      })
    },

    async signIn(input, request) {
      const ctx = context(request)
      return guarded('signIn', ctx.headers, async () => {
        // Any bad input is the one sign-in failure: a separate `validation_failed` would tell a
        // prober which inputs the engine even looks at.
        const result = await auth.passwords
          .login(ctx.req, { email: input.email, password: input.password })
          .catch((error: unknown) => {
            if (error instanceof AuthError && error.code === 'validation_failed')
              throw new AuthError('invalid_credentials')
            throw error
          })
        if (result.status !== 'signed-in') throw new TwoFactorPending()
        return signedInActor(ctx.req)
      })
    },

    async signOut(request) {
      const ctx = context(request)
      return guarded('signOut', ctx.headers, async () => {
        if (!(await auth.state(ctx.req)) && !(await auth.pendingChallenge(ctx.req)))
          throw new AuthError('unauthenticated')
        await auth.passwords.logout(ctx.req)
        return null
      })
    },

    async startPasswordReset(input, request) {
      const ctx = context(request)
      return guarded('startPasswordReset', ctx.headers, async () => {
        await auth.passwordReset.request(ctx.req, { email: input.email })
        return null
      })
    },

    async completePasswordReset(input, request) {
      const ctx = context(request)
      return guarded('completePasswordReset', ctx.headers, async () => {
        await auth.passwordReset.reset(ctx.req, { token: input.token, password: input.newPassword })
        return null
      })
    },

    async createTenant(input, request) {
      const ctx = context(request)
      return guarded('createTenant', ctx.headers, async () =>
        membership(await auth.teams.create(ctx.req, { name: input.name, slug: input.slug })),
      )
    },

    async listTenants(request) {
      const ctx = context(request)
      return guarded('listTenants', ctx.headers, async () =>
        (await auth.teams.list(ctx.req)).map(membership),
      )
    },

    async switchTenant(input, request) {
      const ctx = context(request)
      return guarded('switchTenant', ctx.headers, async () => {
        if (!(await auth.state(ctx.req))) throw new AuthError('unauthenticated')
        const teamId =
          typeof input.tenantId === 'string' ? input.tenantId.toLowerCase() : input.tenantId
        await auth.teams.switch(ctx.req, { teamId })
        return signedInActor(ctx.req)
      })
    },

    addMemberAsSystem: (input) =>
      system('addMemberAsSystem', async () => {
        assertIds(input.tenantId, input.userId)
        const outcome = await auth.system.setMember({
          teamId: input.tenantId.toLowerCase(),
          userId: input.userId.toLowerCase(),
          role: input.role,
        })
        if (outcome !== 'ok') throw new AuthError('validation_failed')
        return null
      }),

    removeMemberAsSystem: (input) =>
      system('removeMemberAsSystem', async () => {
        assertIds(input.tenantId, input.userId)
        const outcome = await auth.system.removeMember({
          teamId: input.tenantId.toLowerCase(),
          userId: input.userId.toLowerCase(),
        })
        if (outcome !== 'ok') throw new AuthError('validation_failed')
        return null
      }),

    findUserAsSystem: (input) =>
      system('findUserAsSystem', async () => {
        const user = await auth.system.findUserByEmail(input.email)
        return user ? toUser(user) : null
      }),

    createUserAsSystem: (input) =>
      system('createUserAsSystem', async () => {
        if (typeof input.name !== 'string' || typeof input.password !== 'string')
          throw new AuthError('validation_failed')
        return toUser(
          await auth.system.createUser({
            name: input.name,
            email: input.email,
            password: input.password,
          }),
        )
      }),

    createTenantAsSystem: (input) =>
      system('createTenantAsSystem', async () => {
        assertIds(input.ownerUserId)
        if (typeof input.slug !== 'string') throw new AuthError('validation_failed')
        const team = await auth.system.createTeam({
          name: input.name,
          slug: input.slug,
          ownerId: input.ownerUserId.toLowerCase(),
        })
        return membership({ ...team, role: OWNER_ROLE })
      }),

    findTenantAsSystem: (input) =>
      system('findTenantAsSystem', async () => {
        const team = await auth.system.findTeamBySlug(input.slug)
        return team
          ? Object.freeze({ tenantId: team.id, name: team.name, slug: team.slug ?? '' })
          : null
      }),

    listMembersAsSystem: (input) =>
      system('listMembersAsSystem', async () => {
        assertIds(input.tenantId)
        return (await auth.system.listMembers(input.tenantId.toLowerCase())).map(
          ({ member, user }) =>
            Object.freeze({
              userId: user.id,
              email: user.email,
              name: user.name,
              roles: [member.role],
            }),
        )
      }),
  }
  return Object.freeze(engine)
}
