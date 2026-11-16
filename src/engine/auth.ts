/**
 * `createAuth()`: wires the ports into the services. This is what the framework's auth provider
 * calls once at boot and binds in the container.
 *
 * @module
 */
import type { AuthConfig } from './config.ts'
import {
  type AuthDeps,
  COOKIE_NAMES,
  type CookieKind,
  createBackground,
  resolveCookieName,
} from './core/deps.ts'
import { activeSession, readSession } from './core/sessions.ts'
import { type ChallengeMethod, challengeMethods } from './core/sign-in.ts'
import { createKeyRing } from './crypto/keys.ts'
import { createLimiter } from './limits/limiter.ts'
import { createLockout } from './limits/lockout.ts'
import { createScryptHasher, type PasswordHasher } from './password/hasher.ts'
import type { PasswordCheck } from './password/rules.ts'
import { type Clock, systemClock } from './ports/clock.ts'
import type { AuthRequest } from './ports/cookies.ts'
import type { CounterStore } from './ports/counter-store.ts'
import type { AuthEventSink, AuthLogger, LoginMethod } from './ports/events.ts'
import type { AuthMailer } from './ports/mailer.ts'
import type { AuthStore } from './ports/store.ts'
import { type EmailLinkService, emailLinkService } from './services/email-link.ts'
import { type ImpersonationService, impersonationService } from './services/impersonation.ts'
import { type PasskeyService, passkeyService } from './services/passkeys.ts'
import { type PasswordResetService, passwordResetService } from './services/password-reset.ts'
import { type PasswordService, passwordService } from './services/passwords.ts'
import { type SessionService, sessionService } from './services/sessions.ts'
import { type SystemService, systemService } from './services/system.ts'
import { type CurrentTeam, type TeamService, teamService } from './services/teams.ts'
import { type TokenService, tokenService } from './services/tokens.ts'
import { type TwoFactorService, twoFactorService } from './services/two-factor.ts'
import { type VerificationService, verificationService } from './services/verification.ts'

/** The ports the framework provides. See the README, "Interfaces the framework must provide". */
export interface AuthPorts {
  readonly config: AuthConfig
  readonly store: AuthStore
  /** Shared counters for rate limits and lockouts (the framework cache). */
  readonly counters: CounterStore
  readonly mailer: AuthMailer
  readonly events: AuthEventSink
  /** `APP_KEY`: `base64:` + 32 random bytes. Every keyed digest and signature derives from it. */
  readonly appKey: string
  readonly clock?: Clock
  readonly logger?: AuthLogger
  readonly hasher?: PasswordHasher
  /** Optional breached/common-password check (`commonPasswordCheck`, `rangeBreachCheck`). */
  readonly passwordCheck?: PasswordCheck
  /** Refuse passwords when the check cannot run (default: allow, with a warning). */
  readonly passwordCheckOnUnknown?: 'open' | 'closed'
}

/** The signed-in user as the app sees it on every request. */
export interface AuthState {
  readonly user: {
    readonly id: string
    readonly email: string
    readonly name: string
    readonly emailVerified: boolean
    readonly twoFactorEnabled: boolean
  }
  readonly session: {
    readonly method: LoginMethod
    readonly createdAt: number
    readonly passwordConfirmedAt: number | null
  }
  /** Set while an admin impersonates this user: the UI MUST show a banner with a "leave" button. */
  readonly impersonator: {
    readonly id: string
    readonly name: string
    readonly email: string
  } | null
  readonly team: CurrentTeam | null
  readonly roles: readonly string[]
}

/** Everything `createAuth` returns. */
export interface Auth {
  readonly config: AuthConfig
  /**
   * Every cookie name this core uses, resolved for the app's scheme (`__Host-strutvane_session`
   * on https). The ONE source the framework's CSRF check and session middleware read (#105).
   */
  readonly cookieNames: Readonly<Record<CookieKind, string>>
  /** The signed-in user, or `null` for guests (a pending 2FA sign-in is a guest). */
  state(req: AuthRequest): Promise<AuthState | null>
  /** When a sign-in waits for its second factor: the methods it can use; otherwise `null`. */
  pendingChallenge(
    req: AuthRequest,
  ): Promise<{ readonly methods: readonly ChallengeMethod[] } | null>
  readonly passwords: PasswordService
  readonly passwordReset: PasswordResetService
  readonly verification: VerificationService
  readonly emailLink: EmailLinkService
  readonly twoFactor: TwoFactorService
  readonly passkeys: PasskeyService
  readonly sessions: SessionService
  readonly tokens: TokenService
  readonly teams: TeamService
  readonly impersonation: ImpersonationService
  readonly system: SystemService
  /** Resolves once queued background work (mail) has settled: for tests and graceful shutdown. */
  idle(): Promise<void>
}

/**
 * Build the auth core from the framework's ports.
 *
 * @example
 * ```ts
 * const auth = createAuth({
 *   config: defineAuthConfig({ appUrl: 'https://app.example.com', features: { twoFactor: true } }),
 *   store: sqliteAuthStore(db), counters: sqliteCounterStore(db),
 *   mailer, events, appKey: process.env.APP_KEY ?? '',
 * })
 * const state = await auth.state(req)
 * ```
 */
export function createAuth(ports: AuthPorts): Auth {
  const clock = ports.clock ?? systemClock
  const deps: AuthDeps = {
    config: ports.config,
    store: ports.store,
    counters: ports.counters,
    keys: createKeyRing(ports.appKey),
    clock,
    mailer: ports.mailer,
    events: ports.events,
    logger: ports.logger,
    hasher: ports.hasher ?? createScryptHasher(),
    passwordCheck: ports.passwordCheck,
    passwordCheckOnUnknown: ports.passwordCheckOnUnknown ?? 'open',
    limiter: createLimiter(ports.counters, clock),
    lockout: createLockout(ports.counters, clock, ports.config.lockout),
    background: createBackground(ports.logger),
  }
  const teams = teamService(deps)

  const cookieNames = Object.freeze(
    Object.fromEntries(
      Object.keys(COOKIE_NAMES).map((kind) => [
        kind,
        resolveCookieName(ports.config.secureCookies, kind as CookieKind),
      ]),
    ) as Record<CookieKind, string>,
  )
  const auth: Auth = {
    config: ports.config,
    cookieNames,
    async state(req: AuthRequest): Promise<AuthState | null> {
      const active = await activeSession(deps, req)
      if (!active) return null
      const { user, session } = active
      const admin =
        session.impersonatorId === null
          ? undefined
          : await deps.store.findUserById(session.impersonatorId)
      return {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          emailVerified: user.emailVerifiedAt !== null,
          twoFactorEnabled: user.twoFactorConfirmedAt !== null,
        },
        session: {
          method: session.method,
          createdAt: session.createdAt,
          passwordConfirmedAt: session.passwordConfirmedAt,
        },
        impersonator: admin ? { id: admin.id, name: admin.name, email: admin.email } : null,
        team: deps.config.features.teams ? await teams.current(req) : null,
        roles: await deps.store.listUserRoles(user.id),
      }
    },
    async pendingChallenge(req: AuthRequest) {
      const session = await readSession(deps, req)
      if (session?.state !== 'two-factor') return null
      const user = await deps.store.findUserById(session.userId)
      return user ? { methods: await challengeMethods(deps, user) } : null
    },
    passwords: passwordService(deps),
    passwordReset: passwordResetService(deps),
    verification: verificationService(deps),
    emailLink: emailLinkService(deps),
    twoFactor: twoFactorService(deps),
    passkeys: passkeyService(deps),
    sessions: sessionService(deps),
    tokens: tokenService(deps),
    teams,
    impersonation: impersonationService(deps),
    system: systemService(deps),
    idle: () => deps.background.idle(),
  }
  return Object.freeze(auth)
}
