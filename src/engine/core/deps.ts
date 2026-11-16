/**
 * The dependency bundle every service receives, plus the small helpers they share (emitting
 * events, background mail delivery, feature gates).
 *
 * @module
 */
import type { AuthConfig, AuthFeatures } from '../config.ts'
import type { KeyRing } from '../crypto/keys.ts'
import { featureDisabled } from '../errors.ts'
import { normalizeIp } from '../limits/ip.ts'
import type { Limiter } from '../limits/limiter.ts'
import type { Lockout } from '../limits/lockout.ts'
import type { PasswordHasher } from '../password/hasher.ts'
import type { PasswordCheck } from '../password/rules.ts'
import type { Clock } from '../ports/clock.ts'
import type { AuthRequest } from '../ports/cookies.ts'
import type { CounterStore } from '../ports/counter-store.ts'
import type { AuthEvent, AuthEventSink, AuthLogger } from '../ports/events.ts'
import type { AuthMail, AuthMailer } from '../ports/mailer.ts'
import type { AuthStore } from '../ports/store.ts'
import { parseSecret } from '../tokens/formats.ts'

/** Work started after the response (mail delivery), tracked so tests and shutdown can await it. */
export interface Background {
  run(label: string, task: () => Promise<void>): void
  /** Resolves when every task started so far has settled. */
  idle(): Promise<void>
}

/** Create a {@link Background} that reports failures to the logger (ids only). */
export function createBackground(logger: AuthLogger | undefined): Background {
  const pending = new Set<Promise<void>>()
  return {
    run(label, task) {
      // Start on a later tick: the caller's response time must not include the task (enumeration).
      const p: Promise<void> = new Promise<void>((resolve) => setImmediate(resolve))
        .then(task)
        .catch(() => {
          try {
            logger?.warn('auth: background task failed', { task: label })
          } catch {
            // A broken logger must not break auth.
          }
        })
        .finally(() => pending.delete(p))
      pending.add(p)
    },
    async idle() {
      while (pending.size > 0) await Promise.allSettled([...pending])
    },
  }
}

/** Everything a service needs. Built once by `createAuth`. */
export interface AuthDeps {
  readonly config: AuthConfig
  readonly store: AuthStore
  readonly counters: CounterStore
  readonly keys: KeyRing
  readonly clock: Clock
  readonly mailer: AuthMailer
  readonly events: AuthEventSink
  readonly logger: AuthLogger | undefined
  readonly hasher: PasswordHasher
  readonly passwordCheck: PasswordCheck | undefined
  readonly passwordCheckOnUnknown: 'open' | 'closed'
  readonly limiter: Limiter
  readonly lockout: Lockout
  readonly background: Background
}

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never

/** An event without the fields {@link emit} fills in. */
export type EventInput = DistributiveOmit<AuthEvent, 'at' | 'ip' | 'actorId' | 'subjectId'>

/**
 * Who is acting on this request: the impersonating admin when the presented session is an
 * impersonation, else the session's user when it is active, else `null`. Read from the session
 * row (not from what a service passes), so no event can forget it while impersonating.
 */
async function actorOf(deps: AuthDeps, req: AuthRequest | undefined): Promise<string | null> {
  const raw = parseSecret(req?.cookies.get(cookieName(deps, 'session')))
  if (raw === undefined) return null
  const session = await deps.store.findSession(deps.keys.digest('session', raw))
  if (session?.state !== 'active') return null
  return session.impersonatorId ?? session.userId
}

/** Emit an audit event, stamped with the time, client address, actor and subject. Never throws. */
export async function emit(
  deps: AuthDeps,
  req: AuthRequest | undefined,
  event: EventInput,
): Promise<void> {
  let actorId: string | null = null
  try {
    actorId = await actorOf(deps, req)
  } catch {
    // An audit stamp must not break the action it records.
  }
  const subjectId = 'userId' in event && typeof event.userId === 'string' ? event.userId : null
  const full = {
    ...event,
    at: deps.clock.now(),
    ip: normalizeIp(req?.ip) ?? null,
    actorId,
    subjectId,
  } as AuthEvent
  try {
    await deps.events.emit(full)
  } catch {
    try {
      deps.logger?.warn('auth: the event sink failed', { event: full.type })
    } catch {
      // Nothing left to tell.
    }
  }
}

/** Send a mail in the background so the response time never depends on it. */
export function sendMail(deps: AuthDeps, mail: AuthMail): void {
  deps.background.run(`mail:${mail.kind}`, () => deps.mailer.send(mail))
}

/** Throw the disabled-feature error (a plain 404) unless `feature` is on. */
export function requireFeature(deps: AuthDeps, feature: keyof AuthFeatures): void {
  if (!deps.config.features[feature]) throw featureDisabled()
}

/** The account key for limits and lockouts: a keyed digest, so counters never hold an email. */
export function accountKey(deps: AuthDeps, normalizedEmail: string): string {
  return deps.keys.digest('email-digest', normalizedEmail).slice(0, 32)
}

/**
 * Every cookie the auth core sets, in ONE place (CONSISTENCY #24, #105). The framework's CSRF
 * check, its session middleware and this core must agree on these names; reading them from here
 * (resolved per scheme: `auth.cookieNames`) is what keeps them from drifting apart.
 */
export const COOKIE_NAMES: {
  readonly session: 'strutvane_session'
  readonly emailLink: 'strutvane_link'
  readonly device: 'strutvane_device'
  readonly webauthn: 'strutvane_webauthn'
  readonly registration: 'strutvane_register'
} = Object.freeze({
  session: 'strutvane_session',
  emailLink: 'strutvane_link',
  device: 'strutvane_device',
  webauthn: 'strutvane_webauthn',
  registration: 'strutvane_register',
} as const)

/** Which cookie: a key of {@link COOKIE_NAMES} (a free-form name does not compile). */
export type CookieKind = keyof typeof COOKIE_NAMES

/** A cookie's name for this app: `__Host-` prefixed on https, so a sibling host cannot set or shadow it. */
export function cookieName(deps: AuthDeps, kind: CookieKind): string {
  return resolveCookieName(deps.config.secureCookies, kind, deps.config.sessionCookie)
}

/**
 * {@link cookieName} without the deps: what `auth.cookieNames` is built from. `sessionBase`
 * replaces the session cookie's base name (`config/session.ts` `cookie`; the framework's CSRF
 * check reads the same value, #105).
 *
 * @example
 * resolveCookieName(true, 'session') // '__Host-strutvane_session'
 */
export function resolveCookieName(
  secure: boolean,
  kind: CookieKind,
  sessionBase: string = COOKIE_NAMES.session,
): string {
  const base = kind === 'session' ? sessionBase : COOKIE_NAMES[kind]
  return secure ? `__Host-${base}` : base
}
