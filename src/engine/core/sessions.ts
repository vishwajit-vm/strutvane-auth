/**
 * Server-side sessions: creation, rotation, timeouts and the guards other services use.
 *
 * - The cookie carries a 256-bit random id; the store holds only its keyed digest, so a database
 *   read (a backup, a SQL bug) yields no usable session (review F-09).
 * - **A new id on every sign-in** (the presented session, if any, is deleted: no fixation), and on
 *   every privilege change (2FA on/off, password change, team switch, impersonation).
 * - **Idle timeout** (no request for `idleMs`) and **absolute timeout** (`expiresAt`). Rotation keeps
 *   `expiresAt`, so rotating can never extend a session's life; only a fresh sign-in does.
 * - A `two-factor` session (password accepted, second factor pending) is a GUEST to every guard.
 *
 * @module
 */
import { randomSecret } from '../crypto/random.ts'
import { AuthError } from '../errors.ts'
import { normalizeIp } from '../limits/ip.ts'
import type { AuthRequest } from '../ports/cookies.ts'
import type { LoginMethod } from '../ports/events.ts'
import type { SessionRecord, SessionState, UserRecord } from '../ports/store.ts'
import { parseSecret } from '../tokens/formats.ts'
import { type AuthDeps, cookieName } from './deps.ts'

/** lastSeenAt is written at most this often (one write per minute per session, not per request). */
const TOUCH_EVERY_MS = 60_000

/** The name of the session cookie for this app. */
export function sessionCookie(deps: AuthDeps): string {
  return cookieName(deps, 'session')
}

/** The global role allowed to impersonate (and protected from being impersonated). */
export const IMPERSONATOR_ROLE = 'admin'

/**
 * Is an impersonation session still allowed RIGHT NOW? Re-checked on every request, because the
 * conditions checked at `start()` can stop holding while the session runs: the feature is switched
 * off, the admin loses the role (or is deleted), or the target becomes an admin. Without this, a
 * demoted admin keeps acting as the user until the hour runs out.
 */
async function impersonationStillAllowed(deps: AuthDeps, session: SessionRecord): Promise<boolean> {
  if (session.impersonatorId === null) return true
  if (!deps.config.features.impersonation) return false
  const admin = await deps.store.findUserById(session.impersonatorId)
  if (!admin || !(await deps.store.listUserRoles(admin.id)).includes(IMPERSONATOR_ROLE))
    return false
  return !(await deps.store.listUserRoles(session.userId)).includes(IMPERSONATOR_ROLE)
}

/** A session that passed every check, with its user. */
export interface ActiveSession {
  readonly session: SessionRecord
  readonly user: UserRecord
}

/**
 * Read the presented session in ANY state, enforcing both timeouts. An expired session is deleted
 * and its cookie cleared.
 */
export async function readSession(
  deps: AuthDeps,
  req: AuthRequest,
): Promise<SessionRecord | undefined> {
  const raw = parseSecret(req.cookies.get(sessionCookie(deps)))
  if (raw === undefined) return undefined
  const digest = deps.keys.digest('session', raw)
  const session = await deps.store.findSession(digest)
  if (!session) return undefined
  const now = deps.clock.now()
  if (now >= session.expiresAt || now - session.lastSeenAt >= session.idleMs) {
    await deps.store.deleteSession(digest)
    req.cookies.clear(sessionCookie(deps))
    return undefined
  }
  return session
}

/** What {@link startSession} needs. */
export interface StartSessionInput {
  readonly userId: string
  readonly state: SessionState
  readonly method: LoginMethod
  readonly remember: boolean
  readonly impersonatorId?: string | null
  /** Override the absolute lifetime (pending 2FA, impersonation). */
  readonly lifetimeMs?: number
}

function writeCookie(deps: AuthDeps, req: AuthRequest, raw: string, session: SessionRecord): void {
  // A "remember me" session survives a browser restart; every other one is a browser-session cookie.
  req.cookies.set(
    sessionCookie(deps),
    raw,
    session.remember
      ? { maxAgeSeconds: Math.floor((session.expiresAt - deps.clock.now()) / 1000) }
      : {},
  )
}

/**
 * Start a brand-new session (sign-in). The presented session, whatever its state, is deleted
 * first: an id planted in the victim's browser before sign-in is never upgraded (fixation).
 */
export async function startSession(
  deps: AuthDeps,
  req: AuthRequest,
  input: StartSessionInput,
): Promise<SessionRecord> {
  const presented = parseSecret(req.cookies.get(sessionCookie(deps)))
  if (presented !== undefined)
    await deps.store.deleteSession(deps.keys.digest('session', presented))
  const now = deps.clock.now()
  const { sessions } = deps.config
  const lifetime = input.lifetimeMs ?? (input.remember ? sessions.rememberMs : sessions.absoluteMs)
  const raw = randomSecret()
  const session: SessionRecord = {
    digest: deps.keys.digest('session', raw),
    userId: input.userId,
    state: input.state,
    createdAt: now,
    lastSeenAt: now,
    expiresAt: now + lifetime,
    idleMs: input.remember ? sessions.rememberMs : Math.min(sessions.idleMs, lifetime),
    remember: input.remember,
    method: input.method,
    passwordConfirmedAt: null,
    impersonatorId: input.impersonatorId ?? null,
    ip: normalizeIp(req.ip) ?? null,
    userAgent: req.userAgent?.slice(0, 255) ?? null,
  }
  await deps.store.createSession(session)
  writeCookie(deps, req, raw, session)
  return session
}

/**
 * Give the current session a new id (privilege change). Everything else, including the absolute
 * expiry and the password-confirmation time, carries over.
 */
export async function rotateSession(
  deps: AuthDeps,
  req: AuthRequest,
  current: SessionRecord,
): Promise<SessionRecord> {
  const raw = randomSecret()
  const next: SessionRecord = {
    ...current,
    digest: deps.keys.digest('session', raw),
    lastSeenAt: deps.clock.now(),
  }
  await deps.store.createSession(next)
  await deps.store.deleteSession(current.digest)
  writeCookie(deps, req, raw, next)
  return next
}

/** Delete the presented session and clear its cookie. Resolves the session that ended, if any. */
export async function endSession(
  deps: AuthDeps,
  req: AuthRequest,
): Promise<SessionRecord | undefined> {
  const session = await readSession(deps, req)
  if (session) await deps.store.deleteSession(session.digest)
  req.cookies.clear(sessionCookie(deps))
  return session
}

/** The signed-in session and user, or `undefined` for guests (including pending 2FA). */
export async function activeSession(
  deps: AuthDeps,
  req: AuthRequest,
): Promise<ActiveSession | undefined> {
  const session = await readSession(deps, req)
  if (session?.state !== 'active') return undefined
  const user = await deps.store.findUserById(session.userId)
  if (!user || !(await impersonationStillAllowed(deps, session))) {
    // Fail closed: the row is deleted, so a replayed copy of the cookie gets nothing either.
    await deps.store.deleteSession(session.digest)
    req.cookies.clear(sessionCookie(deps))
    return undefined
  }
  const now = deps.clock.now()
  if (now - session.lastSeenAt >= TOUCH_EVERY_MS) {
    await deps.store.updateSession(session.digest, { lastSeenAt: now })
    return { session: { ...session, lastSeenAt: now }, user }
  }
  return { session, user }
}

/** Like {@link activeSession} but throws `UNAUTHENTICATED` for guests. */
export async function requireActive(deps: AuthDeps, req: AuthRequest): Promise<ActiveSession> {
  const active = await activeSession(deps, req)
  if (!active) throw new AuthError('UNAUTHENTICATED')
  return active
}

/**
 * Refuse while an admin is impersonating. Credentials, second factors, tokens and sessions belong
 * to the real user; an impersonating admin must not change them (or mint a token that outlives the
 * impersonation).
 */
export function assertNotImpersonating(active: ActiveSession): void {
  if (active.session.impersonatorId !== null) throw new AuthError('FORBIDDEN')
}

/** Throw `PASSWORD_CONFIRMATION_REQUIRED` unless the user confirmed within the window (3 h). */
export function requireRecentConfirmation(deps: AuthDeps, active: ActiveSession): void {
  const at = active.session.passwordConfirmedAt
  if (at === null || deps.clock.now() - at > deps.config.sessions.confirmPasswordMs)
    throw new AuthError('PASSWORD_CONFIRMATION_REQUIRED')
}
