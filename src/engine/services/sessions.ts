/**
 * "Browser sessions" in settings (Jetstream's page): list your sessions, sign out one or all the
 * others.
 *
 * Each session is shown by a HANDLE (the first 16 hex characters of its stored digest), never by
 * its id: the id is the bearer credential, the digest prefix identifies a row and is useless to an
 * attacker. Signing out the others needs a recent password confirmation (Laravel's
 * `logoutOtherDevices($password)`), and rotates the current id.
 *
 * @module
 */

import { type AuthDeps, emit } from '../core/deps.ts'
import {
  assertNotImpersonating,
  requireActive,
  requireRecentConfirmation,
  rotateSession,
} from '../core/sessions.ts'
import { AuthError } from '../errors.ts'
import type { AuthRequest } from '../ports/cookies.ts'
import type { LoginMethod } from '../ports/events.ts'

/** A session as listed in settings. */
export interface SessionView {
  readonly handle: string
  readonly current: boolean
  /** True for a session an administrator opened by impersonating this user (#116). */
  readonly impersonated: boolean
  /** "Signed in by an administrator" for impersonation sessions, else `null`. */
  readonly label: string | null
  readonly method: LoginMethod
  readonly createdAt: number
  readonly lastSeenAt: number
  readonly ip: string | null
  readonly userAgent: string | null
}

/** Session management operations (always on with sign-in). */
export interface SessionService {
  /**
   * The signed-in user's active sessions, newest first.
   *
   * @example
   * ```ts
   * const sessions = await auth.sessions.list(req)
   * ```
   */
  list(req: AuthRequest): Promise<readonly SessionView[]>
  /** Sign out one other session by its handle. */
  revoke(req: AuthRequest, input: { readonly handle: unknown }): Promise<void>
  /** Sign out every other session (needs a recent password confirmation). */
  revokeOthers(req: AuthRequest): Promise<number>
}

const handleOf = (digest: string): string => digest.slice(0, 16)

/** The label of an impersonation session in the user's list (the framework may translate it). */
export const IMPERSONATION_LABEL = 'Signed in by an administrator'

/** Build the {@link SessionService}. */
export function sessionService(deps: AuthDeps): SessionService {
  return {
    async list(req) {
      const active = await requireActive(deps, req)
      const now = deps.clock.now()
      return (await deps.store.listUserSessions(active.user.id))
        .filter((s) => s.state === 'active' && s.expiresAt > now && now - s.lastSeenAt < s.idleMs)
        .sort((a, b) => b.lastSeenAt - a.lastSeenAt)
        .map((s) => ({
          handle: handleOf(s.digest),
          current: s.digest === active.session.digest,
          // An impersonation session is shown for what it is, but the admin's address and browser
          // are the admin's personal data, not the user's (CONSISTENCY #116).
          impersonated: s.impersonatorId !== null,
          label: s.impersonatorId !== null ? IMPERSONATION_LABEL : null,
          method: s.method,
          createdAt: s.createdAt,
          lastSeenAt: s.lastSeenAt,
          ip: s.impersonatorId !== null ? null : s.ip,
          userAgent: s.impersonatorId !== null ? null : s.userAgent,
        }))
    },

    async revoke(req, input) {
      const active = await requireActive(deps, req)
      assertNotImpersonating(active)
      const target = (await deps.store.listUserSessions(active.user.id)).find(
        (s) => typeof input.handle === 'string' && handleOf(s.digest) === input.handle,
      )
      if (!target || target.digest === active.session.digest) throw new AuthError('not_found')
      await deps.store.deleteSession(target.digest)
      await emit(deps, req, { type: 'session.revoked', userId: active.user.id, count: 1 })
    },

    async revokeOthers(req) {
      const active = await requireActive(deps, req)
      assertNotImpersonating(active)
      requireRecentConfirmation(deps, active)
      const count = await deps.store.deleteUserSessions(active.user.id, active.session.digest)
      await rotateSession(deps, req, active.session)
      await emit(deps, req, { type: 'session.revoked', userId: active.user.id, count })
      return count
    },
  }
}
