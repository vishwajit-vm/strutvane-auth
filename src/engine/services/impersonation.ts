/**
 * Admin impersonation ("sign in as this user" for support).
 *
 * - Only users with the global `admin` role, with a recent password confirmation.
 * - Never another admin (no lateral movement between admins), never yourself, never nested.
 * - Audited: `impersonation.started` / `impersonation.stopped` carry both ids.
 * - The impersonation session is a NEW session id with `impersonatorId` set and a 1-hour absolute
 *   lifetime; the admin's own session is ended, so nothing of the admin's privileges rides along.
 *   `AuthState.impersonator` is the banner flag the UI must show.
 * - While impersonating, the target's credentials, second factors, tokens and sessions cannot be
 *   changed (`assertNotImpersonating` in every such service).
 * - One-click leave: `stop()` ends the impersonation session and starts a fresh admin session.
 * - Re-checked on every request (`activeSession`): turning the feature off, removing the admin's
 *   role or making the target an admin ends a running impersonation at once.
 *
 * @module
 */

import { type AuthDeps, emit, requireFeature } from '../core/deps.ts'
import {
  endSession,
  IMPERSONATOR_ROLE,
  readSession,
  requireActive,
  requireRecentConfirmation,
  startSession,
} from '../core/sessions.ts'
import { AuthError } from '../errors.ts'
import type { AuthRequest } from '../ports/cookies.ts'

/** The role allowed to impersonate (and protected from being impersonated). */
export const ADMIN_ROLE: string = IMPERSONATOR_ROLE

const IMPERSONATION_MS = 60 * 60_000

/** Impersonation operations (feature `impersonation`). */
export interface ImpersonationService {
  /**
   * Start impersonating `userId`.
   *
   * @example
   * ```ts
   * await auth.impersonation.start(req, { userId }) // POST /impersonate/:user
   * ```
   */
  start(req: AuthRequest, input: { readonly userId: unknown }): Promise<void>
  /** Leave the impersonation and return to the admin's own (fresh) session. */
  stop(req: AuthRequest): Promise<void>
}

/** Build the {@link ImpersonationService}. */
export function impersonationService(deps: AuthDeps): ImpersonationService {
  return {
    async start(req, input) {
      requireFeature(deps, 'impersonation')
      const active = await requireActive(deps, req)
      if (active.session.impersonatorId !== null) throw new AuthError('FORBIDDEN')
      if (!(await deps.store.listUserRoles(active.user.id)).includes(ADMIN_ROLE))
        throw new AuthError('FORBIDDEN')
      requireRecentConfirmation(deps, active)
      if (typeof input.userId !== 'string') throw new AuthError('NOT_FOUND')
      const target = await deps.store.findUserById(input.userId)
      if (!target) throw new AuthError('NOT_FOUND')
      if (
        target.id === active.user.id ||
        (await deps.store.listUserRoles(target.id)).includes(ADMIN_ROLE)
      )
        throw new AuthError('FORBIDDEN')
      await startSession(deps, req, {
        userId: target.id,
        state: 'active',
        method: active.session.method,
        remember: false,
        impersonatorId: active.user.id,
        lifetimeMs: Math.min(IMPERSONATION_MS, deps.config.sessions.absoluteMs),
      })
      await emit(deps, req, {
        type: 'impersonation.started',
        adminId: active.user.id,
        userId: target.id,
      })
    },

    async stop(req) {
      requireFeature(deps, 'impersonation')
      const session = await readSession(deps, req)
      if (!session || session.impersonatorId === null) throw new AuthError('NOT_FOUND')
      // Recorded while the impersonation session still exists, so the actor is the admin.
      await emit(deps, req, {
        type: 'impersonation.stopped',
        adminId: session.impersonatorId,
        userId: session.userId,
      })
      await endSession(deps, req)
      const admin = await deps.store.findUserById(session.impersonatorId)
      // The admin returns with a fresh session (and must confirm the password again for anything
      // sensitive). If the admin was deleted meanwhile, they are simply signed out.
      if (admin)
        await startSession(deps, req, {
          userId: admin.id,
          state: 'active',
          method: session.method,
          remember: false,
        })
    },
  }
}
