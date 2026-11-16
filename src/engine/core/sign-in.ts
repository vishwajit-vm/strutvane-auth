/**
 * The shared end of every sign-in: after a first factor (password, email link, passkey) succeeds,
 * either start the session or park the user in a pending two-factor session.
 *
 * Every first factor goes through {@link completeFirstFactor}, so no path can skip 2FA (a password
 * sign-in and an email-link sign-in are held to the same rule).
 *
 * @module
 */
import type { AuthRequest } from '../ports/cookies.ts'
import type { LoginMethod, SecondFactor } from '../ports/events.ts'
import type { SessionRecord, UserRecord } from '../ports/store.ts'
import { parseSecret } from '../tokens/formats.ts'
import { type AuthDeps, cookieName, emit } from './deps.ts'
import { startSession } from './sessions.ts'

/** The second factors a pending sign-in may use. */
export type ChallengeMethod = 'totp' | 'recovery-code' | 'passkey'

/** The outcome of a first factor. */
export type SignInResult =
  | { readonly status: 'signed-in' }
  | { readonly status: 'two-factor-required'; readonly methods: readonly ChallengeMethod[] }

/** The "remember this device" cookie name. */
export function deviceCookie(deps: AuthDeps): string {
  return cookieName(deps, 'device')
}

/** True when two-factor is on for the app AND confirmed by this user. */
export function hasTwoFactor(deps: AuthDeps, user: UserRecord): boolean {
  return (
    deps.config.features.twoFactor &&
    user.twoFactorConfirmedAt !== null &&
    user.twoFactorSecret !== null
  )
}

async function trustedDevice(deps: AuthDeps, req: AuthRequest, user: UserRecord): Promise<boolean> {
  const raw = parseSecret(req.cookies.get(deviceCookie(deps)))
  if (raw === undefined) return false
  const record = await deps.store.findOneTime(
    deps.keys.digest('trusted-device', raw),
    'trusted-device',
  )
  // The cookie must belong to THIS user: a device trusted by Alice does not skip Bob's 2FA.
  return record !== undefined && record.userId === user.id && record.expiresAt > deps.clock.now()
}

/** The second factors this user can use right now. */
export async function challengeMethods(
  deps: AuthDeps,
  user: UserRecord,
): Promise<readonly ChallengeMethod[]> {
  const methods: ChallengeMethod[] = ['totp', 'recovery-code']
  if (deps.config.features.passkeys && (await deps.store.listPasskeys(user.id)).length > 0)
    methods.push('passkey')
  return methods
}

/**
 * Finish a successful first factor: a full session, or a pending two-factor session.
 *
 * The pending session is a fresh id with a short absolute lifetime (10 minutes); it carries the
 * "remember me" choice so the final session honours it.
 */
export async function completeFirstFactor(
  deps: AuthDeps,
  req: AuthRequest,
  user: UserRecord,
  method: LoginMethod,
  remember: boolean,
): Promise<SignInResult> {
  if (hasTwoFactor(deps, user) && !(await trustedDevice(deps, req, user))) {
    await startSession(deps, req, {
      userId: user.id,
      state: 'two-factor',
      method,
      remember,
      lifetimeMs: deps.config.sessions.twoFactorPendingMs,
    })
    return { status: 'two-factor-required', methods: await challengeMethods(deps, user) }
  }
  await startSession(deps, req, { userId: user.id, state: 'active', method, remember })
  await emit(deps, req, {
    type: 'login',
    userId: user.id,
    method,
    secondFactor: hasTwoFactor(deps, user) ? 'trusted-device' : null,
  })
  return { status: 'signed-in' }
}

/** Finish a pending two-factor sign-in: a NEW session id (the pending one is deleted). */
export async function completeSecondFactor(
  deps: AuthDeps,
  req: AuthRequest,
  pending: SessionRecord,
  factor: SecondFactor,
): Promise<SignInResult> {
  await startSession(deps, req, {
    userId: pending.userId,
    state: 'active',
    method: pending.method,
    remember: pending.remember,
  })
  await emit(deps, req, {
    type: 'login',
    userId: pending.userId,
    method: pending.method,
    secondFactor: factor,
  })
  return { status: 'signed-in' }
}
