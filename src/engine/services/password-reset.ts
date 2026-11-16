/**
 * Password reset (Laravel's password broker, with v1's stricter defaults).
 *
 * - The request answers the same for known and unknown emails, and the mail goes out in the
 *   background, so neither the body nor the timing reveals an account. The mail goes to the
 *   STORED address, never the typed one (review F-08).
 * - The token is 256 random bits, stored only as a keyed digest, valid for 60 minutes, single-use
 *   (atomic consume), and dies when the password changes by any route.
 * - A completed reset signs out EVERYWHERE: every session, every personal access token, every
 *   remembered device and every other reset or email link of that user. It does not sign the
 *   requester in (they sign in with the new password, and 2FA still applies).
 *
 * @module
 */

import { type AuthDeps, accountKey, emit, requireFeature, sendMail } from '../core/deps.ts'
import { deviceCookie } from '../core/sign-in.ts'
import { randomSecret } from '../crypto/random.ts'
import { AuthError } from '../errors.ts'
import { rateLimitSubject } from '../limits/ip.ts'
import { parseEmail } from '../password/email.ts'
import { assertPasswordAllowed } from '../password/rules.ts'
import type { AuthRequest } from '../ports/cookies.ts'
import { parseSecret } from '../tokens/formats.ts'

/** Password reset operations (part of the `passwordLogin` feature). */
export interface PasswordResetService {
  /**
   * Mail a reset link if the account exists. Always resolves `{ status: 'sent' }`.
   *
   * @example
   * ```ts
   * await auth.passwordReset.request(req, { email: 'ada@acme.test' })
   * ```
   */
  request(
    req: AuthRequest,
    input: { readonly email: unknown },
  ): Promise<{ readonly status: 'sent' }>
  /**
   * Set a new password with the token from the link.
   *
   * @example
   * ```ts
   * await auth.passwordReset.reset(req, { token: params.token, password: body.password })
   * ```
   */
  reset(
    req: AuthRequest,
    input: { readonly token: unknown; readonly password: unknown },
  ): Promise<void>
}

/** Build the {@link PasswordResetService}. */
export function passwordResetService(deps: AuthDeps): PasswordResetService {
  const { limits } = deps.config
  return {
    async request(req, input) {
      requireFeature(deps, 'passwordLogin')
      const email = parseEmail(input.email)
      if (email === undefined)
        throw new AuthError('VALIDATION_FAILED', { issues: [{ field: 'email', code: 'invalid' }] })
      const retry = await deps.limiter.hit([
        [`reset:ip:${rateLimitSubject(req.ip)}`, limits.resetPerIp],
        [`reset:acct:${accountKey(deps, email)}`, limits.resetPerAccount],
      ])
      if (retry !== undefined) throw new AuthError('RATE_LIMITED', { retryAfterSeconds: retry })
      const user = await deps.store.findUserByEmail(email)
      if (user) {
        const token = randomSecret()
        const now = deps.clock.now()
        await deps.store.putOneTime({
          digest: deps.keys.digest('password-reset', token),
          purpose: 'password-reset',
          userId: user.id,
          payload: {},
          createdAt: now,
          expiresAt: now + deps.config.links.passwordResetMs,
        })
        sendMail(deps, {
          kind: 'password-reset',
          to: user.email,
          userId: user.id,
          url: `${deps.config.appUrl}/reset-password/${token}`,
        })
      }
      return { status: 'sent' }
    },

    async reset(req, input) {
      requireFeature(deps, 'passwordLogin')
      const retry = await deps.limiter.hit([
        [`reset-complete:ip:${rateLimitSubject(req.ip)}`, limits.resetPerIp],
      ])
      if (retry !== undefined) throw new AuthError('RATE_LIMITED', { retryAfterSeconds: retry })
      const token = parseSecret(input.token)
      if (token === undefined) throw new AuthError('INVALID_TOKEN')
      const digest = deps.keys.digest('password-reset', token)
      const found = await deps.store.findOneTime(digest, 'password-reset')
      if (!found || found.expiresAt <= deps.clock.now() || found.userId === null)
        throw new AuthError('INVALID_TOKEN')
      // Validate the new password BEFORE consuming, so a too-short password does not burn the link.
      const password = await assertPasswordAllowed(input.password, {
        min: deps.config.passwords.min,
        max: deps.config.passwords.max,
        check: deps.passwordCheck,
        onUnknown: deps.passwordCheckOnUnknown,
        logger: deps.logger,
      })
      const hash = await deps.hasher.hash(password)
      // Single use, atomically: of two concurrent submissions exactly one gets here.
      const consumed = await deps.store.consumeOneTime(digest, 'password-reset')
      // Re-check the expiry AT the consume: hashing and the breach check ran since the lookup, and
      // the link may have expired meanwhile (consumed either way, so it cannot be retried).
      if (!consumed || consumed.userId === null || consumed.expiresAt <= deps.clock.now())
        throw new AuthError('INVALID_TOKEN')
      const user = await deps.store.findUserById(consumed.userId)
      if (!user) throw new AuthError('INVALID_TOKEN')
      // Revoke FIRST, set the password LAST: the store has no transactions, so if it fails
      // part-way the account is left with the old password and fewer credentials (fail closed),
      // never with the new password while a thief's sessions or tokens survive.
      await deps.store.deleteUserOneTime(user.id, 'password-reset')
      await deps.store.deleteUserOneTime(user.id, 'email-link')
      await deps.store.deleteUserOneTime(user.id, 'trusted-device')
      req.cookies.clear(deviceCookie(deps))
      const sessions = await deps.store.deleteUserSessions(user.id)
      await deps.store.deleteUserTokens(user.id)
      // A reset proves the mailbox AND sets an owner-chosen password, after revoking everything:
      // exactly the #114 remedy, so it also verifies a never-verified address.
      const verifies = deps.config.features.emailVerification && user.emailVerifiedAt === null
      await deps.store.updateUser(
        user.id,
        verifies
          ? { passwordHash: hash, emailVerifiedAt: deps.clock.now() }
          : { passwordHash: hash },
      )
      // A reset proves control of the mailbox: lift a password lockout on this account.
      await deps.lockout.succeed(`login:${accountKey(deps, user.email)}`)
      if (sessions > 0)
        await emit(deps, req, { type: 'session.revoked', userId: user.id, count: sessions })
      if (verifies) await emit(deps, req, { type: 'email.verified', userId: user.id })
      await emit(deps, req, { type: 'password.changed', userId: user.id, via: 'reset' })
      sendMail(deps, { kind: 'password-changed', to: user.email, userId: user.id })
    },
  }
}
