/**
 * Passwordless sign-in by email link, bound to the browser that asked.
 *
 * The request sets a random nonce cookie in the requesting browser and stores the link token's
 * digest WITH the nonce's digest. Opening the link only signs in when the same nonce cookie comes
 * back. So a link that is forwarded, intercepted in transit, or opened by a mail scanner signs in
 * nobody; the rightful browser can still use it (a mismatch does not burn the link).
 *
 * Other properties:
 * - 15 minutes, single-use (atomic consume), and a successful sign-in kills the user's other links;
 * - the request answers the same whether or not the account exists, and mails in the background;
 * - the link proves the mailbox, so it also verifies the email;
 * - 2FA still applies: a user with 2FA lands in the pending two-factor state.
 *
 * Why consume on POST and not on GET: mail scanners prefetch GET links. The UI's GET page shows a
 * "Sign in" button that POSTs the token (the example adapter does exactly that).
 *
 * @module
 */

import { type AuthDeps, accountKey, cookieName, requireFeature, sendMail } from '../core/deps.ts'
import { completeFirstFactor, type SignInResult } from '../core/sign-in.ts'
import { safeEqual } from '../crypto/constant-time.ts'
import { randomSecret } from '../crypto/random.ts'
import { AuthError } from '../errors.ts'
import { rateLimitSubject } from '../limits/ip.ts'
import { parseEmail } from '../password/email.ts'
import type { AuthRequest } from '../ports/cookies.ts'
import { parseSecret } from '../tokens/formats.ts'
import { proveMailbox } from './verification.ts'

/**
 * An email-link sign-in's outcome. `setPasswordToken` is present when this was the first mailbox
 * proof of a never-verified account and its pre-verification password was wiped (#114): the UI
 * sends the owner on to set a new password with it.
 */
export type EmailLinkResult = SignInResult & { readonly setPasswordToken?: string }

/** Email-link operations (feature `emailLink`). */
export interface EmailLinkService {
  /**
   * Mail a sign-in link if the account exists and bind it to this browser. Always `sent`.
   *
   * @example
   * ```ts
   * await auth.emailLink.request(req, { email: 'ada@acme.test' })
   * ```
   */
  request(
    req: AuthRequest,
    input: { readonly email: unknown },
  ): Promise<{ readonly status: 'sent' }>
  /**
   * Sign in with the token from the link (POST from the link's confirmation page).
   *
   * @example
   * ```ts
   * const r = await auth.emailLink.consume(req, { token: params.token })
   * ```
   */
  consume(
    req: AuthRequest,
    input: { readonly token: unknown; readonly remember?: unknown },
  ): Promise<EmailLinkResult>
}

/** The browser-binding cookie name. */
export function linkNonceCookie(deps: AuthDeps): string {
  return cookieName(deps, 'emailLink')
}

/** Build the {@link EmailLinkService}. */
export function emailLinkService(deps: AuthDeps): EmailLinkService {
  const { limits } = deps.config
  return {
    async request(req, input) {
      requireFeature(deps, 'emailLink')
      const email = parseEmail(input.email)
      if (email === undefined)
        throw new AuthError('validation_failed', { issues: [{ field: 'email', code: 'invalid' }] })
      const retry = await deps.limiter.hit([
        [`email-link:ip:${rateLimitSubject(req.ip)}`, limits.emailLinkPerIp],
        [`email-link:acct:${accountKey(deps, email)}`, limits.emailLinkPerAccount],
      ])
      if (retry !== undefined) throw new AuthError('rate_limited', { retryAfterSeconds: retry })
      // Keep an existing nonce: two requests from one browser must both stay usable there.
      const nonce = parseSecret(req.cookies.get(linkNonceCookie(deps))) ?? randomSecret()
      req.cookies.set(linkNonceCookie(deps), nonce, {
        maxAgeSeconds: Math.floor(deps.config.links.emailLinkMs / 1000),
      })
      const user = await deps.store.findUserByEmail(email)
      if (user) {
        const token = randomSecret()
        const now = deps.clock.now()
        await deps.store.putOneTime({
          digest: deps.keys.digest('email-link', token),
          purpose: 'email-link',
          userId: user.id,
          payload: { nonce: deps.keys.digest('email-link-nonce', nonce) },
          createdAt: now,
          expiresAt: now + deps.config.links.emailLinkMs,
        })
        sendMail(deps, {
          kind: 'email-link',
          to: user.email,
          userId: user.id,
          url: `${deps.config.appUrl}/email-link/${token}`,
        })
      }
      return { status: 'sent' }
    },

    async consume(req, input) {
      requireFeature(deps, 'emailLink')
      const token = parseSecret(input.token)
      if (token === undefined) throw new AuthError('invalid_token')
      const digest = deps.keys.digest('email-link', token)
      const found = await deps.store.findOneTime(digest, 'email-link')
      if (!found || found.expiresAt <= deps.clock.now() || found.userId === null)
        throw new AuthError('invalid_token')
      const nonce = parseSecret(req.cookies.get(linkNonceCookie(deps)))
      const expected = found.payload['nonce'] ?? ''
      if (nonce === undefined || !safeEqual(deps.keys.digest('email-link-nonce', nonce), expected))
        throw new AuthError('email_link_other_browser')
      const consumed = await deps.store.consumeOneTime(digest, 'email-link')
      // Expiry is judged at the consume, not only at the earlier lookup.
      if (!consumed || consumed.userId === null || consumed.expiresAt <= deps.clock.now())
        throw new AuthError('invalid_token')
      req.cookies.clear(linkNonceCookie(deps))
      const user = await deps.store.findUserById(consumed.userId)
      if (!user) throw new AuthError('invalid_token')
      await deps.store.deleteUserOneTime(user.id, 'email-link')
      // The link proves the mailbox: a never-verified account is wiped and verified first (#114).
      const proof = await proveMailbox(deps, req, user)
      let current = proof.user
      if (current.emailVerifiedAt === null) {
        // Verification off: still record that the address works.
        const now = deps.clock.now()
        await deps.store.updateUser(user.id, { emailVerifiedAt: now })
        current = { ...current, emailVerifiedAt: now }
      }
      const result = await completeFirstFactor(
        deps,
        req,
        current,
        'email-link',
        input.remember === true,
      )
      return proof.setPasswordToken === undefined
        ? result
        : { ...result, setPasswordToken: proof.setPasswordToken }
    },
  }
}
