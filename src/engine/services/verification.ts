/**
 * Email verification with signed links (Laravel's `/email/verify/{id}/{hash}?expires&signature`).
 *
 * The link is stateless: `signature = HMAC(subkey, "<id>.<hash>.<expires>")`, where `hash` is a keyed
 * digest of the CURRENT email. So a link expires after 60 minutes, cannot be edited (any changed
 * character breaks the signature), and stops working if the address changes. Verifying twice is
 * harmless (idempotent). Resending is throttled per account: one per minute, six per hour.
 *
 * @module
 */
import { createHmac } from 'node:crypto'
import { type AuthDeps, cookieName, emit, requireFeature, sendMail } from '../core/deps.ts'
import { requireActive } from '../core/sessions.ts'
import { safeEqual } from '../crypto/constant-time.ts'
import { randomSecret } from '../crypto/random.ts'
import { AuthError } from '../errors.ts'
import type { AuthRequest } from '../ports/cookies.ts'
import type { UserRecord } from '../ports/store.ts'
import { parseSecret, parseVerificationLink } from '../tokens/formats.ts'

/**
 * The `{hash}` in the link: a keyed digest of the current address, under its OWN subkey. Not the
 * `email-digest` subkey: that one keys the rate-limit counters and the `emailDigest` in audit
 * events, and a value that travels by mail must not equal one that lives in logs and caches.
 */
function emailHash(deps: AuthDeps, email: string): string {
  return deps.keys.digest('email-verification-hash', email).slice(0, 40)
}

function sign(deps: AuthDeps, id: string, hash: string, expires: number): string {
  return createHmac('sha256', deps.keys.subkey('email-verification'))
    .update(`${id}.${hash}.${expires}`)
    .digest('hex')
}

/** The signed verification URL for `user`, valid for the configured window. */
export function verificationUrl(deps: AuthDeps, user: UserRecord): string {
  const hash = emailHash(deps, user.email)
  const expires = Math.floor((deps.clock.now() + deps.config.links.verificationMs) / 1000)
  return `${deps.config.appUrl}/email/verify/${user.id}/${hash}?expires=${expires}&signature=${sign(deps, user.id, hash, expires)}`
}

/**
 * Mail a verification link unless the per-account cooldown or hourly cap says no. Resolves the
 * seconds to wait when refused. Shared by "resend" and by a refused password sign-in.
 */
async function mailVerificationLink(deps: AuthDeps, user: UserRecord): Promise<number | undefined> {
  const coolKey = `verify-resend:cool:${user.id}`
  const now = deps.clock.now()
  const coolUntil = await deps.counters.get(coolKey)
  if (coolUntil !== undefined && coolUntil > now) return Math.ceil((coolUntil - now) / 1000)
  const retry = await deps.limiter.hit([
    [`verify-resend:hour:${user.id}`, deps.config.limits.verificationResendPerAccount],
  ])
  if (retry !== undefined) return retry
  const coolMs = deps.config.limits.verificationResendCooldown.windowSeconds * 1000
  await deps.counters.set(coolKey, now + coolMs, coolMs)
  sendMail(deps, {
    kind: 'verify-email',
    to: user.email,
    userId: user.id,
    url: verificationUrl(deps, user),
  })
  return undefined
}

/** Re-send the verification mail for a refused password sign-in (quietly throttled). */
export async function remindToVerify(deps: AuthDeps, user: UserRecord): Promise<void> {
  await mailVerificationLink(deps, user)
}

/** The cookie that binds a registration to the browser that made it (CONSISTENCY #122). */
export function registrationCookie(deps: AuthDeps): string {
  return cookieName(deps, 'registration')
}

/**
 * Bind a new registration to this browser: a random nonce in a `__Host-` cookie (on https), its
 * keyed digest stored with the user id, both expiring with the verification link. Called for a
 * TAKEN address too, without the stored half, so the cookie never tells whether an account exists.
 */
export async function bindRegistration(
  deps: AuthDeps,
  req: AuthRequest,
  user: UserRecord | undefined,
): Promise<void> {
  const nonce = randomSecret()
  const ttl = deps.config.links.verificationMs
  req.cookies.set(registrationCookie(deps), nonce, { maxAgeSeconds: Math.floor(ttl / 1000) })
  if (user === undefined) return
  const now = deps.clock.now()
  await deps.store.putOneTime({
    digest: deps.keys.digest('registration-nonce', nonce),
    purpose: 'registration',
    userId: user.id,
    payload: {},
    createdAt: now,
    expiresAt: now + ttl,
  })
}

/**
 * Is this request from the browser that registered `user`? Consumes the binding either way, so a
 * nonce answers once. A nonce bound to ANOTHER account is never a match.
 */
async function sameRegisteringBrowser(
  deps: AuthDeps,
  req: AuthRequest,
  user: UserRecord,
): Promise<boolean> {
  const nonce = parseSecret(req.cookies.get(registrationCookie(deps)))
  if (nonce === undefined) return false
  const record = await deps.store.findOneTime(
    deps.keys.digest('registration-nonce', nonce),
    'registration',
  )
  if (!record || record.userId !== user.id) return false
  const consumed = await deps.store.consumeOneTime(record.digest, 'registration')
  req.cookies.clear(registrationCookie(deps))
  return consumed !== undefined && consumed.expiresAt > deps.clock.now()
}

/** What {@link proveMailbox} did. */
export interface MailboxProof {
  /** The user after the proof. */
  readonly user: UserRecord
  /** A password-reset token for the owner's new password, when a pre-verification one was wiped. */
  readonly setPasswordToken: string | undefined
}

/**
 * The FIRST proof that someone controls the mailbox (the verification link or an email-link
 * sign-in) of an account that was registered but never verified (CONSISTENCY #114).
 *
 * Why wipe: anyone can register a victim's address with a password the ATTACKER knows ("account
 * pre-hijacking"). The victim later proves the mailbox and adopts the account, so whatever existed
 * before that proof was set by an unknown party. The pre-verification password, every session,
 * every token and every outstanding link are cleared (revoke first, then mark verified), and the
 * owner sets a new password with the returned reset token.
 *
 * The exception (#122) keeps normal sign-ups friction-free: a verification link opened in the SAME
 * browser that registered (`sameBrowser`, proven by the registration nonce cookie) keeps the
 * chosen password, because whoever chose it also holds the mailbox. An email-link sign-in always
 * wipes: it carries no registration binding.
 *
 * Only with `emailVerification` on: when it is off, `emailVerifiedAt` means nothing and nothing is
 * wiped. A verified account is returned unchanged.
 */
export async function proveMailbox(
  deps: AuthDeps,
  req: AuthRequest,
  user: UserRecord,
  options: { readonly sameBrowser?: boolean } = {},
): Promise<MailboxProof> {
  if (!deps.config.features.emailVerification || user.emailVerifiedAt !== null)
    return { user, setPasswordToken: undefined }
  if (options.sameBrowser === true) {
    // The link was opened in the browser that registered (#122): whoever chose the password also
    // holds the mailbox, so the password stays and there is no extra step.
    const now = deps.clock.now()
    await deps.store.updateUser(user.id, { emailVerifiedAt: now })
    await emit(deps, req, { type: 'email.verified', userId: user.id })
    return { user: { ...user, emailVerifiedAt: now }, setPasswordToken: undefined }
  }
  const sessions = await deps.store.deleteUserSessions(user.id)
  await deps.store.deleteUserTokens(user.id)
  await deps.store.deleteUserOneTime(user.id, 'password-reset')
  await deps.store.deleteUserOneTime(user.id, 'email-link')
  await deps.store.deleteUserOneTime(user.id, 'trusted-device')
  await deps.store.deleteUserOneTime(user.id, 'registration')
  const now = deps.clock.now()
  const hadPassword = user.passwordHash !== null
  await deps.store.updateUser(user.id, { passwordHash: null, emailVerifiedAt: now })
  if (sessions > 0)
    await emit(deps, req, { type: 'session.revoked', userId: user.id, count: sessions })
  await emit(deps, req, { type: 'email.verified', userId: user.id })
  let setPasswordToken: string | undefined
  if (hadPassword && deps.config.features.passwordLogin) {
    setPasswordToken = randomSecret()
    await deps.store.putOneTime({
      digest: deps.keys.digest('password-reset', setPasswordToken),
      purpose: 'password-reset',
      userId: user.id,
      payload: {},
      createdAt: now,
      expiresAt: now + deps.config.links.passwordResetMs,
    })
  }
  return { user: { ...user, passwordHash: null, emailVerifiedAt: now }, setPasswordToken }
}

/** What {@link VerificationService.verify} answers. */
export type VerifyResult =
  | { readonly status: 'verified' }
  /** A pre-verification password was wiped (#114): send the owner on to set one with `token`. */
  | { readonly status: 'set-password'; readonly token: string }

/** Email verification operations (feature `emailVerification`). */
export interface VerificationService {
  /**
   * Mail a fresh link to the signed-in user (throttled).
   *
   * @example
   * ```ts
   * await auth.verification.resend(req) // POST /email/verification-notification
   * ```
   */
  resend(req: AuthRequest): Promise<{ readonly status: 'sent' | 'already-verified' }>
  /**
   * Verify from the link's parts (route params + query). No session is needed: the signature is
   * the proof, so the link works on another device.
   *
   * @example
   * ```ts
   * await auth.verification.verify(req, { id, hash, expires: query.expires, signature: query.signature })
   * ```
   */
  verify(
    req: AuthRequest,
    parts: {
      readonly id: unknown
      readonly hash: unknown
      readonly expires: unknown
      readonly signature: unknown
    },
  ): Promise<VerifyResult>
  /** Throw `EMAIL_NOT_VERIFIED` when verification is on and `user` has not verified (the `verified` guard). */
  assertVerified(user: UserRecord): void
}

/** Build the {@link VerificationService}. */
export function verificationService(deps: AuthDeps): VerificationService {
  return {
    async resend(req) {
      requireFeature(deps, 'emailVerification')
      const { user } = await requireActive(deps, req)
      if (user.emailVerifiedAt !== null) return { status: 'already-verified' }
      // A cooldown between sends (only a successful send starts it), then an hourly cap.
      const retry = await mailVerificationLink(deps, user)
      if (retry !== undefined) throw new AuthError('RATE_LIMITED', { retryAfterSeconds: retry })
      return { status: 'sent' }
    },

    async verify(req, parts) {
      requireFeature(deps, 'emailVerification')
      const link = parseVerificationLink(parts)
      if (!link) throw new AuthError('INVALID_TOKEN')
      if (!safeEqual(link.signature, sign(deps, link.id, link.hash, link.expires)))
        throw new AuthError('INVALID_TOKEN')
      if (link.expires * 1000 <= deps.clock.now()) throw new AuthError('INVALID_TOKEN')
      const user = await deps.store.findUserById(link.id)
      if (!user || !safeEqual(link.hash, emailHash(deps, user.email)))
        throw new AuthError('INVALID_TOKEN')
      if (user.emailVerifiedAt !== null) return { status: 'verified' }
      const proof = await proveMailbox(deps, req, user, {
        sameBrowser: await sameRegisteringBrowser(deps, req, user),
      })
      return proof.setPasswordToken === undefined
        ? { status: 'verified' }
        : { status: 'set-password', token: proof.setPasswordToken }
    },

    assertVerified(user) {
      if (deps.config.features.emailVerification && user.emailVerifiedAt === null)
        throw new AuthError('EMAIL_NOT_VERIFIED')
    },
  }
}
