/**
 * Email + password: registration, sign-in, sign-out, password change and password confirmation.
 *
 * Sign-in is timing-safe and never says which part was wrong:
 * 1. rate limits (per IP /64 and per account digest) and the lockout are checked BEFORE hashing;
 * 2. the password is verified against the stored hash, or against a dummy hash with the same cost
 *    when there is no user or no password, so known and unknown emails take the same time;
 * 3. every failure is the same `INVALID_CREDENTIALS`, for a missing account, a passwordless
 *    account and a wrong password alike;
 * 4. on success, an outdated hash is upgraded (rehash-on-login) and the lockout resets.
 *
 * @module
 */

import { type AuthDeps, accountKey, emit, requireFeature, sendMail } from '../core/deps.ts'
import {
  type ActiveSession,
  assertNotImpersonating,
  endSession,
  requireActive,
  requireRecentConfirmation,
  rotateSession,
  startSession,
} from '../core/sessions.ts'
import { completeFirstFactor, deviceCookie, type SignInResult } from '../core/sign-in.ts'
import { newId } from '../crypto/random.ts'
import { AuthError, type AuthIssue } from '../errors.ts'
import { rateLimitSubject } from '../limits/ip.ts'
import { parseEmail } from '../password/email.ts'
import { assertPasswordAllowed, passwordLengthOk } from '../password/rules.ts'
import type { AuthRequest } from '../ports/cookies.ts'
import type { UserRecord } from '../ports/store.ts'
import { createPersonalTeam } from './teams.ts'
import { bindRegistration, remindToVerify, verificationUrl } from './verification.ts'

/** Input for {@link PasswordService.login}. */
export interface LoginInput {
  readonly email: unknown
  readonly password: unknown
  readonly remember?: unknown
}

/** Input for {@link PasswordService.register}. */
export interface RegisterInput {
  readonly name: unknown
  readonly email: unknown
  /** Required when password sign-in is on; ignored for email-link-only apps. */
  readonly password?: unknown
}

/**
 * What registration answers. With email verification on, the answer is ALWAYS
 * `verification-sent`, whether the address was free or taken, so registration cannot be used to
 * find out who has an account (the owner of a taken address gets a "you already have an account"
 * mail instead).
 */
export type RegisterResult =
  | { readonly status: 'verification-sent' }
  | { readonly status: 'signed-in' }

/** Email + password operations. */
export interface PasswordService {
  /**
   * Public sign-up (feature `registration`, off by default).
   *
   * @example
   * ```ts
   * await auth.passwords.register(req, { name: 'Ada', email: 'ada@acme.test', password: 'a long passphrase' })
   * ```
   */
  register(req: AuthRequest, input: RegisterInput): Promise<RegisterResult>
  /**
   * Sign in with email and password; may answer `two-factor-required`.
   *
   * @example
   * ```ts
   * const r = await auth.passwords.login(req, { email, password, remember: true })
   * if (r.status === 'two-factor-required') redirect('/two-factor-challenge')
   * ```
   */
  login(req: AuthRequest, input: LoginInput): Promise<SignInResult>
  /** Sign out: the session is deleted server-side, so an old copy of the cookie stops working. */
  logout(req: AuthRequest): Promise<void>
  /**
   * Change the password from settings. Needs the current password (or, for an account that has
   * none yet, a recent confirmation by passkey). Revokes every OTHER session, outstanding reset
   * links and remembered devices, and rotates the current session id.
   */
  change(
    req: AuthRequest,
    input: { readonly current?: unknown; readonly password: unknown },
  ): Promise<void>
  /** "Confirm password" before a sensitive action; opens a 3-hour window on this session. */
  confirm(req: AuthRequest, input: { readonly password: unknown }): Promise<void>
}

function parseName(value: unknown): string {
  if (typeof value !== 'string')
    throw new AuthError('VALIDATION_FAILED', { issues: [{ field: 'name', code: 'required' }] })
  const name = value.trim()
  if (name.length < 1 || name.length > 200)
    throw new AuthError('VALIDATION_FAILED', { issues: [{ field: 'name', code: 'invalid' }] })
  return name
}

function requireEmail(value: unknown): string {
  const email = parseEmail(value)
  if (email === undefined)
    throw new AuthError('VALIDATION_FAILED', { issues: [{ field: 'email', code: 'invalid' }] })
  return email
}

async function limited(
  deps: AuthDeps,
  checks: Parameters<AuthDeps['limiter']['hit']>[0],
): Promise<void> {
  const retry = await deps.limiter.hit(checks)
  if (retry !== undefined) throw new AuthError('RATE_LIMITED', { retryAfterSeconds: retry })
}

/** Build the {@link PasswordService}. */
export function passwordService(deps: AuthDeps): PasswordService {
  const { limits } = deps.config

  const allowed = (password: unknown, field?: string): Promise<string> =>
    assertPasswordAllowed(password, {
      min: deps.config.passwords.min,
      max: deps.config.passwords.max,
      check: deps.passwordCheck,
      onUnknown: deps.passwordCheckOnUnknown,
      logger: deps.logger,
      ...(field !== undefined ? { field } : {}),
    })

  const verifyUserPassword = async (
    user: UserRecord | undefined,
    password: string,
  ): Promise<boolean> =>
    user?.passwordHash
      ? deps.hasher.verify(password, user.passwordHash)
      : deps.hasher.verifyDummy(password)

  /**
   * Check a signed-in user's CURRENT password (confirm, change). One shared per-account budget, so
   * a stolen session cannot brute-force the password through whichever endpoint is unlimited, and
   * the same length bound as sign-in before any hashing.
   */
  const checkCurrentPassword = async (
    active: ActiveSession,
    password: unknown,
    issues?: readonly AuthIssue[],
  ): Promise<void> => {
    await limited(deps, [[`confirm:${active.user.id}`, limits.confirmPasswordPerAccount]])
    const fail = () => new AuthError('INVALID_CREDENTIALS', issues ? { issues } : {})
    if (typeof password !== 'string' || !passwordLengthOk(password, deps.config.passwords.max))
      throw fail()
    if (!(await verifyUserPassword(active.user, password)) || active.user.passwordHash === null)
      throw fail()
  }

  return {
    async register(req, input) {
      requireFeature(deps, 'registration')
      await limited(deps, [[`register:ip:${rateLimitSubject(req.ip)}`, limits.registerPerIp]])
      const name = parseName(input.name)
      const email = requireEmail(input.email)
      // Always hash (when passwords are on), whether or not the email is taken: equal timing.
      const passwordHash = deps.config.features.passwordLogin
        ? await deps.hasher.hash(await allowed(input.password))
        : null
      const now = deps.clock.now()
      const existing = await deps.store.findUserByEmail(email)
      const created =
        existing === undefined
          ? await deps.store.createUser({
              id: newId(),
              email,
              name,
              passwordHash,
              emailVerifiedAt: null,
              twoFactorSecret: null,
              twoFactorConfirmedAt: null,
              twoFactorLastStep: null,
              currentTeamId: null,
              createdAt: now,
            })
          : undefined
      if (deps.config.features.emailVerification) {
        // Bind the registration to this browser (#122); a taken address gets the same cookie.
        await bindRegistration(deps, req, created)
        if (created) {
          if (deps.config.features.teams) await createPersonalTeam(deps, req, created)
          await emit(deps, req, { type: 'registered', userId: created.id })
          sendMail(deps, {
            kind: 'verify-email',
            to: created.email,
            userId: created.id,
            url: verificationUrl(deps, created),
          })
        } else {
          // Taken (or lost a race): tell the owner, answer exactly as for a new account.
          const owner = existing ?? (await deps.store.findUserByEmail(email))
          if (owner)
            sendMail(deps, { kind: 'registration-attempt', to: owner.email, userId: owner.id })
        }
        return { status: 'verification-sent' }
      }
      // Without verification there is no way to confirm the address, so a taken email has to be
      // reported (the documented, rate-limited enumeration of apps that skip verification).
      if (!created)
        throw new AuthError('EMAIL_TAKEN', { issues: [{ field: 'email', code: 'taken' }] })
      if (deps.config.features.teams) await createPersonalTeam(deps, req, created)
      await emit(deps, req, { type: 'registered', userId: created.id })
      await startSession(deps, req, {
        userId: created.id,
        state: 'active',
        method: 'password',
        remember: false,
      })
      await emit(deps, req, {
        type: 'login',
        userId: created.id,
        method: 'password',
        secondFactor: null,
      })
      return { status: 'signed-in' }
    },

    async login(req, input) {
      requireFeature(deps, 'passwordLogin')
      const email = requireEmail(input.email)
      if (
        typeof input.password !== 'string' ||
        !passwordLengthOk(input.password, deps.config.passwords.max)
      )
        throw new AuthError('VALIDATION_FAILED', {
          issues: [{ field: 'password', code: 'invalid' }],
        })
      const account = accountKey(deps, email)
      const fail = async (
        reason: 'invalid-credentials' | 'locked' | 'rate-limited' | 'email-not-verified',
        userId: string | null,
      ) =>
        emit(deps, req, {
          type: 'login.failed',
          stage: 'first-factor',
          reason,
          userId,
          emailDigest: account,
        })

      const retry = await deps.limiter.hit([
        [`login:ip:${rateLimitSubject(req.ip)}`, limits.loginPerIp],
        [`login:acct:${account}`, limits.loginPerAccount],
      ])
      if (retry !== undefined) {
        await fail('rate-limited', null)
        throw new AuthError('RATE_LIMITED', { retryAfterSeconds: retry })
      }
      const locked = await deps.lockout.lockedFor(`login:${account}`)
      if (locked !== undefined) {
        await fail('locked', null)
        throw new AuthError('RATE_LIMITED', { retryAfterSeconds: locked })
      }

      const user = await deps.store.findUserByEmail(email)
      const ok = await verifyUserPassword(user, input.password)
      if (!ok || !user || user.passwordHash === null) {
        await fail('invalid-credentials', user?.id ?? null)
        const lockedFor = await deps.lockout.fail(`login:${account}`)
        if (lockedFor !== undefined)
          await emit(deps, req, {
            type: 'lockout',
            scope: 'login',
            emailDigest: account,
            userId: user?.id ?? null,
            seconds: lockedFor,
          })
        throw new AuthError('INVALID_CREDENTIALS')
      }
      // With verification on, password sign-in waits for the mailbox proof (#114): until then the
      // password may be an attacker's (account pre-hijacking). Only a CORRECT password gets here, so
      // this answer is no enumeration oracle; the mail is re-sent (throttled), as there is no session.
      if (deps.config.features.emailVerification && user.emailVerifiedAt === null) {
        await fail('email-not-verified', user.id)
        await remindToVerify(deps, user)
        throw new AuthError('EMAIL_NOT_VERIFIED')
      }
      if (deps.hasher.needsRehash(user.passwordHash)) {
        await deps.store.updateUser(user.id, {
          passwordHash: await deps.hasher.hash(input.password),
        })
        await emit(deps, req, { type: 'password.rehashed', userId: user.id })
      }
      await deps.lockout.succeed(`login:${account}`)
      return completeFirstFactor(deps, req, user, 'password', input.remember === true)
    },

    async logout(req) {
      const ended = await endSession(deps, req)
      if (ended && ended.state === 'active')
        await emit(deps, req, { type: 'logout', userId: ended.userId })
    },

    async change(req, input) {
      requireFeature(deps, 'passwordLogin')
      const active = await requireActive(deps, req)
      assertNotImpersonating(active)
      const { user } = active
      if (user.passwordHash !== null) {
        await checkCurrentPassword(active, input.current, [{ field: 'current', code: 'mismatch' }])
      } else {
        requireRecentConfirmation(deps, active)
      }
      const password = await allowed(input.password)
      const hash = await deps.hasher.hash(password)
      // A password change ends everything a thief may hold: other sessions, outstanding reset
      // links (an old link must not reset the NEW password), remembered devices. Revoke FIRST and
      // write the new hash LAST, so a storage failure part-way never leaves the new password in
      // place with a thief's session still alive (fail closed).
      await deps.store.deleteUserOneTime(user.id, 'password-reset')
      await deps.store.deleteUserOneTime(user.id, 'trusted-device')
      req.cookies.clear(deviceCookie(deps))
      const revoked = await deps.store.deleteUserSessions(user.id, active.session.digest)
      await deps.store.updateUser(user.id, { passwordHash: hash })
      await rotateSession(deps, req, active.session)
      if (revoked > 0)
        await emit(deps, req, { type: 'session.revoked', userId: user.id, count: revoked })
      await emit(deps, req, { type: 'password.changed', userId: user.id, via: 'settings' })
      sendMail(deps, { kind: 'password-changed', to: user.email, userId: user.id })
    },

    async confirm(req, input) {
      const active = await requireActive(deps, req)
      // An impersonating admin does not know the user's password and must not gain the window.
      assertNotImpersonating(active)
      await checkCurrentPassword(active, input.password)
      await deps.store.updateSession(active.session.digest, {
        passwordConfirmedAt: deps.clock.now(),
      })
    },
  }
}
