/**
 * Two-factor authentication: TOTP (RFC 6238), recovery codes and "remember this device".
 *
 * - **Encrypted at rest:** the TOTP secret is AES-256-GCM ciphertext bound to the user id.
 * - **Confirm before enabling:** `enable()` stores an UNCONFIRMED secret; 2FA is enforced only after
 *   `confirm()` proves the authenticator produces valid codes (Fortify's `confirm: true`).
 * - **Replay protection:** a code's time step must be newer than the last accepted one, enforced by
 *   the store's atomic `advanceTotpStep`, so the same code (or an older one) never works twice.
 * - **Recovery codes:** 10 by default (8–10), ~50 bits each, shown once, stored as keyed digests,
 *   single-use by atomic delete; regenerating replaces them all.
 * - **Limits:** the second-factor limiter and lockout key on the ACCOUNT, not the pending session,
 *   so starting a fresh sign-in does not reset the budget (review F-09).
 * - Turning 2FA on or off, or regenerating codes, needs a recent password confirmation and rotates
 *   the session id.
 *
 * @module
 */
import { randomBytes } from 'node:crypto'
import { type AuthDeps, emit, requireFeature } from '../core/deps.ts'
import {
  type ActiveSession,
  assertNotImpersonating,
  readSession,
  requireActive,
  requireRecentConfirmation,
  rotateSession,
} from '../core/sessions.ts'
import { completeSecondFactor, deviceCookie, type SignInResult } from '../core/sign-in.ts'
import { open, seal } from '../crypto/aead.ts'
import { base32Encode, randomCode, randomSecret } from '../crypto/random.ts'
import { AuthError } from '../errors.ts'
import type { AuthRequest } from '../ports/cookies.ts'
import type { UserRecord } from '../ports/store.ts'
import { formatRecoveryCode, parseRecoveryCode, parseTotpCode } from '../tokens/formats.ts'
import { otpauthUri, verifyTotp } from '../totp/totp.ts'

/** What {@link TwoFactorService.enable} returns: show the QR code and the text secret once. */
export interface TwoFactorSetup {
  /** base32, for manual entry. */
  readonly secret: string
  /** Draw it as a QR code. */
  readonly otpauthUri: string
}

/** Input for {@link TwoFactorService.challenge}: exactly one of `code` or `recoveryCode`. */
export interface ChallengeInput {
  readonly code?: unknown
  readonly recoveryCode?: unknown
  /** Skip 2FA on this browser for the configured number of days. */
  readonly rememberDevice?: unknown
}

/** Two-factor operations (feature `twoFactor`). */
export interface TwoFactorService {
  /**
   * Start setup: a new secret, not enforced until confirmed.
   *
   * @example
   * ```ts
   * const { otpauthUri } = await auth.twoFactor.enable(req) // POST /user/two-factor-authentication
   * ```
   */
  enable(req: AuthRequest): Promise<TwoFactorSetup>
  /**
   * Prove the authenticator works; turns 2FA on and returns the recovery codes (shown once).
   *
   * @example
   * ```ts
   * const { recoveryCodes } = await auth.twoFactor.confirm(req, { code: '123456' })
   * ```
   */
  confirm(
    req: AuthRequest,
    input: { readonly code: unknown },
  ): Promise<{ readonly recoveryCodes: readonly string[] }>
  /** Turn 2FA off (needs a recent password confirmation). Forgets remembered devices. */
  disable(req: AuthRequest): Promise<void>
  /** Replace every recovery code (needs a recent password confirmation). */
  regenerateRecoveryCodes(req: AuthRequest): Promise<{ readonly recoveryCodes: readonly string[] }>
  /** How many unused recovery codes the signed-in user has left. */
  remainingRecoveryCodes(req: AuthRequest): Promise<number>
  /**
   * Answer the pending sign-in's challenge with a TOTP code or a recovery code.
   *
   * @example
   * ```ts
   * await auth.twoFactor.challenge(req, { code: '123456', rememberDevice: true })
   * ```
   */
  challenge(req: AuthRequest, input: ChallengeInput): Promise<SignInResult>
}

/** Build the {@link TwoFactorService}. */
export function twoFactorService(deps: AuthDeps): TwoFactorService {
  const secretKey = (): Buffer => deps.keys.subkey('two-factor-secret')

  const settingsSession = async (req: AuthRequest): Promise<ActiveSession> => {
    requireFeature(deps, 'twoFactor')
    const active = await requireActive(deps, req)
    assertNotImpersonating(active)
    return active
  }

  const newRecoveryCodes = async (userId: string): Promise<string[]> => {
    const codes = Array.from({ length: deps.config.twoFactor.recoveryCodes }, () => randomCode(10))
    await deps.store.replaceRecoveryCodes(
      userId,
      codes.map((c) => deps.keys.digest('recovery-code', `${userId}:${c}`)),
    )
    return codes.map(formatRecoveryCode)
  }

  /** Check a TOTP code and claim its time step atomically. */
  const acceptTotp = async (user: UserRecord, code: string): Promise<boolean> => {
    if (user.twoFactorSecret === null) return false
    const secret = open(secretKey(), user.twoFactorSecret, user.id)
    if (secret === undefined) return false
    const step = verifyTotp(Buffer.from(secret, 'base64url'), code, deps.clock.now())
    return step !== undefined && (await deps.store.advanceTotpStep(user.id, step))
  }

  /** Account-keyed limit + lockout around a second-factor attempt. */
  const guarded = async (
    req: AuthRequest,
    user: UserRecord,
    attempt: () => Promise<boolean>,
  ): Promise<void> => {
    const key = `2fa:${user.id}`
    const fail = (reason: 'invalid-code' | 'locked' | 'rate-limited') =>
      emit(deps, req, {
        type: 'login.failed',
        stage: 'second-factor',
        reason,
        userId: user.id,
        emailDigest: null,
      })
    const locked = await deps.lockout.lockedFor(key)
    if (locked !== undefined) {
      await fail('locked')
      throw new AuthError('rate_limited', { retryAfterSeconds: locked })
    }
    const retry = await deps.limiter.hit([[key, deps.config.limits.twoFactorPerAccount]])
    if (retry !== undefined) {
      await fail('rate-limited')
      throw new AuthError('rate_limited', { retryAfterSeconds: retry })
    }
    if (!(await attempt())) {
      await fail('invalid-code')
      const lockedFor = await deps.lockout.fail(key)
      if (lockedFor !== undefined)
        await emit(deps, req, {
          type: 'lockout',
          scope: 'two-factor',
          emailDigest: null,
          userId: user.id,
          seconds: lockedFor,
        })
      throw new AuthError('invalid_code')
    }
    await deps.lockout.succeed(key)
  }

  return {
    async enable(req) {
      const active = await settingsSession(req)
      requireRecentConfirmation(deps, active)
      const { user } = active
      if (user.twoFactorConfirmedAt !== null) throw new AuthError('conflict')
      const secret = randomBytes(20)
      await deps.store.updateUser(user.id, {
        twoFactorSecret: seal(secretKey(), secret.toString('base64url'), user.id),
        twoFactorConfirmedAt: null,
        twoFactorLastStep: null,
      })
      return {
        secret: base32Encode(secret),
        otpauthUri: otpauthUri({
          secret,
          issuer: deps.config.twoFactor.issuer,
          account: user.email,
        }),
      }
    },

    async confirm(req, input) {
      const active = await settingsSession(req)
      const { user } = active
      if (user.twoFactorSecret === null || user.twoFactorConfirmedAt !== null)
        throw new AuthError('conflict')
      const code = parseTotpCode(input.code)
      await guarded(req, user, async () => code !== undefined && (await acceptTotp(user, code)))
      // Codes FIRST, the switch LAST: a storage failure in between must not turn 2FA on with no
      // recovery codes (a lost phone would then lock the user out). A retry replaces the codes.
      const recoveryCodes = await newRecoveryCodes(user.id)
      await deps.store.updateUser(user.id, { twoFactorConfirmedAt: deps.clock.now() })
      await rotateSession(deps, req, active.session)
      await emit(deps, req, { type: 'two-factor.enabled', userId: user.id })
      return { recoveryCodes }
    },

    async disable(req) {
      const active = await settingsSession(req)
      requireRecentConfirmation(deps, active)
      const { user } = active
      await deps.store.updateUser(user.id, {
        twoFactorSecret: null,
        twoFactorConfirmedAt: null,
        twoFactorLastStep: null,
      })
      await deps.store.replaceRecoveryCodes(user.id, [])
      await deps.store.deleteUserOneTime(user.id, 'trusted-device')
      req.cookies.clear(deviceCookie(deps))
      await rotateSession(deps, req, active.session)
      await emit(deps, req, { type: 'two-factor.disabled', userId: user.id })
    },

    async regenerateRecoveryCodes(req) {
      const active = await settingsSession(req)
      requireRecentConfirmation(deps, active)
      if (active.user.twoFactorConfirmedAt === null) throw new AuthError('conflict')
      const recoveryCodes = await newRecoveryCodes(active.user.id)
      await emit(deps, req, { type: 'recovery-codes.regenerated', userId: active.user.id })
      return { recoveryCodes }
    },

    async remainingRecoveryCodes(req) {
      const active = await settingsSession(req)
      return deps.store.countRecoveryCodes(active.user.id)
    },

    async challenge(req, input) {
      requireFeature(deps, 'twoFactor')
      const pending = await readSession(deps, req)
      if (pending?.state !== 'two-factor') throw new AuthError('unauthenticated')
      const user = await deps.store.findUserById(pending.userId)
      if (!user || user.twoFactorConfirmedAt === null) throw new AuthError('unauthenticated')
      let factor: 'totp' | 'recovery-code'
      if (input.code !== undefined) {
        factor = 'totp'
        const code = parseTotpCode(input.code)
        await guarded(req, user, async () => code !== undefined && (await acceptTotp(user, code)))
      } else if (input.recoveryCode !== undefined) {
        factor = 'recovery-code'
        const code = parseRecoveryCode(input.recoveryCode)
        await guarded(
          req,
          user,
          async () =>
            code !== undefined &&
            (await deps.store.consumeRecoveryCode(
              user.id,
              deps.keys.digest('recovery-code', `${user.id}:${code}`),
            )),
        )
        await emit(deps, req, {
          type: 'recovery-code.used',
          userId: user.id,
          remaining: await deps.store.countRecoveryCodes(user.id),
        })
      } else {
        throw new AuthError('validation_failed', { issues: [{ field: 'code', code: 'required' }] })
      }
      if (input.rememberDevice === true && deps.config.twoFactor.rememberDeviceMs > 0) {
        const raw = randomSecret()
        const now = deps.clock.now()
        await deps.store.putOneTime({
          digest: deps.keys.digest('trusted-device', raw),
          purpose: 'trusted-device',
          userId: user.id,
          payload: {},
          createdAt: now,
          expiresAt: now + deps.config.twoFactor.rememberDeviceMs,
        })
        req.cookies.set(deviceCookie(deps), raw, {
          maxAgeSeconds: Math.floor(deps.config.twoFactor.rememberDeviceMs / 1000),
        })
      }
      return completeSecondFactor(deps, req, pending, factor)
    },
  }
}
