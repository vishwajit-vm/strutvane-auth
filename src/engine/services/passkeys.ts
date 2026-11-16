/**
 * Passkeys (WebAuthn) with `@simplewebauthn/server` 14.1.0 (MIT; npm, checked 2026-11-15).
 *
 * Three uses of one credential:
 * - **passwordless sign-in** (`mode: 'passwordless'`): a discoverable credential with user
 *   verification REQUIRED. A passkey with user verification is already two factors (the device and
 *   its PIN or biometric), so it signs in fully, without a TOTP challenge;
 * - **second factor** (`mode: 'second-factor'`): during a pending two-factor sign-in, the user's own
 *   passkey answers the challenge instead of a TOTP code;
 * - **confirm** (`mode: 'confirm'`): opens the password-confirmation window, so passwordless
 *   accounts can still reach sensitive settings.
 *
 * Challenges are single-use: each options call stores the challenge under a random nonce cookie
 * (as a keyed digest, 5 minutes) and the verify call consumes it atomically, so a captured response
 * cannot be replayed. The signature counter is checked by the library and stored after each use.
 *
 * The WebAuthn user handle is `HMAC(subkey, userId)`: stable per user, reveals nothing, and needs
 * no extra column (Fortify's `user_handle_secret`).
 *
 * @module
 */
import { createHmac } from 'node:crypto'
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server'
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server'
import type { PasskeyConfig } from '../config.ts'
import { type AuthDeps, cookieName, emit, requireFeature } from '../core/deps.ts'
import {
  assertNotImpersonating,
  readSession,
  requireActive,
  requireRecentConfirmation,
  startSession,
} from '../core/sessions.ts'
import {
  completeFirstFactor,
  completeSecondFactor,
  hasTwoFactor,
  type SignInResult,
} from '../core/sign-in.ts'
import { newId, randomSecret } from '../crypto/random.ts'
import { AuthError } from '../errors.ts'
import { rateLimitSubject } from '../limits/ip.ts'
import type { AuthRequest } from '../ports/cookies.ts'
import type { OneTimePurpose, PasskeyRecord } from '../ports/store.ts'
import { parseSecret } from '../tokens/formats.ts'

/** How an authentication ceremony will be used. */
export type PasskeyMode = 'passwordless' | 'second-factor' | 'confirm'

/** A passkey as shown in settings (no key material). */
export interface PasskeyView {
  readonly id: string
  readonly name: string
  readonly createdAt: number
  readonly lastUsedAt: number | null
  readonly backedUp: boolean
}

/** Passkey operations (feature `passkeys`). */
export interface PasskeyService {
  /**
   * Options for `navigator.credentials.create()` (needs a recent password confirmation).
   *
   * @example
   * ```ts
   * const options = await auth.passkeys.registrationOptions(req)
   * // browser: startRegistration({ optionsJSON: options })
   * ```
   */
  registrationOptions(req: AuthRequest): Promise<PublicKeyCredentialCreationOptionsJSON>
  /** Verify the browser's answer and save the passkey under `name`. */
  register(
    req: AuthRequest,
    input: { readonly response: unknown; readonly name?: unknown },
  ): Promise<PasskeyView>
  /** Options for `navigator.credentials.get()`. */
  authenticationOptions(
    req: AuthRequest,
    input: { readonly mode: PasskeyMode },
  ): Promise<PublicKeyCredentialRequestOptionsJSON>
  /**
   * Verify the browser's answer for the ceremony started by {@link authenticationOptions}.
   *
   * @example
   * ```ts
   * const r = await auth.passkeys.authenticate(req, { response })
   * ```
   */
  authenticate(
    req: AuthRequest,
    input: { readonly response: unknown; readonly remember?: unknown },
  ): Promise<SignInResult | { readonly status: 'confirmed' }>
  list(req: AuthRequest): Promise<readonly PasskeyView[]>
  rename(req: AuthRequest, input: { readonly id: unknown; readonly name: unknown }): Promise<void>
  /** Remove one passkey (needs a recent password confirmation). */
  remove(req: AuthRequest, input: { readonly id: unknown }): Promise<void>
}

const CHALLENGE_MS = 5 * 60_000

const view = (p: PasskeyRecord): PasskeyView => ({
  id: p.id,
  name: p.name,
  createdAt: p.createdAt,
  lastUsedAt: p.lastUsedAt,
  backedUp: p.backedUp,
})

function parseName(value: unknown, fallback: string): string {
  if (value === undefined) return fallback
  if (typeof value !== 'string' || value.trim().length < 1 || value.trim().length > 100)
    throw new AuthError('validation_failed', { issues: [{ field: 'name', code: 'invalid' }] })
  return value.trim()
}

/** Loose structural check before handing untrusted JSON to the library. */
function isCredentialJson(
  value: unknown,
): value is { readonly id: string; readonly response: Record<string, unknown> } {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  return (
    typeof v['id'] === 'string' &&
    v['id'].length <= 1024 &&
    typeof v['response'] === 'object' &&
    v['response'] !== null
  )
}

/** Build the {@link PasskeyService}. */
export function passkeyService(deps: AuthDeps): PasskeyService {
  const nonceCookie = cookieName(deps, 'webauthn')
  const rp = (): PasskeyConfig => {
    const config = deps.config.passkeys
    if (!config) throw new AuthError('not_found')
    return config
  }
  const userHandle = (userId: string): Uint8Array<ArrayBuffer> =>
    new Uint8Array(
      createHmac('sha256', deps.keys.subkey('webauthn-user-handle')).update(userId).digest(),
    )

  /** Store a challenge under a fresh nonce cookie. */
  const putChallenge = async (
    req: AuthRequest,
    purpose: OneTimePurpose,
    userId: string | null,
    payload: Record<string, string>,
  ): Promise<void> => {
    const nonce = randomSecret()
    const now = deps.clock.now()
    await deps.store.putOneTime({
      digest: deps.keys.digest('webauthn-nonce', nonce),
      purpose,
      userId,
      payload,
      createdAt: now,
      expiresAt: now + CHALLENGE_MS,
    })
    req.cookies.set(nonceCookie, nonce, { maxAgeSeconds: CHALLENGE_MS / 1000 })
  }

  /** Consume the challenge this browser started; always single-use. */
  const takeChallenge = async (req: AuthRequest, purpose: OneTimePurpose) => {
    const nonce = parseSecret(req.cookies.get(nonceCookie))
    req.cookies.clear(nonceCookie)
    if (nonce === undefined) throw new AuthError('invalid_token')
    const record = await deps.store.consumeOneTime(
      deps.keys.digest('webauthn-nonce', nonce),
      purpose,
    )
    if (!record || record.expiresAt <= deps.clock.now()) throw new AuthError('invalid_token')
    return record
  }

  const settings = async (req: AuthRequest) => {
    requireFeature(deps, 'passkeys')
    const active = await requireActive(deps, req)
    assertNotImpersonating(active)
    return active
  }

  return {
    async registrationOptions(req) {
      const active = await settings(req)
      requireRecentConfirmation(deps, active)
      const { user } = active
      const existing = await deps.store.listPasskeys(user.id)
      const options = await generateRegistrationOptions({
        rpName: rp().rpName,
        rpID: rp().rpId,
        userName: user.email,
        userDisplayName: user.name,
        userID: userHandle(user.id),
        attestationType: 'none',
        excludeCredentials: existing.map((p) => ({
          id: p.credentialId,
          transports: [...p.transports],
        })),
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      })
      await putChallenge(req, 'webauthn-registration', user.id, { challenge: options.challenge })
      return options
    },

    async register(req, input) {
      const active = await settings(req)
      const challenge = await takeChallenge(req, 'webauthn-registration')
      if (challenge.userId !== active.user.id) throw new AuthError('invalid_token')
      if (!isCredentialJson(input.response))
        throw new AuthError('validation_failed', {
          issues: [{ field: 'response', code: 'invalid' }],
        })
      let verified: Awaited<ReturnType<typeof verifyRegistrationResponse>>
      try {
        verified = await verifyRegistrationResponse({
          response: input.response as unknown as RegistrationResponseJSON,
          expectedChallenge: challenge.payload['challenge'] ?? '',
          expectedOrigin: [...rp().origins],
          expectedRPID: rp().rpId,
          requireUserVerification: true,
        })
      } catch {
        throw new AuthError('invalid_code')
      }
      if (!verified.verified) throw new AuthError('invalid_code')
      const { credential, credentialBackedUp } = verified.registrationInfo
      if (await deps.store.findPasskeyByCredentialId(credential.id)) throw new AuthError('conflict')
      const count = (await deps.store.listPasskeys(active.user.id)).length
      const record: PasskeyRecord = {
        id: newId(),
        userId: active.user.id,
        name: parseName(input.name, `Passkey ${count + 1}`),
        credentialId: credential.id,
        publicKey: Buffer.from(credential.publicKey).toString('base64url'),
        counter: credential.counter,
        transports: credential.transports ?? [],
        backedUp: credentialBackedUp,
        createdAt: deps.clock.now(),
        lastUsedAt: null,
      }
      await deps.store.addPasskey(record)
      await emit(deps, req, { type: 'passkey.added', userId: active.user.id, passkeyId: record.id })
      return view(record)
    },

    async authenticationOptions(req, input) {
      requireFeature(deps, 'passkeys')
      const retry = await deps.limiter.hit([
        [`passkey:ip:${rateLimitSubject(req.ip)}`, deps.config.limits.passkeyPerIp],
      ])
      if (retry !== undefined) throw new AuthError('rate_limited', { retryAfterSeconds: retry })
      let userId: string | null = null
      if (input.mode === 'second-factor') {
        const pending = await readSession(deps, req)
        if (pending?.state !== 'two-factor') throw new AuthError('unauthenticated')
        userId = pending.userId
      } else if (input.mode === 'confirm') {
        userId = (await settings(req)).user.id
      } else if (input.mode !== 'passwordless') {
        throw new AuthError('validation_failed', { issues: [{ field: 'mode', code: 'invalid' }] })
      }
      const allow = userId === null ? [] : await deps.store.listPasskeys(userId)
      const options = await generateAuthenticationOptions({
        rpID: rp().rpId,
        allowCredentials: allow.map((p) => ({ id: p.credentialId, transports: [...p.transports] })),
        userVerification: input.mode === 'second-factor' ? 'preferred' : 'required',
      })
      await putChallenge(req, 'webauthn-authentication', userId, {
        challenge: options.challenge,
        mode: input.mode,
      })
      return options
    },

    async authenticate(req, input) {
      requireFeature(deps, 'passkeys')
      const challenge = await takeChallenge(req, 'webauthn-authentication')
      const mode = challenge.payload['mode']
      if (!isCredentialJson(input.response))
        throw new AuthError('validation_failed', {
          issues: [{ field: 'response', code: 'invalid' }],
        })
      const response = input.response as unknown as AuthenticationResponseJSON
      const passkey = await deps.store.findPasskeyByCredentialId(response.id)
      // A second-factor or confirm ceremony must be answered with THIS user's passkey.
      if (!passkey || (challenge.userId !== null && passkey.userId !== challenge.userId))
        throw new AuthError('invalid_code')
      const handle = response.response.userHandle
      if (
        handle !== undefined &&
        handle !== Buffer.from(userHandle(passkey.userId)).toString('base64url')
      )
        throw new AuthError('invalid_code')
      let verified: Awaited<ReturnType<typeof verifyAuthenticationResponse>>
      try {
        verified = await verifyAuthenticationResponse({
          response,
          expectedChallenge: challenge.payload['challenge'] ?? '',
          expectedOrigin: [...rp().origins],
          expectedRPID: rp().rpId,
          credential: {
            id: passkey.credentialId,
            publicKey: new Uint8Array(Buffer.from(passkey.publicKey, 'base64url')),
            counter: passkey.counter,
            transports: [...passkey.transports],
          },
          requireUserVerification: mode !== 'second-factor',
        })
      } catch {
        throw new AuthError('invalid_code')
      }
      if (!verified.verified) throw new AuthError('invalid_code')
      const now = deps.clock.now()
      // Compare-and-set on the counter the verification used: of two concurrent sign-ins with the
      // same counter (a clone racing the original), only one may record it (CONSISTENCY #117).
      const advanced = await deps.store.advancePasskeyCounter(passkey.id, passkey.counter, {
        counter: verified.authenticationInfo.newCounter,
        lastUsedAt: now,
        backedUp: verified.authenticationInfo.credentialBackedUp,
      })
      if (!advanced) throw new AuthError('invalid_code')
      const user = await deps.store.findUserById(passkey.userId)
      if (!user) throw new AuthError('invalid_code')

      if (mode === 'confirm') {
        const active = await settings(req)
        if (active.user.id !== user.id) throw new AuthError('invalid_code')
        await deps.store.updateSession(active.session.digest, { passwordConfirmedAt: now })
        return { status: 'confirmed' }
      }
      if (mode === 'second-factor') {
        const pending = await readSession(deps, req)
        if (pending?.state !== 'two-factor' || pending.userId !== user.id)
          throw new AuthError('unauthenticated')
        return completeSecondFactor(deps, req, pending, 'passkey')
      }
      // Passwordless: user verification already made this two factors. Do not route through the
      // TOTP gate, but do record that a 2FA user signed in with a strong factor.
      const remember = input.remember === true
      if (hasTwoFactor(deps, user)) {
        await completeSecondFactorDirect(deps, req, user.id, remember)
        return { status: 'signed-in' }
      }
      return completeFirstFactor(deps, req, user, 'passkey', remember)
    },

    async list(req) {
      const active = await settings(req)
      return (await deps.store.listPasskeys(active.user.id)).map(view)
    },

    async rename(req, input) {
      const active = await settings(req)
      const passkeys = await deps.store.listPasskeys(active.user.id)
      const target = passkeys.find((p) => p.id === input.id)
      if (!target) throw new AuthError('not_found')
      await deps.store.updatePasskey(target.id, { name: parseName(input.name, target.name) })
    },

    async remove(req, input) {
      const active = await settings(req)
      requireRecentConfirmation(deps, active)
      if (
        typeof input.id !== 'string' ||
        !(await deps.store.deletePasskey(active.user.id, input.id))
      )
        throw new AuthError('not_found')
      await emit(deps, req, {
        type: 'passkey.removed',
        userId: active.user.id,
        passkeyId: input.id,
      })
    },
  }
}

/** A passkey sign-in for a 2FA user: a full session, logged as passkey + passkey. */
async function completeSecondFactorDirect(
  deps: AuthDeps,
  req: AuthRequest,
  userId: string,
  remember: boolean,
): Promise<void> {
  await startSession(deps, req, { userId, state: 'active', method: 'passkey', remember })
  await emit(deps, req, { type: 'login', userId, method: 'passkey', secondFactor: 'passkey' })
}
