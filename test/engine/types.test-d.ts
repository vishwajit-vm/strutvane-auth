/**
 * Type-level tests: checked by `tsc --noEmit` (part of `npm test`), never executed. Each
 * `@ts-expect-error` proves a misuse does not compile; if the types loosen, the directive itself
 * becomes an error ("unused @ts-expect-error") and the typecheck fails.
 */
import { describe, expectTypeOf, it } from 'vitest'
import type { Auth, AuthState } from '../../src/engine/auth.ts'
import { defineAuthConfig } from '../../src/engine/config.ts'
import type { SignInResult } from '../../src/engine/core/sign-in.ts'
import { AuthError, type AuthErrorCode } from '../../src/engine/errors.ts'
import type { AuthEvent } from '../../src/engine/ports/events.ts'
import type { AuthMail } from '../../src/engine/ports/mailer.ts'
import type { SessionPatch, UserPatch } from '../../src/engine/ports/store.ts'
import type { PasskeyMode } from '../../src/engine/services/passkeys.ts'

function configTypes(): void {
  defineAuthConfig({
    appUrl: 'https://x.test',
    features: { twoFactor: true },
    roles: 'admin-manager-member-viewer',
  })
  // @ts-expect-error an unknown feature switch is a compile error, not a silently ignored key
  defineAuthConfig({ appUrl: 'https://x.test', features: { magicLogin: true } })
  // @ts-expect-error role presets are a closed set
  defineAuthConfig({ appUrl: 'https://x.test', roles: 'everyone-is-admin' })
  // @ts-expect-error appUrl is required (links and cookie security derive from it)
  defineAuthConfig({ features: {} })
  // @ts-expect-error feature switches are booleans
  defineAuthConfig({ appUrl: 'https://x.test', features: { registration: 'yes' } })
}

function eventTypes(): AuthEvent[] {
  const ok: AuthEvent = {
    type: 'login',
    at: 1,
    ip: null,
    actorId: null,
    subjectId: 'u',
    userId: 'u',
    method: 'password',
    secondFactor: null,
  }
  const leaky: AuthEvent = {
    type: 'login',
    at: 1,
    ip: null,
    actorId: null,
    subjectId: 'u',
    userId: 'u',
    method: 'password',
    secondFactor: null,
    // @ts-expect-error events have no free-form fields, so a secret cannot ride along
    password: 'x',
  }
  const tokenLeak: AuthEvent = {
    type: 'token.created',
    at: 1,
    ip: null,
    actorId: null,
    subjectId: 'u',
    userId: 'u',
    tokenId: 't',
    // @ts-expect-error a token event carries the token ID, never the token
    plainText: 'svp_x',
  }
  const unknown: AuthEvent = {
    // @ts-expect-error unknown event types do not exist
    type: 'password.leaked',
    at: 1,
    ip: null,
    actorId: null,
    subjectId: null,
  }
  return [ok, leaky, tokenLeak, unknown]
}

function mailTypes(): AuthMail[] {
  const ok: AuthMail = {
    kind: 'password-reset',
    to: 'a@b.io',
    userId: 'u',
    url: 'https://x.test/reset-password/t',
  }
  // @ts-expect-error a reset mail needs its link
  const noUrl: AuthMail = { kind: 'password-reset', to: 'a@b.io', userId: 'u' }
  return [ok, noUrl]
}

function resultNarrowing(result: SignInResult): number {
  // @ts-expect-error methods only exist once narrowed to two-factor-required
  const before = result.methods
  if (result.status === 'two-factor-required')
    return result.methods.length + (before === undefined ? 0 : 1)
  return 0
}

function errorCodes(): void {
  const code: AuthErrorCode = 'rate_limited'
  new AuthError(code)
  // @ts-expect-error error codes are a closed, stable set
  new AuthError('SOMETHING_ELSE')
}

function storePatches(): void {
  const user: UserPatch = { passwordHash: null, twoFactorConfirmedAt: 1 }
  // @ts-expect-error a user patch cannot change the id
  const id: UserPatch = { id: 'other' }
  // @ts-expect-error nor the email (address changes need their own verified flow)
  const email: UserPatch = { email: 'attacker@evil.test' }
  const session: SessionPatch = { lastSeenAt: 1 }
  // @ts-expect-error a session patch cannot move a session to another user
  const hijack: SessionPatch = { userId: 'victim' }
  // @ts-expect-error nor set the impersonator
  const imp: SessionPatch = { impersonatorId: 'admin' }
  void [user, id, email, session, hijack, imp]
}

function stateIsReadonly(state: AuthState, auth: Auth): void {
  // @ts-expect-error the state handed to the app is read-only
  state.user.id = 'someone-else'
  // @ts-expect-error the services object is frozen and read-only
  auth.passwords = { ...auth.passwords }
  const mode: PasskeyMode = 'passwordless'
  // @ts-expect-error ceremony modes are a closed set
  const bad: PasskeyMode = 'anything'
  void [mode, bad]
}

describe('engine: misuse that must not compile', () => {
  it('every check above is a compile-time check (an unused @ts-expect-error fails the typecheck)', () => {
    for (const check of [
      configTypes,
      eventTypes,
      mailTypes,
      resultNarrowing,
      errorCodes,
      storePatches,
      stateIsReadonly,
    ])
      expectTypeOf(check).toBeFunction()
  })
})
