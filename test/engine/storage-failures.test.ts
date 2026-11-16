/**
 * Storage failing part-way through a security-relevant flow must never leave a half-applied state
 * that is WEAKER than either the before or the after state. The store port has no transactions, so
 * each flow orders its writes to fail closed: revoke first, grant last.
 *
 * Each test makes one store method throw in turn and checks the invariant that must hold whatever
 * step failed.
 */
import { describe, expect, it } from 'vitest'
import { base32Decode } from '../../src/engine/crypto/random.ts'
import type { AuthStore } from '../../src/engine/ports/store.ts'
import { totp } from '../../src/engine/totp/totp.ts'
import { Browser, type Harness, harness, PASSWORD, STORES } from './helpers/harness.ts'

const NEW_PASSWORD = 'brand new passphrase 42'

/** Make `method` throw on its next call(s) (the services hold this same store object). */
function breakOnce(store: AuthStore, method: keyof AuthStore): void {
  const target = store as unknown as Record<string, unknown>
  target[method] = async () => {
    throw new Error(`storage down: ${method}`)
  }
}

async function signsInWith(h: Harness, email: string, password: string): Promise<boolean> {
  try {
    return (
      (await h.auth.passwords.login(new Browser('198.51.100.9').req, { email, password }))
        .status === 'signed-in'
    )
  } catch {
    return false
  }
}

describe.each(STORES)('storage failures fail closed (%s store)', (store) => {
  it('password reset: a new password never takes effect while the old sessions or tokens survive', async () => {
    for (const method of [
      'deleteUserOneTime',
      'deleteUserSessions',
      'deleteUserTokens',
      'updateUser',
    ] as const) {
      const h = harness({ store, config: { features: { apiTokens: true } } })
      const user = await h.user()
      const thief = await h.signedIn(user.email, '192.0.2.66')
      const { plainText } = await h.auth.tokens.create(thief.req, { name: 'loot' })
      await h.auth.passwordReset.request(new Browser().req, { email: user.email })
      const token = await h.mailedToken('password-reset')
      breakOnce(h.store, method)
      await expect(
        h.auth.passwordReset.reset(new Browser().req, { token, password: NEW_PASSWORD }),
      ).rejects.toThrow('storage down')
      if (await signsInWith(h, user.email, NEW_PASSWORD)) {
        expect(await h.auth.state(thief.req), method).toBeNull()
        expect(await h.auth.tokens.authenticate(`Bearer ${plainText}`), method).toBeUndefined()
      }
    }
  })

  it('password change: a new password never takes effect while other sessions survive', async () => {
    for (const method of ['deleteUserOneTime', 'deleteUserSessions', 'updateUser'] as const) {
      const h = harness({ store })
      const user = await h.user()
      const me = await h.signedIn(user.email)
      const thief = await h.signedIn(user.email, '192.0.2.66')
      breakOnce(h.store, method)
      await expect(
        h.auth.passwords.change(me.req, { current: PASSWORD, password: NEW_PASSWORD }),
      ).rejects.toThrow('storage down')
      if (await signsInWith(h, user.email, NEW_PASSWORD))
        expect(await h.auth.state(thief.req), method).toBeNull()
    }
  })

  it('two-factor confirm: 2FA is never switched on without recovery codes', async () => {
    for (const method of ['replaceRecoveryCodes', 'updateUser'] as const) {
      const h = harness({ store, config: { features: { twoFactor: true } } })
      const user = await h.user()
      const b = await h.signedIn(user.email)
      await h.auth.passwords.confirm(b.req, { password: PASSWORD })
      const setup = await h.auth.twoFactor.enable(b.req)
      const secret = base32Decode(setup.secret) ?? Buffer.alloc(0)
      breakOnce(h.store, method)
      await expect(
        h.auth.twoFactor.confirm(b.req, { code: totp(secret, h.clock.now()) }),
      ).rejects.toThrow('storage down')
      const after = await h.store.findUserById(user.id)
      if (after?.twoFactorConfirmedAt !== null)
        expect(await h.store.countRecoveryCodes(user.id), method).toBeGreaterThan(0)
    }
  })
})
