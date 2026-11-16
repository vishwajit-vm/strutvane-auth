/**
 * Account pre-hijacking (CONSISTENCY #114). With email verification on, anyone can register a
 * victim's address with a password the ATTACKER knows. Unless the mailbox owner's first proof of
 * ownership wipes what was set before it, the attacker keeps a working password (and any session
 * or token) on the account the victim then adopts.
 *
 * The rules under test:
 * 1. password sign-in is refused until the address is verified;
 * 2. the first mailbox proof (verification link, email-link sign-in, password reset) of a never-
 *    verified account clears the pre-verification password, sessions and tokens, and the owner
 *    sets a new password.
 */
import { describe, expect, it } from 'vitest'
import { parseVerificationUrl } from '../../src/engine/tokens/formats.ts'
import {
  Browser,
  type Harness,
  harness,
  PASSWORD,
  rejectsWith,
  START,
  STORES,
} from './helpers/harness.ts'

const config = {
  features: { registration: true, emailVerification: true, emailLink: true, tokens: true },
}
const ATTACKER_PASSWORD = 'attacker knows this one'
const OWNER_PASSWORD = 'the real owner picks this'

/** The parts of the last verification link mailed (to `to`, if given). */
async function verificationParts(h: Harness, to?: string) {
  const mail = await h.mail('verify-email', to)
  const parts = 'url' in mail ? parseVerificationUrl(mail.url) : undefined
  if (!parts) throw new Error('no link')
  return {
    id: parts.id,
    hash: parts.hash,
    expires: String(parts.expires),
    signature: parts.signature,
  }
}

describe.each(STORES)('account pre-hijacking (%s store)', (store) => {
  async function attackerRegisters() {
    const h = harness({ store, config })
    await h.auth.passwords.register(new Browser('192.0.2.66').req, {
      name: 'Victim',
      email: 'victim@acme.test',
      password: ATTACKER_PASSWORD,
    })
    const user = await h.store.findUserByEmail('victim@acme.test')
    if (!user) throw new Error('no user')
    // A session that exists from before the rule (an older deploy, or verification switched on later).
    await h.store.createSession({
      digest: 'f'.repeat(64),
      userId: user.id,
      state: 'active',
      createdAt: START,
      lastSeenAt: START,
      expiresAt: START + 3_600_000,
      idleMs: 3_600_000,
      remember: false,
      method: 'password',
      passwordConfirmedAt: null,
      impersonatorId: null,
      ip: null,
      userAgent: null,
    })
    return { h, user }
  }

  it('password sign-in is refused until the address is verified (and only a CORRECT password learns why)', async () => {
    const { h } = await attackerRegisters()
    await rejectsWith(
      () =>
        h.auth.passwords.login(new Browser().req, {
          email: 'victim@acme.test',
          password: 'some wrong password',
        }),
      'INVALID_CREDENTIALS',
    )
    const b = new Browser()
    await rejectsWith(
      () =>
        h.auth.passwords.login(b.req, { email: 'victim@acme.test', password: ATTACKER_PASSWORD }),
      'EMAIL_NOT_VERIFIED',
    )
    expect(b.jar.size).toBe(0)
    // The refusal re-sends the verification mail (throttled), since there is no session to ask from.
    await h.auth.idle()
    expect(h.mails.filter((m) => m.kind === 'verify-email')).toHaveLength(2)
    await rejectsWith(
      () =>
        h.auth.passwords.login(new Browser().req, {
          email: 'victim@acme.test',
          password: ATTACKER_PASSWORD,
        }),
      'EMAIL_NOT_VERIFIED',
    )
    await h.auth.idle()
    expect(h.mails.filter((m) => m.kind === 'verify-email')).toHaveLength(2)
  })

  it('the verification link wipes the pre-verification password, sessions and tokens; the owner sets a new one', async () => {
    const { h, user } = await attackerRegisters()
    const mail = await h.mail('verify-email')
    const parts = 'url' in mail ? parseVerificationUrl(mail.url) : undefined
    if (!parts) throw new Error('no link')
    const result = await h.auth.verification.verify(new Browser().req, {
      id: parts.id,
      hash: parts.hash,
      expires: String(parts.expires),
      signature: parts.signature,
    })
    expect(result.status).toBe('set-password')
    expect((await h.store.findUserById(user.id))?.passwordHash).toBeNull()
    expect(await h.store.listUserSessions(user.id)).toHaveLength(0)
    await rejectsWith(
      () =>
        h.auth.passwords.login(new Browser().req, {
          email: 'victim@acme.test',
          password: ATTACKER_PASSWORD,
        }),
      'INVALID_CREDENTIALS',
    )
    if (result.status !== 'set-password') return
    await h.auth.passwordReset.reset(new Browser().req, {
      token: result.token,
      password: OWNER_PASSWORD,
    })
    expect(
      (
        await h.auth.passwords.login(new Browser().req, {
          email: 'victim@acme.test',
          password: OWNER_PASSWORD,
        })
      ).status,
    ).toBe('signed-in')
    // A second click on the same link changes nothing (idempotent, no new token).
    expect(
      (
        await h.auth.verification.verify(new Browser().req, {
          id: parts.id,
          hash: parts.hash,
          expires: String(parts.expires),
          signature: parts.signature,
        })
      ).status,
    ).toBe('verified')
  })

  it('an email-link sign-in is a mailbox proof too: the attacker password dies, the owner can set one', async () => {
    const { h, user } = await attackerRegisters()
    const owner = new Browser()
    await h.auth.emailLink.request(owner.req, { email: 'victim@acme.test' })
    const result = await h.auth.emailLink.consume(owner.req, {
      token: await h.mailedToken('email-link'),
    })
    expect(result.status).toBe('signed-in')
    expect(await h.store.listUserSessions(user.id)).toHaveLength(1) // only the owner's new one
    await rejectsWith(
      () =>
        h.auth.passwords.login(new Browser().req, {
          email: 'victim@acme.test',
          password: ATTACKER_PASSWORD,
        }),
      'INVALID_CREDENTIALS',
    )
    expect(result.setPasswordToken).toBeDefined()
    await h.auth.passwordReset.reset(new Browser().req, {
      token: result.setPasswordToken,
      password: OWNER_PASSWORD,
    })
    expect(
      (
        await h.auth.passwords.login(new Browser().req, {
          email: 'victim@acme.test',
          password: OWNER_PASSWORD,
        })
      ).status,
    ).toBe('signed-in')
  })

  it('#122: verifying in the SAME browser that registered keeps the chosen password (no extra step)', async () => {
    const h = harness({ store, config })
    const browser = new Browser()
    await h.auth.passwords.register(browser.req, {
      name: 'Ada',
      email: 'ada@acme.test',
      password: OWNER_PASSWORD,
    })
    expect(browser.get('strutvane_register')).toBeDefined()
    const parts = await verificationParts(h)
    const result = await h.auth.verification.verify(browser.req, parts)
    expect(result).toEqual({ status: 'verified' })
    expect(browser.get('strutvane_register')).toBeUndefined() // the binding is spent
    expect(
      (
        await h.auth.passwords.login(new Browser().req, {
          email: 'ada@acme.test',
          password: OWNER_PASSWORD,
        })
      ).status,
    ).toBe('signed-in')
  })

  it('#122: verifying from a DIFFERENT browser clears the pre-verification password and hands over a set-password token', async () => {
    const h = harness({ store, config })
    await h.auth.passwords.register(new Browser().req, {
      name: 'Ada',
      email: 'ada@acme.test',
      password: OWNER_PASSWORD,
    })
    const phone = new Browser('198.51.100.20')
    const result = await h.auth.verification.verify(phone.req, await verificationParts(h))
    expect(result.status).toBe('set-password')
    await rejectsWith(
      () =>
        h.auth.passwords.login(new Browser().req, {
          email: 'ada@acme.test',
          password: OWNER_PASSWORD,
        }),
      'INVALID_CREDENTIALS',
    )
  })

  it("#122: the attacker's registration nonce does not keep the attacker's password, even for another account", async () => {
    const h = harness({ store, config })
    // The attacker registers the victim's address in the attacker's own browser...
    const attacker = new Browser('192.0.2.66')
    await h.auth.passwords.register(attacker.req, {
      name: 'Victim',
      email: 'victim@acme.test',
      password: ATTACKER_PASSWORD,
    })
    // ...and also registers an account of their own, to hold a nonce for a link they can open.
    await h.auth.passwords.register(attacker.req, {
      name: 'Mallory',
      email: 'mallory@evil.test',
      password: ATTACKER_PASSWORD,
    })
    // The victim verifies from the mail, in the victim's browser: different browser, so wiped.
    const victimLink = await verificationParts(h, 'victim@acme.test')
    expect((await h.auth.verification.verify(new Browser().req, victimLink)).status).toBe(
      'set-password',
    )
    await rejectsWith(
      () =>
        h.auth.passwords.login(new Browser().req, {
          email: 'victim@acme.test',
          password: ATTACKER_PASSWORD,
        }),
      'INVALID_CREDENTIALS',
    )
  })

  it('#122: a nonce bound to one account never counts as "same browser" for another account', async () => {
    const h = harness({ store, config })
    const shared = new Browser()
    await h.auth.passwords.register(shared.req, {
      name: 'A',
      email: 'a@acme.test',
      password: OWNER_PASSWORD,
    })
    await h.auth.passwords.register(new Browser().req, {
      name: 'B',
      email: 'b@acme.test',
      password: OWNER_PASSWORD,
    })
    expect(
      (await h.auth.verification.verify(shared.req, await verificationParts(h, 'b@acme.test')))
        .status,
    ).toBe('set-password')
  })

  it('#122: the binding cookie follows the strutvane_* naming and is __Host- on https', async () => {
    const h = harness({ store, config: { ...config, appUrl: 'https://app.example.com' } })
    const b = new Browser()
    await h.auth.passwords.register(b.req, {
      name: 'Ada',
      email: 'ada@acme.test',
      password: OWNER_PASSWORD,
    })
    expect([...b.jar.keys()]).toEqual(['__Host-strutvane_register'])
  })

  it('#122: registration sets the same cookie whether or not the address was taken (no enumeration)', async () => {
    const h = harness({ store, config })
    await h.user('taken@acme.test')
    const fresh = new Browser()
    const taken = new Browser()
    await h.auth.passwords.register(fresh.req, {
      name: 'N',
      email: 'new@acme.test',
      password: OWNER_PASSWORD,
    })
    await h.auth.passwords.register(taken.req, {
      name: 'T',
      email: 'taken@acme.test',
      password: OWNER_PASSWORD,
    })
    expect([...fresh.jar.keys()]).toEqual([...taken.jar.keys()])
  })

  it('a verified account is untouched by later mailbox proofs', async () => {
    const h = harness({ store, config })
    const user = await h.user('ada@acme.test')
    const keep = await h.signedIn(user.email)
    const b = new Browser()
    await h.auth.emailLink.request(b.req, { email: user.email })
    const result = await h.auth.emailLink.consume(b.req, {
      token: await h.mailedToken('email-link'),
    })
    expect(result.setPasswordToken).toBeUndefined()
    expect(await h.auth.state(keep.req)).not.toBeNull()
    expect(
      (await h.auth.passwords.login(new Browser().req, { email: user.email, password: PASSWORD }))
        .status,
    ).toBe('signed-in')
  })
})
