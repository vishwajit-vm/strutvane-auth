import { describe, expect, it } from 'vitest'
import { AuthError } from '../../src/engine/errors.ts'
import { manualClock } from '../../src/engine/ports/clock.ts'
import { parseVerificationUrl } from '../../src/engine/tokens/formats.ts'
import { Browser, harness, PASSWORD, rejectsWith, START, STORES } from './helpers/harness.ts'

const NEW_PASSWORD = 'a new long passphrase'

describe.each(STORES)('password reset (%s store)', (store) => {
  it('answers the same for known and unknown emails; only known emails get mail, at the STORED address', async () => {
    const h = harness({ store })
    await h.user('ada@acme.test')
    const a = await h.auth.passwordReset.request(new Browser().req, { email: 'ADA@acme.test ' })
    const b = await h.auth.passwordReset.request(new Browser().req, { email: 'nobody@acme.test' })
    expect(a).toEqual(b)
    await h.auth.idle()
    expect(h.mails.filter((m) => m.kind === 'password-reset').map((m) => m.to)).toEqual([
      'ada@acme.test',
    ])
  })

  it('resets once, expires after 60 minutes, and signs out everywhere (sessions + tokens)', async () => {
    const h = harness({ store, config: { features: { apiTokens: true } } })
    const user = await h.user()
    const session = await h.signedIn(user.email)
    await h.auth.tokens.create(session.req, { name: 'CI' })
    await h.auth.passwordReset.request(new Browser().req, { email: user.email })
    const token = await h.mailedToken('password-reset')
    await rejectsWith(
      () => h.auth.passwordReset.reset(new Browser().req, { token, password: 'short' }),
      'weak_password',
    )
    // a too-short password did not burn the link
    await h.auth.passwordReset.reset(new Browser().req, { token, password: NEW_PASSWORD })
    expect(await h.auth.state(session.req)).toBeNull()
    expect(await h.store.listTokens(user.id)).toHaveLength(0)
    await rejectsWith(
      () =>
        h.auth.passwordReset.reset(new Browser().req, { token, password: 'second use attempt' }),
      'invalid_token',
    )
    expect(
      (
        await h.auth.passwords.login(new Browser().req, {
          email: user.email,
          password: NEW_PASSWORD,
        })
      ).status,
    ).toBe('signed-in')
    expect(h.eventsOf('password.changed')).toEqual([
      expect.objectContaining({ via: 'reset', userId: user.id }),
    ])

    await h.auth.passwordReset.request(new Browser().req, { email: user.email })
    const late = await h.mailedToken('password-reset')
    h.clock.advance(60 * 60_000)
    await rejectsWith(
      () => h.auth.passwordReset.reset(new Browser().req, { token: late, password: NEW_PASSWORD }),
      'invalid_token',
    )
  })

  it('expiry boundary: a link that expires DURING the slow part (hashing, breach check) is refused', async () => {
    const clock = manualClock(START)
    let slow = false
    // The breach check (and scrypt) run between the link lookup and the single-use consume; on a
    // loaded server that window is real. Here it lasts past the link's 60 minutes.
    const passwordCheck = async (): Promise<'ok'> => {
      if (slow) clock.advance(2 * 60_000)
      return 'ok'
    }
    const h = harness({ store, clock, passwordCheck })
    const user = await h.user()
    await h.auth.passwordReset.request(new Browser().req, { email: user.email })
    const token = await h.mailedToken('password-reset')
    clock.advance(59 * 60_000)
    slow = true
    await rejectsWith(
      () => h.auth.passwordReset.reset(new Browser().req, { token, password: NEW_PASSWORD }),
      'invalid_token',
    )
    expect(
      (await h.auth.passwords.login(new Browser().req, { email: user.email, password: PASSWORD }))
        .status,
    ).toBe('signed-in')
  })

  it('a completed reset invalidates every other outstanding reset link', async () => {
    const h = harness({ store })
    const user = await h.user()
    await h.auth.passwordReset.request(new Browser().req, { email: user.email })
    const first = await h.mailedToken('password-reset')
    await h.auth.passwordReset.request(new Browser().req, { email: user.email })
    const second = await h.mailedToken('password-reset')
    expect(first).not.toBe(second)
    await h.auth.passwordReset.reset(new Browser().req, { token: second, password: NEW_PASSWORD })
    await rejectsWith(
      () =>
        h.auth.passwordReset.reset(new Browser().req, {
          token: first,
          password: 'attacker phrase here',
        }),
      'invalid_token',
    )
  })

  it('token reuse race: two concurrent resets with one link, exactly one wins', async () => {
    const h = harness({ store })
    const user = await h.user()
    await h.auth.passwordReset.request(new Browser().req, { email: user.email })
    const token = await h.mailedToken('password-reset')
    const results = await Promise.allSettled([
      h.auth.passwordReset.reset(new Browser('192.0.2.1').req, {
        token,
        password: 'first new passphrase',
      }),
      h.auth.passwordReset.reset(new Browser('192.0.2.2').req, {
        token,
        password: 'second new passphrase',
      }),
    ])
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
  })

  it('is rate-limited per account across IPs, and stores only a digest of the token', async () => {
    const h = harness({ store })
    const user = await h.user()
    for (let i = 0; i < 3; i++)
      await h.auth.passwordReset.request(new Browser(`192.0.2.${i}`).req, { email: user.email })
    await rejectsWith(
      () => h.auth.passwordReset.request(new Browser('192.0.2.9').req, { email: user.email }),
      'rate_limited',
    )
    const token = await h.mailedToken('password-reset')
    const digestRow = await h.store.findOneTime(token, 'password-reset')
    expect(digestRow).toBeUndefined() // the raw token is not a key in the store
  })

  it('a reset lifts a password lockout (the mailbox proved ownership)', async () => {
    const h = harness({ store })
    const user = await h.user()
    for (let i = 0; i < 5; i++)
      await h.auth.passwords
        .login(new Browser(`198.51.100.${i}`).req, {
          email: user.email,
          password: 'wrong password!',
        })
        .catch(() => undefined)
    await rejectsWith(
      () =>
        h.auth.passwords.login(new Browser('192.0.2.77').req, {
          email: user.email,
          password: PASSWORD,
        }),
      'rate_limited',
    )
    await h.auth.passwordReset.request(new Browser().req, { email: user.email })
    await h.auth.passwordReset.reset(new Browser().req, {
      token: await h.mailedToken('password-reset'),
      password: NEW_PASSWORD,
    })
    expect(
      (
        await h.auth.passwords.login(new Browser('192.0.2.78').req, {
          email: user.email,
          password: NEW_PASSWORD,
        })
      ).status,
    ).toBe('signed-in')
  })
})

describe.each(STORES)('email verification (%s store)', (store) => {
  const features = { emailVerification: true, registration: true }

  it('verifies with the signed link, idempotently, without a session', async () => {
    const h = harness({ store, config: { features } })
    await h.auth.passwords.register(new Browser().req, {
      name: 'Ada',
      email: 'ada@acme.test',
      password: PASSWORD,
    })
    const mail = await h.mail('verify-email')
    if (!('url' in mail)) throw new Error('no url')
    const parts = parseVerificationUrl(mail.url)
    expect(parts).toBeDefined()
    if (!parts) return
    const input = {
      id: parts.id,
      hash: parts.hash,
      expires: String(parts.expires),
      signature: parts.signature,
    }
    await h.auth.verification.verify(new Browser().req, input)
    await h.auth.verification.verify(new Browser().req, input)
    expect((await h.store.findUserById(parts.id))?.emailVerifiedAt).toBe(h.clock.now())
    expect(h.eventsOf('email.verified')).toHaveLength(1)
  })

  it('key separation: the mailed email hash shares no value with the limiter keys or event digests', async () => {
    const h = harness({ store, config: { features } })
    await h.auth.passwords.register(new Browser().req, {
      name: 'Ada',
      email: 'ada@acme.test',
      password: PASSWORD,
    })
    const mail = await h.mail('verify-email')
    const parts = 'url' in mail ? parseVerificationUrl(mail.url) : undefined
    await h.auth.passwords
      .login(new Browser().req, { email: 'ada@acme.test', password: 'wrong password!' })
      .catch(() => undefined)
    const eventDigest = h.eventsOf('login.failed')[0]?.emailDigest ?? ''
    expect(eventDigest).not.toBe('')
    // The URL travels by mail (and through mail logs, scanners, forwards); the event digest and
    // the counter keys travel elsewhere. One must not be derivable from (or equal to) the other.
    expect(parts?.hash.slice(0, eventDigest.length)).not.toBe(eventDigest)
  })

  it('refuses edited, expired and other-user links, and links for an old email address', async () => {
    const h = harness({ store, config: { features } })
    await h.auth.passwords.register(new Browser().req, {
      name: 'Ada',
      email: 'ada@acme.test',
      password: PASSWORD,
    })
    await h.auth.passwords.register(new Browser().req, {
      name: 'Bob',
      email: 'bob@acme.test',
      password: PASSWORD,
    })
    const ada = parseVerificationUrl(
      ((await h.mail('verify-email', 'ada@acme.test')) as { url: string }).url,
    )
    const bob = parseVerificationUrl(
      ((await h.mail('verify-email', 'bob@acme.test')) as { url: string }).url,
    )
    if (!ada || !bob) throw new Error('bad links')
    const base = {
      id: ada.id,
      hash: ada.hash,
      expires: String(ada.expires),
      signature: ada.signature,
    }
    await rejectsWith(
      () => h.auth.verification.verify(new Browser().req, { ...base, id: bob.id }),
      'invalid_signature',
    )
    await rejectsWith(
      () =>
        h.auth.verification.verify(new Browser().req, {
          ...base,
          expires: String(ada.expires + 3600),
        }),
      'invalid_signature',
    )
    await rejectsWith(
      () => h.auth.verification.verify(new Browser().req, { ...base, signature: bob.signature }),
      'invalid_signature',
    )
    await rejectsWith(
      () => h.auth.verification.verify(new Browser().req, { ...base, hash: bob.hash }),
      'invalid_signature',
    )
    h.clock.advance(60 * 60_000 + 1000)
    // #67: an intact link past its time is `signature_expired`; an edited one stays
    // `invalid_signature` even when it is also expired (the signature is checked first).
    await rejectsWith(
      () => h.auth.verification.verify(new Browser().req, base),
      'signature_expired',
    )
    await rejectsWith(
      () => h.auth.verification.verify(new Browser().req, { ...base, signature: bob.signature }),
      'invalid_signature',
    )
    await rejectsWith(
      () =>
        h.auth.verification.verify(new Browser().req, {
          id: 'x',
          hash: 1,
          expires: null,
          signature: [],
        }),
      'invalid_signature',
    )
    for (const code of ['invalid_signature', 'signature_expired'] as const)
      expect(new AuthError(code).status).toBe(403)
  })

  it('resend is throttled: one per minute, six per hour; verified users get "already-verified"', async () => {
    const h = harness({ store, config: { features } })
    const ada = await h.user('ada@acme.test', { verified: true })
    // A signed-in, unverified user: password sign-in now needs a verified address (#114), so the
    // session comes first and the address is "unverified" after (verification switched on later).
    const b = await h.signedIn('ada@acme.test')
    await h.store.updateUser(ada.id, { emailVerifiedAt: null })
    expect(await h.auth.verification.resend(b.req)).toEqual({ status: 'sent' })
    await rejectsWith(() => h.auth.verification.resend(b.req), 'rate_limited')
    for (let i = 0; i < 5; i++) {
      h.clock.advance(61_000)
      expect(await h.auth.verification.resend(b.req)).toEqual({ status: 'sent' })
    }
    h.clock.advance(61_000)
    await rejectsWith(() => h.auth.verification.resend(b.req), 'rate_limited')
    await h.user('eve@acme.test', { verified: true })
    expect(await h.auth.verification.resend((await h.signedIn('eve@acme.test')).req)).toEqual({
      status: 'already-verified',
    })
  })

  it('assertVerified is the `verified` guard', async () => {
    const h = harness({ store, config: { features } })
    const user = await h.user('ada@acme.test', { verified: false })
    expect(() => h.auth.verification.assertVerified(user)).toThrow(/Verify/)
    const off = harness({ store })
    expect(() => off.auth.verification.assertVerified(user)).not.toThrow()
  })
})

describe.each(STORES)('email link sign-in (%s store)', (store) => {
  const features = { emailLink: true }

  it('signs in from the browser that asked; single-use; verifies the email', async () => {
    const h = harness({ store, config: { features } })
    const user = await h.user('ada@acme.test', { verified: false })
    const b = new Browser()
    expect(await h.auth.emailLink.request(b.req, { email: 'ada@acme.test' })).toEqual({
      status: 'sent',
    })
    const token = await h.mailedToken('email-link')
    expect(await h.auth.emailLink.consume(b.req, { token })).toEqual({ status: 'signed-in' })
    expect((await h.auth.state(b.req))?.session.method).toBe('email-link')
    expect((await h.store.findUserById(user.id))?.emailVerifiedAt).not.toBeNull()
    await rejectsWith(() => h.auth.emailLink.consume(b.req, { token }), 'invalid_token')
  })

  it('on https the browser-binding nonce is a __Host- cookie (no sibling host can plant it)', async () => {
    const h = harness({
      store,
      config: { appUrl: 'https://app.example.com', features: { emailLink: true } },
    })
    await h.user('ada@acme.test')
    const b = new Browser()
    await h.auth.emailLink.request(b.req, { email: 'ada@acme.test' })
    expect(b.get('__Host-strutvane_link')).toBeDefined()
    expect(b.get('strutvane_link')).toBeUndefined()
  })

  it('attack: a FORWARDED link does not sign in the recipient, and does not burn the link', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    const owner = new Browser('192.0.2.1')
    await h.auth.emailLink.request(owner.req, { email: 'ada@acme.test' })
    const token = await h.mailedToken('email-link')
    const recipient = new Browser('198.51.100.66')
    await rejectsWith(
      () => h.auth.emailLink.consume(recipient.req, { token }),
      'email_link_other_browser',
    )
    // even with their own nonce cookie from requesting a link for themselves
    await h.auth.emailLink.request(recipient.req, { email: 'someone-else@acme.test' })
    await rejectsWith(
      () => h.auth.emailLink.consume(recipient.req, { token }),
      'email_link_other_browser',
    )
    expect(await h.auth.state(recipient.req)).toBeNull()
    expect((await h.auth.emailLink.consume(owner.req, { token })).status).toBe('signed-in')
  })

  it('answers the same whether or not the account exists (and mails only real accounts)', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    const known = new Browser()
    const unknown = new Browser()
    const a = await h.auth.emailLink.request(known.req, { email: 'ada@acme.test' })
    const b = await h.auth.emailLink.request(unknown.req, { email: 'ghost@acme.test' })
    expect(a).toEqual(b)
    expect([...known.jar.keys()]).toEqual([...unknown.jar.keys()]) // both get a nonce cookie
    await h.auth.idle()
    expect(h.mails.filter((m) => m.kind === 'email-link')).toHaveLength(1)
  })

  it('expires after 15 minutes; two requests from one browser both stay usable there', async () => {
    const h = harness({
      store,
      config: { features, limits: { emailLinkPerAccount: { max: 10, windowSeconds: 900 } } },
    })
    await h.user()
    const b = new Browser()
    await h.auth.emailLink.request(b.req, { email: 'ada@acme.test' })
    const first = await h.mailedToken('email-link')
    await h.auth.emailLink.request(b.req, { email: 'ada@acme.test' })
    const second = await h.mailedToken('email-link')
    expect(first).not.toBe(second)
    h.clock.advance(15 * 60_000)
    await rejectsWith(() => h.auth.emailLink.consume(b.req, { token: second }), 'invalid_token')
    const c = new Browser()
    await h.auth.emailLink.request(c.req, { email: 'ada@acme.test' })
    const one = await h.mailedToken('email-link')
    h.clock.advance(60_000)
    await h.auth.emailLink.request(c.req, { email: 'ada@acme.test' })
    const two = await h.mailedToken('email-link')
    expect((await h.auth.emailLink.consume(c.req, { token: one })).status).toBe('signed-in')
    // a successful sign-in kills the user's other outstanding links
    await rejectsWith(() => h.auth.emailLink.consume(c.req, { token: two }), 'invalid_token')
  })

  it('is rate-limited per account and per IP', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    for (let i = 0; i < 3; i++)
      await h.auth.emailLink.request(new Browser(`192.0.2.${i}`).req, { email: 'ada@acme.test' })
    await rejectsWith(
      () => h.auth.emailLink.request(new Browser('192.0.2.50').req, { email: 'ada@acme.test' }),
      'rate_limited',
    )
    for (let i = 0; i < 5; i++)
      await h.auth.emailLink.request(new Browser('198.51.100.9').req, { email: `u${i}@acme.test` })
    await rejectsWith(
      () => h.auth.emailLink.request(new Browser('198.51.100.9').req, { email: 'u9@acme.test' }),
      'rate_limited',
    )
  })
})
