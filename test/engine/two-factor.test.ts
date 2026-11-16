import { describe, expect, it } from 'vitest'
import { base32Decode } from '../../src/engine/crypto/random.ts'
import { totp } from '../../src/engine/totp/totp.ts'
import { Browser, type Harness, harness, PASSWORD, rejectsWith, STORES } from './helpers/harness.ts'

const features = { twoFactor: true, emailLink: true, tokens: true }

/** Turn 2FA on for a signed-in browser; resolve the raw secret and the recovery codes. */
async function enable(
  h: Harness,
  b: Browser,
): Promise<{ secret: Buffer; codes: readonly string[] }> {
  await h.auth.passwords.confirm(b.req, { password: PASSWORD })
  const setup = await h.auth.twoFactor.enable(b.req)
  const secret = base32Decode(setup.secret) ?? Buffer.alloc(0)
  h.secrets.add(setup.secret)
  const { recoveryCodes } = await h.auth.twoFactor.confirm(b.req, {
    code: totp(secret, h.clock.now()),
  })
  for (const c of recoveryCodes) h.secrets.add(c)
  h.clock.advance(30_000) // the confirm code's step is now used
  return { secret, codes: recoveryCodes }
}

async function passwordStep(h: Harness, ip = '203.0.113.10'): Promise<Browser> {
  const b = new Browser(ip)
  const r = await h.auth.passwords.login(b.req, { email: 'ada@acme.test', password: PASSWORD })
  expect(r).toEqual({ status: 'two-factor-required', methods: ['totp', 'recovery-code'] })
  return b
}

describe.each(STORES)('two-factor (%s store)', (store) => {
  it('setup needs a recent password confirmation and is NOT enforced until confirmed', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    const b = await h.signedIn('ada@acme.test')
    await rejectsWith(() => h.auth.twoFactor.enable(b.req), 'PASSWORD_CONFIRMATION_REQUIRED')
    await h.auth.passwords.confirm(b.req, { password: PASSWORD })
    const setup = await h.auth.twoFactor.enable(b.req)
    expect(setup.otpauthUri).toMatch(
      /^otpauth:\/\/totp\/localhost:ada%40acme\.test\?secret=[A-Z2-7]+&/,
    )
    // unconfirmed: password alone still signs in
    expect(
      (
        await h.auth.passwords.login(new Browser().req, {
          email: 'ada@acme.test',
          password: PASSWORD,
        })
      ).status,
    ).toBe('signed-in')
    await rejectsWith(() => h.auth.twoFactor.confirm(b.req, { code: '000000' }), 'INVALID_CODE')
    expect((await h.auth.state(b.req))?.user.twoFactorEnabled).toBe(false)
  })

  it('confirm turns it on, returns 10 unique recovery codes once, rotates the session, and stores the secret encrypted', async () => {
    const h = harness({ store, config: { features } })
    const user = await h.user()
    const b = await h.signedIn('ada@acme.test')
    const before = b.get('strutvane_session')
    const { secret, codes } = await enable(h, b)
    expect(codes).toHaveLength(10)
    expect(new Set(codes).size).toBe(10)
    for (const c of codes) expect(c).toMatch(/^[A-Z2-9]{5}-[A-Z2-9]{5}$/)
    expect(b.get('strutvane_session')).not.toBe(before)
    expect((await h.auth.state(b.req))?.user.twoFactorEnabled).toBe(true)
    const row = await h.store.findUserById(user.id)
    expect(row?.twoFactorSecret).toMatch(/^v1\./)
    expect(row?.twoFactorSecret).not.toContain(secret.toString('base64url'))
    expect(h.eventsOf('two-factor.enabled')).toHaveLength(1)
    expect(await h.auth.twoFactor.remainingRecoveryCodes(b.req)).toBe(10)
  })

  it('a pending two-factor session is a guest everywhere, and the final session gets a NEW id', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    const { secret } = await enable(h, await h.signedIn('ada@acme.test'))
    const b = await passwordStep(h)
    const pendingId = b.get('strutvane_session')
    expect(await h.auth.state(b.req)).toBeNull()
    expect(await h.auth.pendingChallenge(b.req)).toEqual({ methods: ['totp', 'recovery-code'] })
    await rejectsWith(() => h.auth.tokens.list(b.req), 'UNAUTHENTICATED')
    await rejectsWith(() => h.auth.sessions.list(b.req), 'UNAUTHENTICATED')
    await rejectsWith(
      () => h.auth.passwords.confirm(b.req, { password: PASSWORD }),
      'UNAUTHENTICATED',
    )
    const stolenPending = b.clone()
    expect(await h.auth.twoFactor.challenge(b.req, { code: totp(secret, h.clock.now()) })).toEqual({
      status: 'signed-in',
    })
    expect(b.get('strutvane_session')).not.toBe(pendingId)
    expect(await h.auth.state(b.req)).not.toBeNull()
    expect(await h.auth.state(stolenPending.req)).toBeNull()
    expect(h.eventsOf('login').at(-1)).toMatchObject({ method: 'password', secondFactor: 'totp' })
  })

  it('attack: TOTP replay — a used code (or an older one) never works again', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    const { secret } = await enable(h, await h.signedIn('ada@acme.test'))
    const code = totp(secret, h.clock.now())
    const older = totp(secret, h.clock.now() - 30_000)
    await h.auth.twoFactor.challenge((await passwordStep(h)).req, { code })
    await rejectsWith(
      async () => h.auth.twoFactor.challenge((await passwordStep(h)).req, { code }),
      'INVALID_CODE',
    )
    await rejectsWith(
      async () => h.auth.twoFactor.challenge((await passwordStep(h)).req, { code: older }),
      'INVALID_CODE',
    )
    h.clock.advance(30_000)
    expect(
      (
        await h.auth.twoFactor.challenge((await passwordStep(h)).req, {
          code: totp(secret, h.clock.now()),
        })
      ).status,
    ).toBe('signed-in')
  })

  it('attack: TOTP replay race — the same code submitted twice at once succeeds once', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    const { secret } = await enable(h, await h.signedIn('ada@acme.test'))
    const a = await passwordStep(h, '192.0.2.1')
    const b = await passwordStep(h, '192.0.2.2')
    const code = totp(secret, h.clock.now())
    const results = await Promise.allSettled([
      h.auth.twoFactor.challenge(a.req, { code }),
      h.auth.twoFactor.challenge(b.req, { code }),
    ])
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
  })

  it('attack: recovery code reuse — each code works exactly once', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    const { codes } = await enable(h, await h.signedIn('ada@acme.test'))
    const code = codes[0] ?? ''
    expect(
      (
        await h.auth.twoFactor.challenge((await passwordStep(h)).req, {
          recoveryCode: code.toLowerCase().replace('-', ' '),
        })
      ).status,
    ).toBe('signed-in')
    await rejectsWith(
      async () => h.auth.twoFactor.challenge((await passwordStep(h)).req, { recoveryCode: code }),
      'INVALID_CODE',
    )
    expect(h.eventsOf('recovery-code.used')).toEqual([expect.objectContaining({ remaining: 9 })])
    expect(h.eventsOf('login').at(-1)).toMatchObject({ secondFactor: 'recovery-code' })
  })

  it('regenerating recovery codes kills the old ones', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    const b = await h.signedIn('ada@acme.test')
    const { codes } = await enable(h, b)
    const { recoveryCodes } = await h.auth.twoFactor.regenerateRecoveryCodes(b.req)
    expect(recoveryCodes).toHaveLength(10)
    await rejectsWith(
      async () =>
        h.auth.twoFactor.challenge((await passwordStep(h)).req, { recoveryCode: codes[1] }),
      'INVALID_CODE',
    )
    expect(
      (
        await h.auth.twoFactor.challenge((await passwordStep(h)).req, {
          recoveryCode: recoveryCodes[1],
        })
      ).status,
    ).toBe('signed-in')
  })

  it('attack: brute force across fresh sign-ins — the 2FA limit keys on the ACCOUNT', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    const { secret } = await enable(h, await h.signedIn('ada@acme.test'))
    // 6 wrong codes spread over 3 fresh password sign-ins (2 each) still lock the account.
    let attempts = 0
    for (let round = 0; round < 3; round++) {
      const b = await passwordStep(h, `198.51.100.${round}`)
      for (let i = 0; i < 2; i++) {
        attempts++
        await h.auth.twoFactor.challenge(b.req, { code: '000000' }).catch(() => undefined)
      }
    }
    expect(attempts).toBe(6)
    const fresh = await passwordStep(h, '192.0.2.200')
    await rejectsWith(
      () => h.auth.twoFactor.challenge(fresh.req, { code: totp(secret, h.clock.now()) }),
      'RATE_LIMITED',
    )
    expect(h.eventsOf('lockout').filter((e) => e.scope === 'two-factor').length).toBeGreaterThan(0)
  })

  it('the pending state expires after 10 minutes', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    const { secret } = await enable(h, await h.signedIn('ada@acme.test'))
    const b = await passwordStep(h)
    h.clock.advance(10 * 60_000)
    await rejectsWith(
      () => h.auth.twoFactor.challenge(b.req, { code: totp(secret, h.clock.now()) }),
      'UNAUTHENTICATED',
    )
  })

  it('every first factor goes through 2FA: the email link too', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    await enable(h, await h.signedIn('ada@acme.test'))
    const b = new Browser()
    await h.auth.emailLink.request(b.req, { email: 'ada@acme.test' })
    expect(
      (await h.auth.emailLink.consume(b.req, { token: await h.mailedToken('email-link') })).status,
    ).toBe('two-factor-required')
    expect(await h.auth.state(b.req)).toBeNull()
  })

  it('"remember this device" skips 2FA only for that user on that browser, until 2FA or the password changes', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    await h.user('bob@acme.test')
    const settings = await h.signedIn('ada@acme.test')
    const { secret } = await enable(h, settings)
    const laptop = await passwordStep(h)
    await h.auth.twoFactor.challenge(laptop.req, {
      code: totp(secret, h.clock.now()),
      rememberDevice: true,
    })
    expect(laptop.get('strutvane_device')).toBeDefined()
    expect(
      (await h.auth.passwords.login(laptop.req, { email: 'ada@acme.test', password: PASSWORD }))
        .status,
    ).toBe('signed-in')
    expect(h.eventsOf('login').at(-1)).toMatchObject({ secondFactor: 'trusted-device' })
    // another browser still needs the code
    await passwordStep(h, '192.0.2.40')
    // Bob, with 2FA, presenting Ada's device cookie, does not skip his 2FA
    const bobSettings = await h.signedIn('bob@acme.test')
    await h.auth.passwords.confirm(bobSettings.req, { password: PASSWORD })
    const bobSetup = await h.auth.twoFactor.enable(bobSettings.req)
    const bobSecret = base32Decode(bobSetup.secret) ?? Buffer.alloc(0)
    await h.auth.twoFactor.confirm(bobSettings.req, { code: totp(bobSecret, h.clock.now()) })
    const hijack = laptop.clone()
    expect(
      (await h.auth.passwords.login(hijack.req, { email: 'bob@acme.test', password: PASSWORD }))
        .status,
    ).toBe('two-factor-required')
    // disabling 2FA forgets trusted devices
    await h.auth.passwords.confirm(settings.req, { password: PASSWORD })
    await h.auth.twoFactor.disable(settings.req)
    await h.auth.passwords.confirm(settings.req, { password: PASSWORD })
    const again = await h.auth.twoFactor.enable(settings.req)
    h.clock.advance(30_000)
    await h.auth.twoFactor.confirm(settings.req, {
      code: totp(base32Decode(again.secret) ?? Buffer.alloc(0), h.clock.now()),
    })
    expect(
      (await h.auth.passwords.login(laptop.req, { email: 'ada@acme.test', password: PASSWORD }))
        .status,
    ).toBe('two-factor-required')
  })

  it('disable needs a recent confirmation, then password alone signs in again', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    const b = await h.signedIn('ada@acme.test')
    await enable(h, b)
    // let the confirmation window lapse while staying active
    for (let i = 0; i < 4; i++) {
      h.clock.advance(60 * 60_000)
      await h.auth.state(b.req)
    }
    await rejectsWith(() => h.auth.twoFactor.disable(b.req), 'PASSWORD_CONFIRMATION_REQUIRED')
    await h.auth.passwords.confirm(b.req, { password: PASSWORD })
    await h.auth.twoFactor.disable(b.req)
    expect(h.eventsOf('two-factor.disabled')).toHaveLength(1)
    expect(
      (
        await h.auth.passwords.login(new Browser().req, {
          email: 'ada@acme.test',
          password: PASSWORD,
        })
      ).status,
    ).toBe('signed-in')
  })

  it('malformed codes are refused (and counted) without errors', async () => {
    const h = harness({ store, config: { features } })
    await h.user()
    await enable(h, await h.signedIn('ada@acme.test'))
    const b = await passwordStep(h)
    for (const code of [123456, '12345', '1234567', 'abcdef', { toString: () => '123456' }])
      await rejectsWith(() => h.auth.twoFactor.challenge(b.req, { code }), 'INVALID_CODE')
    await rejectsWith(() => h.auth.twoFactor.challenge(b.req, { code: '000000' }), 'RATE_LIMITED')
    await rejectsWith(() => h.auth.twoFactor.challenge(b.req, {}), 'VALIDATION_FAILED')
  })
})
