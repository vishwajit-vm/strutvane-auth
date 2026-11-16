import { describe, expect, it } from 'vitest'
import { base32Decode } from '../../src/engine/crypto/random.ts'
import { totp } from '../../src/engine/totp/totp.ts'
import { SoftAuthenticator } from './helpers/authenticator.ts'
import { Browser, type Harness, harness, PASSWORD, rejectsWith, STORES } from './helpers/harness.ts'

const ORIGIN = 'http://localhost:3000'
const config = {
  features: { passkeys: true, twoFactor: true },
  passkeys: { rpId: 'localhost', rpName: 'Acme', origins: [ORIGIN] },
}

async function addPasskey(h: Harness, b: Browser, device: SoftAuthenticator, name?: string) {
  await h.auth.passwords.confirm(b.req, { password: PASSWORD })
  const options = await h.auth.passkeys.registrationOptions(b.req)
  return h.auth.passkeys.register(b.req, {
    response: device.register(options),
    ...(name ? { name } : {}),
  })
}

async function passwordless(
  h: Harness,
  device: SoftAuthenticator,
  b = new Browser(),
  overrides: Parameters<SoftAuthenticator['assert']>[1] = {},
) {
  const options = await h.auth.passkeys.authenticationOptions(b.req, { mode: 'passwordless' })
  expect(options.allowCredentials ?? []).toHaveLength(0) // discoverable: no account hint leaks
  const response = device.assert(options, overrides)
  return { b, response, result: await h.auth.passkeys.authenticate(b.req, { response }) }
}

describe.each(STORES)('passkeys (%s store)', (store) => {
  it('registers several passkeys per user (needs a recent confirmation), lists, renames and removes them', async () => {
    const h = harness({ store, config })
    const user = await h.user()
    const b = await h.signedIn(user.email)
    await rejectsWith(
      () => h.auth.passkeys.registrationOptions(b.req),
      'PASSWORD_CONFIRMATION_REQUIRED',
    )
    const phone = new SoftAuthenticator(ORIGIN)
    const key = new SoftAuthenticator(ORIGIN)
    const first = await addPasskey(h, b, phone, 'Phone')
    await addPasskey(h, b, key)
    const options = await h.auth.passkeys.registrationOptions(b.req)
    expect(options.excludeCredentials).toHaveLength(2)
    expect(options.authenticatorSelection).toMatchObject({
      residentKey: 'required',
      userVerification: 'required',
    })
    const list = await h.auth.passkeys.list(b.req)
    expect(list.map((p) => p.name)).toEqual(['Phone', 'Passkey 2'])
    expect(JSON.stringify(list)).not.toMatch(/publicKey|credentialId/)
    await h.auth.passkeys.rename(b.req, { id: first.id, name: 'Work phone' })
    expect((await h.auth.passkeys.list(b.req))[0]?.name).toBe('Work phone')
    await h.auth.passkeys.remove(b.req, { id: first.id })
    expect(await h.auth.passkeys.list(b.req)).toHaveLength(1)
    await rejectsWith(() => h.auth.passkeys.remove(b.req, { id: first.id }), 'NOT_FOUND')
    expect(h.eventsOf('passkey.added')).toHaveLength(2)
    expect(h.eventsOf('passkey.removed')).toHaveLength(1)
  })

  it("cannot remove or rename another user's passkey", async () => {
    const h = harness({ store, config })
    await h.user('ada@acme.test')
    await h.user('eve@acme.test')
    const ada = await h.signedIn('ada@acme.test')
    const passkey = await addPasskey(h, ada, new SoftAuthenticator(ORIGIN))
    const eve = await h.signedIn('eve@acme.test')
    await h.auth.passwords.confirm(eve.req, { password: PASSWORD })
    await rejectsWith(() => h.auth.passkeys.remove(eve.req, { id: passkey.id }), 'NOT_FOUND')
    await rejectsWith(
      () => h.auth.passkeys.rename(eve.req, { id: passkey.id, name: 'mine' }),
      'NOT_FOUND',
    )
  })

  it('signs in passwordless with a fresh session; the signature counter is stored', async () => {
    const h = harness({ store, config })
    const user = await h.user()
    const device = new SoftAuthenticator(ORIGIN)
    await addPasskey(h, await h.signedIn(user.email), device)
    const { b, result } = await passwordless(h, device)
    expect(result).toEqual({ status: 'signed-in' })
    expect((await h.auth.state(b.req))?.session.method).toBe('passkey')
    const stored = await h.store.listPasskeys(user.id)
    expect(stored[0]?.counter).toBe(1)
    expect(stored[0]?.lastUsedAt).toBe(h.clock.now())
  })

  it('attack: a captured assertion cannot be replayed (single-use challenge)', async () => {
    const h = harness({ store, config })
    const user = await h.user()
    const device = new SoftAuthenticator(ORIGIN)
    await addPasskey(h, await h.signedIn(user.email), device)
    const { response } = await passwordless(h, device)
    // replay into a new ceremony: the challenge differs
    const attacker = new Browser('198.51.100.7')
    await h.auth.passkeys.authenticationOptions(attacker.req, { mode: 'passwordless' })
    await rejectsWith(
      () => h.auth.passkeys.authenticate(attacker.req, { response }),
      'INVALID_CODE',
    )
    // replay with no ceremony at all
    await rejectsWith(
      () => h.auth.passkeys.authenticate(new Browser().req, { response }),
      'INVALID_TOKEN',
    )
  })

  it('attack: a cloned authenticator (counter did not move), a wrong origin, or no user verification is refused', async () => {
    const h = harness({ store, config })
    const user = await h.user()
    const device = new SoftAuthenticator(ORIGIN)
    await addPasskey(h, await h.signedIn(user.email), device)
    await passwordless(h, device)
    await rejectsWith(
      () => passwordless(h, device, new Browser(), { keepCounter: true }),
      'INVALID_CODE',
    )
    await rejectsWith(
      () => passwordless(h, device, new Browser(), { origin: 'https://evil.example' }),
      'INVALID_CODE',
    )
    await rejectsWith(() => passwordless(h, device, new Browser(), { uv: false }), 'INVALID_CODE')
  })

  it('race: two sign-ins from a cloned authenticator with the SAME counter, at once: exactly one wins', async () => {
    const h = harness({ store, config })
    const user = await h.user()
    const device = new SoftAuthenticator(ORIGIN)
    await addPasskey(h, await h.signedIn(user.email), device)
    await passwordless(h, device) // stored counter: 1
    const a = new Browser()
    const b = new Browser()
    const optionsA = await h.auth.passkeys.authenticationOptions(a.req, { mode: 'passwordless' })
    const optionsB = await h.auth.passkeys.authenticationOptions(b.req, { mode: 'passwordless' })
    const responseA = device.assert(optionsA) // counter 2
    const responseB = device.assert(optionsB, { keepCounter: true }) // the clone: also 2
    const results = await Promise.allSettled([
      h.auth.passkeys.authenticate(a.req, { response: responseA }),
      h.auth.passkeys.authenticate(b.req, { response: responseB }),
    ])
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
    expect((await h.store.listPasskeys(user.id))[0]?.counter).toBe(2)
  })

  it('a registration answered for another challenge or origin is refused', async () => {
    const h = harness({ store, config })
    const user = await h.user()
    const b = await h.signedIn(user.email)
    await h.auth.passwords.confirm(b.req, { password: PASSWORD })
    const device = new SoftAuthenticator(ORIGIN)
    let options = await h.auth.passkeys.registrationOptions(b.req)
    await rejectsWith(
      () =>
        h.auth.passkeys.register(b.req, {
          response: device.register(options, { challenge: 'AAAA' }),
        }),
      'INVALID_CODE',
    )
    options = await h.auth.passkeys.registrationOptions(b.req)
    await rejectsWith(
      () =>
        h.auth.passkeys.register(b.req, {
          response: device.register(options, { origin: 'https://evil.example' }),
        }),
      'INVALID_CODE',
    )
    options = await h.auth.passkeys.registrationOptions(b.req)
    await rejectsWith(
      () => h.auth.passkeys.register(b.req, { response: 'not json' }),
      'VALIDATION_FAILED',
    )
    expect(await h.store.listPasskeys(user.id)).toHaveLength(0)
  })

  it("works as a second factor, but only with the signing-in user's OWN passkey", async () => {
    const h = harness({ store, config })
    await h.user('ada@acme.test')
    await h.user('eve@acme.test')
    const ada = await h.signedIn('ada@acme.test')
    const adaKey = new SoftAuthenticator(ORIGIN)
    await addPasskey(h, ada, adaKey)
    const eveKey = new SoftAuthenticator(ORIGIN)
    await addPasskey(h, await h.signedIn('eve@acme.test'), eveKey)
    await h.auth.passwords.confirm(ada.req, { password: PASSWORD })
    const setup = await h.auth.twoFactor.enable(ada.req)
    await h.auth.twoFactor.confirm(ada.req, {
      code: totp(base32Decode(setup.secret) ?? Buffer.alloc(0), h.clock.now()),
    })

    const pending = new Browser()
    expect(
      await h.auth.passwords.login(pending.req, { email: 'ada@acme.test', password: PASSWORD }),
    ).toEqual({
      status: 'two-factor-required',
      methods: ['totp', 'recovery-code', 'passkey'],
    })
    let options = await h.auth.passkeys.authenticationOptions(pending.req, {
      mode: 'second-factor',
    })
    expect(options.allowCredentials).toHaveLength(1)
    // Eve's (valid) passkey cannot answer Ada's challenge
    const eveAnswer = eveKey.assert({ ...options, allowCredentials: [] })
    await rejectsWith(
      () => h.auth.passkeys.authenticate(pending.req, { response: eveAnswer }),
      'INVALID_CODE',
    )
    options = await h.auth.passkeys.authenticationOptions(pending.req, { mode: 'second-factor' })
    expect(
      await h.auth.passkeys.authenticate(pending.req, { response: adaKey.assert(options) }),
    ).toEqual({ status: 'signed-in' })
    expect(h.eventsOf('login').at(-1)).toMatchObject({
      method: 'password',
      secondFactor: 'passkey',
    })
    // a guest without a pending sign-in cannot start a second-factor ceremony
    await rejectsWith(
      () => h.auth.passkeys.authenticationOptions(new Browser().req, { mode: 'second-factor' }),
      'UNAUTHENTICATED',
    )
    // passwordless for a 2FA user: the passkey with user verification is both factors
    const { result } = await passwordless(h, adaKey)
    expect(result).toEqual({ status: 'signed-in' })
    expect(h.eventsOf('login').at(-1)).toMatchObject({ method: 'passkey', secondFactor: 'passkey' })
  })

  it('confirms the "password" for passwordless accounts', async () => {
    const h = harness({ store, config })
    const user = await h.user('ada@acme.test')
    const device = new SoftAuthenticator(ORIGIN)
    await addPasskey(h, await h.signedIn(user.email), device)
    const { b } = await passwordless(h, device)
    expect((await h.auth.state(b.req))?.session.passwordConfirmedAt).toBeNull()
    const options = await h.auth.passkeys.authenticationOptions(b.req, { mode: 'confirm' })
    expect(await h.auth.passkeys.authenticate(b.req, { response: device.assert(options) })).toEqual(
      { status: 'confirmed' },
    )
    expect((await h.auth.state(b.req))?.session.passwordConfirmedAt).toBe(h.clock.now())
  })
})
