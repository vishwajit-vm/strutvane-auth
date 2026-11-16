/**
 * Cookie names (CONSISTENCY #24, #105): every cookie uses the `strutvane_` prefix, `__Host-` on
 * https, and all of them come from ONE source (`COOKIE_NAMES`, exposed resolved as
 * `auth.cookieNames`), so the framework's CSRF check and the session layer cannot drift apart.
 */
import { describe, expect, it } from 'vitest'
import { COOKIE_NAMES } from '../../src/engine/core/deps.ts'
import { Browser, harness, PASSWORD } from './helpers/harness.ts'

const HTTPS = 'https://app.example.com'

describe('cookie names', () => {
  it('one source lists every cookie, all with the strutvane_ prefix', () => {
    expect(COOKIE_NAMES).toEqual({
      session: 'strutvane_session',
      emailLink: 'strutvane_link',
      device: 'strutvane_device',
      webauthn: 'strutvane_webauthn',
      registration: 'strutvane_register',
    })
  })

  it('auth.cookieNames resolves them per scheme: __Host- on https, plain on local http', () => {
    const secure = harness({ config: { appUrl: HTTPS } }).auth.cookieNames
    expect(Object.values(secure).every((name) => name.startsWith('__Host-strutvane_'))).toBe(true)
    expect(secure.session).toBe('__Host-strutvane_session')
    const local = harness().auth.cookieNames
    expect(local.session).toBe('strutvane_session')
  })

  it('every cookie actually set on https carries its __Host-strutvane_ name', async () => {
    const h = harness({
      config: {
        appUrl: HTTPS,
        features: {
          registration: true,
          emailVerification: true,
          emailLink: true,
          twoFactor: true,
          passkeys: true,
        },
        passkeys: { rpId: 'app.example.com', rpName: 'Acme', origins: [HTTPS] },
      },
    })
    const seen = new Set<string>()
    const note = (b: Browser) => {
      for (const name of b.jar.keys()) seen.add(name)
    }
    const reg = new Browser()
    await h.auth.passwords.register(reg.req, {
      name: 'New',
      email: 'new@acme.test',
      password: PASSWORD,
    })
    note(reg)
    await h.user('ada@acme.test')
    const link = new Browser()
    await h.auth.emailLink.request(link.req, { email: 'ada@acme.test' })
    note(link)
    const b = await h.signedIn('ada@acme.test')
    note(b)
    await h.auth.passwords.confirm(b.req, { password: PASSWORD })
    await h.auth.passkeys.registrationOptions(b.req)
    note(b)
    expect([...seen].sort()).toEqual(
      [
        '__Host-strutvane_link',
        '__Host-strutvane_register',
        '__Host-strutvane_session',
        '__Host-strutvane_webauthn',
      ].sort(),
    )
    expect(h.auth.cookieNames.device).toBe('__Host-strutvane_device')
  })
})
