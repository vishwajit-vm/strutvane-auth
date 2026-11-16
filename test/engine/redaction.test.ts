import { describe, expect, it } from 'vitest'
import { createAuth } from '../../src/engine/auth.ts'
import { defineAuthConfig } from '../../src/engine/config.ts'
import { base32Decode } from '../../src/engine/crypto/random.ts'
import { manualClock } from '../../src/engine/ports/clock.ts'
import { memoryAuthStore, memoryCounterStore } from '../../src/engine/store/memory.ts'
import { totp } from '../../src/engine/totp/totp.ts'
import { SoftAuthenticator } from './helpers/authenticator.ts'
import { APP_KEY, Browser, FAST_HASHER, harness, PASSWORD, START } from './helpers/harness.ts'

const ORIGIN = 'http://localhost:3000'

describe('no secrets in events or logs', () => {
  it('a full run through every feature emits no password, token, code, cookie, link or TOTP secret', async () => {
    const h = harness({
      store: 'sqlite',
      config: {
        features: {
          registration: true,
          emailVerification: true,
          emailLink: true,
          twoFactor: true,
          passkeys: true,
          tokens: true,
          teams: true,
          impersonation: true,
        },
        passkeys: { rpId: 'localhost', rpName: 'Acme', origins: [ORIGIN] },
      },
    })
    const secrets = h.secrets
    secrets.add(PASSWORD)
    const remember = (b: Browser) => {
      for (const v of b.jar.values()) secrets.add(v)
    }
    // registration + verification
    const reg = new Browser()
    await h.auth.passwords.register(reg.req, {
      name: 'Ada',
      email: 'ada@acme.test',
      password: PASSWORD,
    })
    await h.mail('verify-email')
    const admin = await h.user('root@acme.test', { roles: ['admin'] })
    // failed logins + lockout
    for (let i = 0; i < 6; i++) {
      const wrong = `wrong-password-${i}-xyz`
      secrets.add(wrong)
      await h.auth.passwords
        .login(new Browser(`198.51.100.${i}`).req, { email: 'ada@acme.test', password: wrong })
        .catch(() => undefined)
    }
    h.clock.advance(2 * 60 * 60_000)
    // reset
    await h.auth.passwordReset.request(new Browser().req, { email: 'ada@acme.test' })
    const newPassword = 'second secret passphrase'
    secrets.add(newPassword)
    await h.auth.passwordReset.reset(new Browser().req, {
      token: await h.mailedToken('password-reset'),
      password: newPassword,
    })
    // email link
    const linkBrowser = new Browser()
    await h.auth.emailLink.request(linkBrowser.req, { email: 'ada@acme.test' })
    await h.auth.emailLink.consume(linkBrowser.req, { token: await h.mailedToken('email-link') })
    remember(linkBrowser)
    // 2FA
    await h.auth.passwords.confirm(linkBrowser.req, { password: newPassword })
    const setup = await h.auth.twoFactor.enable(linkBrowser.req)
    secrets.add(setup.secret)
    secrets.add(setup.otpauthUri)
    const secret = base32Decode(setup.secret) ?? Buffer.alloc(0)
    const confirmCode = totp(secret, h.clock.now())
    secrets.add(confirmCode)
    const { recoveryCodes } = await h.auth.twoFactor.confirm(linkBrowser.req, { code: confirmCode })
    for (const c of recoveryCodes) secrets.add(c)
    remember(linkBrowser)
    const pending = new Browser()
    await h.auth.passwords.login(pending.req, { email: 'ada@acme.test', password: newPassword })
    remember(pending)
    await h.auth.twoFactor.challenge(pending.req, { code: '000000' }).catch(() => undefined)
    await h.auth.twoFactor.challenge(pending.req, {
      recoveryCode: recoveryCodes[0],
      rememberDevice: true,
    })
    remember(pending)
    // passkeys
    await h.auth.passwords.confirm(pending.req, { password: newPassword })
    const device = new SoftAuthenticator(ORIGIN)
    const options = await h.auth.passkeys.registrationOptions(pending.req)
    remember(pending)
    secrets.add(options.challenge)
    await h.auth.passkeys.register(pending.req, { response: device.register(options) })
    // tokens
    const { plainText } = await h.auth.tokens.create(pending.req, { name: 'CI' })
    secrets.add(plainText)
    await h.auth.tokens.authenticate(`Bearer ${plainText}`)
    // teams
    const team = await h.auth.teams.create(pending.req, { name: 'Acme' })
    await h.auth.teams.invite(pending.req, {
      teamId: team.id,
      email: 'vic@acme.test',
      role: 'member',
    })
    await h.mailedToken('team-invitation')
    // impersonation
    const adminBrowser = await h.signedIn(admin.email)
    await h.auth.passwords.confirm(adminBrowser.req, { password: PASSWORD })
    await h.auth.impersonation.start(adminBrowser.req, {
      userId: (await h.store.findUserByEmail('ada@acme.test'))?.id,
    })
    remember(adminBrowser)
    await h.auth.impersonation.stop(adminBrowser.req)
    remember(adminBrowser)
    await h.auth.passwords.logout(adminBrowser.req)
    await h.auth.idle()

    const recorded = JSON.stringify({ events: h.events, logs: h.logs })
    expect(h.events.length).toBeGreaterThan(20)
    const leaked = [...secrets].filter((s) => s.length >= 6 && recorded.includes(s))
    expect(leaked).toEqual([])
    // every event type the audit log promises appeared
    const types = new Set(h.events.map((e) => e.type))
    for (const t of [
      'registered',
      'login',
      'login.failed',
      'lockout',
      'logout',
      'password.changed',
      'two-factor.enabled',
      'token.created',
      'impersonation.started',
      'impersonation.stopped',
    ] as const)
      expect(types.has(t), t).toBe(true)
  })

  it('failing mailers and event sinks are logged by kind only, and never break the operation', async () => {
    const logs: string[] = []
    const clock = manualClock(START)
    const auth = createAuth({
      config: defineAuthConfig({ appUrl: 'http://localhost:3000' }),
      store: memoryAuthStore(),
      counters: memoryCounterStore(clock),
      clock,
      appKey: APP_KEY,
      hasher: FAST_HASHER,
      mailer: {
        send: async (mail) =>
          Promise.reject(new Error(`SMTP refused ${'url' in mail ? mail.url : ''}`)),
      },
      events: {
        emit: () => {
          throw new Error('sink down')
        },
      },
      logger: { warn: (m, c) => void logs.push(`${m} ${JSON.stringify(c ?? {})}`) },
    })
    await auth.system.createUser({ name: 'Ada', email: 'ada@acme.test', password: PASSWORD })
    expect(await auth.passwordReset.request(new Browser().req, { email: 'ada@acme.test' })).toEqual(
      { status: 'sent' },
    )
    await auth.passwords.login(new Browser().req, { email: 'ada@acme.test', password: PASSWORD })
    await auth.idle()
    expect(logs.some((l) => l.includes('mail:password-reset'))).toBe(true)
    expect(logs.some((l) => l.includes('event sink failed'))).toBe(true)
    expect(logs.join('\n')).not.toMatch(/reset-password\/|SMTP refused/)
  })

  it('error bodies never echo the submitted credentials', async () => {
    const h = harness()
    try {
      await h.auth.passwords.login(new Browser().req, {
        email: 'ada@acme.test',
        password: 'my-very-secret-pw',
      })
    } catch (e) {
      expect(JSON.stringify(e)).not.toContain('my-very-secret-pw')
      expect(String(e)).not.toContain('my-very-secret-pw')
      expect(String(e)).not.toContain('ada@acme.test')
    }
  })
})
