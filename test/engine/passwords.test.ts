import { describe, expect, it } from 'vitest'
import { sessionCookie } from '../../src/engine/core/sessions.ts'
import { AUTH_MESSAGES, AuthError } from '../../src/engine/errors.ts'
import { createScryptHasher, type PasswordHasher } from '../../src/engine/password/hasher.ts'
import { Browser, FAST_HASHER, harness, PASSWORD, rejectsWith, STORES } from './helpers/harness.ts'

const COOKIE = 'strutvane_session'

describe.each(STORES)('email + password (%s store)', (store) => {
  describe('registration', () => {
    it('is off by default: a 404-style not_found, never 403', async () => {
      const h = harness({ store })
      await rejectsWith(
        () =>
          h.auth.passwords.register(new Browser().req, {
            name: 'x',
            email: 'x@y.io',
            password: PASSWORD,
          }),
        'not_found',
      )
    })

    it('with verification on, new and taken emails get the SAME answer and no session', async () => {
      const h = harness({
        store,
        config: { features: { registration: true, emailVerification: true } },
      })
      await h.user('taken@acme.test')
      const fresh = new Browser()
      const taken = new Browser()
      const a = await h.auth.passwords.register(fresh.req, {
        name: 'New',
        email: 'new@acme.test',
        password: PASSWORD,
      })
      const b = await h.auth.passwords.register(taken.req, {
        name: 'Again',
        email: 'TAKEN@acme.test',
        password: PASSWORD,
      })
      expect(a).toEqual(b)
      expect(a).toEqual({ status: 'verification-sent' })
      // No session either way; the only cookie is the registration binding (#122), set for both.
      expect([...fresh.jar.keys()]).toEqual(['strutvane_register'])
      expect([...taken.jar.keys()]).toEqual(['strutvane_register'])
      expect((await h.mail('verify-email')).to).toBe('new@acme.test')
      // The owner of the taken address is told; the requester learns nothing.
      expect((await h.mail('registration-attempt')).to).toBe('taken@acme.test')
      expect(h.eventsOf('registered')).toHaveLength(1)
    })

    it('without verification it signs in, and a taken email is reported (documented trade-off)', async () => {
      const h = harness({ store, config: { features: { registration: true } } })
      const b = new Browser()
      expect(
        await h.auth.passwords.register(b.req, {
          name: 'Ada',
          email: 'ada@acme.test',
          password: PASSWORD,
        }),
      ).toEqual({ status: 'signed-in' })
      expect((await h.auth.state(b.req))?.user.email).toBe('ada@acme.test')
      await rejectsWith(
        () =>
          h.auth.passwords.register(new Browser().req, {
            name: 'A',
            email: 'Ada@Acme.test',
            password: PASSWORD,
          }),
        'email_taken',
      )
    })

    it('validates every field and never throws an internal error on hostile types', async () => {
      const h = harness({ store, config: { features: { registration: true } } })
      for (const input of [
        { name: '', email: 'a@b.io', password: PASSWORD },
        { name: 'A', email: 'nope', password: PASSWORD },
        { name: 'A', email: { $ne: null }, password: PASSWORD },
        { name: ['A'], email: 'a@b.io', password: PASSWORD },
        { name: 'A', email: 'a@b.io', password: 123456789012345 },
      ])
        await rejectsWith(
          () => h.auth.passwords.register(new Browser().req, input),
          'validation_failed',
        )
      await rejectsWith(
        () =>
          h.auth.passwords.register(new Browser().req, {
            name: 'A',
            email: 'a@b.io',
            password: 'short',
          }),
        'weak_password',
      )
    })
  })

  describe('sign-in', () => {
    it('signs in with a fresh session cookie and a login event', async () => {
      const h = harness({ store })
      const user = await h.user()
      const b = new Browser()
      expect(
        await h.auth.passwords.login(b.req, { email: ' ADA@acme.test ', password: PASSWORD }),
      ).toEqual({ status: 'signed-in' })
      expect(b.get(COOKIE)).toMatch(/^[A-Za-z0-9_-]{43}$/)
      expect((await h.auth.state(b.req))?.user.id).toBe(user.id)
      expect(h.eventsOf('login')).toEqual([
        expect.objectContaining({ userId: user.id, method: 'password', secondFactor: null }),
      ])
    })

    it('no enumeration by message: unknown email, wrong password and passwordless account fail identically', async () => {
      const h = harness({ store })
      await h.user('known@acme.test')
      await h.user('nopass@acme.test', { password: null })
      const errors: AuthError[] = []
      for (const [email, password] of [
        ['known@acme.test', 'wrong password here'],
        ['unknown@acme.test', 'wrong password here'],
        ['nopass@acme.test', 'wrong password here'],
      ] as const) {
        try {
          await h.auth.passwords.login(new Browser().req, { email, password })
        } catch (e) {
          if (e instanceof AuthError) errors.push(e)
        }
      }
      expect(errors.map((e) => [e.code, e.message, e.status, e.options])).toEqual(
        Array(3).fill(['invalid_credentials', AUTH_MESSAGES.invalid_credentials, 422, {}]),
      )
    })

    it('no enumeration by work: every path runs exactly one full-cost hash verification', async () => {
      const calls: string[] = []
      const spy: PasswordHasher = {
        hash: (pw) => FAST_HASHER.hash(pw),
        verify: async (pw, stored) => {
          calls.push('verify')
          return FAST_HASHER.verify(pw, stored)
        },
        needsRehash: (s) => FAST_HASHER.needsRehash(s),
        verifyDummy: async (pw) => {
          calls.push('dummy')
          return FAST_HASHER.verifyDummy(pw)
        },
      }
      const h = harness({ store, hasher: spy })
      await h.user('known@acme.test')
      await h.user('nopass@acme.test', { password: null })
      for (const email of ['known@acme.test', 'unknown@acme.test', 'nopass@acme.test']) {
        calls.length = 0
        await rejectsWith(
          () =>
            h.auth.passwords.login(new Browser().req, { email, password: 'wrong password here' }),
          'invalid_credentials',
        )
        expect(calls).toHaveLength(1)
      }
    })

    it('no enumeration by timing: known and unknown emails take about the same time (real scrypt)', async () => {
      const h = harness({
        store,
        config: {
          limits: {
            loginPerIp: { max: 1000, windowSeconds: 60 },
            loginPerAccount: { max: 1000, windowSeconds: 60 },
          },
          lockout: { threshold: 1000 },
        },
      })
      await h.user('known@acme.test')
      // CPU time of this process (scrypt runs on libuv's pool, which process.cpuUsage includes), not
      // wall-clock time: wall time also counts every OTHER process on a busy machine, so the ratio
      // drifted to 1.7 under load while the work was identical. The work is what an attacker's
      // timing reflects; the structural test above proves each path does one full-cost hash.
      const time = async (email: string): Promise<number> => {
        const before = process.cpuUsage()
        await h.auth.passwords
          .login(new Browser().req, { email, password: 'wrong password here' })
          .catch(() => undefined)
        const used = process.cpuUsage(before)
        return (used.user + used.system) / 1000
      }
      await time('warmup@acme.test')
      const known: number[] = []
      const unknown: number[] = []
      for (let i = 0; i < 12; i++) {
        known.push(await time('known@acme.test'))
        unknown.push(await time(`unknown${i}@acme.test`))
      }
      const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)] ?? 0
      const ratio = median(known) / median(unknown)
      expect(ratio).toBeGreaterThan(0.6)
      expect(ratio).toBeLessThan(1.6)
    })

    it('rehash-on-login upgrades an old hash to the current parameters', async () => {
      const db =
        store === 'sqlite' ? new (await import('node:sqlite')).DatabaseSync(':memory:') : undefined
      const old = harness({ store, ...(db ? { db } : {}) })
      const user = await old.user()
      const stronger = createScryptHasher({ params: { logN: 15, r: 8, p: 1 } })
      const h = db ? harness({ store, db, hasher: stronger }) : harness({ store, hasher: stronger })
      // memory stores are per-harness: copy the user across
      if (!db) await h.store.createUser(user)
      expect(user.passwordHash?.startsWith('$scrypt$ln=14')).toBe(true)
      await h.auth.passwords.login(new Browser().req, { email: user.email, password: PASSWORD })
      const after = await h.store.findUserById(user.id)
      expect(after?.passwordHash?.startsWith('$scrypt$ln=15')).toBe(true)
      expect(h.eventsOf('password.rehashed')).toHaveLength(1)
      // and it still verifies with the new hash
      await h.auth.passwords.login(new Browser().req, { email: user.email, password: PASSWORD })
      expect(h.eventsOf('password.rehashed')).toHaveLength(1)
    })

    it('rejects hostile input types before any lookup', async () => {
      const h = harness({ store })
      for (const input of [
        { email: { $gt: '' }, password: PASSWORD },
        { email: ['ada@acme.test'], password: PASSWORD },
        { email: 'ada@acme.test', password: 0 },
        { email: 'ada@acme.test', password: { length: 1 } },
        { email: 'ada@acme.test', password: 'x'.repeat(10_000) },
      ])
        await rejectsWith(
          () => h.auth.passwords.login(new Browser().req, input),
          'validation_failed',
        )
    })
  })

  describe('rate limits and lockout', () => {
    it('limits per IP with Retry-After; another IP is unaffected', async () => {
      const h = harness({ store, config: { lockout: { threshold: 1000 } } })
      await h.user()
      for (let i = 0; i < 10; i++)
        await rejectsWith(
          () =>
            h.auth.passwords.login(new Browser('198.51.100.1').req, {
              email: `x${i}@acme.test`,
              password: 'wrong password!',
            }),
          'invalid_credentials',
        )
      const limited = await rejectsWith(
        () =>
          h.auth.passwords.login(new Browser('198.51.100.1').req, {
            email: 'ada@acme.test',
            password: PASSWORD,
          }),
        'rate_limited',
      )
      expect(limited.retryAfterSeconds).toBeGreaterThan(0)
      expect(
        (
          await h.auth.passwords.login(new Browser('198.51.100.2').req, {
            email: 'ada@acme.test',
            password: PASSWORD,
          })
        ).status,
      ).toBe('signed-in')
    })

    it('bypass attempt: rotating IPv6 addresses inside one /64 does not reset the per-IP limit', async () => {
      const h = harness({ store, config: { lockout: { threshold: 1000 } } })
      for (let i = 0; i < 10; i++)
        await rejectsWith(
          () =>
            h.auth.passwords.login(new Browser(`2001:db8:5:6::${i.toString(16)}`).req, {
              email: `x${i}@acme.test`,
              password: 'wrong password!',
            }),
          'invalid_credentials',
        )
      await rejectsWith(
        () =>
          h.auth.passwords.login(new Browser('2001:db8:5:6:ffff::99').req, {
            email: 'y@acme.test',
            password: 'wrong password!',
          }),
        'rate_limited',
      )
    })

    it('bypass attempt: requests without a client address share one bucket (fail closed)', async () => {
      const h = harness({ store, config: { lockout: { threshold: 1000 } } })
      for (let i = 0; i < 10; i++)
        await rejectsWith(
          () =>
            h.auth.passwords.login(new Browser(undefined).req, {
              email: `x${i}@acme.test`,
              password: 'wrong password!',
            }),
          'invalid_credentials',
        )
      await rejectsWith(
        () =>
          h.auth.passwords.login(new Browser(undefined).req, {
            email: 'y@acme.test',
            password: 'wrong password!',
          }),
        'rate_limited',
      )
    })

    it('bypass attempt: a distributed attack on one account from many IPs hits the per-account limit', async () => {
      const h = harness({ store, config: { lockout: { threshold: 1000 } } })
      await h.user()
      for (let i = 0; i < 20; i++)
        await rejectsWith(
          () =>
            h.auth.passwords.login(new Browser(`198.51.100.${i}`).req, {
              email: 'ada@acme.test',
              password: 'wrong password!',
            }),
          'invalid_credentials',
        )
      // Case and spacing variants of the email are the SAME account key.
      await rejectsWith(
        () =>
          h.auth.passwords.login(new Browser('192.0.2.200').req, {
            email: ' ADA@ACME.TEST',
            password: PASSWORD,
          }),
        'rate_limited',
      )
    })

    it('locks out after 5 consecutive failures, with doubling backoff, identically for unknown emails', async () => {
      const h = harness({ store })
      await h.user()
      const fail = (email: string, ip: string) =>
        rejectsWith(
          () => h.auth.passwords.login(new Browser(ip).req, { email, password: 'wrong password!' }),
          'invalid_credentials',
        )
      for (let i = 0; i < 5; i++) {
        await fail('ada@acme.test', `198.51.100.${i}`)
        await fail('ghost@acme.test', `198.51.100.${i + 50}`)
      }
      const known = await rejectsWith(
        () =>
          h.auth.passwords.login(new Browser('192.0.2.1').req, {
            email: 'ada@acme.test',
            password: PASSWORD,
          }),
        'rate_limited',
      )
      const ghost = await rejectsWith(
        () =>
          h.auth.passwords.login(new Browser('192.0.2.2').req, {
            email: 'ghost@acme.test',
            password: PASSWORD,
          }),
        'rate_limited',
      )
      expect(known.retryAfterSeconds).toBe(60)
      expect(ghost.retryAfterSeconds).toBe(60)
      const lockouts = h.eventsOf('lockout')
      expect(lockouts).toHaveLength(2)
      h.clock.advance(61_000)
      await fail('ada@acme.test', '192.0.2.3')
      const longer = await rejectsWith(
        () =>
          h.auth.passwords.login(new Browser('192.0.2.4').req, {
            email: 'ada@acme.test',
            password: PASSWORD,
          }),
        'rate_limited',
      )
      expect(longer.retryAfterSeconds).toBe(120)
      h.clock.advance(121_000)
      expect(
        (
          await h.auth.passwords.login(new Browser('192.0.2.5').req, {
            email: 'ada@acme.test',
            password: PASSWORD,
          })
        ).status,
      ).toBe('signed-in')
      // success resets the count
      await fail('ada@acme.test', '192.0.2.6')
      expect(
        (
          await h.auth.passwords.login(new Browser('192.0.2.7').req, {
            email: 'ada@acme.test',
            password: PASSWORD,
          })
        ).status,
      ).toBe('signed-in')
    })
  })

  describe('sessions', () => {
    it('session fixation: a cookie planted before sign-in is never upgraded', async () => {
      const h = harness({ store })
      await h.user()
      const victim = new Browser()
      victim.set(COOKIE, 'A'.repeat(43)) // attacker-chosen id
      const attackerCopy = victim.clone()
      await h.auth.passwords.login(victim.req, { email: 'ada@acme.test', password: PASSWORD })
      expect(victim.get(COOKIE)).not.toBe('A'.repeat(43))
      expect(await h.auth.state(attackerCopy.req)).toBeNull()
      // A real pre-existing session is deleted too, not reused.
      const old = await h.signedIn('ada@acme.test')
      const before = old.clone()
      await h.auth.passwords.login(old.req, { email: 'ada@acme.test', password: PASSWORD })
      expect(await h.auth.state(before.req)).toBeNull()
      expect(await h.auth.state(old.req)).not.toBeNull()
    })

    it('the store never holds the raw session id', async () => {
      const h = harness({ store })
      const user = await h.user()
      const b = await h.signedIn(user.email)
      const raw = b.get(COOKIE) ?? ''
      const rows = await h.store.listUserSessions(user.id)
      expect(rows).toHaveLength(1)
      expect(JSON.stringify(rows)).not.toContain(raw)
    })

    it('logout deletes the session server-side, so a copied cookie stops working', async () => {
      const h = harness({ store })
      await h.user()
      const b = await h.signedIn('ada@acme.test')
      const stolen = b.clone('192.0.2.99')
      await h.auth.passwords.logout(b.req)
      expect(b.get(COOKIE)).toBeUndefined()
      expect(await h.auth.state(stolen.req)).toBeNull()
      expect(h.eventsOf('logout')).toHaveLength(1)
    })

    it('idle and absolute timeouts; "remember me" lasts longer', async () => {
      const h = harness({ store })
      await h.user()
      const b = await h.signedIn('ada@acme.test')
      h.clock.advance(119 * 60_000)
      expect(await h.auth.state(b.req)).not.toBeNull() // touched
      h.clock.advance(119 * 60_000)
      expect(await h.auth.state(b.req)).not.toBeNull()
      h.clock.advance(121 * 60_000) // idle > 120 min
      expect(await h.auth.state(b.req)).toBeNull()
      const active = await h.signedIn('ada@acme.test')
      for (let i = 0; i < 12; i++) {
        h.clock.advance(60 * 60_000 - 1)
        expect(await h.auth.state(active.req)).not.toBeNull()
      }
      h.clock.advance(60 * 60_000) // beyond 12 h absolute despite activity
      expect(await h.auth.state(active.req)).toBeNull()
      const remembered = new Browser()
      await h.auth.passwords.login(remembered.req, {
        email: 'ada@acme.test',
        password: PASSWORD,
        remember: true,
      })
      h.clock.advance(5 * 24 * 60 * 60_000)
      expect(await h.auth.state(remembered.req)).not.toBeNull()
      h.clock.advance(26 * 24 * 60 * 60_000)
      expect(await h.auth.state(remembered.req)).toBeNull()
    })

    it('lists sessions by handle (never the id) and signs out the others after confirmation', async () => {
      const h = harness({ store })
      const user = await h.user()
      const laptop = await h.signedIn(user.email, '192.0.2.1')
      const phone = await h.signedIn(user.email, '192.0.2.2')
      const list = await h.auth.sessions.list(laptop.req)
      expect(list).toHaveLength(2)
      expect(list.filter((s) => s.current)).toHaveLength(1)
      expect(JSON.stringify(list)).not.toContain(laptop.get(COOKIE) ?? 'x')
      expect(JSON.stringify(list)).not.toContain(phone.get(COOKIE) ?? 'x')
      await rejectsWith(
        () => h.auth.sessions.revokeOthers(laptop.req),
        'password_confirmation_required',
      )
      await h.auth.passwords.confirm(laptop.req, { password: PASSWORD })
      const before = laptop.get(COOKIE)
      expect(await h.auth.sessions.revokeOthers(laptop.req)).toBe(1)
      expect(laptop.get(COOKIE)).not.toBe(before) // rotated
      expect(await h.auth.state(phone.req)).toBeNull()
      expect(await h.auth.state(laptop.req)).not.toBeNull()
      // revoke one by handle
      const tablet = await h.signedIn(user.email, '192.0.2.3')
      const handle = (await h.auth.sessions.list(laptop.req)).find((s) => !s.current)?.handle
      await h.auth.sessions.revoke(laptop.req, { handle })
      expect(await h.auth.state(tablet.req)).toBeNull()
      await rejectsWith(
        () => h.auth.sessions.revoke(laptop.req, { handle: 'ffffffffffffffff' }),
        'not_found',
      )
    })

    it('password confirmation opens a 3-hour window, and is rate-limited', async () => {
      const h = harness({ store })
      await h.user()
      const b = await h.signedIn('ada@acme.test')
      await rejectsWith(
        () => h.auth.passwords.confirm(b.req, { password: 'wrong password!' }),
        'invalid_credentials',
      )
      await h.auth.passwords.confirm(b.req, { password: PASSWORD })
      await h.auth.passwords.confirm(b.req, { password: PASSWORD })
      expect((await h.auth.state(b.req))?.session.passwordConfirmedAt).toBe(h.clock.now())
      for (let i = 0; i < 3; i++) {
        h.clock.advance(60 * 60_000) // stay active (idle timeout is 2 h)
        await h.auth.state(b.req)
      }
      h.clock.advance(1)
      await rejectsWith(() => h.auth.sessions.revokeOthers(b.req), 'password_confirmation_required')
      for (let i = 0; i < 5; i++)
        await h.auth.passwords.confirm(b.req, { password: 'wrong' }).catch(() => undefined)
      await rejectsWith(
        () => h.auth.passwords.confirm(b.req, { password: PASSWORD }),
        'rate_limited',
      )
    })

    it('changing the password needs the current one, ends other sessions and old reset links, rotates the id', async () => {
      const h = harness({ store })
      const user = await h.user()
      const me = await h.signedIn(user.email)
      const other = await h.signedIn(user.email, '192.0.2.50')
      await h.auth.passwordReset.request(new Browser().req, { email: user.email })
      const oldLink = await h.mailedToken('password-reset')
      await rejectsWith(
        () =>
          h.auth.passwords.change(me.req, {
            current: 'wrong password!',
            password: 'brand new passphrase',
          }),
        'invalid_credentials',
      )
      const before = me.get(COOKIE)
      await h.auth.passwords.change(me.req, { current: PASSWORD, password: 'brand new passphrase' })
      expect(me.get(COOKIE)).not.toBe(before)
      expect(await h.auth.state(me.req)).not.toBeNull()
      expect(await h.auth.state(other.req)).toBeNull()
      await rejectsWith(
        () =>
          h.auth.passwordReset.reset(new Browser().req, {
            token: oldLink,
            password: 'attacker sets this',
          }),
        'invalid_token',
      )
      expect((await h.mail('password-changed')).to).toBe(user.email)
      expect(h.eventsOf('password.changed')).toEqual([expect.objectContaining({ via: 'settings' })])
      await rejectsWith(
        () => h.auth.passwords.login(new Browser().req, { email: user.email, password: PASSWORD }),
        'invalid_credentials',
      )
    })

    it('attack: guessing the current password through "change password" is rate-limited like confirmation', async () => {
      const h = harness({ store })
      const user = await h.user()
      const thief = await h.signedIn(user.email) // a stolen session cookie
      for (let i = 0; i < 5; i++)
        await rejectsWith(
          () =>
            h.auth.passwords.change(thief.req, {
              current: `guess number ${i}!`,
              password: 'thief picks this one',
            }),
          'invalid_credentials',
        )
      await rejectsWith(
        () =>
          h.auth.passwords.change(thief.req, {
            current: PASSWORD,
            password: 'thief picks this one',
          }),
        'rate_limited',
      )
      await rejectsWith(
        () => h.auth.passwords.confirm(thief.req, { password: PASSWORD }),
        'rate_limited',
      )
    })

    it('every password check is length-bounded before hashing, with one measure for setting and checking', async () => {
      let derives = 0
      const spy: PasswordHasher = {
        hash: (pw) => FAST_HASHER.hash(pw),
        verify: (pw, stored) => {
          derives += 1
          return FAST_HASHER.verify(pw, stored)
        },
        needsRehash: (stored) => FAST_HASHER.needsRehash(stored),
        verifyDummy: (pw) => {
          derives += 1
          return FAST_HASHER.verifyDummy(pw)
        },
      }
      const h = harness({ store, hasher: spy })
      // 200 characters once normalised (allowed, max 256), but 400 UTF-16 units as typed (decomposed é).
      const decomposed = 'e\u0301'.repeat(200)
      const user = await h.user('ada@acme.test', { password: decomposed })
      const b = new Browser()
      expect(
        (await h.auth.passwords.login(b.req, { email: user.email, password: decomposed })).status,
      ).toBe('signed-in')
      await h.auth.passwords.confirm(b.req, { password: decomposed })
      derives = 0
      const huge = 'x'.repeat(1_000_000)
      await rejectsWith(
        () => h.auth.passwords.change(b.req, { current: huge, password: 'brand new passphrase' }),
        'invalid_credentials',
      )
      await rejectsWith(
        () => h.auth.passwords.confirm(b.req, { password: huge }),
        'invalid_credentials',
      )
      await rejectsWith(
        () => h.auth.passwords.login(new Browser().req, { email: user.email, password: huge }),
        'validation_failed',
      )
      await rejectsWith(
        () => h.auth.system.createUser({ name: 'x', email: 'x@acme.test', password: huge }),
        'weak_password',
      )
      expect(derives).toBe(0)
    })

    it('cookie names get the __Host- prefix on https', async () => {
      const h = harness({ store, config: { appUrl: 'https://app.example.com' } })
      await h.user()
      const b = await h.signedIn('ada@acme.test')
      expect(b.get('__Host-strutvane_session')).toBeDefined()
      expect(b.get(COOKIE)).toBeUndefined()
    })
  })
})

describe('session cookie helper', () => {
  it('names the cookie per scheme', () => {
    expect(COOKIE).toBe('strutvane_session')
    expect(typeof sessionCookie).toBe('function')
  })
})
