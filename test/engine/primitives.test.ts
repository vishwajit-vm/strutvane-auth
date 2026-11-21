import { createHash, pbkdf2Sync, randomBytes, timingSafeEqual } from 'node:crypto'
import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { defineAuthConfig } from '../../src/engine/config.ts'
import { open, seal } from '../../src/engine/crypto/aead.ts'
import { safeEqual } from '../../src/engine/crypto/constant-time.ts'
import { createKeyRing } from '../../src/engine/crypto/keys.ts'
import { base32Decode, base32Encode, randomCode } from '../../src/engine/crypto/random.ts'
import { rateLimitSubject } from '../../src/engine/limits/ip.ts'
import { createLimiter } from '../../src/engine/limits/limiter.ts'
import { createLockout } from '../../src/engine/limits/lockout.ts'
import { normalizeEmail, parseEmail } from '../../src/engine/password/email.ts'
import { createScryptHasher, type LegacyVerifier } from '../../src/engine/password/hasher.ts'
import {
  assertPasswordAllowed,
  commonPasswordCheck,
  rangeBreachCheck,
} from '../../src/engine/password/rules.ts'
import { manualClock } from '../../src/engine/ports/clock.ts'
import { memoryCounterStore } from '../../src/engine/store/memory.ts'
import { hotp, otpauthUri, totp, verifyTotp } from '../../src/engine/totp/totp.ts'
import { APP_KEY, FAST_HASHER, rejectsWith, START } from './helpers/harness.ts'

describe('key ring', () => {
  it('derives independent subkeys per purpose and refuses short APP_KEYs', () => {
    const keys = createKeyRing(APP_KEY)
    expect(keys.digest('session', 'x')).not.toBe(keys.digest('password-reset', 'x'))
    expect(keys.digest('session', 'x')).toMatch(/^[0-9a-f]{64}$/)
    expect(keys.digest('session', 'x')).toBe(createKeyRing(APP_KEY).digest('session', 'x'))
    expect(keys.digest('session', 'x')).not.toBe(
      createKeyRing(`base64:${randomBytes(32).toString('base64')}`).digest('session', 'x'),
    )
    // A keyed digest is not the plain SHA-256 a leaked table could be checked against.
    expect(keys.digest('session', 'x')).not.toBe(createHash('sha256').update('x').digest('hex'))
    expect(() => createKeyRing('short')).toThrow(/32 bytes/)
    expect(() => createKeyRing(`base64:${randomBytes(16).toString('base64')}`)).toThrow(RangeError)
  })
})

describe('AES-GCM sealing (TOTP secret at rest)', () => {
  const key = createKeyRing(APP_KEY).subkey('two-factor-secret')
  it('round-trips, and refuses tampering or another user context', () => {
    const sealed = seal(key, 'secret-value', 'user-1')
    expect(sealed).not.toContain('secret-value')
    expect(open(key, sealed, 'user-1')).toBe('secret-value')
    expect(open(key, sealed, 'user-2')).toBeUndefined()
    const parts = sealed.split('.')
    const flipped = [...parts]
    flipped[2] = Buffer.from(
      Buffer.from(parts[2] ?? '', 'base64url').map((b, i) => (i === 0 ? b ^ 1 : b)),
    ).toString('base64url')
    expect(open(key, flipped.join('.'), 'user-1')).toBeUndefined()
    expect(open(key, 'garbage', 'user-1')).toBeUndefined()
    // a truncated authentication tag is refused, not accepted as a weaker check
    const truncated = [...parts]
    truncated[3] = Buffer.from(parts[3] ?? '', 'base64url')
      .subarray(0, 4)
      .toString('base64url')
    expect(open(key, truncated.join('.'), 'user-1')).toBeUndefined()
    expect(
      open(
        createKeyRing(`base64:${randomBytes(32).toString('base64')}`).subkey('two-factor-secret'),
        sealed,
        'user-1',
      ),
    ).toBeUndefined()
    expect(seal(key, 'same', 'u')).not.toBe(seal(key, 'same', 'u')) // random nonce
  })
})

describe('encodings', () => {
  it('base32 round-trips and rejects bad alphabets', () => {
    for (let i = 0; i < 50; i++) {
      const bytes = randomBytes(i)
      expect(base32Decode(base32Encode(bytes))?.equals(bytes)).toBe(true)
    }
    expect(base32Decode('ABC1')).toBeUndefined()
  })
  it('random codes use the unambiguous alphabet', () => {
    for (let i = 0; i < 200; i++)
      expect(randomCode(10)).toMatch(/^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{10}$/)
  })
  it('safeEqual compares by value', () => {
    expect(safeEqual('a', 'a')).toBe(true)
    expect(safeEqual('a', 'b')).toBe(false)
    expect(safeEqual('a', 'aa')).toBe(false)
  })
  it('normalises emails once (case, spaces, Unicode NFC)', () => {
    expect(normalizeEmail('  Ada@Example.COM ')).toBe('ada@example.com')
    expect(normalizeEmail('JÓHN@x.io')).toBe(normalizeEmail('jÓhn@x.io'))
    expect(parseEmail('not-an-email')).toBeUndefined()
    expect(parseEmail(0)).toBeUndefined()
    expect(parseEmail({})).toBeUndefined()
  })
  it('attack: invisible and control characters cannot make a look-alike account', () => {
    // Each renders like admin@acme.test in an admin screen or a mail client, but is another account.
    const hidden = ['​', '‍', '⁠', '­', '‮', '⁦', '\u0000', '\u0007', '\u001b', '\ud800', '']
    for (const ch of hidden) {
      expect(parseEmail(`admin${ch}@acme.test`), JSON.stringify(ch)).toBeUndefined()
      expect(parseEmail(`admin@ac${ch}me.test`), JSON.stringify(ch)).toBeUndefined()
    }
    // Real international addresses still work.
    expect(parseEmail('jösé@exämple.test')).toBe('jösé@exämple.test')
    expect(parseEmail('用户@例子.测试')).toBe('用户@例子.测试')
  })
})

describe('scrypt hasher', () => {
  it('hashes in a self-describing format and verifies', async () => {
    const stored = await FAST_HASHER.hash('a long passphrase here')
    expect(stored).toMatch(/^\$scrypt\$ln=14,r=8,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{86}$/)
    expect(await FAST_HASHER.verify('a long passphrase here', stored)).toBe(true)
    expect(await FAST_HASHER.verify('a long passphrase herE', stored)).toBe(false)
    expect(await FAST_HASHER.hash('same')).not.toBe(await FAST_HASHER.hash('same')) // salted
  })
  it('normalises Unicode (NFKC) so the same password typed differently matches', async () => {
    const stored = await FAST_HASHER.hash('café au lait twelve')
    expect(await FAST_HASHER.verify('café au lait twelve', stored)).toBe(true)
  })
  it('asks for a rehash when the parameters are raised, and never for current ones', async () => {
    const old = await FAST_HASHER.hash('pw-pw-pw-pw-pw')
    const stronger = createScryptHasher({ params: { logN: 15, r: 8, p: 1 } })
    expect(FAST_HASHER.needsRehash(old)).toBe(false)
    expect(stronger.needsRehash(old)).toBe(true)
    expect(await stronger.verify('pw-pw-pw-pw-pw', old)).toBe(true) // old hashes still verify
    expect(stronger.needsRehash('$2y$12$legacy')).toBe(true)
  })
  it('verifies legacy formats through a plug-in and treats malformed or absurd hashes as a mismatch', async () => {
    const legacy: LegacyVerifier = {
      id: 'pbkdf2',
      matches: (h) => h.startsWith('pbkdf2$'),
      async verify(pw, h) {
        const [, salt = '', key = ''] = h.split('$')
        return timingSafeEqual(pbkdf2Sync(pw, salt, 1000, 32, 'sha256'), Buffer.from(key, 'hex'))
      },
    }
    const hasher = createScryptHasher({ params: { logN: 14, r: 8, p: 1 }, legacy: [legacy] })
    const imported = `pbkdf2$salt$${pbkdf2Sync('imported password', 'salt', 1000, 32, 'sha256').toString('hex')}`
    expect(await hasher.verify('imported password', imported)).toBe(true)
    expect(await hasher.verify('wrong', imported)).toBe(false)
    expect(await hasher.verify('x', 'not a hash')).toBe(false)
    // A tampered row asking for 2^30 memory is refused, not executed.
    expect(
      await hasher.verify('x', `$scrypt$ln=30,r=8,p=1$${'A'.repeat(22)}$${'A'.repeat(86)}`),
    ).toBe(false)
    expect(await hasher.verifyDummy('anything')).toBe(false)
  })
  it('refuses weak parameters at construction', () => {
    expect(() => createScryptHasher({ params: { logN: 10, r: 8, p: 1 } })).toThrow(RangeError)
  })
  it('attack: a tampered row cannot buy a huge cost through r and p (each within its own range)', async () => {
    const hasher = createScryptHasher({ params: { logN: 14, r: 8, p: 1 } })
    // logN 16 is "allowed", but r=32 and p=16 make it 32x the work of the default (2^25 vs 2^20).
    const t0 = performance.now()
    expect(
      await hasher.verify('x', `$scrypt$ln=16,r=32,p=16$${'A'.repeat(22)}$${'A'.repeat(86)}`),
    ).toBe(false)
    expect(performance.now() - t0).toBeLessThan(2_000)
    // The same budget binds the hasher's own parameters, so it never writes a hash it would refuse.
    expect(() => createScryptHasher({ params: { logN: 16, r: 32, p: 16 } })).toThrow(RangeError)
    expect(() => createScryptHasher({ params: { logN: 20, r: 16, p: 1 } })).toThrow(RangeError)
    expect(() => createScryptHasher({ params: { logN: 20, r: 8, p: 1 } })).not.toThrow()
  })
  it('default parameters are OWASP 2^17 (time measured for the README)', async () => {
    const hasher = createScryptHasher()
    const t0 = performance.now()
    const stored = await hasher.hash('measure me please')
    const ms = performance.now() - t0
    expect(stored.startsWith('$scrypt$ln=17,r=8,p=1$')).toBe(true)
    expect(ms).toBeLessThan(5000)
  })
})

describe('password rules and checks', () => {
  const base = {
    min: 12,
    max: 256,
    check: commonPasswordCheck,
    onUnknown: 'open' as const,
    logger: undefined,
  }
  it('enforces length and the common list', async () => {
    await rejectsWith(() => assertPasswordAllowed('short', base), 'weak_password')
    await rejectsWith(() => assertPasswordAllowed('x'.repeat(257), base), 'weak_password')
    await rejectsWith(() => assertPasswordAllowed('Password1234', base), 'weak_password')
    await rejectsWith(() => assertPasswordAllowed('aaaaaaaaaaaaaaaa', base), 'weak_password')
    await rejectsWith(() => assertPasswordAllowed(123456789012, base), 'validation_failed')
    expect(await assertPasswordAllowed('a perfectly fine phrase', base)).toBe(
      'a perfectly fine phrase',
    )
  })
  it('the k-anonymity breach check sends only a 5-char prefix; outages fail open with a warning or closed', async () => {
    const sha1 = createHash('sha1').update('pwned password 1').digest('hex').toUpperCase()
    const seen: string[] = []
    const check = rangeBreachCheck(async (prefix) => {
      seen.push(prefix)
      return `${sha1.slice(5)}:42\r\nABCDEF:1`
    })
    expect(await check('pwned password 1')).toBe('compromised')
    expect(await check('not in the list at all')).toBe('ok')
    expect(seen.every((p) => /^[0-9A-F]{5}$/.test(p))).toBe(true)
    const down = rangeBreachCheck(async () => Promise.reject(new Error('offline')))
    const warnings: string[] = []
    const logger = { warn: (m: string) => void warnings.push(m) }
    expect(
      await assertPasswordAllowed('some long passphrase', { ...base, check: down, logger }),
    ).toBe('some long passphrase')
    expect(warnings).toHaveLength(1)
    await rejectsWith(
      () =>
        assertPasswordAllowed('some long passphrase', {
          ...base,
          check: down,
          onUnknown: 'closed',
          logger,
        }),
      'weak_password',
    )
  })
})

describe('TOTP (RFC 6238 / RFC 4226 vectors)', () => {
  const sha1Secret = Buffer.from('12345678901234567890')
  it('matches the RFC 4226 HOTP vectors', () => {
    const expected = [
      '755224',
      '287082',
      '359152',
      '969429',
      '338314',
      '254676',
      '287922',
      '162583',
      '399871',
      '520489',
    ]
    expected.forEach((code, i) => {
      expect(hotp(sha1Secret, i)).toBe(code)
    })
  })
  it('matches the RFC 6238 TOTP vectors (8 digits, SHA-1/256/512)', () => {
    const s256 = Buffer.from('12345678901234567890123456789012')
    const s512 = Buffer.from('1234567890123456789012345678901234567890123456789012345678901234')
    const cases: [number, string, string, string][] = [
      [59, '94287082', '46119246', '90693936'],
      [1111111109, '07081804', '68084774', '25091201'],
      [1234567890, '89005924', '91819424', '93441116'],
      [20000000000, '65353130', '77737706', '47863826'],
    ]
    for (const [t, c1, c256, c512] of cases) {
      expect(totp(sha1Secret, t * 1000, { digits: 8 })).toBe(c1)
      expect(totp(s256, t * 1000, { digits: 8, algorithm: 'sha256' })).toBe(c256)
      expect(totp(s512, t * 1000, { digits: 8, algorithm: 'sha512' })).toBe(c512)
    }
  })
  it('accepts one step of drift either way and returns the matched step', () => {
    const now = START
    const step = Math.floor(now / 30_000)
    expect(verifyTotp(sha1Secret, totp(sha1Secret, now), now)).toBe(step)
    expect(verifyTotp(sha1Secret, totp(sha1Secret, now - 30_000), now)).toBe(step - 1)
    expect(verifyTotp(sha1Secret, totp(sha1Secret, now + 30_000), now)).toBe(step + 1)
    expect(verifyTotp(sha1Secret, totp(sha1Secret, now - 60_000), now)).toBeUndefined()
    expect(verifyTotp(sha1Secret, '12345', now)).toBeUndefined()
  })
  it('builds an otpauth URI authenticator apps accept', () => {
    const uri = otpauthUri({ secret: sha1Secret, issuer: 'Acme', account: 'ada@acme.test' })
    expect(uri).toBe(
      `otpauth://totp/Acme:ada%40acme.test?secret=${base32Encode(sha1Secret)}&issuer=Acme&algorithm=SHA1&digits=6&period=30`,
    )
  })
})

describe('rate limiting', () => {
  it('IPv6 counts per /64 and an unknown address shares one bucket', () => {
    expect(rateLimitSubject('2001:db8:1:2:aaaa::1')).toBe(
      rateLimitSubject('2001:db8:1:2:ffff:ffff:ffff:ffff'),
    )
    expect(rateLimitSubject('2001:db8:1:3::1')).not.toBe(rateLimitSubject('2001:db8:1:2::1'))
    expect(rateLimitSubject('::ffff:203.0.113.5')).toBe('203.0.113.5')
    expect(rateLimitSubject(undefined)).toBe('unknown')
    expect(rateLimitSubject('not an ip')).toBe('unknown')
  })
  it('bypass attempt: every spelling of an IPv4-mapped address is the same client', () => {
    const octet = fc.integer({ min: 0, max: 255 })
    fc.assert(
      fc.property(octet, octet, octet, octet, (a, b, c, d) => {
        const v4 = `${a}.${b}.${c}.${d}`
        const hi = ((a << 8) | b).toString(16)
        const lo = ((c << 8) | d).toString(16)
        const spellings = [
          `::ffff:${v4}`,
          `::FFFF:${v4}`,
          `0:0:0:0:0:ffff:${v4}`,
          `::ffff:${hi}:${lo}`,
          `0000:0000:0000:0000:0000:FFFF:${hi}:${lo}`,
          `[::ffff:${v4}]`,
        ]
        for (const spelling of spellings) expect(rateLimitSubject(spelling), spelling).toBe(v4)
      }),
    )
    // Mapped addresses must not collapse into one shared IPv6 /64 (one client would lock out all).
    expect(rateLimitSubject('::ffff:1:2')).not.toBe(rateLimitSubject('::ffff:3:4'))
  })

  it('sliding window: no 2x burst at a window boundary', async () => {
    const clock = manualClock(Date.UTC(2026, 0, 1))
    const limiter = createLimiter(memoryCounterStore(clock), clock)
    const rule = { max: 10, windowSeconds: 60 }
    clock.advance(59_000) // the end of a window
    for (let i = 0; i < 10; i++) expect(await limiter.hit([['k', rule]])).toBeUndefined()
    clock.advance(2_000) // just after the boundary: a fixed window would allow 10 more now
    const retry = await limiter.hit([['k', rule]])
    expect(retry).toBeGreaterThan(0)
    clock.advance(60_000)
    expect(await limiter.hit([['k', rule]])).toBeUndefined()
  })
  it('the worst key decides and every key is counted', async () => {
    const clock = manualClock(START)
    const limiter = createLimiter(memoryCounterStore(clock), clock)
    for (let i = 0; i < 3; i++)
      await limiter.hit([
        ['a', { max: 3, windowSeconds: 60 }],
        ['b', { max: 100, windowSeconds: 60 }],
      ])
    expect(
      await limiter.hit([
        ['a', { max: 3, windowSeconds: 60 }],
        ['b', { max: 100, windowSeconds: 60 }],
      ]),
    ).toBeGreaterThan(0)
  })
  it('lockout backs off exponentially and resets on success', async () => {
    const clock = manualClock(START)
    const lockout = createLockout(memoryCounterStore(clock), clock, {
      threshold: 3,
      baseMs: 60_000,
      maxMs: 300_000,
    })
    expect(await lockout.fail('k')).toBeUndefined()
    expect(await lockout.fail('k')).toBeUndefined()
    expect(await lockout.fail('k')).toBe(60)
    expect(await lockout.lockedFor('k')).toBe(60)
    expect(await lockout.fail('k')).toBe(120)
    expect(await lockout.fail('k')).toBe(240)
    expect(await lockout.fail('k')).toBe(300) // capped
    clock.advance(301_000)
    expect(await lockout.lockedFor('k')).toBeUndefined()
    await lockout.succeed('k')
    expect(await lockout.fail('k')).toBeUndefined()
  })
})

describe('config', () => {
  it('defaults are secure: registration off, 12-char minimum, 60/15 minute links, 3 h confirmation', () => {
    const c = defineAuthConfig({ appUrl: 'https://app.example.com/some/path' })
    expect(c.features.registration).toBe(false)
    expect(c.features.password).toBe(true)
    expect(c.passwords.min).toBe(12)
    expect(c.links.passwordResetMs).toBe(60 * 60_000)
    expect(c.links.emailLinkMs).toBe(15 * 60_000)
    expect(c.sessions.confirmPasswordMs).toBe(3 * 60 * 60_000)
    expect(c.secureCookies).toBe(true)
    expect(c.appUrl).toBe('https://app.example.com')
    expect(c.roles).toEqual(['admin', 'member'])
    expect(
      defineAuthConfig({ appUrl: 'https://x.test', roles: 'admin-manager-member-viewer' }).roles,
    ).toEqual(['admin', 'manager', 'member', 'viewer'])
  })
  it('fails at boot on nonsense', () => {
    expect(() =>
      defineAuthConfig({ appUrl: 'https://x.test', features: { passkeys: true } }),
    ).toThrow(/passkeys/)
    expect(() => defineAuthConfig({ appUrl: 'https://x.test', passwords: { min: 4 } })).toThrow(
      RangeError,
    )
    expect(() =>
      defineAuthConfig({ appUrl: 'https://x.test', twoFactor: { recoveryCodes: 4 } }),
    ).toThrow(RangeError)
    expect(() =>
      defineAuthConfig({ appUrl: 'https://x.test', tokens: { abilities: ['DROP TABLE'] } }),
    ).toThrow(TypeError)
    expect(() =>
      defineAuthConfig({
        appUrl: 'https://x.test',
        limits: { loginPerIp: { max: 0, windowSeconds: 60 } },
      }),
    ).toThrow(RangeError)
    expect(() => defineAuthConfig({ appUrl: 'not a url' })).toThrow()
  })
  it('fails at boot on settings that would silently weaken a control', () => {
    const base = { appUrl: 'https://app.example.com' }
    const pk = (rpId: string, origins: readonly string[]) => () =>
      defineAuthConfig({
        ...base,
        features: { passkeys: true },
        passkeys: { rpId, rpName: 'Acme', origins },
      })
    // Passkeys: origins must be exact http(s) origins under the rpId; https except on localhost.
    expect(pk('example.com', ['https://app.example.com'])).not.toThrow()
    expect(pk('localhost', ['http://localhost:3000'])).not.toThrow()
    expect(pk('example.com', ['https://evil.test'])).toThrow(/passkeys/)
    expect(pk('example.com', ['https://notexample.com'])).toThrow(/passkeys/)
    expect(pk('example.com', ['http://app.example.com'])).toThrow(/passkeys/)
    expect(pk('example.com', ['*'])).toThrow(/passkeys/)
    expect(pk('example.com', ['https://app.example.com/login'])).toThrow(/passkeys/)
    expect(pk('example.com', [])).toThrow(/passkeys/)
    expect(pk('https://example.com', ['https://example.com'])).toThrow(/passkeys/)
    // The lockout threshold: Infinity or NaN switched the lockout off without a word.
    for (const threshold of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])
      expect(
        () => defineAuthConfig({ ...base, lockout: { threshold } }),
        String(threshold),
      ).toThrow(RangeError)
    expect(() =>
      defineAuthConfig({ ...base, lockout: { baseSeconds: 600, maxSeconds: 60 } }),
    ).toThrow(RangeError)
    // Email links bind to the requesting browser by a cookie; over plain http that cookie can be
    // planted by anyone on the path or a sibling host (login CSRF), so HTTPS is required outside
    // local development, where the cookie is `__Host-` + Secure (CONSISTENCY #117).
    expect(() =>
      defineAuthConfig({ appUrl: 'http://app.example.com', features: { emailLink: true } }),
    ).toThrow(/emailLink/)
    expect(() =>
      defineAuthConfig({ appUrl: 'http://staging.acme.test', features: { emailLink: true } }),
    ).toThrow(/emailLink/)
    // Every sign-in method sets cookies: plain http outside local development is refused for each.
    for (const features of [
      {},
      { password: false, passkeys: true },
      { password: false, emailLink: true },
    ])
      expect(
        () =>
          defineAuthConfig({
            appUrl: 'http://app.example.com',
            features,
            passkeys: { rpId: 'example.com', rpName: 'Acme', origins: ['https://app.example.com'] },
          }),
        JSON.stringify(features),
      ).toThrow(/https/)
    // Without any sign-in method there is no cookie: such a config is allowed on http.
    expect(() =>
      defineAuthConfig({ appUrl: 'http://app.example.com', features: { password: false } }),
    ).not.toThrow()
    for (const local of [
      'http://localhost:3000',
      'http://127.0.0.1:8080',
      'http://[::1]:3000',
      'http://app.localhost',
    ])
      expect(
        () => defineAuthConfig({ appUrl: local, features: { emailLink: true } }),
        local,
      ).not.toThrow()
    expect(
      defineAuthConfig({ appUrl: 'https://app.example.com', features: { emailLink: true } })
        .secureCookies,
    ).toBe(true)
    // Links are built on appUrl: only http(s) makes sense (javascript: has origin "null").
    expect(() => defineAuthConfig({ appUrl: 'javascript:alert(1)' })).toThrow(TypeError)
    expect(() => defineAuthConfig({ appUrl: 'file:///etc/passwd' })).toThrow(TypeError)
  })
})
