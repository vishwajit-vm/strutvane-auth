import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { open, seal } from '../../src/engine/crypto/aead.ts'
import { createKeyRing } from '../../src/engine/crypto/keys.ts'
import { base32Decode, randomSecret } from '../../src/engine/crypto/random.ts'
import { parseCookieHeader } from '../../src/engine/http/cookies.ts'
import { rateLimitSubject } from '../../src/engine/limits/ip.ts'
import { parseEmail } from '../../src/engine/password/email.ts'
import {
  createPersonalAccessToken,
  formatRecoveryCode,
  parseBearer,
  parsePersonalAccessToken,
  parseRecoveryCode,
  parseSecret,
  parseTotpCode,
  parseVerificationLink,
  parseVerificationUrl,
} from '../../src/engine/tokens/formats.ts'
import { APP_KEY, Browser, FAST_HASHER, harness, PASSWORD } from './helpers/harness.ts'

const RUNS = { numRuns: 2000 }
const PREFIX = 'svp_'

/** Change the character at `index` to a different one from `alphabet`. */
function mutate(value: string, index: number, alphabet: string, pick: number): string {
  const current = value[index] ?? ''
  const choices = [...alphabet].filter((c) => c !== current)
  return value.slice(0, index) + (choices[pick % choices.length] ?? 'x') + value.slice(index + 1)
}

describe('parsers never throw on hostile input', () => {
  it('every parser returns undefined (or a value) for arbitrary input', () => {
    fc.assert(
      fc.property(fc.anything(), (input) => {
        expect(() => {
          parseSecret(input)
          parsePersonalAccessToken(input, PREFIX)
          parseBearer(input)
          parseRecoveryCode(input)
          parseTotpCode(input)
          parseEmail(input)
          parseVerificationUrl(input)
          parseVerificationLink({ id: input, hash: input, expires: input, signature: input })
        }).not.toThrow()
      }),
      RUNS,
    )
  })

  it('string-shaped junk: URLs, cookies, IPs, base32 and sealed values', () => {
    const key = createKeyRing(APP_KEY).subkey('two-factor-secret')
    fc.assert(
      fc.property(fc.string({ unit: 'binary', maxLength: 300 }), (s) => {
        expect(() => parseVerificationUrl(`http://localhost:3000/email/verify/${s}`)).not.toThrow()
        expect(() => parseCookieHeader(s)).not.toThrow()
        expect(() => rateLimitSubject(s)).not.toThrow()
        expect(() => base32Decode(s)).not.toThrow()
        expect(open(key, s, 'u')).toBeUndefined()
        expect(open(key, `v1.${s}.${s}.${s}`, 'u')).toBeUndefined()
      }),
      RUNS,
    )
  })
})

describe('valid values parse; any single-character change is refused', () => {
  it('personal access tokens (prefix + checksum)', () => {
    const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-'
    fc.assert(
      fc.property(fc.nat(), fc.nat(), (i, pick) => {
        const token = createPersonalAccessToken(PREFIX)
        expect(parsePersonalAccessToken(token, PREFIX)).toBe(token)
        expect(parseBearer(`Bearer ${token}`)).toBe(token)
        const changed = mutate(token, i % token.length, alphabet, pick)
        expect(parsePersonalAccessToken(changed, PREFIX)).toBeUndefined()
        expect(parsePersonalAccessToken(token.slice(0, -1), PREFIX)).toBeUndefined()
        expect(parsePersonalAccessToken(`${token}0`, PREFIX)).toBeUndefined()
      }),
      { numRuns: 3000 },
    )
  })

  it('256-bit secrets: shape only (the digest lookup decides the rest)', () => {
    fc.assert(
      fc.property(fc.nat(), (i) => {
        const s = randomSecret()
        expect(parseSecret(s)).toBe(s)
        expect(parseSecret(mutate(s, i % s.length, '+/=.~ ', i))).toBeUndefined()
        expect(parseSecret(s.slice(1))).toBeUndefined()
        expect(parseSecret(`${s}A`)).toBeUndefined()
      }),
      RUNS,
    )
  })

  it('recovery codes forgive case, spaces and the dash, nothing else', () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{10}$/),
        fc.nat(),
        (code, i) => {
          expect(parseRecoveryCode(formatRecoveryCode(code))).toBe(code)
          expect(parseRecoveryCode(code.toLowerCase())).toBe(code)
          expect(parseRecoveryCode(mutate(code, i % 10, '01OIL!', i))).toBeUndefined()
        },
      ),
      RUNS,
    )
  })

  it('TOTP codes: exactly six digits', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 20 }), (s) => {
        const parsed = parseTotpCode(s)
        if (parsed !== undefined) expect(parsed).toMatch(/^\d{6}$/)
      }),
      RUNS,
    )
  })
})

describe('signed verification links: any edit breaks the signature (service level)', () => {
  it('fuzzed edits to a real link are always INVALID_TOKEN, the original always verifies', async () => {
    const h = harness({ config: { features: { registration: true, emailVerification: true } } })
    await h.auth.passwords.register(new Browser().req, {
      name: 'Ada',
      email: 'ada@acme.test',
      password: PASSWORD,
    })
    const mail = await h.mail('verify-email')
    const url = 'url' in mail ? mail.url : ''
    const parts = parseVerificationUrl(url)
    if (!parts) throw new Error('unparseable link')
    const fields = ['id', 'hash', 'expires', 'signature'] as const
    await fc.assert(
      fc.asyncProperty(fc.constantFrom(...fields), fc.nat(), fc.nat(), async (field, i, pick) => {
        const original = String(parts[field])
        const alphabet = field === 'expires' ? '0123456789' : '0123456789abcdef'
        const changed = {
          id: parts.id,
          hash: parts.hash,
          expires: String(parts.expires),
          signature: parts.signature,
          [field]: mutate(original, i % original.length, alphabet, pick),
        }
        await expect(h.auth.verification.verify(new Browser().req, changed)).rejects.toMatchObject({
          code: 'INVALID_TOKEN',
        })
      }),
      { numRuns: 300 },
    )
    await h.auth.verification.verify(new Browser().req, {
      id: parts.id,
      hash: parts.hash,
      expires: String(parts.expires),
      signature: parts.signature,
    })
  })
})

describe('hasher with hostile stored values', () => {
  it('never throws and never matches', async () => {
    await fc.assert(
      fc.asyncProperty(fc.string({ maxLength: 200 }), async (stored) => {
        expect(await FAST_HASHER.verify('password', stored)).toBe(false)
      }),
      { numRuns: 25 },
    )
  })
})

describe('sealed secrets', () => {
  it('round-trip any plaintext, bound to the context', () => {
    const key = createKeyRing(APP_KEY).subkey('two-factor-secret')
    fc.assert(
      fc.property(fc.string({ maxLength: 100 }), fc.string({ maxLength: 40 }), (text, ctx) => {
        const sealed = seal(key, text, ctx)
        expect(open(key, sealed, ctx)).toBe(text)
        expect(open(key, sealed, `${ctx}x`)).toBeUndefined()
      }),
      { numRuns: 500 },
    )
  })
})
