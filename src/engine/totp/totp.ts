/**
 * TOTP (RFC 6238) on `node:crypto`: no dependency.
 *
 * HOTP (RFC 4226) over the time step `floor(unixSeconds / 30)`, HMAC-SHA1, 6 digits: what every
 * authenticator app supports. Verification accepts the previous, current and next step (clock
 * drift of up to 30 s either way) and returns WHICH step matched, so the caller can refuse a step
 * that was already used (replay protection, via the store's atomic `advanceTotpStep`).
 *
 * @module
 */
import { createHmac, timingSafeEqual } from 'node:crypto'
import { base32Encode } from '../crypto/random.ts'

/** TOTP parameters. Defaults: SHA-1, 6 digits, 30-second steps (RFC 6238 + app compatibility). */
export interface TotpOptions {
  readonly algorithm?: 'sha1' | 'sha256' | 'sha512'
  readonly digits?: number
  readonly stepSeconds?: number
}

/** The time step for `atMs`. */
export function totpStep(atMs: number, stepSeconds = 30): number {
  return Math.floor(atMs / 1000 / stepSeconds)
}

/**
 * The HOTP code for one counter value (RFC 4226 §5.3 dynamic truncation).
 *
 * @example
 * ```ts
 * hotp(Buffer.from('12345678901234567890'), 1) // '287082' (RFC 4226 appendix D)
 * ```
 */
export function hotp(secret: Buffer, counter: number, options: TotpOptions = {}): string {
  const digits = options.digits ?? 6
  const message = Buffer.alloc(8)
  message.writeBigUInt64BE(BigInt(counter))
  const mac = createHmac(options.algorithm ?? 'sha1', secret)
    .update(message)
    .digest()
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f
  const binary = mac.readUInt32BE(offset) & 0x7fffffff
  return (binary % 10 ** digits).toString().padStart(digits, '0')
}

/** The TOTP code at `atMs`. */
export function totp(secret: Buffer, atMs: number, options: TotpOptions = {}): string {
  return hotp(secret, totpStep(atMs, options.stepSeconds), options)
}

/**
 * Check `code` against the steps around `atMs`; resolve the matching step or `undefined`.
 * Every candidate is compared in constant time and ALL candidates are always checked.
 */
export function verifyTotp(
  secret: Buffer,
  code: string,
  atMs: number,
  options: TotpOptions & { readonly window?: number } = {},
): number | undefined {
  const window = options.window ?? 1
  const current = totpStep(atMs, options.stepSeconds)
  const presented = Buffer.from(code.padEnd(options.digits ?? 6, 'x'), 'utf8')
  let match: number | undefined
  for (let step = current - window; step <= current + window; step++) {
    const expected = Buffer.from(hotp(secret, step, options), 'utf8')
    if (
      expected.length === presented.length &&
      timingSafeEqual(expected, presented) &&
      match === undefined
    )
      match = step
  }
  return match
}

/**
 * The `otpauth://` URI authenticator apps scan (as a QR code drawn by the UI).
 *
 * @example
 * ```ts
 * otpauthUri({ secret, issuer: 'Acme', account: 'ada@acme.test' })
 * // 'otpauth://totp/Acme:ada%40acme.test?secret=…&issuer=Acme&algorithm=SHA1&digits=6&period=30'
 * ```
 */
export function otpauthUri(input: {
  readonly secret: Buffer
  readonly issuer: string
  readonly account: string
}): string {
  const label = `${encodeURIComponent(input.issuer)}:${encodeURIComponent(input.account)}`
  const params = new URLSearchParams({
    secret: base32Encode(input.secret),
    issuer: input.issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  })
  return `otpauth://totp/${label}?${params.toString()}`
}
