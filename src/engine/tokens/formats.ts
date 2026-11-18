/**
 * Every secret string the auth core hands out, and the strict parsers for them.
 *
 * Why strict parsers before any lookup: untrusted input reaches the store only in a known shape.
 * Wrong types (`{"token": 0}`, arrays, objects; review F-08), wrong lengths and wrong alphabets are
 * refused here, cheaply and without touching the database. `test/parsers.fuzz.test.ts` fuzzes each
 * parser: arbitrary input never throws, and any one-character change to a valid value is refused.
 *
 * @module
 */
import { randomBytes } from 'node:crypto'
import { crc32 } from 'node:zlib'
import { normalizeCode, SECRET_PATTERN } from '../crypto/random.ts'

/** Parse a 256-bit base64url secret (session ids, reset/link/invite tokens, nonces). */
export function parseSecret(value: unknown): string | undefined {
  return typeof value === 'string' && SECRET_PATTERN.test(value) ? value : undefined
}

const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
const PAT_SECRET_CHARS = 40
const PAT_CHECKSUM_CHARS = 6

function randomBase62(length: number): string {
  let out = ''
  while (out.length < length) {
    for (const byte of randomBytes(length * 2)) {
      // 248 = 4 * 62: reject higher bytes so every symbol is equally likely.
      if (byte < 248) out += BASE62[byte % 62]
      if (out.length === length) break
    }
  }
  return out
}

function base62Fixed(value: number, length: number): string {
  let n = value
  let out = ''
  for (let i = 0; i < length; i++) {
    out = (BASE62[n % 62] ?? '0') + out
    n = Math.floor(n / 62)
  }
  return out
}

/**
 * A new personal access token: `<prefix><40 base62 chars><6 base62 CRC-32 chars>`
 * (about 238 random bits). The prefix lets secret scanners (GitHub, GitGuardian) find leaked
 * tokens; the checksum lets them, and the parser, reject typos without a database lookup.
 *
 * @example
 * ```ts
 * createPersonalAccessToken('svp_') // 'svp_3fK…Q9xA1b2C'
 * ```
 */
export function createPersonalAccessToken(prefix: string): string {
  const body = `${prefix}${randomBase62(PAT_SECRET_CHARS)}`
  return `${body}${base62Fixed(crc32(body), PAT_CHECKSUM_CHARS)}`
}

/** Parse a personal access token; `undefined` unless the prefix, shape and checksum all match. */
export function parsePersonalAccessToken(value: unknown, prefix: string): string | undefined {
  if (
    typeof value !== 'string' ||
    value.length !== prefix.length + PAT_SECRET_CHARS + PAT_CHECKSUM_CHARS
  )
    return undefined
  if (!value.startsWith(prefix)) return undefined
  const rest = value.slice(prefix.length)
  if (!/^[0-9A-Za-z]+$/.test(rest)) return undefined
  const body = value.slice(0, prefix.length + PAT_SECRET_CHARS)
  const checksum = value.slice(prefix.length + PAT_SECRET_CHARS)
  return base62Fixed(crc32(body), PAT_CHECKSUM_CHARS) === checksum ? value : undefined
}

/** Extract the token from an `Authorization: Bearer …` header value. */
export function parseBearer(header: unknown): string | undefined {
  if (typeof header !== 'string' || header.length > 200) return undefined
  // RFC 6750: "Bearer" 1*SP token (the scheme is case-insensitive).
  const m = /^Bearer +([^\s]+)$/i.exec(header.trim())
  return m?.[1]
}

const RECOVERY_LENGTH = 10
const RECOVERY_PATTERN = /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{10}$/

/** Format a recovery code for display: `ABCDE-FGHJK`. */
export function formatRecoveryCode(code: string): string {
  return `${code.slice(0, RECOVERY_LENGTH / 2)}-${code.slice(RECOVERY_LENGTH / 2)}`
}

/** Parse a typed recovery code (case, spaces and the dash are forgiven); `undefined` if malformed. */
export function parseRecoveryCode(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 32) return undefined
  const code = normalizeCode(value)
  return RECOVERY_PATTERN.test(code) ? code : undefined
}

/** Parse a six-digit TOTP code (spaces forgiven). */
export function parseTotpCode(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 16) return undefined
  const code = value.replace(/\s/g, '')
  return /^\d{6}$/.test(code) ? code : undefined
}

/** The parts of a signed email-verification link (Laravel's `/email/verify/{id}/{hash}`). */
export interface VerificationLinkParts {
  readonly id: string
  readonly hash: string
  readonly expires: number
  readonly signature: string
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** True for a lowercase UUID (every row id this core creates). */
export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID.test(value)
}

/** The largest id a signed 64-bit `bigint` primary key holds. */
const MAX_BIGINT_ID = 9223372036854775807n

/**
 * True for a row id of the app's `users` table: a canonical positive integer (`'1'`, `'42'`; no
 * sign, no leading zero, at most a signed 64-bit `bigint`). The users table belongs to the app
 * (decision #2), and its `t.id()` key is an auto-increment integer.
 *
 * @example
 * isIntegerId('42') // true
 * isIntegerId('042') // false
 */
export function isIntegerId(value: unknown): value is string {
  return (
    typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value) <= MAX_BIGINT_ID
  )
}

/**
 * True for a user id this engine can hold: the users table's integer id (persistent stores) or a
 * lowercase UUID (the in-memory store). Anything else is refused before any lookup.
 *
 * @example
 * isUserId('7') // true
 * isUserId('7; DROP TABLE users') // false
 */
export function isUserId(value: unknown): value is string {
  return isIntegerId(value) || isUuid(value)
}

/**
 * Parse a verification link's parts from loose input (route params + query). Refuses anything
 * that is not exactly a user id ({@link isUserId}), a 40-hex email hash, an integer expiry and a
 * 64-hex signature.
 */
export function parseVerificationLink(input: {
  readonly id?: unknown
  readonly hash?: unknown
  readonly expires?: unknown
  readonly signature?: unknown
}): VerificationLinkParts | undefined {
  const { id, hash, expires, signature } = input
  if (!isUserId(id)) return undefined
  if (typeof hash !== 'string' || !/^[0-9a-f]{40}$/.test(hash)) return undefined
  if (typeof signature !== 'string' || !/^[0-9a-f]{64}$/.test(signature)) return undefined
  const exp =
    typeof expires === 'string' && /^\d{1,12}$/.test(expires) ? Number(expires) : Number.NaN
  if (!Number.isSafeInteger(exp)) return undefined
  return { id, hash, expires: exp, signature }
}

/** Parse a full verification URL (as mailed) into its parts. */
export function parseVerificationUrl(url: unknown): VerificationLinkParts | undefined {
  if (typeof url !== 'string' || url.length > 2048) return undefined
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return undefined
  }
  const m = /^\/email\/verify\/([^/]+)\/([^/]+)$/.exec(parsed.pathname)
  if (!m) return undefined
  const keys = [...parsed.searchParams.keys()]
  if (
    keys.length !== 2 ||
    !parsed.searchParams.has('expires') ||
    !parsed.searchParams.has('signature')
  )
    return undefined
  return parseVerificationLink({
    id: m[1],
    hash: m[2],
    expires: parsed.searchParams.get('expires') ?? undefined,
    signature: parsed.searchParams.get('signature') ?? undefined,
  })
}
