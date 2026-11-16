/**
 * Random secrets and the encodings used for them.
 *
 * @module
 */
import { randomBytes, randomUUID } from 'node:crypto'

/** A 256-bit random secret as base64url (43 characters, no padding). */
export function randomSecret(): string {
  return randomBytes(32).toString('base64url')
}

/** The shape {@link randomSecret} produces. Parsers check it before any lookup. */
export const SECRET_PATTERN: RegExp = /^[A-Za-z0-9_-]{43}$/

/** A random v4 UUID for row ids (unguessable, so ids are not an enumeration oracle; F-23). */
export function newId(): string {
  return randomUUID()
}

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/** RFC 4648 base32 without padding (authenticator apps expect it for TOTP secrets). */
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31]
  return out
}

/** Decode RFC 4648 base32 (case-insensitive, spaces and padding ignored); `undefined` if invalid. */
export function base32Decode(text: string): Buffer | undefined {
  const clean = text.replace(/[\s=]/g, '').toUpperCase()
  let bits = 0
  let value = 0
  const out: number[] = []
  for (const ch of clean) {
    const index = BASE32.indexOf(ch)
    if (index < 0) return undefined
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Buffer.from(out)
}

/** The alphabet for human-typed codes: no 0/O, 1/I/L, so codes survive being read aloud. */
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'

/**
 * A human-friendly random code of `length` characters from a 31-symbol alphabet (about 4.95 bits
 * each), using rejection sampling so every symbol is equally likely.
 */
export function randomCode(length: number): string {
  let out = ''
  while (out.length < length) {
    for (const byte of randomBytes(length * 2)) {
      // 248 = 8 * 31: bytes at or above it would bias the first symbols.
      if (byte < 248) out += CODE_ALPHABET[byte % 31]
      if (out.length === length) break
    }
  }
  return out
}

/** Normalise a typed code for comparison: upper-case, no spaces or dashes. */
export function normalizeCode(input: string): string {
  return input.replace(/[\s-]/g, '').toUpperCase()
}
