/**
 * Email normalisation: one canonical form for storage, lookups and rate-limit keys.
 *
 * Why: if the limiter keys on one form and SQL matches more variants (MySQL's default `_ai_ci`
 * collation matches `JÖHN@x` to `john@x`), every variant gets a fresh bucket on the same account
 * (review F-08). Normalising once here, storing only the normalised value and comparing it byte
 * for byte closes that.
 *
 * @module
 */

const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/

/**
 * Trim, NFC-normalise and lower-case an email.
 *
 * @example
 * ```ts
 * normalizeEmail('  Ada@Example.COM ') // 'ada@example.com'
 * ```
 */
export function normalizeEmail(email: string): string {
  return email.trim().normalize('NFC').toLowerCase()
}

/**
 * Control, format (zero-width, soft hyphen, bidi overrides), surrogate, private-use and unassigned
 * characters. None belongs in an address, and each lets `admin<U+200B>@acme.test` register as a
 * DIFFERENT account that renders exactly like `admin@acme.test` in admin screens and mail clients.
 */
const INVISIBLE = /\p{C}/u

/** Normalise and validate; `undefined` when `value` is not a plausible email. */
export function parseEmail(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 254) return undefined
  const email = normalizeEmail(value)
  return EMAIL.test(email) && !INVISIBLE.test(email) ? email : undefined
}
