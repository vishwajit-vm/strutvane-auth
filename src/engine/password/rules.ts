/**
 * Password rules and the optional breached/common-password hook.
 *
 * Rules follow NIST SP 800-63B: a minimum length (12 by default), a generous maximum, no
 * composition rules ("one symbol"), and a check against known-bad passwords. The check is a hook so
 * an app can plug in a k-anonymity breach service; the built-in one is a small offline list of the
 * most common passwords.
 *
 * @module
 */
import { createHash } from 'node:crypto'
import { AuthError, type AuthIssueInput } from '../errors.ts'
import type { AuthLogger } from '../ports/events.ts'

/** What a password check says. `unknown` means the check could not run (a service was down). */
export type PasswordVerdict = 'ok' | 'compromised' | 'unknown'

/**
 * Decides whether a password is known to be compromised or too common.
 *
 * @example
 * ```ts
 * const check: PasswordCheck = async (pw) => (await myBreachApi(pw)) ? 'compromised' : 'ok'
 * createAuth({ ..., passwordCheck: check })
 * ```
 */
export type PasswordCheck = (password: string) => Promise<PasswordVerdict>

/** A few of the most common passwords that are at least 12 characters long. Lower-cased. */
const COMMON = new Set([
  '123456789012',
  '1234567890123',
  'qwertyuiopas',
  'password1234',
  'password12345',
  'passwordpassword',
  'iloveyou1234',
  'qwerty123456',
  'administrator',
  'letmein12345',
  '111111111111',
  'aaaaaaaaaaaa',
  'abcdefghijkl',
  'welcome12345',
  'changeme1234',
  '1q2w3e4r5t6y',
  'zaq12wsxcde3',
  'qazwsxedcrfv',
  'trustno11234',
  'correcthorsebatterystaple',
])

/**
 * The built-in offline check: refuses the common list and passwords that are one repeated
 * character. Fast, private, no network.
 */
export const commonPasswordCheck: PasswordCheck = async (password) => {
  const lower = password.toLowerCase().replace(/\s+/g, '')
  if (COMMON.has(lower) || /^(.)\1+$/.test(lower)) return 'compromised'
  return 'ok'
}

/**
 * A breach check against a k-anonymity range API (the "Pwned Passwords" model): only the first 5
 * hex characters of the SHA-1 leave the server; the response lists suffixes with counts.
 *
 * `fetchRange` is injected so the core never makes network calls on its own and tests run offline.
 *
 * @example
 * ```ts
 * const check = rangeBreachCheck((prefix) =>
 *   fetch(`https://api.pwnedpasswords.com/range/${prefix}`).then((r) => r.text()))
 * ```
 */
export function rangeBreachCheck(fetchRange: (prefix: string) => Promise<string>): PasswordCheck {
  return async (password) => {
    const sha1 = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase()
    let body: string
    try {
      body = await fetchRange(sha1.slice(0, 5))
    } catch {
      return 'unknown'
    }
    const suffix = sha1.slice(5)
    for (const line of body.split('\n')) {
      const [s, count] = line.trim().split(':')
      if (s === suffix && Number(count) > 0) return 'compromised'
    }
    return 'ok'
  }
}

/**
 * The ONE length measure for passwords, used both when a password is set and when one is checked:
 * Unicode code points after NFKC (what the hasher hashes). A cheap raw-length bound runs first, so
 * a megabyte of input is refused before it is normalised or hashed (DoS). Four UTF-16 units per
 * allowed character covers every real composition (Hangul jamo, astral characters).
 *
 * @example
 * ```ts
 * passwordLengthOk('e\u0301'.repeat(200), 256) // true: 200 characters once normalised
 * ```
 */
export function passwordLength(password: string, max: number): number | undefined {
  if (password.length > max * 4) return undefined
  return [...password.normalize('NFKC')].length
}

/** True when `password` is non-empty and within `max` by {@link passwordLength}. */
export function passwordLengthOk(password: string, max: number): boolean {
  const length = passwordLength(password, max)
  return length !== undefined && length >= 1 && length <= max
}

/** Options for {@link assertPasswordAllowed}. */
export interface PasswordRuleOptions {
  readonly min: number
  readonly max: number
  readonly check: PasswordCheck | undefined
  /** When the check says `unknown`: refuse (`closed`) or allow with a warning (`open`, default). */
  readonly onUnknown: 'open' | 'closed'
  readonly logger: AuthLogger | undefined
  readonly field?: string
}

/**
 * Throw `weak_password` (with field issues) unless `password` passes the rules and the check.
 *
 * Why fail OPEN by default on an unknown verdict: a third-party outage would otherwise stop every
 * sign-up and reset. The warning makes it visible; strict apps set `onUnknown: 'closed'`.
 */
export async function assertPasswordAllowed(
  password: unknown,
  options: PasswordRuleOptions,
): Promise<string> {
  const field = options.field ?? 'password'
  if (typeof password !== 'string')
    throw new AuthError('validation_failed', { issues: [{ field, code: 'required' }] })
  const length = passwordLength(password, options.max) ?? Number.POSITIVE_INFINITY
  const issues: AuthIssueInput[] = []
  if (length < options.min) issues.push({ field, code: 'too_short' })
  if (length > options.max) issues.push({ field, code: 'too_long' })
  if (issues.length > 0) throw new AuthError('weak_password', { issues })
  if (options.check) {
    const verdict = await options.check(password)
    if (verdict === 'compromised')
      throw new AuthError('weak_password', { issues: [{ field, code: 'compromised' }] })
    if (verdict === 'unknown') {
      options.logger?.warn('auth: the password check could not run', {
        failClosed: options.onUnknown === 'closed',
      })
      if (options.onUnknown === 'closed')
        throw new AuthError('weak_password', { issues: [{ field, code: 'check_unavailable' }] })
    }
  }
  return password
}
