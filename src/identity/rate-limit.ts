/**
 * Fixed-window rate limiting with a pluggable store.
 *
 * Identity engines limit sign-in (and other abuse-prone operations) by **two** keys at once:
 * - **per client IP** (resolved through trusted proxies, so a forged `X-Forwarded-For` cannot rotate
 *   it), which stops one client hammering many accounts;
 * - **per account** (a SHA-256 of the normalised email, so the store never holds raw emails), which
 *   stops a botnet with many IPs hammering one account.
 *
 * Trade-off (documented, deliberate): the per-account limit lets an attacker temporarily lock a
 * victim out of password sign-in. Keep it looser than the IP limit and short-windowed; the reset
 * flow is unaffected.
 *
 * Use {@link memoryRateLimitStore} for a single process (dev, tests) and the Postgres store from
 * `@strutvane/auth/postgres` (or your own Redis store) when several processes serve traffic.
 *
 * @module
 */
import { createHash } from 'node:crypto'

/** The state of one key after a hit. */
export interface RateLimitHit {
  /** Hits in the current window, including this one. */
  readonly count: number
  /** Milliseconds until the window resets. */
  readonly resetInMs: number
}

/** Where counters live. Implementations must make `hit` atomic per key. */
export interface RateLimitStore {
  hit(key: string, windowMs: number): Promise<RateLimitHit>
}

/** One limit: at most `max` hits per `windowSeconds`. */
export interface RateLimitRule {
  readonly windowSeconds: number
  readonly max: number
}

/** Options for {@link memoryRateLimitStore}. */
export interface MemoryRateLimitOptions {
  /** Clock (ms). Inject a fake one in tests. */
  readonly now?: () => number
  /**
   * Maximum keys kept, so memory stays bounded. When full, expired windows are dropped first; only
   * then is the oldest live key evicted, and per-IP keys go before per-account keys (an attacker
   * who floods the store with new IPs must not be able to reset a victim account's counter).
   * Default 100,000.
   */
  readonly maxKeys?: number
}

const isAccountKey = (key: string): boolean => key.includes(':account:')

/** An in-process store. Not shared between processes. */
export function memoryRateLimitStore(options: MemoryRateLimitOptions = {}): RateLimitStore {
  const now = options.now ?? Date.now
  const maxKeys = options.maxKeys ?? 100_000
  const windows = new Map<string, { count: number; resetAt: number }>()
  // A lower bound on the earliest `resetAt` in the map: sweeping is O(n), so it runs only when
  // something can actually have expired (never on every insert of a full, live store).
  let nextExpiry = Number.POSITIVE_INFINITY

  const sweep = (t: number): void => {
    if (t < nextExpiry) return
    nextExpiry = Number.POSITIVE_INFINITY
    for (const [key, entry] of windows) {
      if (entry.resetAt <= t) windows.delete(key)
      else nextExpiry = Math.min(nextExpiry, entry.resetAt)
    }
  }

  const evictOne = (): void => {
    // Oldest first (Map iteration is insertion order), but never an account key while an IP key
    // remains.
    let oldestAccount: string | undefined
    for (const key of windows.keys()) {
      if (!isAccountKey(key)) {
        windows.delete(key)
        return
      }
      oldestAccount ??= key
    }
    if (oldestAccount !== undefined) windows.delete(oldestAccount)
  }

  return {
    async hit(key, windowMs) {
      const t = now()
      let entry = windows.get(key)
      if (!entry || entry.resetAt <= t) {
        entry = { count: 0, resetAt: t + windowMs }
        windows.delete(key)
        if (windows.size >= maxKeys) sweep(t)
        if (windows.size >= maxKeys) evictOne()
        windows.set(key, entry)
        nextExpiry = Math.min(nextExpiry, entry.resetAt)
      }
      entry.count++
      return { count: entry.count, resetInMs: Math.max(0, entry.resetAt - t) }
    },
  }
}

/** The result of a limiter check. */
export type RateLimitResult =
  | { readonly limited: false }
  | { readonly limited: true; readonly retryAfterSeconds: number }

/** A check against several (key, rule) pairs; every key is counted, the worst one decides. */
export async function checkRateLimits(
  store: RateLimitStore,
  checks: readonly (readonly [key: string, rule: RateLimitRule])[],
): Promise<RateLimitResult> {
  let retry = 0
  for (const [key, rule] of checks) {
    const { count, resetInMs } = await store.hit(key, rule.windowSeconds * 1000)
    if (count > rule.max) retry = Math.max(retry, Math.max(1, Math.ceil(resetInMs / 1000)))
  }
  return retry > 0 ? { limited: true, retryAfterSeconds: retry } : { limited: false }
}

/** Normalise an email for lookups and limits: trimmed, lower-cased. */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase()
}

/** The per-account limiter key: a hash, so the store never holds raw email addresses. */
export function accountKey(scope: string, email: string): string {
  return `${scope}:account:${createHash('sha256').update(normalizeEmail(email)).digest('hex')}`
}

/** Validate a rule at boot. */
export function assertRule(name: string, rule: RateLimitRule): RateLimitRule {
  if (
    !Number.isInteger(rule.max) ||
    rule.max < 1 ||
    !Number.isFinite(rule.windowSeconds) ||
    rule.windowSeconds <= 0
  ) {
    throw new RangeError(`${name}: max must be a positive integer and windowSeconds positive`)
  }
  return rule
}
