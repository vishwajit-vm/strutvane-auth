/**
 * Account lockout with exponential backoff, after consecutive failures.
 *
 * Rate limits bound the attempt RATE; the lockout bounds the attempt COUNT for one account: after
 * `threshold` consecutive failures the account is locked for `base`, then 2x, 4x … up to `max` for
 * every further failure. A success resets it.
 *
 * Keys are digests of the normalised email (not user ids), so an email WITHOUT an account locks
 * exactly like one with an account: the lockout cannot be used to find out which emails exist.
 *
 * Trade-off (documented): anyone can lock a victim out of PASSWORD sign-in for a while. Password
 * reset, email links and passkeys are not affected by this lockout, so the victim always has a way
 * in, and the backoff caps at `max`.
 *
 * @module
 */
import type { Clock } from '../ports/clock.ts'
import type { CounterStore } from '../ports/counter-store.ts'

/** Options for {@link createLockout}. */
export interface LockoutOptions {
  readonly threshold: number
  readonly baseMs: number
  readonly maxMs: number
}

/**
 * Tracks consecutive failures per key.
 *
 * @example
 * ```ts
 * const wait = await lockout.lockedFor(key)
 * if (wait !== undefined) throw new AuthError('RATE_LIMITED', { retryAfterSeconds: wait })
 * ```
 */
export interface Lockout {
  /** Seconds left on an active lock, or `undefined`. */
  lockedFor(key: string): Promise<number | undefined>
  /** Record a failure; resolves the lock length in seconds when this failure (re)locked the key. */
  fail(key: string): Promise<number | undefined>
  /** Record a success: the failure count starts again. */
  succeed(key: string): Promise<void>
}

const DAY = 24 * 60 * 60 * 1000

/** Create a {@link Lockout}. */
export function createLockout(
  counters: CounterStore,
  clock: Clock,
  options: LockoutOptions,
): Lockout {
  return {
    async lockedFor(key) {
      const until = await counters.get(`lock:${key}:until`)
      if (until === undefined) return undefined
      const left = until - clock.now()
      return left > 0 ? Math.ceil(left / 1000) : undefined
    },
    async fail(key) {
      const failures = await counters.increment(`lock:${key}:fails`, DAY)
      if (failures < options.threshold) return undefined
      const duration = Math.min(
        options.maxMs,
        options.baseMs * 2 ** Math.min(30, failures - options.threshold),
      )
      await counters.set(`lock:${key}:until`, clock.now() + duration, duration)
      return Math.ceil(duration / 1000)
    },
    async succeed(key) {
      await counters.delete(`lock:${key}:fails`)
      await counters.delete(`lock:${key}:until`)
    },
  }
}
