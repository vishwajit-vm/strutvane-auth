/**
 * Sliding-window rate limiting on the shared {@link CounterStore}.
 *
 * Why sliding and not fixed windows: a fixed window lets an attacker spend the whole budget at the
 * end of one window and again at the start of the next (2x the limit in a moment; review F-22).
 * This uses the standard sliding-window counter: the previous window's count, weighted by how much
 * of it still overlaps, plus the current window's count. Two counters per key, O(1).
 *
 * Every attempt counts, including refused ones, so hammering a limited key keeps it limited.
 *
 * @module
 */
import type { RateRule } from '../config.ts'
import type { Clock } from '../ports/clock.ts'
import type { CounterStore } from '../ports/counter-store.ts'

/** One check: a key and the rule it is held to. */
export type LimitCheck = readonly [key: string, rule: RateRule]

/**
 * Counts hits on several keys at once; the worst key decides.
 *
 * @example
 * ```ts
 * const retry = await limiter.hit([[`login:ip:${subject}`, limits.loginPerIp], [`login:acct:${d}`, limits.loginPerAccount]])
 * if (retry !== undefined) throw new AuthError('RATE_LIMITED', { retryAfterSeconds: retry })
 * ```
 */
export interface Limiter {
  /** Count one hit on every key; resolve the seconds to wait if any key is over its limit. */
  hit(checks: readonly LimitCheck[]): Promise<number | undefined>
}

/** Create a {@link Limiter}. */
export function createLimiter(counters: CounterStore, clock: Clock): Limiter {
  const one = async ([key, rule]: LimitCheck): Promise<number | undefined> => {
    const windowMs = rule.windowSeconds * 1000
    const now = clock.now()
    const index = Math.floor(now / windowMs)
    const elapsed = now - index * windowMs
    // The current counter must outlive the NEXT window too, where it is the "previous" one.
    const current = await counters.increment(`rl:${key}:${index}`, windowMs * 2)
    const previous = (await counters.get(`rl:${key}:${index - 1}`)) ?? 0
    const overlap = 1 - elapsed / windowMs
    const estimate = previous * overlap + current
    if (estimate <= rule.max) return undefined
    // When does the estimate fall back to `max`? If the current window alone is over, during the
    // next window, once enough of `current` has slid out: t >= W * (1 - max / current). Otherwise
    // `previous` is the reason, and it slides out within this window.
    const waitMs =
      current > rule.max
        ? windowMs - elapsed + windowMs * (1 - rule.max / current)
        : windowMs * (1 - (rule.max - current) / previous) - elapsed
    return Math.max(1, Math.ceil(waitMs / 1000))
  }
  return {
    async hit(checks) {
      let worst: number | undefined
      for (const check of checks) {
        const retry = await one(check)
        if (retry !== undefined) worst = Math.max(worst ?? 0, retry)
      }
      return worst
    },
  }
}
