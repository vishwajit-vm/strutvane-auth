/**
 * The clock port. Every expiry (sessions, links, TOTP steps, rate-limit windows) reads time from
 * here, never from `Date.now()` directly, so tests can move time and the framework can share one
 * clock (spike 12's `ClockToken`).
 *
 * @module
 */

/**
 * A source of the current time in epoch milliseconds.
 *
 * @example
 * ```ts
 * const clock: Clock = { now: () => Date.now() }
 * ```
 */
export interface Clock {
  now(): number
}

/** The real wall clock. */
export const systemClock: Clock = Object.freeze({ now: () => Date.now() })

/**
 * A clock tests can move by hand.
 *
 * @example
 * ```ts
 * const clock = manualClock(Date.UTC(2026, 10, 15))
 * clock.advance(61 * 60_000) // a 60-minute link is now expired
 * ```
 */
export interface ManualClock extends Clock {
  advance(ms: number): void
  set(ms: number): void
}

/** Create a {@link ManualClock} starting at `start` (epoch ms). */
export function manualClock(start: number): ManualClock {
  let t = start
  return {
    now: () => t,
    advance: (ms) => {
      t += ms
    },
    set: (ms) => {
      t = ms
    },
  }
}
