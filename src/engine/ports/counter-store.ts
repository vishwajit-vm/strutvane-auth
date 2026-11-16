/**
 * The counter store port: the shared, expiring counters behind rate limits and lockouts.
 *
 * Why a separate port from {@link AuthStore}: in the framework this is the cache (`cache` table or
 * Redis, Laravel's model), not an auth table, and it must be SHARED between processes, or N
 * instances give an attacker N times the limit (review F-22). Keys never contain raw emails or
 * IPs in full: callers pass digests and /64-reduced subjects.
 *
 * @module
 */

/**
 * Expiring integer counters.
 *
 * @example
 * ```ts
 * const counters: CounterStore = sqliteCounterStore(db) // or the framework's cache
 * await counters.increment('login:ip:203.0.113.7:w42', 120_000)
 * ```
 */
export interface CounterStore {
  /**
   * Atomically add 1 and return the new value. A missing or expired key starts at 0. `ttlMs` sets
   * the expiry when the key is created; later increments keep it.
   */
  increment(key: string, ttlMs: number): Promise<number>
  /** The current value, or `undefined` if missing or expired. */
  get(key: string): Promise<number | undefined>
  /** Overwrite the value with a new expiry. */
  set(key: string, value: number, ttlMs: number): Promise<void>
  delete(key: string): Promise<void>
}
