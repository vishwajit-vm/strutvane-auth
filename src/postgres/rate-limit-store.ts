/**
 * A rate-limit store in Postgres, shared by every app process (ADR-0013: "rate limiting with shared
 * storage, not per-process memory"). One atomic `INSERT … ON CONFLICT` per hit, timed by the
 * database clock so app servers with skewed clocks agree.
 *
 * @module
 */
import type { RateLimitHit, RateLimitStore } from '../identity/rate-limit.ts'
import { quoteTable } from '../policy/schema.ts'
import type { Queryable } from './audit-query.ts'

/** Options for {@link postgresRateLimitStore}. */
export interface PostgresRateLimitOptions {
  /** Table name. Default `strutvane_rate_limits`. */
  readonly table?: string
}

/** The table the store needs, for your migrations. */
export function rateLimitTableSql(options: PostgresRateLimitOptions = {}): string {
  const table = quoteTable(options.table ?? 'strutvane_rate_limits')
  return `CREATE TABLE IF NOT EXISTS ${table} (key text PRIMARY KEY, count integer NOT NULL, reset_at timestamptz NOT NULL)`
}

/** A {@link RateLimitStore} backed by a Postgres table, plus a `prune()` for a scheduled job. */
export function postgresRateLimitStore(
  db: Queryable,
  options: PostgresRateLimitOptions = {},
): RateLimitStore & { prune(): Promise<number> } {
  const table = quoteTable(options.table ?? 'strutvane_rate_limits')
  const hitSql =
    `INSERT INTO ${table} AS r (key, count, reset_at) VALUES ($1, 1, now() + $2::int * interval '1 millisecond') ` +
    `ON CONFLICT (key) DO UPDATE SET ` +
    `count = CASE WHEN r.reset_at <= now() THEN 1 ELSE r.count + 1 END, ` +
    `reset_at = CASE WHEN r.reset_at <= now() THEN EXCLUDED.reset_at ELSE r.reset_at END ` +
    `RETURNING r.count AS count, GREATEST(0, CEIL(EXTRACT(EPOCH FROM (r.reset_at - now())) * 1000))::int AS reset_in_ms`
  return {
    async hit(key: string, windowMs: number): Promise<RateLimitHit> {
      const { rows } = await db.query(hitSql, [key, Math.ceil(windowMs)])
      const row = rows[0] as { count: number; reset_in_ms: number } | undefined
      if (!row) throw new Error('rate limit store returned no row')
      return { count: Number(row.count), resetInMs: Number(row.reset_in_ms) }
    },
    async prune(): Promise<number> {
      const { rows } = await db.query(
        `WITH d AS (DELETE FROM ${table} WHERE reset_at <= now() RETURNING 1) SELECT count(*)::int AS n FROM d`,
      )
      return Number((rows[0] as { n: number } | undefined)?.n ?? 0)
    },
  }
}
