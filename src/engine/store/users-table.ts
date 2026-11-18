/**
 * How the SQL stores read and write the app's `users` table.
 *
 * The table belongs to the app, not to auth (decision #2): the skeleton's
 * `create_users_table` migration creates it (Laravel's columns: an auto-increment `id`, `name`,
 * `email`, `email_verified_at`, `password`, `remember_token`, `created_at`, `updated_at`), and
 * auth's `add_auth_columns_to_users_table` migration adds `two_factor_secret`,
 * `two_factor_confirmed_at`, `two_factor_last_step` and `current_team_id`. Auth never creates or
 * alters it at runtime.
 *
 * So the stores adapt to the framework's column types instead of their own:
 * - **`id` is the database's integer**, generated on insert. The engine sees it as a decimal
 *   string; a value that is not a canonical integer is refused before it reaches SQL, because on
 *   PostgreSQL `WHERE id = 'abc'` against a `bigint` is an error (a 500), not "not found".
 * - **`email_verified_at`, `two_factor_confirmed_at`, `created_at` and `updated_at` are
 *   timestamps**, written the way the framework's ORM writes them (ISO 8601 in UTC, so a
 *   `User` model reads the same instant) and read back as epoch milliseconds, the engine's unit.
 *
 * @module
 */
import { isIntegerId } from '../tokens/formats.ts'

/**
 * The users-table key for an engine user id, or `undefined` when it cannot be one (then no row
 * can match, and the caller answers "not found" without a query).
 *
 * @example
 * userKey('42') // '42'
 * userKey('not-a-number') // undefined
 */
export function userKey(id: string): string | undefined {
  return isIntegerId(id) ? id : undefined
}

/**
 * The id column as the engine's string. Drivers return a `bigint` key as a number (SQLite,
 * PGlite), a `bigint` or a string (node-postgres).
 *
 * @example
 * userIdFrom(7, 'id') // '7'
 */
export function userIdFrom(value: unknown, column: string): string {
  const text =
    typeof value === 'number' && Number.isSafeInteger(value)
      ? String(value)
      : typeof value === 'bigint' || typeof value === 'string'
        ? String(value)
        : undefined
  if (text === undefined || !isIntegerId(text))
    throw new TypeError(`users table: column ${column} is not an integer id`)
  return text
}

/**
 * Epoch milliseconds → the timestamp the framework stores (ISO 8601, UTC), or `null`.
 *
 * @example
 * toTimestamp(0) // '1970-01-01T00:00:00.000Z'
 */
export function toTimestamp(ms: number | null): string | null {
  return ms === null ? null : new Date(ms).toISOString()
}

/**
 * A timestamp column → epoch milliseconds, or `null`. Accepts what the drivers return: a `Date`
 * (node-postgres, PGlite), an ISO string (SQLite, as the ORM writes it) or MySQL's
 * `YYYY-MM-DD HH:MM:SS.sss` (UTC, as the ORM writes it). Anything unreadable throws: a wrong
 * verification or 2FA time must never be guessed.
 *
 * @example
 * fromTimestamp('1970-01-01T00:00:01.000Z', 'created_at') // 1000
 */
export function fromTimestamp(value: unknown, column: string): number | null {
  if (value === null || value === undefined) return null
  let ms = Number.NaN
  if (value instanceof Date) ms = value.getTime()
  else if (typeof value === 'string')
    ms = Date.parse(
      /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(value)
        ? `${value.replace(' ', 'T')}Z`
        : value,
    )
  if (!Number.isFinite(ms)) throw new TypeError(`users table: column ${column} is not a timestamp`)
  return ms
}
