/**
 * The app schema for store tests, inside the test workers: the statements the global setup
 * compiled from the real migrations (see `compile-auth-schema.ts`).
 *
 * @module
 */
import { DatabaseSync } from 'node:sqlite'
import { inject } from 'vitest'
import type { AuthSchema } from './compile-auth-schema.ts'

/**
 * The statements for `dialect`, from the global setup.
 *
 * @example
 * for (const statement of authSchema('postgres')) await client.query(statement)
 */
export function authSchema(dialect: keyof AuthSchema): readonly string[] {
  return inject('authSchema')[dialect]
}

/**
 * A `node:sqlite` database with the app's tables (users + auth), as `node strut migrate` leaves it.
 *
 * @example
 * const store = sqliteAuthStore(sqliteWithAuthSchema())
 */
export function sqliteWithAuthSchema(file = ':memory:'): DatabaseSync {
  const db = new DatabaseSync(file)
  for (const statement of authSchema('sqlite')) db.exec(statement)
  return db
}
