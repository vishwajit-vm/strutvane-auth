/**
 * PostgreSQL for the engine's behaviour suites: ONE in-process PGlite per test file, and a fresh
 * schema (the app's users table plus auth's tables, from the real migrations) per store, so every harness starts empty without paying for a new
 * database (a PGlite instance costs ~250 MB and ~1 s; a schema costs a few milliseconds).
 *
 * Isolation: every query runs inside its own PGlite transaction that first does
 * `SET LOCAL search_path` to the store's schema. PGlite runs one transaction at a time, so two
 * harnesses can never interleave and read each other's tables. The store's own transactions
 * (team + member, the last-admin lock) run the same way.
 *
 * Real concurrency (two connections racing) is not something PGlite can show: the real-Postgres
 * integration suite (`test/integration/postgres-store.test.ts`) races the atomic operations.
 */
import { PGlite } from '@electric-sql/pglite'
import { afterAll } from 'vitest'
import type { PostgresClient, PostgresRow } from '../../../src/engine/store/postgres.ts'
import { authSchema } from '../../support/auth-schema.ts'

let shared: Promise<PGlite> | undefined
let next = 0

afterAll(async () => {
  const db = await shared
  shared = undefined
  await db?.close()
})

type Raw = { query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }> }

/**
 * A {@link PostgresClient} on its own schema of the file's shared PGlite (created on first use).
 * Clients made with the same `schema` share tables (two "app instances" on one database).
 *
 * @example
 * const client = pgliteSchemaClient()
 * const store = postgresAuthStore(client)
 */
export function pgliteSchemaClient(schema = `h${process.pid}_${++next}`): PostgresClient {
  if (!/^[a-z][a-z0-9_]*$/.test(schema)) throw new TypeError(`bad schema name ${schema}`)
  shared ??= PGlite.create()
  const db = shared
  const ready = db.then((pg) =>
    pg.transaction(async (tx) => {
      await tx.query(`CREATE SCHEMA IF NOT EXISTS ${schema}`)
      await tx.query(`SET LOCAL search_path TO ${schema}`)
      for (const statement of authSchema('postgres')) await tx.query(statement)
    }),
  )
  const scoped = (raw: Raw): PostgresClient => ({
    async query(text, values) {
      return {
        rows: (await raw.query(text, values ? [...values] : undefined)).rows as PostgresRow[],
      }
    },
    transaction: (fn) => fn(scoped(raw)),
  })
  const inTx = async <T>(fn: (tx: PostgresClient) => Promise<T>): Promise<T> => {
    await ready
    return (await db).transaction(async (raw) => {
      await raw.query(`SET LOCAL search_path TO ${schema}`)
      return fn(scoped(raw))
    })
  }
  return {
    query: (text, values) => inTx((tx) => tx.query(text, values)),
    transaction: inTx,
  }
}
