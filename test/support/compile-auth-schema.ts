/**
 * The tables every SQL-store test runs on, built exactly as an app gets them (decision #2): the
 * skeleton's `create_users_table` migration (a pinned copy in `skeleton-migrations/`) followed by
 * auth's shipped migrations (`migrations/`), replayed by the framework's own sandbox and compiled
 * by its migrator for each dialect. No hand-written DDL: if a migration changes, every store test
 * runs on the new schema.
 *
 * {@link computeAuthSchema} runs once per test run in the global setup (`test/global-setup.ts`),
 * which hands the statements to every worker (`test/support/auth-schema.ts` reads them). This
 * file must not import `vitest` at runtime: global setups run outside the test workers.
 *
 * @module
 */
import { copyFileSync, mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PGlite } from '@electric-sql/pglite'
import {
  Connection,
  pgliteDriver,
  replayInSandbox,
  runMigrations,
  sqliteDriver,
} from '@strutvane/framework/database'
import { authMigrationsDirectory } from '../../src/migrations.ts'

/** The SQL each dialect runs for the skeleton's users table plus auth's migrations, in order. */
export interface AuthSchema {
  readonly sqlite: readonly string[]
  readonly postgres: readonly string[]
}

declare module 'vitest' {
  export interface ProvidedContext {
    authSchema: AuthSchema
  }
}

/** The folder with the pinned skeleton `users` migration. */
export const SKELETON_MIGRATIONS = new URL('./skeleton-migrations/', import.meta.url)

/**
 * A temporary migrations folder holding the skeleton's users migration and auth's migrations, as
 * an app has it after `node strut auth:migration`. The caller removes it.
 */
export function appMigrationsFolder(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sv-auth-migrations-'))
  for (const file of readdirSync(SKELETON_MIGRATIONS))
    copyFileSync(new URL(file, SKELETON_MIGRATIONS), join(dir, file))
  const auth = authMigrationsDirectory()
  for (const file of readdirSync(auth)) copyFileSync(join(auth, file), join(dir, file))
  return dir
}

async function statementsOn(
  connection: Connection,
  replay: Awaited<ReturnType<typeof replayInSandbox>>,
): Promise<string[]> {
  try {
    const result = await runMigrations(connection, replay, { pretend: true })
    return result.pretend.flatMap((m) => [...m.statements])
  } finally {
    await connection.close()
  }
}

/** Replay the migrations and compile them for SQLite and PostgreSQL (see the module docs). */
export async function computeAuthSchema(): Promise<AuthSchema> {
  const dir = appMigrationsFolder()
  try {
    const replay = await replayInSandbox(dir, { timeoutMs: 120_000 })
    const sqlite = await statementsOn(new Connection(sqliteDriver(':memory:')), replay)
    const postgres = await statementsOn(
      new Connection(pgliteDriver(await PGlite.create())),
      replay,
    )
    return { sqlite, postgres }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}
