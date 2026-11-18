/**
 * Auth's migrations, as files an app copies into `database/migrations` (decision #2).
 *
 * The app owns its schema: the skeleton's `create_users_table` migration creates `users`, and
 * auth ships two ordinary, driver-neutral migrations written with the framework's Schema builder
 * (`migrations/` in this package):
 * 1. `add_auth_columns_to_users_table`: the sign-in columns auth needs on `users`;
 * 2. `create_auth_tables`: auth's own tables (roles, sessions, tokens, passkeys, teams…).
 *
 * `node strut auth:migration` (and the installer) copy them with {@link copyAuthMigrations};
 * `node strut migrate` runs them like any other migration, and `migrate:rollback` undoes them.
 * Nothing in auth creates or alters a table at runtime.
 *
 * @module
 */
import { constants, copyFileSync, existsSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

/** The migration files auth ships, in the order they run. */
export const AUTH_MIGRATIONS: readonly string[] = Object.freeze([
  '2026_11_18_000001_add_auth_columns_to_users_table.ts',
  '2026_11_18_000002_create_auth_tables.ts',
])

/**
 * The folder holding auth's migrations inside the installed package.
 *
 * @example
 * authMigrationsDirectory() // '/app/node_modules/@strutvane/auth/migrations'
 */
export function authMigrationsDirectory(): string {
  // Built code lives in dist/, sources in src/: both sit next to migrations/.
  return fileURLToPath(new URL('../migrations/', import.meta.url))
}

/** What {@link copyAuthMigrations} did. */
export interface CopiedMigrations {
  /** Files written now. */
  readonly copied: readonly string[]
  /** Files already in the folder (left exactly as they are: the app owns them). */
  readonly present: readonly string[]
}

/**
 * Copy auth's migrations into an app's migrations folder. Idempotent: a file that is already
 * there is never overwritten (the app may have edited it), so running it twice changes nothing.
 *
 * @example
 * copyAuthMigrations(join(root, 'database', 'migrations')) // { copied: [...], present: [] }
 */
export function copyAuthMigrations(
  targetDirectory: string,
  sourceDirectory: string = authMigrationsDirectory(),
): CopiedMigrations {
  const copied: string[] = []
  const present: string[] = []
  mkdirSync(targetDirectory, { recursive: true })
  for (const file of AUTH_MIGRATIONS) {
    const target = join(targetDirectory, file)
    if (existsSync(target)) {
      present.push(file)
      continue
    }
    // COPYFILE_EXCL: a file that appeared meanwhile is never clobbered (it throws instead).
    copyFileSync(join(sourceDirectory, file), target, constants.COPYFILE_EXCL)
    copied.push(file)
  }
  return { copied, present }
}
