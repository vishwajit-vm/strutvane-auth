/**
 * `createFirstAdmin()`: the app's first administrator, created once from a seeder (decision #13).
 *
 * It runs on the seeder's own database connection (the framework's `Connection`, `SeedContext.db`),
 * so it works on every engine the framework supports (MySQL, MariaDB, PostgreSQL, SQLite) and
 * needs no running app, `APP_KEY` or identity engine. It writes exactly what the identity engine
 * reads: a row in the app's `users` table (scrypt password hash, email verified) and the `admin`
 * row in auth's `user_roles` table.
 *
 * Rules, and why:
 * - **Once.** If any account already has the role, it refuses with `first_admin_exists` and
 *   changes nothing, so re-running `db:seed` can never reset or add an administrator. An existing
 *   account with the same email is never touched either (`email_taken`): promoting it would hand
 *   admin rights to whoever registered that address first.
 * - **No password in files.** Without `password`, a strong one-time password is generated and
 *   returned exactly once; the caller shows it to the developer. It is never logged or stored
 *   anywhere but as a scrypt hash.
 * - **Concurrent runs** cannot both create an admin: the check and the insert run in one
 *   transaction that first takes a write lock (PostgreSQL: a table lock on `user_roles`;
 *   MySQL/MariaDB: `FOR UPDATE`; SQLite: the database write lock).
 * - **Fail closed** with the fix in the message when auth's migrations have not run
 *   (`auth_tables_missing`).
 *
 * @module
 */
import { randomBytes } from 'node:crypto'
import type { Connection } from '@strutvane/framework/database'
import { TEAM_OWNER_ROLE } from './engine/config.ts'
import { parseEmail } from './engine/password/email.ts'
import { createScryptHasher, type PasswordHasher } from './engine/password/hasher.ts'
import { commonPasswordCheck, passwordLength } from './engine/password/rules.ts'

/** Why {@link createFirstAdmin} refused. Stable, lowercase `snake_case` (decision #68). */
export type FirstAdminErrorCode =
  | 'first_admin_exists'
  | 'email_taken'
  | 'validation_failed'
  | 'auth_tables_missing'

/** A refusal of {@link createFirstAdmin}: nothing was written. `code` is stable; match on it. */
export class FirstAdminError extends Error {
  override readonly name = 'FirstAdminError'
  readonly code: FirstAdminErrorCode
  constructor(code: FirstAdminErrorCode, message: string, options?: ErrorOptions) {
    super(`${message} (${code})`, options)
    this.code = code
  }
}

/** The account to create. */
export interface FirstAdminInput {
  /** The admin's email address (normalised: trimmed, lower-cased). */
  readonly email: string
  /** Display name. Default `Admin`. */
  readonly name?: string
  /**
   * The password (12 to 256 characters, not a common one). Leave it out to get a generated
   * one-time password back instead, so no password is ever written to `.env` or a seeder.
   */
  readonly password?: string
  /** The global role. Default `admin` (the role `config/auth.ts` gives full control). */
  readonly role?: string
}

/** What {@link createFirstAdmin} created. */
export interface FirstAdminResult {
  /** The new row's id in the app's `users` table. */
  readonly userId: string
  readonly email: string
  readonly role: string
  /**
   * The generated password, when none was given. Show it once, then forget it; the admin should
   * change it at the first sign-in.
   */
  readonly oneTimePassword?: string
}

/** The part of the framework's `Connection` this needs (the seeder's `db`). */
export type FirstAdminConnection = Pick<Connection, 'run' | 'transaction' | 'grammar'>

/** Options for tests: a cheaper hasher. */
export interface FirstAdminOptions {
  readonly hasher?: PasswordHasher
}

const ROLE = /^[a-z][a-z0-9_-]{0,63}$/
const MIN_PASSWORD = 12
const MAX_PASSWORD = 256

/** Error codes and messages of a missing table or column, on every engine. */
function isMissingSchema(error: unknown): boolean {
  for (let e: unknown = error, depth = 0; e instanceof Error && depth < 5; depth++) {
    const code = String((e as { code?: unknown }).code ?? '')
    if (/^(?:42P01|42703|ER_NO_SUCH_TABLE|ER_BAD_FIELD_ERROR)$/.test(code)) return true
    if (/no such (?:table|column)|does not exist|doesn't exist|unknown column/i.test(e.message))
      return true
    e = (e as { cause?: unknown }).cause
  }
  return false
}

/** A timestamp in the format the framework's ORM writes for this engine. */
function timestampFor(dialect: string, date: Date): string {
  const iso = date.toISOString()
  return dialect === 'mysql' || dialect === 'mariadb'
    ? `${iso.slice(0, 10)} ${iso.slice(11, 23)}`
    : iso
}

/** A 24-character password from 18 random bytes (144 bits), URL- and shell-safe. */
function generatePassword(): string {
  return randomBytes(18).toString('base64url')
}

async function checkedPassword(password: string | undefined): Promise<string | undefined> {
  if (password === undefined) return undefined
  const length = passwordLength(password, MAX_PASSWORD)
  if (
    length === undefined ||
    length < MIN_PASSWORD ||
    length > MAX_PASSWORD ||
    (await commonPasswordCheck(password)) !== 'ok'
  )
    throw new FirstAdminError(
      'validation_failed',
      `The password must be ${MIN_PASSWORD} to ${MAX_PASSWORD} characters and not a common one. Leave it out to get a one-time password`,
    )
  return password
}

/**
 * Create the app's first administrator, once (see the module docs for the rules).
 *
 * @example
 * ```ts
 * // database/seeders/admin.seeder.ts
 * import { createFirstAdmin, FirstAdminError } from '@strutvane/auth'
 * import { defineSeeder } from '@strutvane/framework/database'
 *
 * export default defineSeeder({
 *   async run({ db }) {
 *     try {
 *       const admin = await createFirstAdmin(db, { email: 'owner@acme.test' })
 *       process.stdout.write(`Admin ${admin.email}, one-time password: ${admin.oneTimePassword}\n`)
 *     } catch (error) {
 *       if (error instanceof FirstAdminError && error.code === 'first_admin_exists') return
 *       throw error
 *     }
 *   },
 * })
 * ```
 */
export async function createFirstAdmin(
  db: FirstAdminConnection,
  input: FirstAdminInput,
  options: FirstAdminOptions = {},
): Promise<FirstAdminResult> {
  const email = parseEmail(input.email)
  if (email === undefined)
    throw new FirstAdminError('validation_failed', 'The admin email is not a valid address')
  const name = (input.name ?? 'Admin').trim()
  if (name.length < 1 || name.length > 200)
    throw new FirstAdminError('validation_failed', 'The admin name must be 1 to 200 characters')
  const role = input.role ?? 'admin'
  if (!ROLE.test(role))
    throw new FirstAdminError('validation_failed', `"${role}" is not a role name (a-z, 0-9, _ -)`)
  // `owner` is the reserved team role (anyone who creates a team holds it there): never global.
  if (role === TEAM_OWNER_ROLE)
    throw new FirstAdminError(
      'validation_failed',
      '"owner" is the team role and cannot be a global role; use "admin" or another platform role',
    )
  const given = await checkedPassword(input.password)
  const oneTimePassword = given === undefined ? generatePassword() : undefined
  // Hash before the transaction: scrypt takes ~100 ms and must not hold the lock.
  const hash = await (options.hasher ?? createScryptHasher()).hash(given ?? oneTimePassword ?? '')

  // Loaded here, not at the top: `@strutvane/auth` stays importable without the ORM loaded.
  const { sql } = await import('@strutvane/framework/database')
  const dialect = db.grammar.dialect
  try {
    await db.run(
      sql`SELECT ${sql.id('two_factor_secret')}, ${sql.id('current_team_id')} FROM ${sql.id('users')} WHERE 1 = 0`,
    )
    await db.run(sql`SELECT ${sql.id('role')} FROM ${sql.id('user_roles')} WHERE 1 = 0`)
  } catch (error) {
    if (!isMissingSchema(error)) throw error
    throw new FirstAdminError(
      'auth_tables_missing',
      "The auth tables do not exist yet. Run `node strut auth:migration` (it copies @strutvane/auth's migrations into database/migrations), then `node strut migrate`",
      { cause: error },
    )
  }

  const userId = await db.transaction(async () => {
    if (dialect === 'postgres')
      // Readers go on; a second first-admin run waits here until this one commits, then sees it.
      await db.run(sql`LOCK TABLE ${sql.id('user_roles')} IN SHARE ROW EXCLUSIVE MODE`)
    const lock = dialect === 'mysql' || dialect === 'mariadb' ? sql` FOR UPDATE` : sql``
    const admins = await db.run(
      sql`SELECT ${sql.id('user_id')} FROM ${sql.id('user_roles')} WHERE ${sql.id('role')} = ${role}${lock}`,
    )
    if (admins.rows.length > 0)
      throw new FirstAdminError(
        'first_admin_exists',
        `An account with the ${role} role already exists; nothing was changed`,
      )
    const taken = await db.run(
      sql`SELECT ${sql.id('id')} FROM ${sql.id('users')} WHERE ${sql.id('email')} = ${email}`,
    )
    if (taken.rows.length > 0)
      throw new FirstAdminError(
        'email_taken',
        `An account with ${email} already exists; it was not changed (promoting it would give admin rights to whoever registered that address). Use another address`,
      )
    const now = timestampFor(dialect, new Date())
    await db.run(
      sql`INSERT INTO ${sql.id('users')} (${sql.id('name')}, ${sql.id('email')}, ${sql.id('password')}, ${sql.id('email_verified_at')}, ${sql.id('created_at')}, ${sql.id('updated_at')})
          VALUES (${name}, ${email}, ${hash}, ${now}, ${now}, ${now})`,
    )
    // Read the id back instead of RETURNING / insertId: the one form every engine supports.
    const created = await db.run(
      sql`SELECT ${sql.id('id')} FROM ${sql.id('users')} WHERE ${sql.id('email')} = ${email}`,
    )
    const id = created.rows[0]?.['id']
    if (typeof id !== 'number' && typeof id !== 'bigint' && typeof id !== 'string')
      throw new TypeError('createFirstAdmin: the users table returned no id')
    await db.run(
      sql`INSERT INTO ${sql.id('user_roles')} (${sql.id('user_id')}, ${sql.id('role')}) VALUES (${id}, ${role})`,
    )
    return String(id)
  })
  return Object.freeze({
    userId,
    email,
    role,
    ...(oneTimePassword === undefined ? {} : { oneTimePassword }),
  })
}
