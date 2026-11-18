const fs = require('node:fs')
const p = 'src/identity/app-identity.ts'
let s = fs.readFileSync(p, 'utf8')
const rep = (a, b) => { if (!s.includes(a)) throw new Error('missing: ' + a.slice(0, 80)); s = s.replace(a, b) }
rep(` * Failure scenarios (each stops the boot with the fix in the message, fail closed):
 * - a persistent store without \`APP_KEY\` (every digest and signature derives from it);
 * - the auth tables do not exist yet (\`migrate\` applies the shipped migration);`,
` * The tables are the app's migrations (decision #2): its own \`users\` table, auth's columns on it
 * and auth's tables (\`node strut auth:migration\` copies the migrations, \`node strut migrate\` runs
 * them). Nothing here creates or alters a table.
 *
 * Failure scenarios (each stops the boot with the fix in the message, fail closed):
 * - a persistent store without \`APP_KEY\` (every digest and signature derives from it);
 * - an auth table or an auth column of \`users\` does not exist yet (run the migrations);`)
rep(`import { POSTGRES_AUTH_STATEMENTS } from '../engine/store/postgres-schema.ts'
import { SQLITE_SCHEMA } from '../engine/store/sqlite-schema.ts'
`, '')
rep(`/** The \`config/database.ts\` section, as far as auth reads it. */
export interface AppDatabaseSection {
  readonly default?: string
  readonly connection?: Readonly<Record<string, unknown>>
}`, `/**
 * The \`config/database.ts\` section, as far as auth reads it: the skeleton's flat shape
 * (\`default\` is the engine, \`database\` the SQLite file) or a \`connection\` object.
 */
export interface AppDatabaseSection {
  readonly default?: string
  /** The database name, or the SQLite file relative to the project root (skeleton shape). */
  readonly database?: unknown
  readonly connection?: Readonly<Record<string, unknown>>
}`)
rep(`  /** The SQL that creates the auth tables (persistent driver only). */
  compileMigrations?(): Promise<string>
  /** Whether any auth table is missing (persistent driver only). */
  tablesMissing?(): Promise<boolean>`, `  /** The SQL that creates the missing tables (the deprecated Better Auth adapter only). */
  compileMigrations?(): Promise<string>
  /** Whether any auth table or auth column of \`users\` is missing (persistent driver only). */
  tablesMissing?(): Promise<boolean>`)
rep(`/** Every table the native engine needs (checked at boot). */
const NATIVE_TABLES = [
  'users',
  'user_roles',
  'sessions',`, `/** Every table the native engine needs (checked at boot). \`users\` is the app's own. */
const NATIVE_TABLES = [
  'users',
  'user_roles',
  'auth_sessions',`)
rep(`] as const
`, `] as const

/** The columns auth's migration adds to the app's \`users\` table (checked at boot). */
const USER_COLUMNS = [
  'two_factor_secret',
  'two_factor_confirmed_at',
  'two_factor_last_step',
  'current_team_id',
] as const

/** One query that fails when any auth table or auth column of \`users\` is missing. */
const SCHEMA_PROBE = \`SELECT \${USER_COLUMNS.map((c) => \`users.\${c}\`).join(', ')} FROM \${NATIVE_TABLES.join(', ')} LIMIT 0\`
`)
rep(`export function isPostgres(db: AppDatabaseSection | undefined): boolean {
  const driver = driverOf(db)
  return driver === 'postgres' || driver === 'azure-postgres'
}`, `export function isPostgres(db: AppDatabaseSection | undefined): boolean {
  const driver = driverOf(db)
  return driver === 'postgres' || driver === 'pgsql' || driver === 'azure-postgres'
}`)
rep(` * The SQLite file of \`config/database.ts\` (\`connection.filename\`, or a \`file:\` url), resolved
 * against the project root. \`undefined\` when it is not a file (\`:memory:\`, a remote libSQL url).
 *
 * @example
 * sqliteFileFrom({ default: 'sqlite', connection: { filename: 'storage/app.sqlite' } }, '/app') // '/app/storage/app.sqlite'`,
` * The SQLite file of \`config/database.ts\`: the skeleton's \`database\` key, \`connection.filename\`
 * or a \`file:\` url (default \`database/database.sqlite\`, the framework's), resolved against the
 * project root. \`undefined\` when it is not a file (\`:memory:\`, a remote libSQL url).
 *
 * @example
 * sqliteFileFrom({ default: 'sqlite', database: 'database/app.sqlite' }, '/app') // '/app/database/app.sqlite'`)
rep(`  else if (url === undefined) file = str(c['filename']) ?? 'storage/database.sqlite'`,
`  else if (url === undefined)
    file = str(c['filename']) ?? str(db?.database) ?? 'database/database.sqlite'`)
rep(`const MIGRATIONS_HINT =
  'The auth tables do not exist yet. Run \`node strut migrate\` (@strutvane/auth ships them as a migration; \`node strut auth:migration\` copies it into database/migrations).'`,
`const MIGRATIONS_HINT =
  "The auth tables (or the auth columns of users) do not exist yet. Run \`node strut auth:migration\` (it copies @strutvane/auth's migrations into database/migrations), then \`node strut migrate\`."`)
rep(`      try {
        await client.query(\`SELECT 1 FROM \${NATIVE_TABLES.join(', ')} LIMIT 0\`)
        return false
      } catch (error) {
        if ((error as { code?: unknown }).code === '42P01') return true // undefined_table
        throw error
      }`, `      try {
        await client.query(SCHEMA_PROBE)
        return false
      } catch (error) {
        const code = (error as { code?: unknown }).code
        if (code === '42P01' || code === '42703') return true // undefined_table / undefined_column
        throw error
      }`)
rep(`    const tablesMissing = async (): Promise<boolean> =>
      NATIVE_TABLES.some(
        (name) =>
          db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name) ===
          undefined,
      )`, `    const tablesMissing = async (): Promise<boolean> => {
      try {
        db.prepare(SCHEMA_PROBE)
        return false
      } catch (error) {
        // node:sqlite reports "no such table" / "no such column" while preparing.
        if (/no such (?:table|column)/.test(error instanceof Error ? error.message : '')) return true
        throw error
      }
    }`)
fs.writeFileSync(p, s)
console.log('ok')
