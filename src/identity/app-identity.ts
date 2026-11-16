/**
 * Which identity engine and store a Strutvane app runs on, chosen from `config/auth.ts` and
 * `config/database.ts`.
 *
 * | `identity` | `session.driver` | database | engine and store |
 * |---|---|---|---|
 * | `native` (default) | `database` (default when a database is configured) | PostgreSQL | native engine, PostgreSQL store: on the framework's `Database` when it is bound (one pool for the app), else a small pool of its own |
 * | `native` | `database` | SQLite | native engine, SQLite store on the same database file (`node:sqlite`) |
 * | `native` | `database` | anything else (MySQL) | native engine in memory, with a warning: the MySQL store waits for the framework ORM |
 * | `native` | `memory` | any | native engine in memory: development and tests |
 * | `better-auth` | `database` | PostgreSQL | **deprecated** Better Auth adapter (ADR-0023) |
 *
 * Failure scenarios (each stops the boot with the fix in the message, fail closed):
 * - a persistent store without `APP_KEY` (every digest and signature derives from it);
 * - the auth tables do not exist yet (`migrate` applies the shipped migration);
 * - `pg` (or, for Better Auth, `better-auth`) is not installed;
 * - the database accepts no connection within 10 s.
 *
 * Pools and files this module opens are closed by {@link AppIdentity.close}; a failed boot closes
 * them too. A framework `Database` passed in is the app's and is never closed here.
 *
 * @module
 */
import { isAbsolute, resolve } from 'node:path'
import type { Logger } from '@strutvane/framework/contracts'
import type { AuthConfig } from '../config.ts'
import type { AuthEventSink } from '../engine/ports/events.ts'
import type { AuthMailer } from '../engine/ports/mailer.ts'
import {
  type FrameworkDatabaseLike,
  frameworkDatabaseClient,
  type PgPoolLike,
  type PostgresClient,
  pgPoolClient,
  postgresAuthStore,
  postgresCounterStore,
} from '../engine/store/postgres.ts'
import { POSTGRES_AUTH_STATEMENTS } from '../engine/store/postgres-schema.ts'
import { SQLITE_SCHEMA } from '../engine/store/sqlite-schema.ts'
import type { GlobalRoles, IdentityEngine, PasswordResetDelivery } from './engine.ts'
import {
  createNativeEngine,
  type NativeEngineOptions,
  type NativeIdentityEngine,
} from './native.ts'

/** The `config/database.ts` section, as far as auth reads it. */
export interface AppDatabaseSection {
  readonly default?: string
  readonly connection?: Readonly<Record<string, unknown>>
}

/** Options for {@link createAppIdentity}. */
export interface AppIdentityOptions {
  readonly auth: AuthConfig
  readonly appUrl: string
  readonly database?: AppDatabaseSection | undefined
  /** The framework's `Database` (`DatabaseToken`), shared when it is PostgreSQL. */
  readonly frameworkDatabase?: FrameworkDatabaseLike | undefined
  /** The project root (relative SQLite file names resolve against it). Default: the cwd. */
  readonly root?: string
  /** `APP_KEY`. Default: `process.env.APP_KEY`. Required for a persistent store. */
  readonly appKey?: string | undefined
  readonly logger: Pick<Logger, 'warn' | 'error'>
  /** Engine settings derived from `config/auth.ts` (features, passwords, sessions…). */
  readonly engineConfig?: NativeEngineOptions['config']
  readonly mailer?: AuthMailer
  readonly events?: AuthEventSink
  readonly globalRoles?: GlobalRoles
  readonly defaultRoles?: readonly string[]
  readonly deliverPasswordReset: PasswordResetDelivery
  /**
   * Check that the auth tables exist (default `true`). The migration command turns it off: it runs
   * precisely because they don't.
   */
  readonly verifyTables?: boolean
}

/** The engine an app runs on, and how to release it. */
export interface AppIdentity {
  readonly engine: IdentityEngine
  /** The native engine, when the app runs on it (the provider mounts its routes). */
  readonly native: NativeIdentityEngine | undefined
  /** `database` (persistent) or `memory`. */
  readonly driver: 'database' | 'memory'
  /** The SQL dialect of a persistent store. */
  readonly dialect?: 'postgres' | 'sqlite'
  /** The SQL that creates the auth tables (persistent driver only). */
  compileMigrations?(): Promise<string>
  /** Whether any auth table is missing (persistent driver only). */
  tablesMissing?(): Promise<boolean>
  close(): Promise<void>
}

/** Thrown when the persistent identity cannot start; the message names the fix. */
export class IdentitySetupError extends Error {
  override readonly name = 'IdentitySetupError'
}

/** Table for the shared rate-limit counters of the deprecated Better Auth adapter. */
export const RATE_LIMIT_TABLE = 'strutvane_rate_limits'

/** How long a pool waits for a database connection before failing (fail closed). */
const CONNECT_TIMEOUT_MS = 10_000

/** Every table the native engine needs (checked at boot). */
const NATIVE_TABLES = [
  'users',
  'user_roles',
  'sessions',
  'auth_one_time_tokens',
  'two_factor_recovery_codes',
  'passkeys',
  'personal_access_tokens',
  'teams',
  'team_members',
  'team_invitations',
  'auth_counters',
] as const

const str = (v: unknown): string | undefined => (typeof v === 'string' && v !== '' ? v : undefined)
const num = (v: unknown): number | undefined =>
  typeof v === 'number' && Number.isFinite(v)
    ? v
    : typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))
      ? Number(v)
      : undefined

/** The database driver named by `config/database.ts`. */
function driverOf(db: AppDatabaseSection | undefined): string | undefined {
  return str(db?.connection?.['driver']) ?? db?.default
}

/**
 * Is this database section PostgreSQL?
 *
 * @example
 * isPostgres({ default: 'postgres' }) // true
 */
export function isPostgres(db: AppDatabaseSection | undefined): boolean {
  const driver = driverOf(db)
  return driver === 'postgres' || driver === 'azure-postgres'
}

/**
 * node-postgres pool options from the generated `config/database.ts` shape (url, or host, port,
 * database, user, password, ssl, pool). `ssl: true` verifies certificates.
 *
 * @example
 * new pg.Pool(poolOptionsFrom({ default: 'postgres', connection: { url: env.DB_URL } }))
 */
export function poolOptionsFrom(db: AppDatabaseSection | undefined): Record<string, unknown> {
  const c = db?.connection ?? {}
  const pool = (c['pool'] ?? {}) as { min?: unknown; max?: unknown }
  const ssl = c['ssl']
  const out: Record<string, unknown> = {
    // Auth traffic is light: a small pool next to the framework's own.
    max: Math.min(num(pool.max) ?? 5, 5),
    application_name: 'strutvane-auth',
    // node-postgres waits forever for a connection by default: a black-holed or wedged database
    // would hang the boot and every authenticated request. Give up and fail closed instead.
    connectionTimeoutMillis: CONNECT_TIMEOUT_MS,
  }
  if (str(c['url'])) out['connectionString'] = str(c['url'])
  for (const key of ['host', 'database', 'user', 'password'] as const)
    if (str(c[key])) out[key] = str(c[key])
  if (num(c['port']) !== undefined) out['port'] = num(c['port'])
  if (ssl === true) out['ssl'] = { rejectUnauthorized: true }
  else if (typeof ssl === 'object' && ssl !== null) out['ssl'] = ssl
  return out
}

/**
 * The SQLite file of `config/database.ts` (`connection.filename`, or a `file:` url), resolved
 * against the project root. `undefined` when it is not a file (`:memory:`, a remote libSQL url).
 *
 * @example
 * sqliteFileFrom({ default: 'sqlite', connection: { filename: 'storage/app.sqlite' } }, '/app') // '/app/storage/app.sqlite'
 */
export function sqliteFileFrom(
  db: AppDatabaseSection | undefined,
  root: string,
): string | undefined {
  const c = db?.connection ?? {}
  const url = str(c['url'])
  let file: string | undefined
  if (url?.startsWith('file:'))
    file = decodeURIComponent(new URL(url).pathname).replace(/^\/([A-Za-z]:)/, '$1')
  else if (url === undefined) file = str(c['filename']) ?? 'storage/database.sqlite'
  if (file === undefined || file === ':memory:') return undefined
  return isAbsolute(file) ? file : resolve(root, file)
}

async function importOrExplain<T>(load: () => Promise<T>, what: string, fix: string): Promise<T> {
  try {
    return await load()
  } catch (error) {
    const code = (error as { code?: unknown }).code
    if (code === 'ERR_MODULE_NOT_FOUND' || code === 'MODULE_NOT_FOUND')
      throw new IdentitySetupError(`${what} is not installed. ${fix}`, { cause: error })
    throw error
  }
}

/** The app key, or a setup error naming the fix. */
function requireAppKey(options: AppIdentityOptions): string {
  const key = options.appKey ?? process.env['APP_KEY']
  if (typeof key !== 'string' || key.length < 32)
    throw new IdentitySetupError(
      'APP_KEY is missing or too short: persistent sign-in derives every digest and signature from it. Generate one with `node strut key:generate`.',
    )
  return key
}

const MIGRATIONS_HINT =
  'The auth tables do not exist yet. Run `node strut migrate` (@strutvane/auth ships them as a migration; `node strut auth:migration` copies it into database/migrations).'

type NativeFactory = (extra?: Partial<NativeEngineOptions>) => NativeIdentityEngine

/**
 * Create the engine for an app (see the module docs for the selection rules).
 *
 * @example
 * const identity = await createAppIdentity({ auth, appUrl, database, logger, deliverPasswordReset })
 * const { actor } = await identity.engine.authenticate(request)
 */
export async function createAppIdentity(options: AppIdentityOptions): Promise<AppIdentity> {
  const { auth, logger } = options
  if (auth.identity === 'better-auth') return betterAuthIdentity(options)
  const configured = auth.session?.driver ?? (options.database ? 'database' : 'memory')
  const native: NativeFactory = (extra = {}) =>
    createNativeEngine({
      baseURL: options.appUrl,
      ...(options.engineConfig ? { config: options.engineConfig } : {}),
      ...(auth.trustedProxies ? { trustedProxies: auth.trustedProxies } : {}),
      deliverPasswordReset: options.deliverPasswordReset,
      ...(options.mailer ? { mailer: options.mailer } : {}),
      ...(options.events ? { events: options.events } : {}),
      ...(options.globalRoles ? { globalRoles: options.globalRoles } : {}),
      ...(options.defaultRoles ? { defaultRoles: options.defaultRoles } : {}),
      logger,
      onUnexpectedError: (context, error) =>
        logger.error('auth engine failure', {
          context,
          error: error instanceof Error ? error.message : String(error),
        }),
      ...extra,
    })
  const memory = (): AppIdentity => {
    const engine = native()
    return { engine, native: engine, driver: 'memory', close: async () => undefined }
  }
  if (configured !== 'database') {
    if (configured !== 'memory')
      logger.warn(
        `auth: session driver "${configured}" is not built yet; accounts and sessions are kept in memory and lost on restart`,
      )
    return memory()
  }
  const driver = driverOf(options.database) ?? options.frameworkDatabase?.dialect
  if (isPostgres(options.database) || driver === 'postgres')
    return postgresIdentity(options, native)
  if (driver === 'sqlite') return sqliteIdentity(options, native)
  logger.warn(
    `auth: persistent sign-in supports PostgreSQL and SQLite today (the ${driver ?? 'configured'} store waits for the framework ORM); accounts and sessions are kept in memory and lost on restart`,
  )
  return memory()
}

async function postgresIdentity(
  options: AppIdentityOptions,
  native: NativeFactory,
): Promise<AppIdentity> {
  const appKey = requireAppKey(options)
  let client: PostgresClient
  let close: () => Promise<void> = async () => undefined
  if (options.frameworkDatabase?.dialect === 'postgres') {
    client = frameworkDatabaseClient(options.frameworkDatabase)
  } else {
    const pg = await importOrExplain(
      () => import('pg'),
      'pg',
      'Install it: npm install pg (it is the PostgreSQL driver).',
    )
    const Pool = (pg.default ?? pg).Pool
    const pool = new Pool(poolOptionsFrom(options.database))
    // An idle client losing its connection must not crash the process.
    pool.on('error', (error: Error) =>
      options.logger.error('auth database pool error', { error: error.message }),
    )
    client = pgPoolClient(pool as unknown as PgPoolLike)
    close = () => pool.end()
  }
  try {
    const tablesMissing = async (): Promise<boolean> => {
      try {
        await client.query(`SELECT 1 FROM ${NATIVE_TABLES.join(', ')} LIMIT 0`)
        return false
      } catch (error) {
        if ((error as { code?: unknown }).code === '42P01') return true // undefined_table
        throw error
      }
    }
    if (options.verifyTables !== false && (await tablesMissing()))
      throw new IdentitySetupError(MIGRATIONS_HINT)
    const engine = native({
      appKey,
      store: postgresAuthStore(client),
      counters: postgresCounterStore(client),
    })
    return {
      engine,
      native: engine,
      driver: 'database',
      dialect: 'postgres',
      compileMigrations: async () => POSTGRES_AUTH_STATEMENTS.join(';\n'),
      tablesMissing,
      close,
    }
  } catch (error) {
    await close().catch(() => undefined)
    throw error
  }
}

async function sqliteIdentity(
  options: AppIdentityOptions,
  native: NativeFactory,
): Promise<AppIdentity> {
  const appKey = requireAppKey(options)
  const file = sqliteFileFrom(options.database, options.root ?? process.cwd())
  if (file === undefined)
    throw new IdentitySetupError(
      'config/database.ts: persistent sign-in on SQLite needs a database file (connection.filename), not :memory: or a remote URL',
    )
  const { DatabaseSync } = await import('node:sqlite')
  const db = new DatabaseSync(file)
  try {
    const tablesMissing = async (): Promise<boolean> =>
      NATIVE_TABLES.some(
        (name) =>
          db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name) ===
          undefined,
      )
    if (options.verifyTables !== false && (await tablesMissing()))
      throw new IdentitySetupError(MIGRATIONS_HINT)
    const { sqliteAuthStore, sqliteCounterStore } = await import('../engine/store/sqlite.ts')
    const engine = native({ appKey, store: sqliteAuthStore(db), counters: sqliteCounterStore(db) })
    return {
      engine,
      native: engine,
      driver: 'database',
      dialect: 'sqlite',
      compileMigrations: async () => SQLITE_SCHEMA.trim(),
      tablesMissing,
      close: async () => db.close(),
    }
  } catch (error) {
    db.close()
    throw error
  }
}

/** The deprecated Better Auth adapter (ADR-0023): only when `identity: 'better-auth'` is set. */
async function betterAuthIdentity(options: AppIdentityOptions): Promise<AppIdentity> {
  const { auth, logger } = options
  if (auth.session?.driver !== undefined && auth.session.driver !== 'database')
    throw new IdentitySetupError(
      'config/auth.ts: identity "better-auth" (deprecated) runs only with session.driver "database"',
    )
  if (!isPostgres(options.database))
    throw new IdentitySetupError(
      'config/auth.ts: identity "better-auth" (deprecated) needs PostgreSQL; remove `identity` to use the native engine',
    )
  if (typeof auth.secret !== 'string' || auth.secret.length < 32)
    throw new IdentitySetupError(
      'config/auth.ts: `secret` (AUTH_SECRET) must be at least 32 random characters for the Better Auth adapter',
    )
  const pg = await importOrExplain(
    () => import('pg'),
    'pg',
    'Install it: npm install pg (it is the PostgreSQL driver).',
  )
  const { createBetterAuthEngine } = await importOrExplain(
    () => import('./better-auth.ts'),
    'better-auth',
    'The deprecated Better Auth adapter needs it: npm install better-auth@1.7.23 (or remove `identity: "better-auth"` to use the native engine).',
  )
  const { postgresRateLimitStore } = await import('../postgres/rate-limit-store.ts')
  const Pool = (pg.default ?? pg).Pool
  const pool = new Pool(poolOptionsFrom(options.database))
  pool.on('error', (error: Error) =>
    logger.error('auth database pool error', { error: error.message }),
  )
  try {
    const engine = createBetterAuthEngine({
      pool,
      baseURL: options.appUrl,
      secret: auth.secret,
      deliverPasswordReset: options.deliverPasswordReset,
      rateLimitStore: postgresRateLimitStore(pool, { table: RATE_LIMIT_TABLE }),
      ...(auth.trustedProxies ? { trustedProxies: auth.trustedProxies } : {}),
      logger,
      onUnexpectedError: (context, error) =>
        logger.error('auth engine failure', {
          context,
          error: error instanceof Error ? error.message : String(error),
        }),
      ...(options.globalRoles ? { globalRoles: options.globalRoles } : {}),
    })
    const tablesMissing = async (): Promise<boolean> => {
      try {
        await pool.query(
          `SELECT 1 FROM "user", "session", "organization", "member", ${RATE_LIMIT_TABLE} LIMIT 0`,
        )
        return false
      } catch (error) {
        if ((error as { code?: unknown }).code === '42P01') return true // undefined_table
        throw error
      }
    }
    if (options.verifyTables !== false && (await tablesMissing()))
      throw new IdentitySetupError(
        'The Better Auth tables do not exist yet. Run `node strut auth:migration`, then `node strut migrate`.',
      )
    return {
      engine,
      native: undefined,
      driver: 'database',
      dialect: 'postgres',
      compileMigrations: () => engine.compileMigrations(),
      tablesMissing,
      close: () => pool.end(),
    }
  } catch (error) {
    await pool.end().catch(() => undefined)
    throw error
  }
}
