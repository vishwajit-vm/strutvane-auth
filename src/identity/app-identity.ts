/**
 * Which identity engine a Strutvane app runs on, chosen from `config/auth.ts` `session.driver`
 * and `config/database.ts`:
 *
 * | `session.driver` | database | engine |
 * |---|---|---|
 * | `database` | PostgreSQL | Better Auth on the app's database: accounts, sessions, tenants and memberships persist across restarts and are shared by every process |
 * | `database` | anything else | native (in memory), with a warning: persistence needs PostgreSQL today |
 * | `memory`, unset | any | native (in memory): development and tests |
 * | `valkey`, `jwt` | any | native, with a warning (not built yet) |
 *
 * Failure scenarios (each stops the boot with the fix in the message):
 * - `better-auth` or `pg` is not installed;
 * - the auth tables do not exist yet (`sv auth:migration`, then `sv migrate`);
 * - the secret is missing or shorter than 32 characters.
 *
 * The pool is closed by {@link AppIdentity.close}; a failed boot closes it too.
 *
 * @module
 */
import type { Logger } from '@strutvane/contracts'
import type { AuthConfig } from '../config.ts'
import type { IdentityEngine, PasswordResetDelivery } from './engine.ts'
import { createNativeEngine, type GlobalRoles } from './native.ts'

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
  readonly logger: Pick<Logger, 'warn' | 'error'>
  readonly globalRoles?: GlobalRoles
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
  /** `database` (persistent, Better Auth) or `memory` (native). */
  readonly driver: 'database' | 'memory'
  /** The SQL that creates or upgrades the auth tables (persistent driver only). */
  compileMigrations?(): Promise<string>
  /** Whether any auth table is missing (persistent driver only). */
  tablesMissing?(): Promise<boolean>
  close(): Promise<void>
}

/** Thrown when the persistent identity cannot start; the message names the fix. */
export class IdentitySetupError extends Error {
  override readonly name = 'IdentitySetupError'
}

/** Table for the shared rate-limit counters (see `postgresRateLimitStore`). */
export const RATE_LIMIT_TABLE = 'strutvane_rate_limits'

const str = (v: unknown): string | undefined => (typeof v === 'string' && v !== '' ? v : undefined)
const num = (v: unknown): number | undefined =>
  typeof v === 'number' && Number.isFinite(v)
    ? v
    : typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))
      ? Number(v)
      : undefined

/** Is this database section PostgreSQL? */
export function isPostgres(db: AppDatabaseSection | undefined): boolean {
  const driver = str(db?.connection?.['driver']) ?? db?.default
  return driver === 'postgres' || driver === 'azure-postgres'
}

/**
 * node-postgres pool options from the generated `config/database.ts` shape (url, or host, port,
 * database, user, password, ssl, pool). `ssl: true` verifies certificates.
 */
export function poolOptionsFrom(db: AppDatabaseSection | undefined): Record<string, unknown> {
  const c = db?.connection ?? {}
  const pool = (c['pool'] ?? {}) as { min?: unknown; max?: unknown }
  const ssl = c['ssl']
  const out: Record<string, unknown> = {
    // Auth traffic is light: a small pool next to the framework's own.
    max: Math.min(num(pool.max) ?? 5, 5),
    application_name: 'strutvane-auth',
  }
  if (str(c['url'])) out['connectionString'] = str(c['url'])
  for (const key of ['host', 'database', 'user', 'password'] as const)
    if (str(c[key])) out[key] = str(c[key])
  if (num(c['port']) !== undefined) out['port'] = num(c['port'])
  if (ssl === true) out['ssl'] = { rejectUnauthorized: true }
  else if (typeof ssl === 'object' && ssl !== null) out['ssl'] = ssl
  return out
}

interface PgPool {
  query(sql: string, params?: unknown[]): Promise<{ rows: unknown[] }>
  end(): Promise<void>
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

/** Create the engine for an app (see the module docs for the selection rules). */
export async function createAppIdentity(options: AppIdentityOptions): Promise<AppIdentity> {
  const { auth, logger } = options
  const driver = auth.session?.driver ?? 'memory'
  const native = (): AppIdentity => ({
    driver: 'memory',
    engine: createNativeEngine({
      baseURL: options.appUrl,
      logger,
      ...(auth.trustedProxies ? { trustedProxies: auth.trustedProxies } : {}),
      deliverPasswordReset: options.deliverPasswordReset,
      ...(auth.session?.idleMinutes ? { sessionTtlSeconds: auth.session.idleMinutes * 60 } : {}),
      onUnexpectedError: (context, error) =>
        logger.error('auth engine failure', {
          context,
          error: error instanceof Error ? error.message : String(error),
        }),
      ...(options.globalRoles ? { globalRoles: options.globalRoles } : {}),
    }),
    close: async () => undefined,
  })
  if (driver !== 'database') {
    if (driver !== 'memory')
      logger.warn(
        `auth: session driver "${driver}" is not built yet; accounts and sessions are kept in memory and lost on restart`,
      )
    return native()
  }
  if (!isPostgres(options.database)) {
    logger.warn(
      'auth: session.driver is "database", but persistent identity needs PostgreSQL; accounts and sessions are kept in memory and lost on restart',
    )
    return native()
  }
  if (typeof auth.secret !== 'string' || auth.secret.length < 32)
    throw new IdentitySetupError(
      'config/auth.ts: `secret` (AUTH_SECRET) must be at least 32 random characters for persistent sessions',
    )
  const pg = await importOrExplain(
    () => import('pg'),
    'pg',
    'Install it: pnpm add pg (it is the PostgreSQL driver).',
  )
  const { createBetterAuthEngine } = await importOrExplain(
    () => import('./better-auth.ts'),
    'better-auth',
    'Persistent sign-in (session.driver "database") runs on Better Auth: pnpm add better-auth@1.7.23',
  )
  const { postgresRateLimitStore } = await import('../postgres/rate-limit-store.ts')
  const Pool = (pg.default ?? pg).Pool
  const pool = new Pool(poolOptionsFrom(options.database)) as unknown as PgPool & {
    on(event: 'error', listener: (error: Error) => void): void
  }
  // An idle client losing its connection must not crash the process.
  pool.on('error', (error) => logger.error('auth database pool error', { error: error.message }))
  try {
    const engine = createBetterAuthEngine({
      pool: pool as never,
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
        'The auth tables do not exist yet. Run `pnpm sv auth:migration` (writes the migration), then `pnpm sv migrate`.',
      )
    return {
      driver: 'database',
      engine,
      compileMigrations: () => engine.compileMigrations(),
      tablesMissing,
      close: () => pool.end(),
    }
  } catch (error) {
    await pool.end().catch(() => undefined)
    throw error
  }
}
