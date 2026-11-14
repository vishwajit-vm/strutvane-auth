/**
 * `withTenant`: run database work inside ONE transaction scoped to a tenant (ADR-0007, rule 3 + 5).
 *
 * Every tenant-scoped interaction starts with
 *
 *     BEGIN;
 *     SELECT set_config('app.tenant_id', $1, true);   -- true = transaction-local
 *
 * - `set_config(…, true)` is the parameterised form of `SET LOCAL`. `SET` cannot take bind
 *   parameters, so a dynamic `SET` would need string interpolation (an injection risk).
 * - The setting dies with the transaction, so a pooled connection (pg Pool or PgBouncer in
 *   transaction mode) never carries one tenant's id into another request. Session-level `SET`
 *   leaked to a different client on 40/40 queries in spike 03; transaction-local leaked 0/2,400.
 *
 * Works with `pg.Pool` and anything with the same minimal shape (PGlite in tests).
 *
 * @module
 */
import { isUuid } from '../policy/schema.ts'

/** The Postgres setting every RLS policy reads. */
export const TENANT_SETTING = 'app.tenant_id'

/** The minimal client shape `withTenant` needs (satisfied by `pg.PoolClient`). */
export interface TenantClient {
  query(text: string, values?: unknown[]): Promise<unknown>
  /** Return the client to the pool, or DESTROY it when given an error. */
  release(error?: Error | boolean): void
  on(event: 'error', listener: (error: Error) => void): unknown
  off(event: 'error', listener: (error: Error) => void): unknown
}

/** The minimal pool shape `withTenant` needs (satisfied by `pg.Pool`). */
export interface TenantPool<C extends TenantClient = TenantClient> {
  connect(): Promise<C>
}

/**
 * `pg.Pool`'s shape: `connect()` is overloaded with a callback form. Declaring both overloads lets
 * TypeScript infer the client type (`PoolClient`) from a real pool; with a single signature it would
 * match the callback overload and lose the type.
 */
export interface CallbackTenantPool<C extends TenantClient = TenantClient> {
  connect(): Promise<C>
  connect(callback: (...args: never[]) => void): void
}

/** Thrown BEFORE any database work when the tenant id is not a UUID. */
export class InvalidTenantIdError extends Error {
  override readonly name = 'InvalidTenantIdError'
  constructor() {
    // The value is deliberately not echoed: it may be attacker-controlled log-injection input.
    super('Invalid tenant id: expected a UUID')
  }
}

/** `COMMIT` was answered with `ROLLBACK`: nothing `work` wrote was saved. */
export class TransactionAbortedError extends Error {
  override readonly name = 'TransactionAbortedError'
  constructor() {
    super(
      'The tenant transaction was rolled back by Postgres (a statement inside it failed); nothing was committed',
    )
  }
}

/** The command tag of a query result, when the driver reports one (`pg` does; PGlite does not). */
const commandOf = (result: unknown): string | undefined => {
  if (typeof result !== 'object' || result === null) return undefined
  const command = (result as { command?: unknown }).command
  return typeof command === 'string' ? command.toUpperCase() : undefined
}

/** Options for {@link withTenant}. */
export interface WithTenantOptions {
  /** The setting name. Default `app.tenant_id`; must match your RLS policies. */
  readonly setting?: string
}

const SETTING = /^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$/

const toError = (value: unknown): Error =>
  value instanceof Error ? value : new Error(String(value))

/**
 * Run `work` in a transaction scoped to `tenantId`.
 *
 * Guarantees:
 * - The tenant id is validated before a connection is even checked out.
 * - Commit when `work` resolves, roll back when it throws; the original error is re-thrown.
 * - A transaction that Postgres aborted (a statement failed inside `work` and the error was caught
 *   and swallowed) is NOT reported as success: Postgres answers `COMMIT` on an aborted transaction
 *   with a `ROLLBACK` command tag, and `withTenant` then rejects with {@link TransactionAbortedError}.
 *   (This needs a driver that reports the command tag, as `pg` does.)
 * - The client is always released. If the transaction could not be closed cleanly (BEGIN, COMMIT
 *   or ROLLBACK failed, or the backend died), the connection is DESTROYED, never re-pooled, so a
 *   connection possibly still inside a tenant transaction is never reused.
 * - A backend dying mid-transaction surfaces as a rejected promise, never as an uncaught `error`
 *   event that would crash the process (`pg.Pool` only listens on idle clients).
 *
 * Contract for `work`: run statements only through the given client, and never issue COMMIT,
 * ROLLBACK, SET or set_config yourself (`findSessionSet` lints for the latter).
 */
export function withTenant<C extends TenantClient, T>(
  pool: CallbackTenantPool<C>,
  tenantId: string,
  work: (client: C) => Promise<T>,
  options?: WithTenantOptions,
): Promise<T>
export function withTenant<C extends TenantClient, T>(
  pool: TenantPool<C>,
  tenantId: string,
  work: (client: C) => Promise<T>,
  options?: WithTenantOptions,
): Promise<T>
export async function withTenant<C extends TenantClient, T>(
  pool: TenantPool<C>,
  tenantId: string,
  work: (client: C) => Promise<T>,
  options: WithTenantOptions = {},
): Promise<T> {
  if (!isUuid(tenantId)) throw new InvalidTenantIdError()
  const setting = options.setting ?? TENANT_SETTING
  if (!SETTING.test(setting)) throw new TypeError(`Invalid setting name ${JSON.stringify(setting)}`)

  const client = await pool.connect()
  let broken: Error | undefined
  const onError = (error: Error): void => {
    broken = error
  }
  client.on('error', onError)
  try {
    try {
      await client.query('BEGIN')
    } catch (error) {
      broken = toError(error)
      throw error
    }
    try {
      await client.query('SELECT set_config($1, $2, true)', [setting, tenantId.toLowerCase()])
      const result = await work(client)
      const committed = commandOf(await client.query('COMMIT'))
      if (committed !== undefined && committed !== 'COMMIT') throw new TransactionAbortedError()
      return result
    } catch (error) {
      try {
        await client.query('ROLLBACK')
      } catch (rollbackError) {
        broken = toError(rollbackError)
      }
      throw error
    }
  } finally {
    client.off('error', onError)
    client.release(broken)
  }
}
