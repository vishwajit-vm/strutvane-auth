/**
 * Migration SQL for tenant isolation with Postgres row-level security, following the five rules of
 * ADR-0007. The output is plain SQL text for your migration files: review it, commit it, own it.
 *
 * @module
 */
import { quoteIdent, quoteTable } from '../policy/schema.ts'
import { TENANT_SETTING } from './with-tenant.ts'

/** Options for {@link tenantRlsSql}. */
export interface TenantRlsOptions {
  /** The table, optionally schema-qualified (`app.invoices`). */
  readonly table: string
  /** The tenant column. Default `tenant_id` (type `uuid`). */
  readonly column?: string
  /** The setting the policy reads. Default `app.tenant_id`. */
  readonly setting?: string
  /**
   * The runtime role (never the owner, a superuser or BYPASSRLS). When given, a PERMISSIVE
   * `USING (true)` policy is added for it, because a RESTRICTIVE policy alone grants nothing. Leave
   * it out if you generate your own permissive (RBAC) policies.
   */
  readonly runtimeRole?: string
}

/** Forward and rollback SQL statements. */
export interface MigrationSql {
  readonly up: readonly string[]
  readonly down: readonly string[]
}

const SETTING = /^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$/

/** `NULLIF(current_setting('app.tenant_id', true), '')::uuid` (ADR-0007 rule 2). */
export function tenantExpression(setting: string = TENANT_SETTING): string {
  if (!SETTING.test(setting)) throw new TypeError(`Invalid setting name ${JSON.stringify(setting)}`)
  // Safe to inline: the pattern admits only [a-z0-9_.].
  return `NULLIF(current_setting('${setting}', true), '')::uuid`
}

/**
 * RLS for one tenant-scoped table:
 * - `ENABLE` and `FORCE ROW LEVEL SECURITY` (FORCE makes it apply to the table owner too);
 * - a RESTRICTIVE `FOR ALL` policy with both `USING` and `WITH CHECK`, so no permissive policy
 *   added later can widen access across tenants, and rows can neither be inserted for nor moved to
 *   another tenant;
 * - the tenant read with `NULLIF(current_setting(…, true), '')::uuid`, so an unscoped connection
 *   sees zero rows instead of erroring (fail closed).
 */
export function tenantRlsSql(options: TenantRlsOptions): MigrationSql {
  const table = quoteTable(options.table)
  const column = quoteIdent(options.column ?? 'tenant_id')
  const base = options.table.split('.').pop() ?? options.table
  const isolation = quoteIdent(`${base}_tenant_isolation`.slice(0, 63))
  const access = quoteIdent(`${base}_runtime_access`.slice(0, 63))
  const tenant = tenantExpression(options.setting)
  const up = [
    `ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`,
    `ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`,
    `CREATE POLICY ${isolation} ON ${table} AS RESTRICTIVE FOR ALL USING (${column} = ${tenant}) WITH CHECK (${column} = ${tenant})`,
  ]
  const down = [`DROP POLICY IF EXISTS ${isolation} ON ${table}`]
  if (options.runtimeRole !== undefined) {
    const role = quoteIdent(options.runtimeRole)
    up.push(
      `CREATE POLICY ${access} ON ${table} AS PERMISSIVE FOR ALL TO ${role} USING (true) WITH CHECK (true)`,
    )
    down.unshift(`DROP POLICY IF EXISTS ${access} ON ${table}`)
  }
  down.push(
    `ALTER TABLE ${table} NO FORCE ROW LEVEL SECURITY`,
    `ALTER TABLE ${table} DISABLE ROW LEVEL SECURITY`,
  )
  return { up, down }
}

/** Options for {@link tenancyRolesSql}. */
export interface TenancyRolesOptions {
  /** Owns the schema and tables; runs migrations. Default `app_owner`. */
  readonly owner?: string
  /** The role the application connects as. Default `app_user`. */
  readonly runtime?: string
}

/**
 * The role split of ADR-0007 rule 4: an owner role for migrations and a runtime role that is never
 * the owner, a superuser or BYPASSRLS. Passwords are deliberately NOT part of the output: set them
 * outside migrations (`ALTER ROLE … PASSWORD` from a secret store), so they never land in git.
 */
export function tenancyRolesSql(options: TenancyRolesOptions = {}): MigrationSql {
  const owner = quoteIdent(options.owner ?? 'app_owner')
  const runtime = quoteIdent(options.runtime ?? 'app_user')
  const flags = 'NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION'
  return {
    up: [`CREATE ROLE ${owner} LOGIN ${flags}`, `CREATE ROLE ${runtime} LOGIN ${flags} NOINHERIT`],
    down: [`DROP ROLE IF EXISTS ${runtime}`, `DROP ROLE IF EXISTS ${owner}`],
  }
}
