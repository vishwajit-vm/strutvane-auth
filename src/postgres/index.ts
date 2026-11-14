/**
 * `@strutvane/auth/postgres`: tenant isolation on PostgreSQL (ADR-0007).
 *
 * - {@link withTenant}: run work in a transaction scoped to one tenant (`set_config(…, true)`).
 * - {@link tenantRlsSql} / {@link tenancyRolesSql}: migration SQL for RESTRICTIVE RLS and roles.
 * - {@link tenancyAudit}: find unprotected tables, bypassing roles and definer views at runtime.
 * - {@link findSessionSet}: lint SQL for session-level tenant settings.
 * - {@link relationKeyAudit}: check that policy relations point at unique keys.
 * - {@link postgresRateLimitStore}: a shared rate-limit store for identity engines.
 *
 * @module
 */
export {
  type Queryable,
  type TenancyAuditOptions,
  type TenancyFinding,
  tenancyAudit,
} from './audit-query.ts'
export { findSessionSet, type SessionSetFinding } from './lint.ts'
export {
  type PostgresRateLimitOptions,
  postgresRateLimitStore,
  rateLimitTableSql,
} from './rate-limit-store.ts'
export { type RelationKeyFinding, relationKeyAudit } from './relation-keys.ts'
export {
  type MigrationSql,
  type TenancyRolesOptions,
  type TenantRlsOptions,
  tenancyRolesSql,
  tenantExpression,
  tenantRlsSql,
} from './rls.ts'
export {
  type CallbackTenantPool,
  InvalidTenantIdError,
  TENANT_SETTING,
  type TenantClient,
  type TenantPool,
  TransactionAbortedError,
  type WithTenantOptions,
  withTenant,
} from './with-tenant.ts'
