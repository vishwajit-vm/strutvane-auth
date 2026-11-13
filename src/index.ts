/**
 * `@strutvane/auth`: authorization (policies compiled to SQL), tenancy, identity and audit for
 * TypeScript apps. Works standalone or inside a Strutvane app (register the permission provider
 * under core's `PermissionProviderToken`).
 *
 * Subpath entry points keep optional dependencies optional:
 * - `@strutvane/auth/sql`: compile filters to Postgres `WHERE` fragments.
 * - `@strutvane/auth/postgres`: `withTenant`, RLS migration SQL, tenancy audit, lint, rate-limit store (needs `pg` at runtime only if you pass a pg pool).
 * - `@strutvane/auth/better-auth`: the hardened Better Auth adapter (needs `better-auth`, `pg`).
 * - `@strutvane/auth/hono`, `@strutvane/auth/node`: HTTP middleware.
 * - `@strutvane/auth/testing`: the identity contract suite and test helpers (needs `vitest`).
 *
 * @module
 */
export {
  type AuditInput,
  type AuditSink,
  type DiffOptions,
  diffChanges,
  type MemoryAuditSink,
  memoryAuditSink,
  type RecordAuditOptions,
  recordAudit,
} from './audit/audit.ts'
export {
  AUTH_ERRORS,
  FieldNotLoadedError,
  InvalidFilterError,
  NotListFilterableError,
  PolicyDefinitionError,
} from './errors.ts'
export {
  normalizeIp,
  resolveClientIp,
  type TrustedProxies,
  trustedProxies,
} from './http/client-ip.ts'
export { attachRequestMeta, type RequestMeta, requestMeta } from './http/request-meta.ts'
export {
  type Authentication,
  type CreateTenantInput,
  type ErrorReporter,
  fail,
  IDENTITY_STATUS,
  type IdentityEngine,
  type IdentityError,
  type IdentityErrorCode,
  type IdentityResult,
  ok,
  type PasswordResetDelivery,
  type SignInInput,
  type SignUpInput,
  type TenantMembership,
} from './identity/engine.ts'
export {
  type ActorAttributes,
  createNativeEngine,
  DEFAULT_RATE_LIMITS,
  type GlobalRoles,
  type IdentityRateLimits,
  type NativeEngineOptions,
} from './identity/native.ts'
export {
  accountKey,
  checkRateLimits,
  type MemoryRateLimitOptions,
  memoryRateLimitStore,
  normalizeEmail,
  type RateLimitHit,
  type RateLimitResult,
  type RateLimitRule,
  type RateLimitStore,
} from './identity/rate-limit.ts'
export {
  type AuthMiddlewareOptions,
  type AuthOutcome,
  type AuthState,
  authenticateRequest,
  problemResponse,
  runWithAuth,
} from './middleware/core.ts'
export { ActorAttributeError, bindActor, isActorRef, resolveActorRef } from './policy/bind.ts'
export type {
  ActorProxy,
  Arg,
  AttrDecl,
  ExprFor,
  FieldExpr,
  NumberExpr,
  RowProxy,
  TextExpr,
  TextOptions,
  TypedActorRef,
  ValueOf,
} from './policy/builder.ts'
export { evaluateFilter, type RecordValue } from './policy/evaluate.ts'
export { and, FALSE, fold, not, or, TRUE } from './policy/filter.ts'
export {
  type CheckContext,
  definePolicy,
  type Explanation,
  type FieldAccessOptions,
  type FieldRuleBuilder,
  type Policy,
  type PolicyApi,
  type PolicyOptions,
  type RuleContext,
  type RuleInfo,
  type RuleOptions,
  type RuleTrace,
} from './policy/policy.ts'
export { createPermissionProvider, type StrutvanePermissionProvider } from './policy/provider.ts'
export {
  type ColumnDef,
  type ColumnType,
  defineSchema,
  type ModelSchema,
  type RelationDef,
} from './policy/schema.ts'
export {
  type FilterLimits,
  foldAscii,
  type ValidateOptions,
  validateFilter,
} from './policy/validate.ts'
export {
  headerResolver,
  pathResolver,
  type ResolveTenantOptions,
  resolveTenant,
  sessionResolver,
  subdomainResolver,
  type TenantLookup,
  type TenantResolution,
  type TenantResolveInput,
  type TenantResolver,
} from './tenancy/resolver.ts'
