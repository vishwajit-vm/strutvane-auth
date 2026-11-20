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
export { type AuthConfig, defineAuthConfig, type SocialProviderConfig } from './config.ts'
// The native identity engine (ADR-0023): the auth core and its ports. Stores: memory here,
// PostgreSQL in `@strutvane/auth/postgres`, SQLite in `@strutvane/auth/sqlite`.
export {
  type Auth,
  type AuthPorts,
  type AuthState as AuthSessionState,
  createAuth,
} from './engine/auth.ts'
export {
  type AuthConfig as AuthEngineConfig,
  type AuthConfigInput as AuthEngineConfigInput,
  type AuthFeatures,
  type AuthFeaturesInput,
  DEFAULT_FEATURES,
  DEFAULT_LIMITS,
  defineAuthConfig as defineAuthEngineConfig,
  type PasskeyConfig,
  type RateLimits,
  type RateRule,
  ROLE_PRESETS,
  type RolePreset,
} from './engine/config.ts'
export { COOKIE_NAMES, type CookieKind } from './engine/core/deps.ts'
export type { ChallengeMethod, SignInResult } from './engine/core/sign-in.ts'
export {
  AUTH_ERROR_STATUS,
  AUTH_ISSUE_MESSAGES,
  AUTH_MESSAGES,
  AuthError,
  type AuthErrorCode,
  type AuthErrorOptions,
  type AuthIssue,
  type AuthIssueInput,
  toIssue,
} from './engine/errors.ts'
export { type AuthHandlerOptions, createAuthHandler } from './engine/http/routes.ts'
export {
  createScryptHasher,
  DEFAULT_SCRYPT,
  type LegacyVerifier,
  type PasswordHasher,
  type ScryptParams,
} from './engine/password/hasher.ts'
export {
  commonPasswordCheck,
  type PasswordCheck,
  type PasswordVerdict,
  rangeBreachCheck,
} from './engine/password/rules.ts'
export { type Clock, type ManualClock, manualClock, systemClock } from './engine/ports/clock.ts'
export type { AuthRequest, CookieJar, CookieOptions } from './engine/ports/cookies.ts'
export type { CounterStore } from './engine/ports/counter-store.ts'
export type {
  AuthEvent,
  AuthEventSink,
  AuthEventType,
  AuthLogger,
  LoginMethod,
  SecondFactor,
} from './engine/ports/events.ts'
export type { AuthMail, AuthMailer } from './engine/ports/mailer.ts'
export type * from './engine/ports/store.ts'
export type { PasskeyMode, PasskeyView } from './engine/services/passkeys.ts'
export type { SessionView } from './engine/services/sessions.ts'
export type {
  MembershipOutcome,
  SystemService,
  TeamMemberView,
} from './engine/services/system.ts'
export type { CurrentTeam, InvitationView } from './engine/services/teams.ts'
export {
  abilityGranted,
  type TokenAuthentication,
  type TokenView,
} from './engine/services/tokens.ts'
export { memoryAuthStore, memoryCounterStore } from './engine/store/memory.ts'
export {
  AUTH_ERRORS,
  FieldNotLoadedError,
  InvalidFilterError,
  NotListFilterableError,
  PolicyDefinitionError,
} from './errors.ts'
export { AUTH_DOMAIN_EVENTS, type AuthDomainPayload, domainEventSink } from './events.ts'
export {
  createFirstAdmin,
  type FirstAdminConnection,
  FirstAdminError,
  type FirstAdminErrorCode,
  type FirstAdminInput,
  type FirstAdminOptions,
  type FirstAdminResult,
} from './first-admin.ts'
export {
  normalizeIp,
  rateLimitSubject,
  resolveClientIp,
  type TrustedProxies,
  trustedProxies,
} from './http/client-ip.ts'
export { attachRequestMeta, type RequestMeta, requestMeta } from './http/request-meta.ts'
export {
  type ActorAttributes,
  type Authentication,
  type CreateTenantInput,
  DEFAULT_RATE_LIMITS,
  type ErrorReporter,
  fail,
  type GlobalRoles,
  IDENTITY_STATUS,
  type IdentityEngine,
  type IdentityError,
  type IdentityErrorCode,
  type IdentityRateLimits,
  type IdentityResult,
  type IdentityUser,
  ok,
  type PasswordResetDelivery,
  type SignInInput,
  type SignUpInput,
  type TenantInfo,
  type TenantMember,
  type TenantMembership,
} from './identity/engine.ts'
export { engineConfigFrom } from './identity/engine-config.ts'
export {
  createNativeEngine,
  type NativeEngineOptions,
  type NativeIdentityEngine,
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
export {
  AUTH_MIGRATIONS,
  authMigrationsDirectory,
  type CopiedMigrations,
  copyAuthMigrations,
} from './migrations.ts'
export {
  ACTOR_ID_TYPES,
  ActorAttributeError,
  actorIdFor,
  type BindOptions,
  bindActor,
  isActorRef,
  resolveActorRef,
} from './policy/bind.ts'
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
  type ExtraGrant,
  type FieldAccessOptions,
  type FieldRuleBuilder,
  type Policy,
  type PolicyApi,
  type PolicyOptions,
  type RoleScope,
  type RuleContext,
  type RuleInfo,
  type RuleOptions,
  type RuleTrace,
} from './policy/policy.ts'
export {
  createPermissionProvider,
  type PermissionProviderOptions,
  type StrutvanePermissionProvider,
} from './policy/provider.ts'
export {
  compileRoleMap,
  type NewModelDefaults,
  type RoleDefinition,
  type RoleGrantInfo,
  type RoleLayer,
  type RoleMapConfig,
  type RolePermission,
} from './policy/roles.ts'
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
  safeLabel,
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
export { AuthMailerToken } from './tokens.ts'
