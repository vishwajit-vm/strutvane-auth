/**
 * The role map: the `roles` block of `config/auth.ts` compiled into allow grants (docs/07 §2.7,
 * §4.4), combined with the policies in `app/policies/*.policy.ts`.
 *
 * ```ts
 * roles: {
 *   admin:  { permissions: ['*', 'user.update'] },                          // platform (global)
 *   member: { scope: 'tenant', permissions: ['*.viewAny', '*.view', { action: '*.update', own: true }] },
 *   viewer: { scope: 'any', permissions: ['*.viewAny', '*.view'] },           // both places
 *   owner:  { permissions: ['*'] },                                          // runs a tenant
 * },
 * wildcardExclude: ['user', 'session', 'role', 'auditEvent'],
 * newModelDefaults: 'inherit-role-patterns',
 * ```
 *
 * ## Semantics (normative)
 * - A permission is `'<resource>.<action>'`, where either part may be `*`; `'*'` alone (or `'*.*'`)
 *   is every action on every resource. It is an **allow** for actors holding the role.
 * - `{ action, own: true }` allows only records whose `ownerId` equals the actor's id. It compiles
 *   to the same filter a policy's `row.ownerId.eq(actor.id)` would, so lists stay filtered in SQL.
 *   It **fails closed**: on a resource whose schema has no text/uuid `ownerId` column (or whose
 *   schema is unknown, i.e. no policy and no `schemas` entry), it never matches. A null actor id
 *   never matches either (fail-closed binding, ADR-0008).
 * - **Platform roles and tenant roles are kept apart.** A role's `scope` says where it lives:
 *   - no scope, or `'global'`: a platform role. Its grants count only outside tenants, and it can
 *     never be given inside a tenant (invitations and memberships refuse it);
 *   - `'tenant'`: a tenant role (members of a tenant hold it there);
 *   - `'any'`: deliberately both. Inside a tenant its grants reach only resources whose schema has
 *     a `tenantId` column (exact grants included), so it never opens platform-wide data there.
 *   `owner` is reserved: the role a tenant's creator holds and the only one that manages members.
 *   Anyone who can sign up can create a tenant and hold it, so it is always tenant-scoped and can
 *   never be a platform role. `admin` is the platform administrator and never a tenant role.
 *   A permission's own `scope` may narrow an `'any'` role's scope; it never widens a role's.
 * - **Resource wildcards are bounded** (`*` and `*.<action>`):
 *   - they never match a resource listed in `wildcardExclude` (identity, authorization, tenancy
 *     and audit records); those are granted by exact `'<resource>.<action>'` only, and naming
 *     one with an action wildcard (`'user.*'`) is a definition error;
 *   - for an actor inside a tenant they only match resources whose schema has a `tenantId`
 *     column. A tenant role (anyone can create a tenant and become its `owner`) must never reach
 *     platform-wide data through a wildcard; exact grants still can.
 * - **Policies keep the last word:** `allowed = (policy allows OR role grants) AND NOT policy
 *   denies`. An explicit `deny` in a policy always wins over the role map.
 * - **No roles configured → no grants:** behaviour is exactly the policies alone (deny by default).
 *
 * ## `newModelDefaults`
 * What a model that no role names explicitly gets:
 * - `'inherit-role-patterns'` (default): resource wildcards (`*.view`, `*`) cover it.
 * - `'admin-only'`: only a full `'*'` grant (by convention the admin role) covers it; every other
 *   role needs an exact grant (`'invoice.view'`, `'invoice.*'`) or a policy rule. Partial resource
 *   wildcards (`'*.view'`) are then rejected at boot, because they could never apply. (Until the
 *   persistent permission catalogue exists, "new" means "not named in the role map".)
 *
 * Definition errors throw {@link PolicyDefinitionError} at boot, never at the first request.
 *
 * @module
 */
import type { Actor, QueryFilter } from '@strutvane/framework/contracts'
import { PolicyDefinitionError } from '../errors.ts'
import { FALSE } from './filter.ts'
import type { ExtraGrant, RoleScope } from './policy.ts'
import type { ModelSchema } from './schema.ts'

/** One entry of a role's permission list: a permission pattern, or an object form. */
export type RolePermission =
  | string
  | {
      /** The permission pattern, e.g. `'*.update'` or `'invoice.approve'`. */
      readonly action: string
      /** Only records whose `ownerId` is the actor's id (fails closed without an `ownerId`). */
      readonly own?: boolean
      /** Overrides the role's scope for this permission. */
      readonly scope?: RoleScope
    }

/** A role and its permissions. */
export interface RoleDefinition {
  readonly permissions: readonly RolePermission[]
  /**
   * Where the role lives and its grants count: `'global'` (the default; a platform role),
   * `'tenant'` (a tenant role) or `'any'` (both, bounded to tenant data inside a tenant). `owner`
   * defaults to, and must be, `'tenant'`.
   */
  readonly scope?: RoleScope
}

/** The reserved role a tenant's creator holds (always tenant-scoped, never a platform role). */
export const TENANT_OWNER_ROLE = 'owner'

/** The platform administrator role (always platform-scoped, never a tenant role). */
export const PLATFORM_ADMIN_ROLE = 'admin'

/**
 * The scope a role has when the role map does not set one.
 *
 * @example
 * defaultRoleScope('owner') // 'tenant'
 */
export function defaultRoleScope(role: string): RoleScope {
  return role === TENANT_OWNER_ROLE ? 'tenant' : 'global'
}

/** The role names of a role map, split by where they may be held. */
export interface RolePartition {
  /** Platform roles (`admin` always; never `owner`): global user roles may only be these. */
  readonly global: readonly string[]
  /** Tenant roles (`owner` always; never `admin`): memberships and invitations may only be these. */
  readonly tenant: readonly string[]
}

/**
 * Split a role map's names into platform and tenant roles by each role's scope (see the module
 * docs). Invalid entries are skipped here; `compileRoleMap` reports them at boot.
 *
 * @example
 * partitionRoles({ member: { scope: 'tenant', permissions: [] } })
 * // { global: ['admin'], tenant: ['owner', 'member'] }
 */
export function partitionRoles(
  roles: Readonly<Record<string, RoleDefinition>> | undefined,
): RolePartition {
  const global = new Set<string>([PLATFORM_ADMIN_ROLE])
  const tenant = new Set<string>([TENANT_OWNER_ROLE])
  for (const [role, definition] of Object.entries(roles ?? {})) {
    if (!ROLE_NAME.test(role) || role === TENANT_OWNER_ROLE || role === PLATFORM_ADMIN_ROLE)
      continue
    const scope: unknown = isRecord(definition) ? definition['scope'] : undefined
    const where =
      typeof scope === 'string' && SCOPES.has(scope) ? (scope as RoleScope) : defaultRoleScope(role)
    if (where !== 'tenant') global.add(role)
    if (where !== 'global') tenant.add(role)
  }
  return Object.freeze({
    global: Object.freeze([...global]),
    tenant: Object.freeze([...tenant]),
  })
}

/** What models not named in the role map get (see the module docs). */
export type NewModelDefaults = 'inherit-role-patterns' | 'admin-only'

/** The role-map part of `config/auth.ts`. */
export interface RoleMapConfig {
  readonly roles?: Readonly<Record<string, RoleDefinition>>
  /** Resources no resource wildcard ever matches (grant them by exact name). */
  readonly wildcardExclude?: readonly string[]
  /** Default `'inherit-role-patterns'`. */
  readonly newModelDefaults?: NewModelDefaults
}

/** One compiled permission, for tooling (`sv auth:matrix`). */
export interface RoleGrantInfo {
  readonly role: string
  /** A resource name, or `'*'`. */
  readonly resource: string
  /** An action name, or `'*'`. */
  readonly action: string
  readonly own: boolean
  readonly scope: RoleScope
  /** The name used in `Decision.reason` (`allow:<name>`). */
  readonly name: string
}

/** A compiled role map. */
export interface RoleLayer {
  /** Every compiled permission, in declaration order. */
  readonly grants: readonly RoleGrantInfo[]
  /** Resources resource wildcards never match. */
  readonly wildcardExclude: readonly string[]
  readonly newModelDefaults: NewModelDefaults
  /** The role names split into platform and tenant roles (see {@link partitionRoles}). */
  readonly partition: RolePartition
  /**
   * The grants that apply to `actor` for `<resource>.<action>`, ready for a policy's
   * `decide`/`filterFor` (see {@link ExtraGrant}). `schema` is the resource's model schema, used
   * for `own` grants and the in-tenant wildcard bound; `undefined` means unknown (both fail closed).
   */
  grantsFor(
    actor: Actor | null,
    resource: string,
    action: string,
    schema: ModelSchema | undefined,
  ): readonly ExtraGrant[]
}

interface Compiled {
  readonly info: RoleGrantInfo
  /** The grant handed out when the permission is unconditional. */
  readonly plain: ExtraGrant
  /** `own` on a resource with an `ownerId`: `ownerId = actor.id`. */
  readonly owned: ExtraGrant
  /** `own` on a resource without a usable `ownerId`: never matches. */
  readonly unownable: ExtraGrant
}

const ROLE_NAME = /^[a-z][a-z0-9_-]{0,63}$/
const RESOURCE = /^[a-z][a-zA-Z0-9_-]{0,63}$/
const ACTION = /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/
const SCOPES: ReadonlySet<string> = new Set(['any', 'global', 'tenant'])
const MODEL_DEFAULTS: ReadonlySet<string> = new Set(['inherit-role-patterns', 'admin-only'])
const PERMISSION_KEYS: ReadonlySet<string> = new Set(['action', 'own', 'scope'])
const ROLE_KEYS: ReadonlySet<string> = new Set(['permissions', 'scope'])
const CONFIG_KEYS: ReadonlySet<string> = new Set(['roles', 'wildcardExclude', 'newModelDefaults'])
const OWNER_CONDITION: QueryFilter = Object.freeze({
  op: 'eq',
  field: 'ownerId',
  value: Object.freeze({ $actor: 'id' }),
}) as QueryFilter

const fail = (message: string): never => {
  throw new PolicyDefinitionError(`config/auth.ts: ${message}`)
}

const isRecord = (v: unknown): v is Readonly<Record<string, unknown>> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

function scopeOf(where: string, value: unknown, fallback: RoleScope): RoleScope {
  if (value === undefined) return fallback
  if (typeof value !== 'string' || !SCOPES.has(value))
    return fail(`${where}: scope must be 'any', 'global' or 'tenant'`)
  return value as RoleScope
}

function unknownKeys(
  where: string,
  value: Readonly<Record<string, unknown>>,
  allowed: ReadonlySet<string>,
): void {
  const extra = Object.keys(value).filter((k) => !allowed.has(k))
  if (extra.length > 0)
    fail(`${where}: unknown option(s) ${extra.map((k) => JSON.stringify(k)).join(', ')}`)
}

/** `'*'` → `['*', '*']`; `'invoice.view'` → `['invoice', 'view']`. */
function parsePattern(where: string, pattern: unknown): readonly [string, string] {
  if (typeof pattern !== 'string') return fail(`${where}: a permission must be a string`)
  if (pattern === '*') return ['*', '*']
  const dot = pattern.indexOf('.')
  const resource = dot < 0 ? '' : pattern.slice(0, dot)
  const action = dot < 0 ? '' : pattern.slice(dot + 1)
  if ((resource === '*' || RESOURCE.test(resource)) && (action === '*' || ACTION.test(action)))
    return [resource, action]
  return fail(
    `${where}: invalid permission ${JSON.stringify(pattern.slice(0, 80))} (use '<resource>.<action>', with * as a wildcard)`,
  )
}

const hasColumn = (schema: ModelSchema | undefined, name: string, types?: ReadonlySet<string>) => {
  if (schema === undefined || !Object.hasOwn(schema.columns, name)) return false
  const column = schema.columns[name]
  return column !== undefined && (types === undefined || types.has(column.type))
}
const ID_TYPES: ReadonlySet<string> = new Set(['text', 'uuid'])

const inScope = (actor: Actor, scope: RoleScope): boolean =>
  scope === 'any' || (scope === 'global') === (actor.tenantId === undefined)

/**
 * Compile and validate a role map. Throws {@link PolicyDefinitionError} on any mistake (unknown
 * option, malformed pattern, invalid role name, an action wildcard on an excluded resource, a
 * partial wildcard under `'admin-only'`), so a typo can never silently grant or drop access.
 */
export function compileRoleMap(config: RoleMapConfig = {}): RoleLayer {
  if (!isRecord(config as unknown)) return fail('the role map must be an object')
  unknownKeys('role map', config as Readonly<Record<string, unknown>>, CONFIG_KEYS)
  const newModelDefaults = config.newModelDefaults ?? 'inherit-role-patterns'
  if (typeof newModelDefaults !== 'string' || !MODEL_DEFAULTS.has(newModelDefaults))
    fail(`newModelDefaults must be 'inherit-role-patterns' or 'admin-only'`)

  const excludeList: unknown = config.wildcardExclude ?? []
  if (!Array.isArray(excludeList)) fail('wildcardExclude must be a list of resource names')
  for (const name of excludeList as unknown[]) {
    if (typeof name !== 'string' || !RESOURCE.test(name))
      fail(`wildcardExclude: invalid resource name ${JSON.stringify(name)}`)
  }
  const excluded: ReadonlySet<string> = new Set(excludeList as string[])

  const roles: unknown = config.roles ?? {}
  if (!isRecord(roles)) fail('roles must be an object of role definitions')
  const compiled: Compiled[] = []
  for (const [role, definition] of Object.entries(roles as Record<string, unknown>)) {
    const where = `roles.${role}`
    if (!ROLE_NAME.test(role))
      fail(`invalid role name ${JSON.stringify(role)} (lower-case letters, digits, - and _)`)
    if (!isRecord(definition)) {
      fail(`${where} must be { permissions: [...] }`)
      continue
    }
    unknownKeys(where, definition, ROLE_KEYS)
    const roleScope = scopeOf(where, definition['scope'], defaultRoleScope(role))
    if (role === TENANT_OWNER_ROLE && roleScope !== 'tenant')
      fail(
        `${where}: owner is the reserved tenant role (anyone who creates a tenant holds it); its scope can only be 'tenant'`,
      )
    if (role === PLATFORM_ADMIN_ROLE && roleScope !== 'global')
      fail(
        `${where}: admin is the platform role and is never held inside a tenant; give tenant permissions to owner or a tenant role`,
      )
    const permissions = definition['permissions']
    if (!Array.isArray(permissions)) fail(`${where}.permissions must be a list`)
    for (const [i, entry] of (permissions as unknown[]).entries()) {
      const at = `${where}.permissions[${i}]`
      let pattern: unknown = entry
      let own = false
      let scope = roleScope
      if (isRecord(entry)) {
        unknownKeys(at, entry, PERMISSION_KEYS)
        pattern = entry['action']
        if (entry['own'] !== undefined && typeof entry['own'] !== 'boolean')
          fail(`${at}: own must be true or false`)
        own = entry['own'] === true
        scope = scopeOf(at, entry['scope'], roleScope)
        // A permission may narrow an `any` role, never widen a role: a platform role is never held
        // inside a tenant, and a tenant role never outside one.
        if (roleScope !== 'any' && scope !== roleScope)
          fail(
            `${at}: scope '${scope}' never applies to ${role}, a ${roleScope === 'global' ? 'platform' : 'tenant'} role (set the role's scope to 'any' to use it in both places)`,
          )
      } else if (typeof entry !== 'string') {
        fail(`${at}: expected a permission string or { action, own?, scope? }`)
      }
      const [resource, action] = parsePattern(at, pattern)
      if (resource !== '*' && action === '*' && excluded.has(resource))
        fail(
          `${at}: '${resource}.*' would grant every action on "${resource}", which is in wildcardExclude; list its actions by name`,
        )
      if (newModelDefaults === 'admin-only' && resource === '*' && action !== '*')
        fail(
          `${at}: '*.${action}' never applies under newModelDefaults 'admin-only'; name the resources (e.g. 'invoice.${action}') or use 'inherit-role-patterns'`,
        )
      const label = `${resource === '*' && action === '*' ? '*' : `${resource}.${action}`}${own ? '(own)' : ''}${scope === 'any' ? '' : `@${scope}`}`
      const name = `role:${role}:${label}`
      const info: RoleGrantInfo = Object.freeze({ role, resource, action, own, scope, name })
      compiled.push({
        info,
        plain: Object.freeze({ name, role, scope }),
        owned: Object.freeze({ name, role, scope, when: OWNER_CONDITION }),
        unownable: Object.freeze({
          name: `${name}:no-ownerId`,
          role,
          scope,
          when: FALSE,
        }),
      })
    }
  }

  const byRole = new Map<string, Compiled[]>()
  for (const c of compiled) {
    const list = byRole.get(c.info.role) ?? []
    list.push(c)
    byRole.set(c.info.role, list)
  }

  const grantsFor = (
    actor: Actor | null,
    resource: string,
    action: string,
    schema: ModelSchema | undefined,
  ): readonly ExtraGrant[] => {
    if (actor === null || byRole.size === 0) return []
    const out: ExtraGrant[] = []
    const inTenant = actor.tenantId !== undefined
    // Evaluated lazily: most calls never reach a resource wildcard.
    let wildcardOk: boolean | undefined
    const wildcardReaches = (): boolean => {
      wildcardOk ??= !excluded.has(resource) && (!inTenant || hasColumn(schema, 'tenantId'))
      return wildcardOk
    }
    // Inside a tenant, an `any` grant (a role deliberately held in both places) reaches only
    // tenant data: never a platform-wide resource, not even by exact name.
    let tenantData: boolean | undefined
    const reachesTenantData = (): boolean => {
      tenantData ??= hasColumn(schema, 'tenantId')
      return tenantData
    }
    for (const role of new Set(actor.roles)) {
      for (const c of byRole.get(role) ?? []) {
        const g = c.info
        if (!inScope(actor, g.scope)) continue
        if (inTenant && g.scope === 'any' && !reachesTenantData()) continue
        if (g.action !== '*' && g.action !== action) continue
        if (g.resource === '*' ? !wildcardReaches() : g.resource !== resource) continue
        out.push(!g.own ? c.plain : hasColumn(schema, 'ownerId', ID_TYPES) ? c.owned : c.unownable)
      }
    }
    return out
  }

  return Object.freeze({
    grants: Object.freeze(compiled.map((c) => c.info)),
    wildcardExclude: Object.freeze([...excluded]),
    newModelDefaults: newModelDefaults as NewModelDefaults,
    partition: partitionRoles(roles as Readonly<Record<string, RoleDefinition>>),
    grantsFor,
  })
}
