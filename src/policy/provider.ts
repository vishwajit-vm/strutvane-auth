/**
 * `createPermissionProvider`: turns a set of policies into the contracts `PermissionProvider`.
 *
 * Register the result under core's `PermissionProviderToken`; the framework only ever talks to
 * that interface, which is why `framework` and `auth` never import each other.
 *
 * Permissions are `"<resource>.<action>"` strings (`"invoice.approve"`). Anything that does not
 * resolve to a known policy and action is denied (deny by default): unknown resources, malformed
 * permission strings, and a resource type that does not match the permission's prefix.
 *
 * With a role map (`options.roles`, the `roles` block of `config/auth.ts`), the grants of the
 * actor's roles join each policy as extra allow rules: `(policy allows OR role grants) AND NOT
 * policy denies` (see `compileRoleMap` for the full semantics). A resource WITHOUT a policy is then
 * decided by the role map alone; its schema (needed for `own` grants and the in-tenant wildcard
 * bound) comes from `options.schemas`, and is otherwise unknown, so those fail closed.
 *
 * @module
 */
import type {
  Actor,
  Decision,
  Permission,
  PermissionProvider,
  QueryFilter,
  ResourceRef,
} from '@strutvane/contracts'
import { PolicyDefinitionError } from '../errors.ts'
import { FALSE } from './filter.ts'
import { definePolicy, type Explanation, type ExtraGrant, type Policy } from './policy.ts'
import { compileRoleMap, type RoleLayer, type RoleMapConfig } from './roles.ts'
import { defineSchema, type ModelSchema } from './schema.ts'

/** The provider, plus helpers for tooling (`sv auth:explain`, `sv auth:matrix`). */
export interface StrutvanePermissionProvider extends PermissionProvider {
  /** The policy for a resource type, if any. */
  policy(resourceType: string): Policy | undefined
  /** Every registered policy. */
  readonly policies: readonly Policy[]
  /** The decision plus a per-rule trace. Unknown resources explain as `default-deny:no-policy`. */
  explain(actor: Actor | null, action: Permission, resource?: ResourceRef): Explanation
  /** The compiled role map (empty when none was configured). */
  readonly roles: RoleLayer
  /**
   * The fields `actor` may filter, sort and search `resourceType` on: exactly the fields the
   * policy lets them read (`Policy.filterableFields`), so a hidden field cannot be inferred one
   * comparison at a time. A resource without a policy uses its `options.schemas` entry (no field
   * rules: every column); an unknown resource returns an empty set (fail closed).
   */
  filterableFields(actor: Actor | null, resourceType: string): Promise<ReadonlySet<string>>
}

/** Options for {@link createPermissionProvider}. */
export interface PermissionProviderOptions {
  /** The role map from `config/auth.ts` (or an already compiled one). Default: no roles. */
  readonly roles?: RoleMapConfig | RoleLayer
  /**
   * Model schemas for resources that have no policy, so the role map can apply `own` grants and
   * the in-tenant wildcard bound to them. Resources with a policy use the policy's schema.
   */
  readonly schemas?: Readonly<Record<string, ModelSchema>>
}

const isLayer = (v: RoleMapConfig | RoleLayer): v is RoleLayer =>
  typeof (v as Partial<RoleLayer>).grantsFor === 'function'

/** A schema that compiles nothing: role-only resources without a known schema. */
const UNKNOWN_SCHEMA: ModelSchema = Object.freeze({
  table: 'strutvane_unknown',
  columns: Object.freeze({}),
})

const PERMISSION = /^([a-z][a-zA-Z0-9_-]{0,63})\.([a-zA-Z][a-zA-Z0-9_-]{0,63})$/

const deny = (reason: string): Decision => Object.freeze({ allowed: false, reason })

/** Build a deny-by-default `PermissionProvider` from policies (one per resource type). */
export function createPermissionProvider(
  policies: readonly Policy[],
  options: PermissionProviderOptions = {},
): StrutvanePermissionProvider {
  const byResource = new Map<string, Policy>()
  for (const p of policies) {
    if (byResource.has(p.resource))
      throw new PolicyDefinitionError(`Two policies for resource "${p.resource}"`)
    byResource.set(p.resource, p)
  }
  const layer =
    options.roles && isLayer(options.roles) ? options.roles : compileRoleMap(options.roles)
  const schemas = new Map<string, ModelSchema>()
  for (const [resource, schema] of Object.entries(options.schemas ?? {}))
    schemas.set(resource, defineSchema(schema))

  /**
   * An empty policy for a resource that only the role map grants: the same combination engine
   * (bound, validated, explainable), with no rules of its own. Built once per resource type;
   * resource types come from app code (model names), never from clients.
   */
  const roleOnly = new Map<string, Policy>()
  const roleOnlyPolicy = (type: string): Policy => {
    let policy = roleOnly.get(type)
    if (!policy) {
      policy = definePolicy(type, { schema: schemas.get(type) ?? UNKNOWN_SCHEMA }, () => undefined)
      roleOnly.set(type, policy)
    }
    return policy
  }

  /**
   * Split and check a permission string, and collect the actor's role grants for it. A reason
   * means "deny"; a resource without a policy and without grants keeps `default-deny:no-policy`.
   */
  const resolve = (
    actor: Actor | null,
    action: Permission,
    resourceType: string | undefined,
  ): { policy: Policy; name: string; grants: readonly ExtraGrant[] } | { reason: string } => {
    const match = typeof action === 'string' ? PERMISSION.exec(action) : null
    if (!match) return { reason: 'default-deny:invalid-permission' }
    const [, type = '', name = ''] = match
    if (resourceType !== undefined && resourceType !== type)
      return { reason: 'default-deny:resource-mismatch' }
    const policy = byResource.get(type)
    const grants = layer.grantsFor(actor, type, name, policy?.schema ?? schemas.get(type))
    if (policy) return { policy, name, grants }
    if (grants.length === 0) return { reason: 'default-deny:no-policy' }
    return { policy: roleOnlyPolicy(type), name, grants }
  }

  const explain = (
    actor: Actor | null,
    action: Permission,
    resource?: ResourceRef,
  ): Explanation => {
    const r = resolve(actor, action, resource?.type)
    if ('reason' in r) {
      return {
        resource: resource?.type ?? '',
        action: String(action),
        decision: deny(r.reason),
        rules: [],
      }
    }
    return r.policy.explain(actor, r.name, resource?.record, r.grants)
  }

  return Object.freeze({
    policies: Object.freeze([...byResource.values()]),
    policy: (type: string) => byResource.get(type),
    roles: layer,
    explain,
    async can(actor: Actor | null, action: Permission, resource?: ResourceRef): Promise<Decision> {
      return explain(actor, action, resource).decision
    },
    async filterableFields(
      actor: Actor | null,
      resourceType: string,
    ): Promise<ReadonlySet<string>> {
      const policy =
        typeof resourceType !== 'string'
          ? undefined
          : (byResource.get(resourceType) ??
            (schemas.has(resourceType) ? roleOnlyPolicy(resourceType) : undefined))
      return Object.freeze(new Set(policy ? policy.filterableFields(actor) : []))
    },
    async filterFor(
      actor: Actor | null,
      action: Permission,
      resourceType: string,
    ): Promise<QueryFilter> {
      const r = resolve(actor, action, resourceType)
      if ('reason' in r) return FALSE
      return r.policy.filterFor(actor, r.name, r.grants)
    },
  })
}
