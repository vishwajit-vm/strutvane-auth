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
import type { Explanation, Policy } from './policy.ts'

/** The provider, plus helpers for tooling (`sv auth:explain`, `sv auth:matrix`). */
export interface StrutvanePermissionProvider extends PermissionProvider {
  /** The policy for a resource type, if any. */
  policy(resourceType: string): Policy | undefined
  /** Every registered policy. */
  readonly policies: readonly Policy[]
  /** The decision plus a per-rule trace. Unknown resources explain as `default-deny:no-policy`. */
  explain(actor: Actor | null, action: Permission, resource?: ResourceRef): Explanation
}

const PERMISSION = /^([a-z][a-zA-Z0-9_-]{0,63})\.([a-zA-Z][a-zA-Z0-9_-]{0,63})$/

const deny = (reason: string): Decision => Object.freeze({ allowed: false, reason })

/** Build a deny-by-default `PermissionProvider` from policies (one per resource type). */
export function createPermissionProvider(policies: readonly Policy[]): StrutvanePermissionProvider {
  const byResource = new Map<string, Policy>()
  for (const p of policies) {
    if (byResource.has(p.resource))
      throw new PolicyDefinitionError(`Two policies for resource "${p.resource}"`)
    byResource.set(p.resource, p)
  }

  /** Split and check a permission string. `undefined` means "deny". */
  const resolve = (
    action: Permission,
    resourceType: string | undefined,
  ): { policy: Policy; name: string } | { reason: string } => {
    const match = typeof action === 'string' ? PERMISSION.exec(action) : null
    if (!match) return { reason: 'default-deny:invalid-permission' }
    const [, type = '', name = ''] = match
    if (resourceType !== undefined && resourceType !== type)
      return { reason: 'default-deny:resource-mismatch' }
    const policy = byResource.get(type)
    if (!policy) return { reason: 'default-deny:no-policy' }
    return { policy, name }
  }

  const explain = (
    actor: Actor | null,
    action: Permission,
    resource?: ResourceRef,
  ): Explanation => {
    const r = resolve(action, resource?.type)
    if ('reason' in r) {
      return {
        resource: resource?.type ?? '',
        action: String(action),
        decision: deny(r.reason),
        rules: [],
      }
    }
    return r.policy.explain(actor, r.name, resource?.record)
  }

  return Object.freeze({
    policies: Object.freeze([...byResource.values()]),
    policy: (type: string) => byResource.get(type),
    explain,
    async can(actor: Actor | null, action: Permission, resource?: ResourceRef): Promise<Decision> {
      return explain(actor, action, resource).decision
    },
    async filterFor(
      actor: Actor | null,
      action: Permission,
      resourceType: string,
    ): Promise<QueryFilter> {
      const r = resolve(action, resourceType)
      if ('reason' in r) return FALSE
      return r.policy.filterFor(actor, r.name)
    },
  })
}
