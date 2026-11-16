/**
 * Field-level read and write rules (`field('amount').readable({ role: … })` / `.writable(…)` in a
 * policy), enforced on the framework's resource pipeline through two hooks (integration map §4):
 *
 * - `resource.serialize`: every record on its way out (lists, show, create/update responses and
 *   included relations) loses the restricted fields the actor may not read;
 * - `resource.beforeWrite`: a create or update that sends a restricted field the actor may not
 *   write is refused with 403 before it reaches the database.
 *
 * Only fields that carry a rule are touched: system columns, relations and fields without rules
 * pass through unchanged. Filters, sorts and search on unreadable fields are refused separately by
 * the framework through `PermissionProvider.filterableFields`.
 *
 * Failure scenarios:
 * - a payload without a usable resource type (a framework without `type`): the type is derived
 *   from the model name (`InvoiceLine` → `invoiceLine`), the framework's own naming rule;
 * - a resource without a policy file (role-map only): it has no field rules, nothing to do;
 * - a malformed actor: the policy throws, the hook fails and the request is a 500 (fail closed,
 *   never a leaked field).
 *
 * @module
 */
import type {
  Actor,
  FieldDescriptor,
  ResourceDescriptor,
  ResourceManifest,
} from '@strutvane/framework/contracts'
import { ForbiddenError, type HookRegistry } from '@strutvane/framework/core'
import type { Policy } from './policy/policy.ts'

/** The part of the permission provider these rules need. */
export interface PolicyLookup {
  policy(type: string): Policy | undefined
}

interface ResourcePayload {
  readonly resource?: unknown
  readonly type?: unknown
  readonly actor?: Actor | null
}

/** `InvoiceLine` → `invoiceLine` (the framework's permission prefix rule). */
const lowerFirst = (name: string): string => name.charAt(0).toLowerCase() + name.slice(1)

/** The policy for a hook payload's resource, or `undefined`. */
function policyOf(payload: ResourcePayload, policies: PolicyLookup): Policy | undefined {
  const type =
    typeof payload.type === 'string'
      ? payload.type
      : typeof payload.resource === 'string'
        ? lowerFirst(payload.resource)
        : undefined
  return type === undefined ? undefined : policies.policy(type)
}

/** Restricted fields the actor may not read. Empty when the policy has no read rules. */
export function unreadableFields(policy: Policy, actor: Actor | null): string[] {
  if (policy.restrictedFields.length === 0) return []
  const readable = new Set(policy.readableFields(actor))
  return policy.restrictedFields.filter((f) => !readable.has(f))
}

/** Keys of `input` that are schema fields the actor may not write. */
export function forbiddenWrites(
  policy: Policy,
  actor: Actor | null,
  input: Readonly<Record<string, unknown>>,
): string[] {
  const writable = new Set(policy.writableFields(actor))
  return Object.keys(input).filter(
    (k) => Object.hasOwn(policy.schema.columns, k) && !writable.has(k),
  )
}

/** Register the two hooks. Returns a function that removes them (tests). */
export function registerFieldRules(
  hooks: HookRegistry<Record<string, unknown>>,
  policies: PolicyLookup,
): () => void {
  const offRead = hooks.on(
    'resource.serialize',
    (raw) => {
      const payload = raw as ResourcePayload & { record?: unknown }
      const policy = policyOf(payload, policies)
      if (!policy || typeof payload.record !== 'object' || payload.record === null) return undefined
      const hide = unreadableFields(policy, payload.actor ?? null)
      if (hide.length === 0) return undefined
      const record: Record<string, unknown> = { ...(payload.record as Record<string, unknown>) }
      for (const f of hide) delete record[f]
      return { ...payload, record }
    },
    { name: 'auth.fieldRead' },
  )
  const offWrite = hooks.on(
    'resource.beforeWrite',
    (raw) => {
      const payload = raw as ResourcePayload & { input?: unknown }
      const policy = policyOf(payload, policies)
      if (!policy || typeof payload.input !== 'object' || payload.input === null) return undefined
      const refused = forbiddenWrites(
        policy,
        payload.actor ?? null,
        payload.input as Record<string, unknown>,
      )
      if (refused.length > 0) throw new ForbiddenError()
      return undefined
    },
    { name: 'auth.fieldWrite' },
  )
  const offManifest = hooks.on(
    'manifest.build',
    (raw) => {
      const payload = raw as { actor?: Actor | null; manifest?: ResourceManifest }
      if (!payload.manifest || !Array.isArray(payload.manifest.resources)) return undefined
      const resources = payload.manifest.resources.map((resource) =>
        manifestResourceFor(resource, payload.actor ?? null, policies),
      )
      return { ...payload, manifest: { ...payload.manifest, resources } }
    },
    { name: 'auth.fieldManifest' },
  )
  return () => {
    offRead()
    offWrite()
    offManifest()
  }
}

/**
 * The actor's view of one manifest resource: fields they may not read are left out (a UI must not
 * offer a column or input it would always receive empty), and fields they may not write are marked
 * read-only.
 */
export function manifestResourceFor(
  resource: ResourceDescriptor,
  actor: Actor | null,
  policies: PolicyLookup,
): ResourceDescriptor {
  const policy = policies.policy(lowerFirst(resource.name))
  if (!policy) return resource
  const hidden = new Set(unreadableFields(policy, actor))
  const writable = new Set(policy.writableFields(actor))
  const fields: FieldDescriptor[] = []
  for (const field of resource.fields) {
    if (hidden.has(field.name)) continue
    const locked =
      Object.hasOwn(policy.schema.columns, field.name) &&
      !writable.has(field.name) &&
      !field.readOnly
    fields.push(locked ? { ...field, readOnly: true } : field)
  }
  return { ...resource, fields }
}
