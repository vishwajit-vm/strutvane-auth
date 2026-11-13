/**
 * Actor binding: replace every `{ $actor: … }` reference in a filter with the acting user's value.
 *
 * Binding happens BEFORE either execution path (in-memory evaluation or SQL compilation), so both
 * see exactly the same literal tree.
 *
 * ## Security rules (normative, RFC-0001 / ADR-0008)
 * - **A null actor value never matches.** `eq(field, <null>)` becomes `FALSE` and `ne` becomes
 *   `TRUE` (still the exact negation); null values are dropped from `in` / `nin` lists; ordering,
 *   `between` and text operators with a null operand become `FALSE`. Without this rule,
 *   "same region as me" would grant every row without a region to an actor without a region.
 * - **A missing actor attribute throws.** The identity layer must set every attribute a policy
 *   references, explicitly (`null` is allowed). Treating "missing" as `null` would silently change
 *   what a policy means.
 * - **Anonymous actors (`null`)** resolve every reference to `null`, so they match nothing through
 *   actor references.
 *
 * @module
 */
import type {
  Actor,
  ActorRef,
  FilterOperand,
  FilterScalar,
  QueryFilter,
} from '@strutvane/contracts'
import { FALSE, TRUE } from './filter.ts'

/** An actor attribute a policy references is missing, or has a value a policy cannot use. A server-side bug (500), never a client error. */
export class ActorAttributeError extends Error {
  override readonly name = 'ActorAttributeError'
}

type Bound = FilterScalar | null

/** Is this operand an actor reference? */
export function isActorRef(value: unknown): value is ActorRef {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { $actor?: unknown }).$actor === 'string'
  )
}

/** Resolve one actor reference to a scalar or `null`. */
export function resolveActorRef(ref: ActorRef, actor: Actor | null): Bound {
  const path = ref.$actor
  if (path === 'id') return actor ? actor.id : null
  if (path === 'tenantId') return actor?.tenantId ?? null
  if (path.startsWith('attrs.')) {
    if (!actor) return null
    const key = path.slice('attrs.'.length)
    if (key.length === 0 || !Object.hasOwn(actor.attrs, key)) {
      throw new ActorAttributeError(
        `A policy references actor.attrs.${key} but the actor does not define it. Set it explicitly in the identity layer (null is allowed).`,
      )
    }
    const value = actor.attrs[key]
    if (
      value === null ||
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean'
    ) {
      return value
    }
    throw new ActorAttributeError(
      `actor.attrs.${key} must be a string, number, boolean or null to be used in a policy (got ${typeof value})`,
    )
  }
  throw new ActorAttributeError(`Unsupported actor reference "${path}"`)
}

function bindOperand(operand: FilterOperand, actor: Actor | null): Bound {
  return isActorRef(operand) ? resolveActorRef(operand, actor) : operand
}

/** Replace every actor reference with its literal value. Pure; returns a new tree. */
export function bindActor(filter: QueryFilter, actor: Actor | null): QueryFilter {
  switch (filter.op) {
    case 'true':
    case 'false':
    case 'isNull':
    case 'isNotNull':
      return filter
    case 'and':
    case 'or':
      return { op: filter.op, filters: filter.filters.map((f) => bindActor(f, actor)) }
    case 'not':
      return { op: 'not', filter: bindActor(filter.filter, actor) }
    case 'eq':
    case 'ne': {
      const value = bindOperand(filter.value, actor)
      if (value === null) return filter.op === 'eq' ? FALSE : TRUE
      return { ...filter, value }
    }
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte': {
      const value = bindOperand(filter.value, actor)
      return value === null ? FALSE : { ...filter, value }
    }
    case 'in':
    case 'nin': {
      const values: FilterScalar[] = []
      for (const operand of filter.values) {
        const value = bindOperand(operand, actor)
        if (value !== null) values.push(value)
      }
      return { ...filter, values }
    }
    case 'between': {
      const from = bindOperand(filter.from, actor)
      const to = bindOperand(filter.to, actor)
      return from === null || to === null ? FALSE : { ...filter, from, to }
    }
    case 'contains':
    case 'startsWith':
    case 'endsWith':
      // Text operands are plain strings in the contract; nothing to bind.
      return filter
  }
}
