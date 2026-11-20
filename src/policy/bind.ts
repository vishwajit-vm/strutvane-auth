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
 * - **Integer ids (AUTH-4).** `actor.id` is a string in the contracts, but every table a Strutvane
 *   app generates has an integer primary key (`t.id()`), so owner rules compare it with `int4`
 *   columns. Compared with an `int4` column, the id binds to the integer it spells, and only when
 *   it is a canonical decimal integer in range (`"42"`, never `"042"`, `"4.2"`, `" 42"`, a uuid
 *   or a value past 2^31-1). Anything else binds to `null`, so it never matches (fail closed): a
 *   service actor or a uuid id can never be read as some row's integer owner.
 * - **Allow rules fail closed under negation** (`{ failClosed: true }`, used by `definePolicy` for
 *   allow rules). On its own, `ne(field, <null>)` binding to `TRUE` is the exact negation of `eq`,
 *   but inside an allow rule it would grant every row (likewise `nin`, and `eq`/`in`/ordering
 *   inside `not`). With `failClosed`, a leaf that depends on a null actor value binds to whatever
 *   makes the enclosing rule match FEWER rows, given the leaf's polarity: `FALSE` where it is
 *   positive, `TRUE` under an odd number of `not`s. Null values are still dropped from `in`
 *   lists where that only narrows the result.
 *
 * @module
 */
import type {
  Actor,
  ActorRef,
  FilterOperand,
  FilterScalar,
  QueryFilter,
} from '@strutvane/framework/contracts'
import { FALSE, TRUE } from './filter.ts'
import { type ColumnType, fitsType } from './schema.ts'

/** An actor attribute a policy references is missing, or has a value a policy cannot use. A server-side bug (500), never a client error. */
export class ActorAttributeError extends Error {
  override readonly name = 'ActorAttributeError'
}

type Bound = FilterScalar | null

/**
 * The column types `actor.id` may be compared with: `text` and `uuid` ids as they are, and
 * `int4` for the integer primary keys every generated table has (`t.id()`, AUTH-4).
 */
export const ACTOR_ID_TYPES: ReadonlySet<ColumnType> = new Set(['text', 'uuid', 'int4'])

/** A canonical decimal integer: no sign on zero, no leading zeros, no spaces, at most 10 digits. */
const CANONICAL_INTEGER = /^(?:0|-?[1-9][0-9]{0,9})$/

/**
 * The value `actor.id` compares with on a column of `type`. For an `int4` column the string id
 * becomes the integer it spells, or `null` when it is not a canonical in-range integer, so a
 * non-numeric id never matches a row (see the module docs). Other types get the id unchanged.
 *
 * @example
 * actorIdFor('42', 'int4') // 42
 * actorIdFor('042', 'int4') // null (never matches)
 * actorIdFor('0193a0b2-7c1e-7d4f-8a9b-0c1d2e3f4a5b', 'uuid') // the uuid, unchanged
 */
export function actorIdFor(id: string | number, type: ColumnType | undefined): FilterScalar | null {
  if (type !== 'int4') return id
  if (typeof id === 'number') return fitsType(id, 'int4') ? id : null
  if (!CANONICAL_INTEGER.test(id)) return null
  const value = Number(id)
  return fitsType(value, 'int4') ? value : null
}
/** Is this operand an actor reference? */
export function isActorRef(value: unknown): value is ActorRef {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { $actor?: unknown }).$actor === 'string'
  )
}

/**
 * Resolve one actor reference to a scalar or `null`. `column` is the type of the column the
 * reference is compared with, when known: it decides how `actor.id` binds (see {@link actorIdFor}).
 */
export function resolveActorRef(ref: ActorRef, actor: Actor | null, column?: ColumnType): Bound {
  const path = ref.$actor
  if (path === 'id') return actor ? actorIdFor(actor.id, column) : null
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

function bindOperand(operand: FilterOperand, ctx: BindContext, field: string): Bound {
  return isActorRef(operand) ? resolveActorRef(operand, ctx.actor, ctx.columnOf?.(field)) : operand
}

/** Options for {@link bindActor}. */
export interface BindOptions {
  /**
   * Bind for an ALLOW rule: a leaf that depends on a null actor value never widens the result,
   * whatever its polarity (see the module docs). Default `false` (plain "null never matches").
   */
  readonly failClosed?: boolean
  /**
   * The column type of a filter field, so `actor.id` binds as an integer where it is compared with
   * an `int4` column (AUTH-4). Without it, actor references bind unchanged.
   */
  readonly columnOf?: (field: string) => ColumnType | undefined
}

/** What every node of one {@link bindActor} call shares. */
interface BindContext {
  readonly actor: Actor | null
  readonly failClosed: boolean
  readonly columnOf: ((field: string) => ColumnType | undefined) | undefined
}

/** Replace every actor reference with its literal value. Pure; returns a new tree. */
export function bindActor(
  filter: QueryFilter,
  actor: Actor | null,
  options: BindOptions = {},
): QueryFilter {
  return bindNode(
    filter,
    { actor, failClosed: options.failClosed === true, columnOf: options.columnOf },
    true,
  )
}

function bindNode(filter: QueryFilter, ctx: BindContext, positive: boolean): QueryFilter {
  const { failClosed } = ctx
  // With failClosed, an unknown (null) leaf binds to the constant that makes the rule match less:
  // FALSE where the leaf counts positively, TRUE where an odd number of `not`s will flip it.
  const narrow = positive ? FALSE : TRUE
  switch (filter.op) {
    case 'true':
    case 'false':
    case 'isNull':
    case 'isNotNull':
      return filter
    case 'and':
    case 'or':
      return {
        op: filter.op,
        filters: filter.filters.map((f) => bindNode(f, ctx, positive)),
      }
    case 'not':
      return { op: 'not', filter: bindNode(filter.filter, ctx, !positive) }
    case 'eq':
    case 'ne': {
      const value = bindOperand(filter.value, ctx, filter.field)
      if (value === null) {
        if (failClosed) return narrow
        return filter.op === 'eq' ? FALSE : TRUE
      }
      return { ...filter, value }
    }
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte': {
      const value = bindOperand(filter.value, ctx, filter.field)
      if (value === null) return failClosed ? narrow : FALSE
      return { ...filter, value }
    }
    case 'in':
    case 'nin': {
      const values: FilterScalar[] = []
      let sawNull = false
      for (const operand of filter.values) {
        const value = bindOperand(operand, ctx, filter.field)
        if (value !== null) values.push(value)
        else sawNull = true
      }
      if (failClosed && sawNull) {
        // Dropping nulls narrows a positive `in` (and a negated `nin`); otherwise bind to narrow.
        const dropNarrows = (filter.op === 'in') === positive
        if (!dropNarrows) return narrow
      }
      return { ...filter, values }
    }
    case 'between': {
      const from = bindOperand(filter.from, ctx, filter.field)
      const to = bindOperand(filter.to, ctx, filter.field)
      if (from === null || to === null) return failClosed ? narrow : FALSE
      return { ...filter, from, to }
    }
    case 'contains':
    case 'startsWith':
    case 'endsWith':
      // Text operands are plain strings in the contract; nothing to bind.
      return filter
  }
}
