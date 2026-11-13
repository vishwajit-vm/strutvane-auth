/**
 * The typed predicate builder: `row.amount.lte(10_000)` → a contracts `QueryFilter`.
 *
 * Rule conditions are written against two proxies, `row` (the record) and `actor` (the user), and
 * produce plain `QueryFilter` data, never JavaScript closures. That is what lets one rule run both
 * in memory (single-record checks) and as a SQL `WHERE` clause (list queries).
 *
 * ## Type safety (compile time)
 * - Unknown fields don't exist on `row`: `row.amout` is a compile error.
 * - Values must match the column type: `row.amount.eq('x')` is a compile error.
 * - Ordering and `between` exist only on numeric columns; text operators only on `text` columns.
 * - Actor references carry a phantom type: `row.amount.eq(actor.id)` is a compile error.
 *
 * ## Safety (run time)
 * The proxies throw a {@link PolicyDefinitionError} for unknown fields, and every condition is
 * validated against the schema when the policy is defined. Untyped callers (plain JavaScript) can
 * therefore not bypass the rules either.
 *
 * @module
 */
import type { ActorRef, FilterOperand, FilterScalar, QueryFilter } from '@strutvane/contracts'
import { PolicyDefinitionError } from '../errors.ts'
import type { ColumnDef, ColumnType, ModelSchema } from './schema.ts'

/** The TypeScript type that a column type holds. */
export type ValueOf<T extends ColumnType> = T extends 'text' | 'uuid'
  ? string
  : T extends 'int4' | 'float8'
    ? number
    : boolean

/**
 * An actor reference with a phantom value type. `__type` never exists at run time; it only lets
 * the compiler reject comparing, say, a number column with the actor's id.
 */
export interface TypedActorRef<T> extends ActorRef {
  readonly __type?: T
}

/** A comparison operand: a literal or a compatible actor reference. */
export type Arg<T> = T | TypedActorRef<T>

/** Options for text operators. */
export interface TextOptions {
  /** Defaults to `false`: ASCII letters A–Z match either case. */
  readonly caseSensitive?: boolean
}

/** Operators available on every column. */
export interface FieldExpr<T> {
  /** Equal (never matches null). `eq(null)` is shorthand for `isNull()`. */
  eq(value: Arg<T> | null): QueryFilter
  /** Exact negation of `eq`, so it DOES match null. `ne(null)` is shorthand for `isNotNull()`. */
  ne(value: Arg<T> | null): QueryFilter
  /** One of the values (never matches null). */
  in(values: readonly Arg<T>[]): QueryFilter
  /** Exact negation of `in` (matches null). */
  nin(values: readonly Arg<T>[]): QueryFilter
  isNull(): QueryFilter
  isNotNull(): QueryFilter
}

/** Operators on numeric columns. All are false when the value is null. */
export interface NumberExpr extends FieldExpr<number> {
  gt(value: Arg<number>): QueryFilter
  gte(value: Arg<number>): QueryFilter
  lt(value: Arg<number>): QueryFilter
  lte(value: Arg<number>): QueryFilter
  /** Inclusive on both ends. */
  between(from: Arg<number>, to: Arg<number>): QueryFilter
}

/** Operators on text columns. The search text is matched literally (`%` and `_` are not wildcards). */
export interface TextExpr extends FieldExpr<string> {
  contains(value: string, options?: TextOptions): QueryFilter
  startsWith(value: string, options?: TextOptions): QueryFilter
  endsWith(value: string, options?: TextOptions): QueryFilter
}

/** The expression interface for a column type. */
export type ExprFor<T extends ColumnType> = T extends 'int4' | 'float8'
  ? NumberExpr
  : T extends 'text'
    ? TextExpr
    : FieldExpr<ValueOf<T>>

type ColumnsProxy<C extends Readonly<Record<string, ColumnDef>>> = {
  readonly [K in keyof C]: ExprFor<C[K]['type']>
}

/** The `row` proxy for a schema: one expression per column, one nested proxy per relation. */
export type RowProxy<S extends ModelSchema> = ColumnsProxy<S['columns']> & {
  readonly [R in keyof NonNullable<S['relations']>]: ColumnsProxy<
    NonNullable<S['relations']>[R]['columns']
  >
}

/** Declared actor attributes: name → column type. Lets policies type-check `actor.attrs.*`. */
export type AttrDecl = Readonly<Record<string, ColumnType>>

/** The `actor` proxy: references only; values are bound per request. */
export interface ActorProxy<A extends AttrDecl> {
  readonly id: TypedActorRef<string>
  readonly tenantId: TypedActorRef<string>
  /**
   * Typed references to the attributes declared in the policy's `attrs` option. Only declared
   * attributes exist, at compile time and at run time, and their values are type-checked per
   * request.
   */
  readonly attrs: { readonly [K in keyof A]: TypedActorRef<ValueOf<A[K]>> }
}

const toOperand = (value: unknown): FilterOperand => {
  if (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as ActorRef).$actor === 'string'
  ) {
    // Strip anything but `$actor` so the tree is plain, serialisable data.
    return { $actor: (value as ActorRef).$actor }
  }
  return value as FilterScalar
}

/** The runtime object behind {@link FieldExpr}, {@link NumberExpr} and {@link TextExpr}. */
function fieldExpr(field: string): NumberExpr & TextExpr {
  const cmp =
    (op: 'gt' | 'gte' | 'lt' | 'lte') =>
    (value: unknown): QueryFilter => ({ op, field, value: toOperand(value) })
  const text =
    (op: 'contains' | 'startsWith' | 'endsWith') =>
    (value: string, options: TextOptions = {}): QueryFilter =>
      options.caseSensitive === undefined
        ? { op, field, value }
        : { op, field, value, caseSensitive: options.caseSensitive }
  return {
    eq: (value: unknown): QueryFilter =>
      value === null ? { op: 'isNull', field } : { op: 'eq', field, value: toOperand(value) },
    ne: (value: unknown): QueryFilter =>
      value === null ? { op: 'isNotNull', field } : { op: 'ne', field, value: toOperand(value) },
    in: (values: readonly unknown[]): QueryFilter => ({
      op: 'in',
      field,
      values: values.map(toOperand),
    }),
    nin: (values: readonly unknown[]): QueryFilter => ({
      op: 'nin',
      field,
      values: values.map(toOperand),
    }),
    isNull: (): QueryFilter => ({ op: 'isNull', field }),
    isNotNull: (): QueryFilter => ({ op: 'isNotNull', field }),
    gt: cmp('gt'),
    gte: cmp('gte'),
    lt: cmp('lt'),
    lte: cmp('lte'),
    between: (from: unknown, to: unknown): QueryFilter => ({
      op: 'between',
      field,
      from: toOperand(from),
      to: toOperand(to),
    }),
    contains: text('contains'),
    startsWith: text('startsWith'),
    endsWith: text('endsWith'),
  }
}

function columnsProxy(
  where: string,
  prefix: string,
  columns: Readonly<Record<string, ColumnDef>>,
): object {
  return new Proxy(
    {},
    {
      get(_target, prop) {
        if (typeof prop !== 'string') return undefined
        if (!Object.hasOwn(columns, prop))
          throw new PolicyDefinitionError(`Unknown field "${prop}" on ${where}`)
        return fieldExpr(prefix + prop)
      },
    },
  )
}

/** Create the runtime `row` proxy for a schema. */
export function createRow<S extends ModelSchema>(schema: S): RowProxy<S> {
  const relations = schema.relations ?? {}
  return new Proxy({} as RowProxy<S>, {
    get(_target, prop) {
      if (typeof prop !== 'string') return undefined
      if (Object.hasOwn(schema.columns, prop)) return fieldExpr(prop)
      const relation = Object.hasOwn(relations, prop) ? relations[prop] : undefined
      if (relation) return columnsProxy(`relation "${prop}"`, `${prop}.`, relation.columns)
      throw new PolicyDefinitionError(`Unknown field or relation "${prop}" on ${schema.table}`)
    },
  })
}

/**
 * Create the runtime `actor` proxy. Referencing an attribute that is not declared throws at
 * definition time, so a typo can never silently become "always null".
 */
export function createActorRefs<A extends AttrDecl>(attrs: A | undefined): ActorProxy<A> {
  return {
    id: { $actor: 'id' },
    tenantId: { $actor: 'tenantId' },
    attrs: new Proxy({} as ActorProxy<A>['attrs'], {
      get(_target, prop) {
        if (typeof prop !== 'string') return undefined
        if (!attrs || !Object.hasOwn(attrs, prop)) {
          throw new PolicyDefinitionError(
            `Actor attribute "${prop}" is not declared in the policy's attrs`,
          )
        }
        return { $actor: `attrs.${prop}` }
      },
    }),
  }
}
