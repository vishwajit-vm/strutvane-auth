/**
 * The shared validation gate (ADR-0008).
 *
 * Both execution paths, in-memory evaluation and SQL compilation, call {@link validateFilter} on
 * the bound filter first. An input is therefore either accepted by both (and then gives identical
 * results, as the equivalence property tests prove) or rejected by both with the same
 * {@link InvalidFilterError}. That is what makes the equivalence guarantee hold, including for
 * untrusted filters sent by a UI.
 *
 * The gate also bounds the cost of untrusted input: node count, nesting depth and list length are
 * capped, so a hostile filter cannot exhaust the stack or produce gigantic SQL.
 *
 * @module
 */
import type { ActorRef, QueryFilter } from '@strutvane/contracts'
import { InvalidFilterError } from '../errors.ts'
import { isActorRef } from './bind.ts'
import { type ColumnType, fitsType, isNumeric, type ModelSchema, resolveField } from './schema.ts'

/** Limits applied to every filter (generous for policies, protective for untrusted input). */
export interface FilterLimits {
  /** Maximum number of nodes in the tree. Default 2,000. */
  readonly maxNodes?: number
  /** Maximum nesting depth. Default 32. */
  readonly maxDepth?: number
  /** Maximum values in one `in` / `nin`. Default 1,000. */
  readonly maxListLength?: number
  /** Maximum length of one string value. Default 10,000. */
  readonly maxStringLength?: number
}

/** Options for {@link validateFilter}. */
export interface ValidateOptions extends FilterLimits {
  /**
   * Accept UNBOUND actor references and check them with this callback instead of rejecting them.
   * Used once, at policy definition time, to type-check rule conditions before any actor exists.
   * Never set for request-time validation: there, every reference must already be bound.
   */
  readonly checkActorRef?: (ref: ActorRef, column: ColumnType, where: string) => void
}

type Resolved = Required<FilterLimits> & Pick<ValidateOptions, 'checkActorRef'>

const DEFAULTS: Required<FilterLimits> = {
  maxNodes: 2000,
  maxDepth: 32,
  maxListLength: 1000,
  maxStringLength: 10_000,
}

const fail = (reason: string): never => {
  throw new InvalidFilterError(reason)
}

/** Lone UTF-16 surrogates cannot be stored in Postgres `text`; reject so both paths agree. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/

function checkString(value: string, where: string, limits: Resolved): void {
  if (value.length > limits.maxStringLength)
    fail(`${where}: string longer than ${limits.maxStringLength} characters`)
  // Postgres `text` cannot store U+0000; JS strings can. Reject so both paths agree (fail closed).
  if (value.includes('\u0000')) fail(`${where}: strings must not contain U+0000`)
  if (LONE_SURROGATE.test(value))
    fail(`${where}: strings must not contain unpaired UTF-16 surrogates`)
}

function checkValue(value: unknown, type: ColumnType, where: string, limits: Resolved): void {
  if (isActorRef(value)) {
    if (limits.checkActorRef) {
      limits.checkActorRef(value, type, where)
      return
    }
    fail(`${where}: unbound actor reference (bind the actor first)`)
  }
  if (value === null || value === undefined)
    fail(`${where}: null is not a comparison value (use isNull)`)
  if (!fitsType(value, type)) fail(`${where}: value does not fit column type ${type}`)
  if (typeof value === 'string') checkString(value, where, limits)
}

function checkField(field: unknown, schema: ModelSchema): ColumnType {
  if (typeof field !== 'string' || field.length === 0 || field.length > 200)
    fail('field must be a non-empty string')
  return resolveField(schema, field as string, fail).column.type
}

/**
 * Validate a BOUND filter against the schema. Throws {@link InvalidFilterError} on any problem.
 *
 * Checks: well-formed nodes (untrusted JSON may be anything); every field exists; every value fits
 * its column type and is not null; ordering and `between` only on numeric fields; text operators
 * only on text fields; no unbound actor references; size and depth limits.
 */
export function validateFilter(
  filter: QueryFilter,
  schema: ModelSchema,
  options: ValidateOptions = {},
): void {
  const l: Resolved = { ...DEFAULTS, ...options }
  let nodes = 0

  const visit = (node: unknown, depth: number): void => {
    nodes++
    if (nodes > l.maxNodes) fail(`filter has more than ${l.maxNodes} nodes`)
    if (depth > l.maxDepth) fail(`filter is nested deeper than ${l.maxDepth} levels`)
    if (typeof node !== 'object' || node === null) fail('filter nodes must be objects')
    const f = node as QueryFilter
    switch (f.op) {
      case 'true':
      case 'false':
        return
      case 'and':
      case 'or':
        if (!Array.isArray(f.filters)) fail(`${f.op}: "filters" must be an array`)
        for (const child of f.filters) visit(child, depth + 1)
        return
      case 'not':
        visit(f.filter, depth + 1)
        return
      case 'isNull':
      case 'isNotNull':
        checkField(f.field, schema)
        return
      case 'eq':
      case 'ne': {
        const type = checkField(f.field, schema)
        checkValue(f.value, type, `${f.op}(${f.field})`, l)
        return
      }
      case 'gt':
      case 'gte':
      case 'lt':
      case 'lte': {
        const type = checkField(f.field, schema)
        // Text ordering depends on collation (JS compares UTF-16 code units, Postgres uses the
        // database collation), so ordering is restricted to numeric columns.
        if (!isNumeric(type))
          fail(`${f.op} is only allowed on numeric fields (${f.field} is ${type})`)
        checkValue(f.value, type, `${f.op}(${f.field})`, l)
        return
      }
      case 'between': {
        const type = checkField(f.field, schema)
        if (!isNumeric(type))
          fail(`between is only allowed on numeric fields (${f.field} is ${type})`)
        checkValue(f.from, type, `between(${f.field}).from`, l)
        checkValue(f.to, type, `between(${f.field}).to`, l)
        return
      }
      case 'in':
      case 'nin': {
        const type = checkField(f.field, schema)
        if (!Array.isArray(f.values)) fail(`${f.op}(${f.field}): "values" must be an array`)
        if (f.values.length > l.maxListLength)
          fail(`${f.op}(${f.field}): more than ${l.maxListLength} values`)
        f.values.forEach((v, i) => {
          checkValue(v, type, `${f.op}(${f.field})[${i}]`, l)
        })
        return
      }
      case 'contains':
      case 'startsWith':
      case 'endsWith': {
        const type = checkField(f.field, schema)
        if (type !== 'text') fail(`${f.op} is only allowed on text fields (${f.field} is ${type})`)
        // The contract allows only a literal string here (no actor references).
        if (typeof f.value !== 'string') fail(`${f.op}(${f.field}): value must be a string`)
        checkValue(f.value, type, `${f.op}(${f.field})`, l)
        if (f.caseSensitive !== undefined && typeof f.caseSensitive !== 'boolean') {
          fail(`${f.op}(${f.field}): caseSensitive must be a boolean`)
        }
        return
      }
      default:
        fail(`unknown operator ${JSON.stringify((f as { op?: unknown }).op)}`)
    }
  }

  visit(filter, 0)
}

/**
 * Fold ASCII letters A–Z to lowercase and leave every other character unchanged.
 *
 * **Why ASCII only?** Full Unicode case folding differs between JavaScript and Postgres (it depends
 * on the database locale and ICU version), which would break the equivalence guarantee for
 * case-insensitive text operators. Folding exactly A–Z is identical in both paths: in SQL it is
 * `translate(col, 'A…Z', 'a…z')`.
 */
export function foldAscii(value: string): string {
  return value.replace(/[A-Z]/g, (c) => c.toLowerCase())
}
