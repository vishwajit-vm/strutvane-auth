/**
 * In-memory evaluation of a bound filter against ONE record (single-record checks: show, update,
 * delete, custom actions).
 *
 * Implements exactly the normative two-valued, NULL-safe semantics of the contracts `QueryFilter`
 * (RFC-0001, ADR-0008), mirrored operator by operator by the SQL compiler in `../sql/compile.ts`.
 * The equivalence property tests run both against real Postgres to prove they agree.
 *
 * @module
 */
import type { FilterScalar, QueryFilter } from '@strutvane/contracts'
import { FieldNotLoadedError } from '../errors.ts'
import { type ColumnType, type ModelSchema, resolveField } from './schema.ts'
import { type FilterLimits, foldAscii, validateFilter } from './validate.ts'

/** A record as loaded for a check. To-one relations are nested objects, or `null` (no related row). */
export type RecordValue = Readonly<Record<string, unknown>>

const never = (reason: string): never => {
  throw new Error(reason)
}

/**
 * Read a field value.
 * - A relation that is `null` yields `null` for its fields (matches the SQL scalar subquery, which
 *   returns NULL when no related row exists).
 * - A field or relation that is `undefined` was not loaded: throw instead of guessing.
 */
function read(record: RecordValue, path: string): unknown {
  const dot = path.indexOf('.')
  const head = dot < 0 ? path : path.slice(0, dot)
  const first = Object.hasOwn(record, head) ? record[head] : undefined
  if (first === undefined)
    throw new FieldNotLoadedError(`Field "${head}" must be loaded to evaluate this policy`)
  if (dot < 0) return first
  if (first === null) return null
  if (typeof first !== 'object')
    throw new FieldNotLoadedError(`Relation "${head}" must be an object or null`)
  const tail = path.slice(dot + 1)
  const value = Object.hasOwn(first, tail) ? (first as Record<string, unknown>)[tail] : undefined
  if (value === undefined)
    throw new FieldNotLoadedError(`Field "${path}" must be loaded to evaluate this policy`)
  return value
}

/** NULL-safe equality, with uuid compared case-insensitively (like Postgres `uuid`). */
function same(a: unknown, b: FilterScalar, type: ColumnType): boolean {
  if (a === null || a === undefined) return false
  if (type === 'uuid' && typeof a === 'string' && typeof b === 'string')
    return a.toLowerCase() === b.toLowerCase()
  return a === b
}

function textOp(
  op: 'contains' | 'startsWith' | 'endsWith',
  a: unknown,
  b: string,
  caseSensitive: boolean,
): boolean {
  if (typeof a !== 'string') return false
  const hay = caseSensitive ? a : foldAscii(a)
  const needle = caseSensitive ? b : foldAscii(b)
  if (op === 'contains') return hay.includes(needle)
  if (op === 'startsWith') return hay.startsWith(needle)
  return hay.endsWith(needle)
}

function evalNode(f: QueryFilter, r: RecordValue, schema: ModelSchema): boolean {
  switch (f.op) {
    case 'true':
      return true
    case 'false':
      return false
    case 'and':
      return f.filters.every((c) => evalNode(c, r, schema))
    case 'or':
      return f.filters.some((c) => evalNode(c, r, schema))
    case 'not':
      return !evalNode(f.filter, r, schema)
    case 'isNull':
      return read(r, f.field) === null
    case 'isNotNull':
      return read(r, f.field) !== null
    case 'eq':
    case 'ne': {
      const type = resolveField(schema, f.field, never).column.type
      const equal = same(read(r, f.field), f.value as FilterScalar, type)
      return f.op === 'eq' ? equal : !equal
    }
    case 'in':
    case 'nin': {
      const type = resolveField(schema, f.field, never).column.type
      const v = read(r, f.field)
      const found = f.values.some((x) => same(v, x as FilterScalar, type))
      return f.op === 'in' ? found : !found
    }
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte': {
      const a = read(r, f.field)
      const b = f.value
      if (typeof a !== 'number' || typeof b !== 'number') return false
      if (f.op === 'gt') return a > b
      if (f.op === 'gte') return a >= b
      if (f.op === 'lt') return a < b
      return a <= b
    }
    case 'between': {
      const a = read(r, f.field)
      if (typeof a !== 'number' || typeof f.from !== 'number' || typeof f.to !== 'number')
        return false
      return a >= f.from && a <= f.to
    }
    case 'contains':
    case 'startsWith':
    case 'endsWith':
      return textOp(f.op, read(r, f.field), f.value, f.caseSensitive === true)
  }
}

/**
 * Evaluate a bound filter against one record. Validates first, so invalid input throws exactly
 * like the SQL compiler does.
 */
export function evaluateFilter(
  filter: QueryFilter,
  record: RecordValue,
  schema: ModelSchema,
  limits?: FilterLimits,
): boolean {
  validateFilter(filter, schema, limits)
  return evalNode(filter, record, schema)
}
