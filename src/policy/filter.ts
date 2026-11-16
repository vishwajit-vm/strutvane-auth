/**
 * Constructors for the contracts `QueryFilter` tree, with constant folding.
 *
 * Folding (`and(TRUE, x)` → `x`, `or()` → `FALSE`, `not(not(x))` → `x`) keeps generated SQL small
 * and readable. It is only valid because the semantics are two-valued (ADR-0008): with SQL's
 * three-valued logic, `not(not(x))` and `x` would differ for NULLs.
 *
 * @module
 */
import type { QueryFilter } from '@strutvane/framework/contracts'

/** Always true. */
export const TRUE: QueryFilter = Object.freeze({ op: 'true' })
/** Always false: how "deny by default" is expressed. */
export const FALSE: QueryFilter = Object.freeze({ op: 'false' })

/** Logical AND with constant folding and flattening. */
export function and(...filters: readonly QueryFilter[]): QueryFilter {
  const flat: QueryFilter[] = []
  for (const f of filters) {
    if (f.op === 'false') return FALSE
    if (f.op === 'true') continue
    if (f.op === 'and') flat.push(...f.filters)
    else flat.push(f)
  }
  if (flat.length === 0) return TRUE
  if (flat.length === 1) return flat[0] as QueryFilter
  return { op: 'and', filters: flat }
}

/** Logical OR with constant folding and flattening. */
export function or(...filters: readonly QueryFilter[]): QueryFilter {
  const flat: QueryFilter[] = []
  for (const f of filters) {
    if (f.op === 'true') return TRUE
    if (f.op === 'false') continue
    if (f.op === 'or') flat.push(...f.filters)
    else flat.push(f)
  }
  if (flat.length === 0) return FALSE
  if (flat.length === 1) return flat[0] as QueryFilter
  return { op: 'or', filters: flat }
}

/** Logical NOT with constant folding and double-negation removal. */
export function not(filter: QueryFilter): QueryFilter {
  if (filter.op === 'true') return FALSE
  if (filter.op === 'false') return TRUE
  if (filter.op === 'not') return filter.filter
  return { op: 'not', filter }
}

/**
 * Re-apply constant folding to a whole tree, bottom-up. Used after actor binding, which can turn
 * comparisons into constants (a null actor value makes `eq` FALSE), so `can()` without a record can
 * tell "always", "never" and "depends on the record" apart, and generated SQL stays minimal.
 */
export function fold(filter: QueryFilter): QueryFilter {
  switch (filter.op) {
    case 'and':
      return and(...filter.filters.map(fold))
    case 'or':
      return or(...filter.filters.map(fold))
    case 'not':
      return not(fold(filter.filter))
    default:
      return filter
  }
}
