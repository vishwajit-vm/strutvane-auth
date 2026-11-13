/**
 * Compile a bound, validated contracts `QueryFilter` into a parameterized Postgres `WHERE` fragment.
 *
 * ## Guarantees
 * - **No value is ever concatenated into SQL.** Every literal becomes a typed placeholder
 *   (`$n::type`). Identifiers come only from the trusted schema and are pattern-checked and quoted.
 * - **Two-valued output.** Every leaf compiles to an expression that is never NULL, so `NOT (…)`
 *   behaves exactly like JavaScript `!`. This is the core of SQL/in-memory equivalence (ADR-0008):
 *   - `eq` → `col IS NOT DISTINCT FROM $1` and `ne` → `col IS DISTINCT FROM $1`. A plain `<>`
 *     would return NULL for a NULL column and silently drop rows that `ne` must match.
 *   - `gt` … `lte`, `between`, `in` → `COALESCE(<expr>, FALSE)`.
 *   - `contains` → `strpos()`, `startsWith` → `starts_with()`, `endsWith` → `right()`: never
 *     `LIKE`, whose `%` and `_` wildcards would change the meaning of user-supplied text.
 *   - Case-insensitive text matching folds exactly A–Z with `translate()` (the parameter is folded
 *     in JavaScript), so results never depend on database locale or ICU version.
 * - **Composable.** The output is a pure predicate over the subject table alias. To-one relation
 *   fields compile to correlated scalar subqueries, so the caller's FROM/JOIN/ORDER/LIMIT is
 *   untouched and a missing related row reads as NULL, exactly like a `null` relation in memory.
 *
 * @module
 */
import type { FilterScalar, QueryFilter } from '@strutvane/contracts'
import {
  type ColumnType,
  type ModelSchema,
  quoteIdent,
  quoteTable,
  resolveField,
} from '../policy/schema.ts'
import { type FilterLimits, foldAscii, validateFilter } from '../policy/validate.ts'

/** A SQL parameter value: a scalar, or a list for `= ANY($n::type[])`. */
export type SqlParam = FilterScalar | readonly FilterScalar[]

/** One piece of a parameterized SQL fragment: raw SQL text, or a typed parameter. */
export type Token = { readonly sql: string } | { readonly param: SqlParam; readonly type: string }

/** Options for {@link compileToTokens}. */
export interface CompileOptions extends FilterLimits {
  /** Alias (or table name) of the subject table in the surrounding query. Default `"t"`. */
  readonly alias?: string
}

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const LOWER = 'abcdefghijklmnopqrstuvwxyz'
const SYMBOL = { gt: '>', gte: '>=', lt: '<', lte: '<=' } as const

/** Unreachable after validation; kept so a bug fails loudly instead of emitting bad SQL. */
const fail = (reason: string): never => {
  throw new Error(reason)
}

class Compiler {
  readonly out: Token[] = []
  readonly #schema: ModelSchema
  readonly #alias: string
  readonly #relationAlias: ReadonlyMap<string, string>

  constructor(schema: ModelSchema, alias: string) {
    this.#schema = schema
    this.#alias = quoteIdent(alias)
    // Relation aliases are generated (never derived from names or input), so they cannot collide.
    this.#relationAlias = new Map(
      Object.keys(schema.relations ?? {}).map((name, i) => [name, `"sv_rel_${i}"`]),
    )
  }

  raw(sql: string): void {
    this.out.push({ sql })
  }

  param(value: SqlParam, type: string): void {
    this.out.push({ param: value, type })
  }

  /** Emit the column (or relation subquery) for a path, optionally ASCII-folded; returns its type. */
  column(path: string, fold = false): ColumnType {
    const { column, relation, relationName } = resolveField(this.#schema, path, fail)
    if (fold) this.raw('translate(')
    if (relation && relationName) {
      const r = this.#relationAlias.get(relationName) ?? fail('unknown relation')
      this.raw(
        `(SELECT ${r}.${quoteIdent(column.column)} FROM ${quoteTable(relation.table)} AS ${r}` +
          ` WHERE ${r}.${quoteIdent(relation.targetKey)} = ${this.#alias}.${quoteIdent(relation.foreignKey)})`,
      )
    } else {
      this.raw(`${this.#alias}.${quoteIdent(column.column)}`)
    }
    if (fold) this.raw(`, '${UPPER}', '${LOWER}')`)
    return column.type
  }

  group(filters: readonly QueryFilter[], joiner: 'AND' | 'OR'): void {
    if (filters.length === 0) {
      this.raw(joiner === 'AND' ? 'TRUE' : 'FALSE')
      return
    }
    this.raw('(')
    filters.forEach((f, i) => {
      if (i > 0) this.raw(` ${joiner} `)
      this.node(f)
    })
    this.raw(')')
  }

  text(f: Extract<QueryFilter, { op: 'contains' | 'startsWith' | 'endsWith' }>): void {
    const fold = f.caseSensitive !== true
    const needle = fold ? foldAscii(f.value) : f.value
    if (f.op === 'contains') {
      this.raw('COALESCE(strpos(')
      this.column(f.field, fold)
      this.raw(', ')
      this.param(needle, 'text')
      this.raw(') > 0, FALSE)')
      return
    }
    if (f.op === 'startsWith') {
      this.raw('COALESCE(starts_with(')
      this.column(f.field, fold)
      this.raw(', ')
      this.param(needle, 'text')
      this.raw('), FALSE)')
      return
    }
    this.raw('COALESCE(right(')
    this.column(f.field, fold)
    this.raw(', char_length(')
    this.param(needle, 'text')
    this.raw(')) = ')
    this.param(needle, 'text')
    this.raw(', FALSE)')
  }

  node(f: QueryFilter): void {
    switch (f.op) {
      case 'true':
        this.raw('TRUE')
        return
      case 'false':
        this.raw('FALSE')
        return
      case 'and':
      case 'or':
        this.group(f.filters, f.op === 'and' ? 'AND' : 'OR')
        return
      case 'not':
        this.raw('(NOT ')
        this.node(f.filter)
        this.raw(')')
        return
      case 'isNull':
      case 'isNotNull':
        this.raw('(')
        this.column(f.field)
        this.raw(f.op === 'isNull' ? ' IS NULL)' : ' IS NOT NULL)')
        return
      case 'eq':
      case 'ne': {
        this.raw('(')
        const type = this.column(f.field)
        this.raw(f.op === 'eq' ? ' IS NOT DISTINCT FROM ' : ' IS DISTINCT FROM ')
        this.param(f.value as FilterScalar, type)
        this.raw(')')
        return
      }
      case 'in':
      case 'nin': {
        if (f.values.length === 0) {
          this.raw(f.op === 'in' ? 'FALSE' : 'TRUE')
          return
        }
        // Values are non-null after binding, so `col = ANY(list)` is NULL only when col is NULL;
        // COALESCE turns that into FALSE for `in`, and TRUE after the NOT for `nin`.
        this.raw(f.op === 'in' ? 'COALESCE(' : '(NOT COALESCE(')
        const type = this.column(f.field)
        this.raw(' = ANY(')
        this.param(f.values as readonly FilterScalar[], `${type}[]`)
        this.raw(f.op === 'in' ? '), FALSE)' : '), FALSE))')
        return
      }
      case 'gt':
      case 'gte':
      case 'lt':
      case 'lte': {
        this.raw('COALESCE(')
        const type = this.column(f.field)
        this.raw(` ${SYMBOL[f.op]} `)
        this.param(f.value as FilterScalar, type)
        this.raw(', FALSE)')
        return
      }
      case 'between': {
        this.raw('COALESCE(')
        const type = this.column(f.field)
        this.raw(' BETWEEN ')
        this.param(f.from as FilterScalar, type)
        this.raw(' AND ')
        this.param(f.to as FilterScalar, type)
        this.raw(', FALSE)')
        return
      }
      case 'contains':
      case 'startsWith':
      case 'endsWith':
        this.text(f)
        return
    }
  }
}

/**
 * Compile to tokens (for query-builder adapters such as Kysely or Drizzle `sql`). Validates first,
 * through the same gate as in-memory evaluation, so invalid input throws identically.
 */
export function compileToTokens(
  filter: QueryFilter,
  schema: ModelSchema,
  options: CompileOptions = {},
): Token[] {
  const { alias = 't', ...limits } = options
  validateFilter(filter, schema, limits)
  const compiler = new Compiler(schema, alias)
  compiler.node(filter)
  return compiler.out
}

/** A rendered fragment for the `pg` / PGlite wire protocol. */
export interface RenderedSql {
  readonly sql: string
  readonly params: SqlParam[]
}

/** Render tokens as `$n::type`-numbered SQL. `firstParam` lets you append to an existing query. */
export function renderPostgres(tokens: readonly Token[], firstParam = 1): RenderedSql {
  if (!Number.isInteger(firstParam) || firstParam < 1)
    throw new RangeError('firstParam must be a positive integer')
  let sql = ''
  const params: SqlParam[] = []
  for (const token of tokens) {
    if ('sql' in token) sql += token.sql
    else {
      params.push(token.param)
      sql += `$${firstParam + params.length - 1}::${token.type}`
    }
  }
  return { sql, params }
}

/** Compile straight to `{ sql, params }`. */
export function compileToSql(
  filter: QueryFilter,
  schema: ModelSchema,
  options: CompileOptions = {},
): RenderedSql {
  return renderPostgres(compileToTokens(filter, schema, options))
}
