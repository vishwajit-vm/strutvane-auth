/**
 * Model metadata the policy engine needs: table and column names, column types, and to-one
 * relations. In a full Strutvane app this comes from `defineModel()`; standalone users declare it
 * with {@link defineSchema}.
 *
 * **Security:** identifiers come ONLY from here (developer-authored, trusted), never from request
 * input. They are still validated against a conservative pattern at definition time and quoted
 * when compiled, so a typo can never become SQL injection.
 *
 * @module
 */
import { PolicyDefinitionError } from '../errors.ts'

/**
 * Column types the engine supports. Each one has identical semantics in memory and in SQL
 * (proven by the equivalence property tests):
 * - `text`: Postgres `text`; ordering is NOT allowed (collation-dependent).
 * - `uuid`: canonical UUID strings, compared case-insensitively (like Postgres `uuid`).
 * - `int4`: 32-bit integers.
 * - `float8`: finite doubles (NaN/Infinity rejected: their ordering differs between JS and SQL).
 * - `bool`: booleans.
 */
export type ColumnType = 'text' | 'uuid' | 'int4' | 'float8' | 'bool'

/** One column. */
export interface ColumnDef {
  /** The SQL column name, e.g. `owner_id`. */
  readonly column: string
  readonly type: ColumnType
}

/** A to-one relation (`belongsTo`): `subject.foreignKey → table.targetKey`. */
export interface RelationDef {
  readonly table: string
  readonly foreignKey: string
  readonly targetKey: string
  readonly columns: Readonly<Record<string, ColumnDef>>
}

/** A model as the policy engine sees it. Field names are the API names (`ownerId`). */
export interface ModelSchema {
  /** SQL table name, optionally schema-qualified (`app.invoices`). */
  readonly table: string
  readonly columns: Readonly<Record<string, ColumnDef>>
  readonly relations?: Readonly<Record<string, RelationDef>>
}

const IDENT = /^[a-z_][a-z0-9_]{0,62}$/
const FIELD = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/
const TYPES: ReadonlySet<string> = new Set(['text', 'uuid', 'int4', 'float8', 'bool'])

/** Quote a trusted SQL identifier, rejecting anything outside a conservative pattern. */
export function quoteIdent(name: string): string {
  if (!IDENT.test(name))
    throw new PolicyDefinitionError(`Unsafe SQL identifier: ${JSON.stringify(name)}`)
  return `"${name}"`
}

/** Quote a possibly schema-qualified table name (`app.invoices` → `"app"."invoices"`). */
export function quoteTable(name: string): string {
  const parts = name.split('.')
  if (parts.length > 2)
    throw new PolicyDefinitionError(`Unsafe table name: ${JSON.stringify(name)}`)
  return parts.map(quoteIdent).join('.')
}

function checkColumns(where: string, columns: Readonly<Record<string, ColumnDef>>): void {
  for (const [field, def] of Object.entries(columns)) {
    if (!FIELD.test(field))
      throw new PolicyDefinitionError(`${where}: invalid field name ${JSON.stringify(field)}`)
    quoteIdent(def.column)
    if (!TYPES.has(def.type))
      throw new PolicyDefinitionError(
        `${where}.${field}: unknown column type ${JSON.stringify(def.type)}`,
      )
  }
}

/**
 * Declare and validate a model schema. Validation happens once, at definition time, so mistakes
 * surface at boot instead of at the first request.
 */
export function defineSchema<const S extends ModelSchema>(schema: S): S {
  quoteTable(schema.table)
  checkColumns(schema.table, schema.columns)
  for (const [name, rel] of Object.entries(schema.relations ?? {})) {
    if (!FIELD.test(name))
      throw new PolicyDefinitionError(
        `${schema.table}: invalid relation name ${JSON.stringify(name)}`,
      )
    if (name in schema.columns)
      throw new PolicyDefinitionError(`${schema.table}: "${name}" is both a field and a relation`)
    quoteTable(rel.table)
    quoteIdent(rel.foreignKey)
    quoteIdent(rel.targetKey)
    checkColumns(`${schema.table}.${name}`, rel.columns)
  }
  return schema
}

/** A resolved field path. */
export interface ResolvedField {
  readonly column: ColumnDef
  readonly relationName?: string
  readonly relation?: RelationDef
}

/**
 * Resolve a dotted field path (`"amount"`, `"customer.region"`) against the schema. Unknown fields,
 * unknown relations and paths deeper than one relation are rejected, for trusted and untrusted
 * filters alike.
 *
 * @throws {InvalidFilterError} via the caller-supplied `fail` function.
 */
export function resolveField(
  schema: ModelSchema,
  path: string,
  fail: (reason: string) => never,
): ResolvedField {
  const parts = path.split('.')
  if (parts.length === 1) {
    const column = Object.hasOwn(schema.columns, path) ? schema.columns[path] : undefined
    if (!column) return fail(`unknown field "${path}" on ${schema.table}`)
    return { column }
  }
  if (parts.length === 2) {
    const [relName = '', field = ''] = parts
    const relations = schema.relations ?? {}
    const relation = Object.hasOwn(relations, relName) ? relations[relName] : undefined
    if (!relation) return fail(`unknown relation "${relName}" on ${schema.table}`)
    const column = Object.hasOwn(relation.columns, field) ? relation.columns[field] : undefined
    if (!column) return fail(`unknown field "${field}" on relation "${relName}"`)
    return { column, relationName: relName, relation }
  }
  return fail(`field paths deeper than one relation are not supported ("${path}")`)
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const INT4_MIN = -2147483648
const INT4_MAX = 2147483647

/** Is `value` a canonical hyphenated UUID string (any case)? */
export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID.test(value)
}

/** Does a non-null JS value fit a column type? */
export function fitsType(value: unknown, type: ColumnType): boolean {
  switch (type) {
    case 'text':
      return typeof value === 'string'
    case 'uuid':
      return isUuid(value)
    case 'int4':
      return (
        typeof value === 'number' &&
        Number.isInteger(value) &&
        value >= INT4_MIN &&
        value <= INT4_MAX
      )
    case 'float8':
      return typeof value === 'number' && Number.isFinite(value)
    case 'bool':
      return typeof value === 'boolean'
  }
}

/** Numeric types allow ordering operators (`gt`, `between`, …). */
export function isNumeric(type: ColumnType): boolean {
  return type === 'int4' || type === 'float8'
}
