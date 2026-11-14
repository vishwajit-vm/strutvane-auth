/**
 * `relationKeyAudit`: check that every to-one relation in your policy schemas points at a UNIQUE
 * key. The SQL compiler reads relation fields with a scalar subquery
 * (`(SELECT … WHERE target_key = t.foreign_key)`), which fails at runtime if more than one row
 * matches, while the in-memory evaluator sees exactly one nested object. A unique target key keeps
 * both paths equivalent and list queries working. Run it in CI after migrations or from `sv doctor`.
 *
 * @module
 */
import { type ModelSchema, quoteTable } from '../policy/schema.ts'
import type { Queryable } from './audit-query.ts'

/** One relation whose target key is not provably unique. */
export interface RelationKeyFinding {
  readonly severity: 'error'
  readonly code: 'RELATION_TABLE_MISSING' | 'RELATION_KEY_NOT_UNIQUE'
  /** `table.column` of the target key. */
  readonly object: string
  readonly message: string
}

const CHECK = `
SELECT to_regclass($1) IS NOT NULL AS found,
       EXISTS (SELECT 1 FROM pg_catalog.pg_index i
               JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
               WHERE i.indrelid = to_regclass($1) AND i.indisunique AND i.indnkeyatts = 1
                 AND i.indpred IS NULL AND a.attname = $2) AS "unique"`

/** Inspect the database; an empty result means every relation key is backed by a unique index. */
export async function relationKeyAudit(
  db: Queryable,
  schemas: readonly ModelSchema[],
): Promise<RelationKeyFinding[]> {
  const findings: RelationKeyFinding[] = []
  const seen = new Set<string>()
  for (const schema of schemas) {
    for (const rel of Object.values(schema.relations ?? {})) {
      const object = `${rel.table}.${rel.targetKey}`
      if (seen.has(object)) continue
      seen.add(object)
      // quoteTable validates the identifiers (trusted schema metadata, still pattern-checked).
      const row = (await db.query(CHECK, [quoteTable(rel.table), rel.targetKey])).rows[0] as
        | { found: boolean; unique: boolean }
        | undefined
      if (!row?.found) {
        findings.push({
          severity: 'error',
          code: 'RELATION_TABLE_MISSING',
          object,
          message: `Relation table ${rel.table} does not exist (or is not visible to this role).`,
        })
      } else if (!row.unique) {
        findings.push({
          severity: 'error',
          code: 'RELATION_KEY_NOT_UNIQUE',
          object,
          message: `${object} has no single-column unique index; policy filters reading this relation can fail with "more than one row returned by a subquery". Make it the primary key or add a UNIQUE constraint.`,
        })
      }
    }
  }
  return findings
}
