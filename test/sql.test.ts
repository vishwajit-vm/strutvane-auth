/** The SQL compiler's output shape, parameterisation and injection resistance. */
import type { QueryFilter } from '@strutvane/contracts'
import { describe, expect, it } from 'vitest'
import { InvalidFilterError, PolicyDefinitionError } from '../src/errors.ts'
import { compileToSql, compileToTokens, renderPostgres } from '../src/sql/index.ts'
import { ALICE, invoiceSchema } from './fixtures.ts'

const sql = (f: QueryFilter, alias?: string) =>
  compileToSql(f, invoiceSchema, alias ? { alias } : {})

describe('compileToSql', () => {
  it('compiles each operator to a two-valued, parameterised expression', () => {
    expect(sql({ op: 'eq', field: 'status', value: 'paid' })).toEqual({
      sql: '(("t"."status" COLLATE "C") IS NOT DISTINCT FROM $1::text)',
      params: ['paid'],
    })
    expect(sql({ op: 'ne', field: 'amount', value: 5 })).toEqual({
      sql: '("t"."amount" IS DISTINCT FROM $1::int4)',
      params: [5],
    })
    expect(sql({ op: 'gte', field: 'score', value: 1.5 }).sql).toBe(
      'COALESCE("t"."score" >= $1::float8, FALSE)',
    )
    expect(sql({ op: 'between', field: 'amount', from: 1, to: 9 })).toEqual({
      sql: 'COALESCE("t"."amount" BETWEEN $1::int4 AND $2::int4, FALSE)',
      params: [1, 9],
    })
    expect(sql({ op: 'in', field: 'ownerId', values: [ALICE] })).toEqual({
      sql: 'COALESCE("t"."owner_id" = ANY($1::uuid[]), FALSE)',
      params: [[ALICE]],
    })
    expect(sql({ op: 'nin', field: 'archived', values: [true] }).sql).toBe(
      '(NOT COALESCE("t"."archived" = ANY($1::bool[]), FALSE))',
    )
    expect(sql({ op: 'in', field: 'amount', values: [] }).sql).toBe('FALSE')
    expect(sql({ op: 'nin', field: 'amount', values: [] }).sql).toBe('TRUE')
    expect(sql({ op: 'isNull', field: 'title' }).sql).toBe('("t"."title" IS NULL)')
    expect(sql({ op: 'isNotNull', field: 'title' }).sql).toBe('("t"."title" IS NOT NULL)')
    expect(sql({ op: 'true' }).sql).toBe('TRUE')
    expect(sql({ op: 'and', filters: [] }).sql).toBe('TRUE')
    expect(sql({ op: 'or', filters: [] }).sql).toBe('FALSE')
    expect(sql({ op: 'not', filter: { op: 'false' } }).sql).toBe('(NOT FALSE)')
  })

  it('text operators never use LIKE, and fold only A–Z', () => {
    const contains = sql({ op: 'contains', field: 'title', value: 'A%_b' })
    expect(contains.sql).toBe(
      'COALESCE(strpos(translate(("t"."title" COLLATE "C"), \'ABCDEFGHIJKLMNOPQRSTUVWXYZ\', \'abcdefghijklmnopqrstuvwxyz\'), $1::text) > 0, FALSE)',
    )
    expect(contains.params).toEqual(['a%_b'])
    expect(sql({ op: 'startsWith', field: 'title', value: 'Ab', caseSensitive: true })).toEqual({
      sql: 'COALESCE(starts_with(("t"."title" COLLATE "C"), $1::text), FALSE)',
      params: ['Ab'],
    })
    expect(sql({ op: 'endsWith', field: 'title', value: 'X', caseSensitive: true })).toEqual({
      sql: 'COALESCE(right(("t"."title" COLLATE "C"), char_length($1::text)) = $2::text, FALSE)',
      params: ['X', 'X'],
    })
    for (const op of ['contains', 'startsWith', 'endsWith'] as const) {
      expect(sql({ op, field: 'title', value: 'x' }).sql).not.toMatch(/LIKE/i)
    }
  })

  it('compiles relation fields to correlated scalar subqueries with generated aliases', () => {
    expect(sql({ op: 'eq', field: 'customer.region', value: 'eu' }, 'inv').sql).toBe(
      '(((SELECT "sv_rel_0"."region" FROM "customers" AS "sv_rel_0" WHERE "sv_rel_0"."id" = "inv"."customer_id") COLLATE "C") IS NOT DISTINCT FROM $1::text)',
    )
  })

  it('groups AND / OR with parentheses and keeps parameter order', () => {
    const r = sql({
      op: 'or',
      filters: [
        {
          op: 'and',
          filters: [
            { op: 'eq', field: 'status', value: 'a' },
            { op: 'gt', field: 'amount', value: 1 },
          ],
        },
        { op: 'not', filter: { op: 'eq', field: 'status', value: 'b' } },
      ],
    })
    expect(r.sql).toBe(
      '(((("t"."status" COLLATE "C") IS NOT DISTINCT FROM $1::text) AND COALESCE("t"."amount" > $2::int4, FALSE)) OR (NOT (("t"."status" COLLATE "C") IS NOT DISTINCT FROM $3::text)))',
    )
    expect(r.params).toEqual(['a', 1, 'b'])
  })

  it('renderPostgres can continue numbering an existing query', () => {
    const tokens = compileToTokens({ op: 'eq', field: 'status', value: 'x' }, invoiceSchema)
    expect(renderPostgres(tokens, 4).sql).toBe(
      '(("t"."status" COLLATE "C") IS NOT DISTINCT FROM $4::text)',
    )
    expect(() => renderPostgres(tokens, 0)).toThrow(RangeError)
    expect(() => renderPostgres(tokens, 1.5)).toThrow(RangeError)
  })

  it('textCollation: "database" leaves text columns on their own collation; bad values throw', () => {
    expect(
      compileToSql({ op: 'eq', field: 'status', value: 'x' }, invoiceSchema, {
        textCollation: 'database',
      }).sql,
    ).toBe('("t"."status" IS NOT DISTINCT FROM $1::text)')
    expect(() =>
      compileToSql({ op: 'true' }, invoiceSchema, { textCollation: 'nope' as 'C' }),
    ).toThrow(TypeError)
    // Non-text columns are never wrapped.
    expect(sql({ op: 'eq', field: 'ownerId', value: ALICE }).sql).not.toContain('COLLATE')
  })

  it('validates through the shared gate before compiling', () => {
    expect(() => sql({ op: 'eq', field: 'nope', value: 1 })).toThrow(InvalidFilterError)
    expect(() => sql({ op: 'gt', field: 'title', value: 'a' })).toThrow(InvalidFilterError)
    expect(() =>
      compileToSql({ op: 'eq', field: 'title', value: 'x'.repeat(20) }, invoiceSchema, {
        maxStringLength: 5,
      }),
    ).toThrow(InvalidFilterError)
  })
})

describe('SQL injection resistance', () => {
  const payloads = [
    "'; DROP TABLE invoices; --",
    "' OR '1'='1",
    '") OR TRUE --',
    '$99::text',
    '\\',
    "x' || pg_sleep(10) || '",
    '/* */ UNION SELECT * FROM users --',
  ]

  it.each(payloads)('a value never reaches the SQL text: %s', (payload) => {
    const r = sql({
      op: 'or',
      filters: [
        { op: 'eq', field: 'title', value: payload },
        { op: 'in', field: 'status', values: [payload] },
        { op: 'contains', field: 'title', value: payload, caseSensitive: true },
        { op: 'startsWith', field: 'customer.region', value: payload, caseSensitive: true },
      ],
    })
    expect(r.sql).not.toContain(payload)
    expect(r.params).toContain(payload)
  })

  it.each(payloads)('field names are only ever looked up, never interpolated: %s', (payload) => {
    expect(() => sql({ op: 'eq', field: payload, value: 'x' })).toThrow(InvalidFilterError)
  })

  it('aliases are validated identifiers', () => {
    expect(() => sql({ op: 'true' }, 't; DROP TABLE x')).toThrow(PolicyDefinitionError)
    expect(() => sql({ op: 'true' }, '"t"')).toThrow(PolicyDefinitionError)
  })
})
