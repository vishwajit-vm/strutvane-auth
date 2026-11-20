/**
 * AUTH-4 on a real PostgreSQL 18: owner rules on BIGINT keys (the skeleton's `users.id` and every
 * generated table, `t.id()`), compiled by auth's SQL compiler and run through node-postgres, select
 * exactly the rows the in-memory check allows. node-postgres reads BIGINT as a string, so the rows
 * are compared by an int4 cast, the way an app's ORM would type them.
 */
import type { Actor } from '@strutvane/framework/contracts'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { definePolicy } from '../../src/policy/policy.ts'
import { defineSchema } from '../../src/policy/schema.ts'
import { compileToSql } from '../../src/sql/index.ts'
import { createDatabase, type TestDatabase } from './helpers.ts'

const docs = defineSchema({
  table: 'docs',
  columns: {
    id: { column: 'id', type: 'int4' },
    owner_id: { column: 'owner_id', type: 'int4' },
  },
})
const policy = definePolicy('doc', { schema: docs }, ({ allow }) => {
  allow('view', { when: ({ row, actor }) => row.owner_id.eq(actor.id) })
  allow('peek', { when: ({ row, actor }) => row.owner_id.ne(actor.id) })
  allow('share', { when: ({ row, actor }) => row.owner_id.in([actor.id, 3]) })
})
const ROWS = [
  { id: 1, owner_id: 1 },
  { id: 2, owner_id: 2 },
  { id: 3, owner_id: 3 },
  { id: 4, owner_id: 1 },
] as const
const actor = (id: string): Actor => ({ id, type: 'user', roles: [], attrs: {} })

describe('owner rules on BIGINT keys (real PostgreSQL)', () => {
  let db: TestDatabase
  beforeAll(async () => {
    db = await createDatabase()
    await db.admin.query('CREATE TABLE docs (id BIGSERIAL PRIMARY KEY, owner_id BIGINT NOT NULL)')
    for (const row of ROWS)
      await db.admin.query('INSERT INTO docs (id, owner_id) VALUES ($1, $2)', [
        row.id,
        row.owner_id,
      ])
  })
  afterAll(async () => {
    await db.drop()
  })

  it.each([
    ['1', 'view'],
    ['2', 'view'],
    ['01', 'view'],
    ['not-a-number', 'view'],
    ['1', 'peek'],
    ['not-a-number', 'peek'],
    ['2', 'share'],
    ['99999999999', 'share'],
  ] as const)('actor %s may %s exactly the rows memory allows', async (who, action) => {
    const filter = policy.filterFor(actor(who), action)
    const { sql, params } = compileToSql(filter, docs, { alias: 't' })
    const result = await db.admin.query<{ id: number }>(
      `SELECT t.id::int4 AS id FROM docs t WHERE ${sql} ORDER BY t.id`,
      params as unknown[],
    )
    const expected = ROWS.filter((row) => policy.can(actor(who), action, row)).map((row) => row.id)
    expect(result.rows.map((row) => row.id)).toEqual(expected)
  })
})
