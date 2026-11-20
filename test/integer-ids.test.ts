/**
 * AUTH-4 (demo acceptance run): owner rules on integer primary keys.
 *
 * Every table a Strutvane app generates has an integer key (`t.id()`, BIGINT), and `users.id` is
 * one too, while `actor.id` is a string in the contracts. A rule such as `row.id.eq(actor.id)` on an
 * `int4` column must therefore bind the id as the integer it spells, and fail closed for anything
 * else. Checked in memory, in the Postgres compiler on PGlite, and through the framework ORM's
 * `wherePolicy` on SQLite (node:sqlite) and on the MySQL and MariaDB grammars (rendered SQL; the
 * unit gate has no MySQL server).
 */
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { PGlite } from '@electric-sql/pglite'
import type { Actor, QueryFilter } from '@strutvane/framework/contracts'
import {
  Connection,
  Model,
  mariadbGrammar,
  mysqlGrammar,
  registerSchema,
  sqliteDriver,
  useConnection,
} from '@strutvane/framework/database'
import { afterAll, describe, expect, it } from 'vitest'
import { actorIdFor, resolveActorRef } from '../src/policy/bind.ts'
import { definePolicy } from '../src/policy/policy.ts'
import { createPermissionProvider } from '../src/policy/provider.ts'
import { compileRoleMap } from '../src/policy/roles.ts'
import { defineSchema } from '../src/policy/schema.ts'
import { compileToSql } from '../src/sql/index.ts'

/** The skeleton's `users` and a generated table, as policies see them (field = column name). */
const users = defineSchema({
  table: 'users',
  columns: { id: { column: 'id', type: 'int4' }, name: { column: 'name', type: 'text' } },
})
const docs = defineSchema({
  table: 'docs',
  columns: {
    id: { column: 'id', type: 'int4' },
    owner_id: { column: 'owner_id', type: 'int4' },
    title: { column: 'title', type: 'text' },
  },
})

const actor = (id: string, roles: string[] = []): Actor => ({ id, type: 'user', roles, attrs: {} })

/** The skeleton's UserPolicy, as a definePolicy: people see their own record. */
const userPolicy = definePolicy('user', { schema: users }, ({ allow }) => {
  allow(['view', 'update'], { when: ({ row, actor: me }) => row.id.eq(me.id) })
})
const docPolicy = definePolicy('doc', { schema: docs }, ({ allow }) => {
  allow('viewAny')
  allow('view', { when: ({ row, actor: me }) => row.owner_id.eq(me.id) })
  // `ne` inside an allow: an id that is not an integer must not turn into "every row".
  allow('peek', { when: ({ row, actor: me }) => row.owner_id.ne(me.id) })
  allow('share', { when: ({ row, actor: me }) => row.owner_id.in([me.id, 3]) })
})

describe('actorIdFor: how actor.id binds on an int4 column', () => {
  it.each([
    ['42', 42],
    ['0', 0],
    ['-7', -7],
    ['2147483647', 2147483647],
    ['-2147483648', -2147483648],
  ])('%s binds to the integer %s', (id, value) => {
    expect(actorIdFor(id, 'int4')).toBe(value)
  })

  it.each([
    '042',
    '-0',
    '+42',
    '4.2',
    '4e1',
    ' 42',
    '42 ',
    '0x2a',
    '',
    '2147483648',
    '-2147483649',
    '99999999999',
    '0190f2a0-0000-7000-8000-00000000000a',
    'svc:billing',
  ])('%j never matches (binds to null)', (id) => {
    expect(actorIdFor(id, 'int4')).toBeNull()
  })

  it('numbers pass only when they fit int4; text and uuid columns get the id unchanged', () => {
    expect(actorIdFor(7, 'int4')).toBe(7)
    expect(actorIdFor(1.5, 'int4')).toBeNull()
    expect(actorIdFor(2 ** 31, 'int4')).toBeNull()
    expect(actorIdFor('042', 'text')).toBe('042')
    expect(actorIdFor('42', 'uuid')).toBe('42')
    expect(actorIdFor('42', undefined)).toBe('42')
    expect(resolveActorRef({ $actor: 'id' }, actor('9'), 'int4')).toBe(9)
    expect(resolveActorRef({ $actor: 'id' }, null, 'int4')).toBeNull()
  })
})

describe('definePolicy with integer keys', () => {
  it('the skeleton user rule: a user sees and updates only their own row', () => {
    expect(userPolicy.can(actor('1'), 'view', { id: 1, name: 'Ada' })).toBe(true)
    expect(userPolicy.can(actor('1'), 'update', { id: 1, name: 'Ada' })).toBe(true)
    expect(userPolicy.can(actor('1'), 'view', { id: 2, name: 'Bob' })).toBe(false)
    expect(userPolicy.can(null, 'view', { id: 1, name: 'Ada' })).toBe(false)
    // Not a canonical integer: never anyone's row (fail closed), never an error.
    expect(userPolicy.can(actor('01'), 'view', { id: 1, name: 'Ada' })).toBe(false)
    expect(
      userPolicy.can(actor('0190f2a0-0000-7000-8000-00000000000a'), 'view', { id: 1, name: 'Ada' }),
    ).toBe(false)
  })

  it('list filters carry the integer, and an unusable id filters to nothing', () => {
    expect(userPolicy.filterFor(actor('12'), 'view')).toEqual({ op: 'eq', field: 'id', value: 12 })
    expect(userPolicy.filterFor(actor('abc'), 'view')).toEqual({ op: 'false' })
    expect(userPolicy.filterFor(null, 'view')).toEqual({ op: 'false' })
  })

  it('ne and in inside an allow rule stay fail-closed for a non-integer id', () => {
    expect(docPolicy.filterFor(actor('5'), 'peek')).toEqual({
      op: 'ne',
      field: 'owner_id',
      value: 5,
    })
    // `ne(null)` alone would be TRUE (every row); in an allow rule it narrows to nothing.
    expect(docPolicy.filterFor(actor('x'), 'peek')).toEqual({ op: 'false' })
    expect(docPolicy.filterFor(actor('x'), 'share')).toEqual({
      op: 'in',
      field: 'owner_id',
      values: [3],
    })
    expect(docPolicy.filterFor(actor('8'), 'share')).toEqual({
      op: 'in',
      field: 'owner_id',
      values: [8, 3],
    })
  })

  it('the role map own: true works on an int4 ownerId', async () => {
    const schema = defineSchema({
      table: 'tickets',
      columns: {
        id: { column: 'id', type: 'int4' },
        ownerId: { column: 'owner_id', type: 'int4' },
      },
    })
    const tickets = definePolicy('ticket', { schema }, () => undefined)
    const provider = createPermissionProvider([tickets], {
      roles: compileRoleMap({
        roles: { member: { permissions: [{ action: '*.update', own: true }] } },
      }),
    })
    const member = actor('7', ['member'])
    const can = async (record: Record<string, unknown>) =>
      (await provider.can(member, 'ticket.update', { type: 'ticket', record })).allowed
    expect(await can({ id: 1, ownerId: 7 })).toBe(true)
    expect(await can({ id: 2, ownerId: 8 })).toBe(false)
    expect(await provider.filterFor(member, 'ticket.update', 'ticket')).toEqual({
      op: 'eq',
      field: 'ownerId',
      value: 7,
    })
    expect(await provider.filterFor(actor('7a', ['member']), 'ticket.update', 'ticket')).toEqual({
      op: 'false',
    })
  })
})

/** Rows every engine gets: three docs, two of them owned by user 1. */
const ROWS = [
  { id: 1, owner_id: 1, title: 'a' },
  { id: 2, owner_id: 2, title: 'b' },
  { id: 3, owner_id: 1, title: 'c' },
] as const

describe('PostgreSQL (PGlite, BIGINT keys): the compiled SQL agrees with memory', () => {
  const pg = new PGlite()
  afterAll(() => pg.close())

  it('owner rules select exactly the rows the in-memory check allows', async () => {
    await pg.exec(
      'CREATE TABLE docs (id BIGINT PRIMARY KEY, owner_id BIGINT NOT NULL, title TEXT NOT NULL)',
    )
    for (const row of ROWS)
      await pg.query('INSERT INTO docs (id, owner_id, title) VALUES ($1, $2, $3)', [
        row.id,
        row.owner_id,
        row.title,
      ])
    for (const [who, action] of [
      ['1', 'view'],
      ['2', 'view'],
      ['x', 'view'],
      ['1', 'peek'],
      ['x', 'peek'],
      ['2', 'share'],
    ] as const) {
      const filter = docPolicy.filterFor(actor(who), action)
      const { sql, params } = compileToSql(filter, docs, { alias: 't' })
      const result = await pg.query<{ id: number }>(
        `SELECT t.id::int4 AS id FROM docs t WHERE ${sql} ORDER BY t.id`,
        params as unknown[],
      )
      const expected = ROWS.filter((row) => docPolicy.can(actor(who), action, row)).map(
        (row) => row.id,
      )
      expect(
        result.rows.map((row) => row.id),
        `${who} ${action}`,
      ).toEqual(expected)
    }
  })
})

/**
 * The framework ORM's `wherePolicy` applies a policy's list filter on SQLite, MySQL and MariaDB
 * (auth's own compiler is Postgres-only). The fields above are named like their columns, so the
 * filter auth returns is exactly what the ORM binds.
 */
describe('the framework ORM (wherePolicy) with auth filters', () => {
  registerSchema({
    version: 1,
    tables: {
      docs: {
        name: 'docs',
        global: true,
        columns: [
          { name: 'id', kind: 'id', nullable: false },
          { name: 'owner_id', kind: 'foreignId', nullable: false },
          { name: 'title', kind: 'string', nullable: false, length: 100 },
        ],
        indexes: [],
      },
    },
  })
  // No app registry augmentation in a package test: the table name is not a known TableName.
  class Doc extends Model('docs' as never) {}
  const dir = mkdtempSync(join(tmpdir(), 'sv-auth-int-ids-'))
  afterAll(() => rmSync(dir, { recursive: true, force: true }))

  it('SQLite (node:sqlite, INTEGER keys): the same rows as memory', async () => {
    const file = join(dir, 'app.sqlite')
    const db = new DatabaseSync(file)
    db.exec('CREATE TABLE docs (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, title TEXT)')
    const insert = db.prepare('INSERT INTO docs (id, owner_id, title) VALUES (?, ?, ?)')
    for (const row of ROWS) insert.run(row.id, row.owner_id, row.title)
    db.close()
    const connection = new Connection(sqliteDriver(file))
    useConnection(connection)
    try {
      for (const [who, action] of [
        ['1', 'view'],
        ['2', 'view'],
        ['x', 'view'],
        ['1', 'peek'],
        ['x', 'peek'],
      ] as const) {
        const filter: QueryFilter = docPolicy.filterFor(actor(who), action)
        const ids = (
          await Doc.query()
            .wherePolicy(filter, { actor: actor(who) })
            .get()
        )
          .map((doc) => Number(Reflect.get(doc, 'id')))
          .sort((a, b) => a - b)
        const expected = ROWS.filter((row) => docPolicy.can(actor(who), action, row)).map(
          (row) => row.id,
        )
        expect(ids, `${who} ${action}`).toEqual(expected)
      }
    } finally {
      await connection.close()
    }
  })

  describe.each([
    ['mysql', mysqlGrammar],
    ['mariadb', mariadbGrammar],
  ] as const)('%s (rendered SQL)', (_name, grammar) => {
    it('compares the integer key with an integer parameter', () => {
      useConnection({ grammar } as unknown as Connection)
      const own = Doc.query()
        .wherePolicy(docPolicy.filterFor(actor('1'), 'view'), { actor: actor('1') })
        .toSql()
      expect(own.sql).toContain('`owner_id`')
      expect(own.params).toContain(1)
      expect(own.params).not.toContain('1')
      const nobody = Doc.query()
        .wherePolicy(docPolicy.filterFor(actor('x'), 'view'), { actor: actor('x') })
        .toSql()
      expect(nobody.params).toEqual([])
      expect(nobody.sql).not.toContain('`owner_id`')
    })
  })
})
