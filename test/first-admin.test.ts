/**
 * Decision #13: `createFirstAdmin()` creates the app's first administrator from a seeder, on the
 * seeder's own framework connection, on every engine. Real SQLite (a file) and PostgreSQL
 * (PGlite) with the real migrated schema; MySQL/MariaDB through a recording connection that
 * renders the SQL with the framework's MySQL grammar (no server in the unit gate).
 */
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { PGlite } from '@electric-sql/pglite'
import {
  Connection,
  mariadbGrammar,
  mysqlGrammar,
  pgliteDriver,
  type SqlFragment,
  sqliteDriver,
} from '@strutvane/framework/database'
import { afterAll, describe, expect, it } from 'vitest'
import { createScryptHasher } from '../src/engine/password/hasher.ts'
import {
  pgliteClient,
  postgresAuthStore,
  postgresCounterStore,
} from '../src/engine/store/postgres.ts'
import { sqliteAuthStore, sqliteCounterStore } from '../src/engine/store/sqlite.ts'
import {
  createFirstAdmin,
  type FirstAdminConnection,
  FirstAdminError,
  type FirstAdminErrorCode,
} from '../src/first-admin.ts'
import { createNativeEngine } from '../src/identity/native.ts'
import { browserRequest, freshIp, TEST_PROXY } from '../src/testing/index.ts'
import { authSchema, sqliteWithAuthSchema } from './support/auth-schema.ts'

const hasher = createScryptHasher({ params: { logN: 14, r: 8, p: 1 } })
const APP_KEY = `base64:${Buffer.alloc(32, 3).toString('base64')}`
const URL_ = 'http://localhost:3000'

const dir = mkdtempSync(join(tmpdir(), 'sv-auth-first-admin-'))
const cleanups: (() => Promise<void>)[] = []
afterAll(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup()
  rmSync(dir, { recursive: true, force: true })
})

/** A migrated database on one engine: the seeder's connection, plus the app's identity engine. */
interface Db {
  readonly connection: Connection
  engine(): ReturnType<typeof createNativeEngine>
  count(table: string): Promise<number>
  user(email: string): Promise<Record<string, unknown> | undefined>
}

let files = 0
async function sqlite(): Promise<Db> {
  const file = join(dir, `app-${++files}.sqlite`)
  sqliteWithAuthSchema(file).close()
  const connection = new Connection(sqliteDriver(file))
  const raw = new DatabaseSync(file)
  cleanups.push(async () => {
    raw.close()
    await connection.close()
  })
  return {
    connection,
    engine: () =>
      createNativeEngine({
        config: { features: { registration: true, teams: true } },
        baseURL: URL_,
        appKey: APP_KEY,
        trustedProxies: [TEST_PROXY],
        deliverPasswordReset: async () => undefined,
        store: sqliteAuthStore(raw),
        counters: sqliteCounterStore(raw),
      }),
    count: async (table) =>
      Number((raw.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n),
    user: async (email) =>
      raw.prepare('SELECT * FROM users WHERE email = ?').get(email) as
        | Record<string, unknown>
        | undefined,
  }
}

async function postgres(): Promise<Db> {
  const pg = await PGlite.create()
  for (const statement of authSchema('postgres')) await pg.query(statement)
  const connection = new Connection(pgliteDriver(pg))
  cleanups.push(async () => {
    await connection.close()
    await pg.close().catch(() => undefined)
  })
  const client = pgliteClient(pg)
  return {
    connection,
    engine: () =>
      createNativeEngine({
        config: { features: { registration: true, teams: true } },
        baseURL: URL_,
        appKey: APP_KEY,
        trustedProxies: [TEST_PROXY],
        deliverPasswordReset: async () => undefined,
        store: postgresAuthStore(client),
        counters: postgresCounterStore(client),
      }),
    count: async (table) =>
      Number((await pg.query<{ n: number }>(`SELECT COUNT(*)::int AS n FROM ${table}`)).rows[0]?.n),
    user: async (email) =>
      (await pg.query<Record<string, unknown>>('SELECT * FROM users WHERE email = $1', [email]))
        .rows[0],
  }
}

async function refused(
  run: () => Promise<unknown>,
  code: FirstAdminErrorCode,
): Promise<FirstAdminError> {
  const error = await run().then(
    () => undefined,
    (e: unknown) => e,
  )
  expect(error).toBeInstanceOf(FirstAdminError)
  expect((error as FirstAdminError).code).toBe(code)
  return error as FirstAdminError
}

describe.each([
  ['sqlite', sqlite],
  ['postgres', postgres],
] as const)('createFirstAdmin (%s)', (_name, open) => {
  it('creates the admin once, with a one-time password the app signs in with', async () => {
    const db = await open()
    const admin = await createFirstAdmin(
      db.connection,
      { email: '  Owner@Acme.TEST ', name: 'Olivia' },
      { hasher },
    )
    expect(admin.email).toBe('owner@acme.test')
    expect(admin.role).toBe('admin')
    expect(admin.userId).toMatch(/^[1-9][0-9]*$/)
    expect(admin.oneTimePassword).toMatch(/^[A-Za-z0-9_-]{24}$/)
    expect(Object.isFrozen(admin)).toBe(true)
    expect(Object.keys(admin).sort()).toEqual(['email', 'oneTimePassword', 'role', 'userId'])

    const row = await db.user('owner@acme.test')
    expect(String(row?.['password'])).toMatch(/^\$scrypt\$/)
    expect(String(row?.['password'])).not.toContain(admin.oneTimePassword ?? '-')
    expect(row?.['name']).toBe('Olivia')
    expect(row?.['email_verified_at']).not.toBeNull()
    expect(row?.['created_at']).not.toBeNull()
    expect(await db.count('user_roles')).toBe(1)

    // The running app (native engine on the same database) accepts the password and the role.
    const engine = db.engine()
    const signedIn = await engine.signIn(
      { email: 'owner@acme.test', password: admin.oneTimePassword ?? '' },
      browserRequest(URL_, { ip: freshIp() }),
    )
    expect(signedIn.ok ? signedIn.value.actor.roles : signedIn.error).toEqual(['admin'])
    expect(signedIn.ok ? signedIn.value.actor.id : null).toBe(admin.userId)
  })

  it('refuses a second admin and changes nothing (re-running the seeder is safe)', async () => {
    const db = await open()
    await createFirstAdmin(db.connection, { email: 'owner@acme.test' }, { hasher })
    const before = await db.user('owner@acme.test')
    const error = await refused(
      () => createFirstAdmin(db.connection, { email: 'owner@acme.test' }, { hasher }),
      'first_admin_exists',
    )
    expect(error.message).toMatch(/nothing was changed/)
    await refused(
      () => createFirstAdmin(db.connection, { email: 'second@acme.test' }, { hasher }),
      'first_admin_exists',
    )
    expect(await db.count('users')).toBe(1)
    expect(await db.count('user_roles')).toBe(1)
    expect((await db.user('owner@acme.test'))?.['password']).toBe(before?.['password'])
  })

  it('never takes over an existing account with the same email', async () => {
    const db = await open()
    const engine = db.engine()
    const existing = await engine.createUserAsSystem({
      email: 'taken@acme.test',
      name: 'Someone',
      password: 'someone else entirely',
    })
    expect(existing.ok).toBe(true)
    await refused(
      () => createFirstAdmin(db.connection, { email: 'taken@acme.test' }, { hasher }),
      'email_taken',
    )
    expect(await db.count('user_roles')).toBe(0)
    expect((await db.user('taken@acme.test'))?.['name']).toBe('Someone')
  })

  it('uses a given password (no one-time password returned) and never echoes it in errors', async () => {
    const db = await open()
    const weak = 'aaaaaaaaaaaaaaaa'
    const error = await refused(
      () => createFirstAdmin(db.connection, { email: 'a@acme.test', password: weak }, { hasher }),
      'validation_failed',
    )
    expect(error.message).not.toContain(weak)
    await refused(
      () =>
        createFirstAdmin(db.connection, { email: 'a@acme.test', password: 'short' }, { hasher }),
      'validation_failed',
    )
    expect(await db.count('users')).toBe(0)
    const chosen = 'an unusual seeding passphrase 7'
    const admin = await createFirstAdmin(
      db.connection,
      { email: 'a@acme.test', password: chosen, role: 'manager' },
      { hasher },
    )
    expect(admin.oneTimePassword).toBeUndefined()
    expect(admin.role).toBe('manager')
    const signedIn = await db
      .engine()
      .signIn({ email: 'a@acme.test', password: chosen }, browserRequest(URL_, { ip: freshIp() }))
    expect(signedIn.ok ? signedIn.value.actor.roles : signedIn.error).toEqual(['manager'])
  })

  it('validates the email, name and role before touching the database', async () => {
    const db = await open()
    for (const input of [
      { email: 'not an email' },
      { email: 'admin​@acme.test' },
      { email: 'a@acme.test', name: '   ' },
      { email: 'a@acme.test', name: 'x'.repeat(201) },
      { email: 'a@acme.test', role: 'Admin' },
      { email: 'a@acme.test', role: "admin'; DROP TABLE users; --" },
      { email: 'a@acme.test', role: 'owner' },
    ])
      await refused(() => createFirstAdmin(db.connection, input, { hasher }), 'validation_failed')
    expect(await db.count('users')).toBe(0)
  })

  it('two concurrent runs create exactly one admin', async () => {
    const db = await open()
    const results = await Promise.allSettled([
      createFirstAdmin(db.connection, { email: 'one@acme.test' }, { hasher }),
      createFirstAdmin(db.connection, { email: 'two@acme.test' }, { hasher }),
    ])
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
    expect(await db.count('user_roles')).toBe(1)
  })
})

describe('createFirstAdmin: fails closed', () => {
  it("names the fix when auth's migrations have not run (sqlite and postgres)", async () => {
    // Only the skeleton's users table: the two statements of its migration.
    const file = join(dir, 'bare.sqlite')
    const bare = new DatabaseSync(file)
    for (const statement of authSchema('sqlite').slice(0, 2)) bare.exec(statement)
    bare.close()
    const connection = new Connection(sqliteDriver(file))
    try {
      const error = await refused(
        () => createFirstAdmin(connection, { email: 'a@acme.test' }, { hasher }),
        'auth_tables_missing',
      )
      expect(error.message).toMatch(/auth:migration.*migrate/)
    } finally {
      await connection.close()
    }
    const pg = await PGlite.create()
    const pgConnection = new Connection(pgliteDriver(pg))
    try {
      await refused(
        () => createFirstAdmin(pgConnection, { email: 'a@acme.test' }, { hasher }),
        'auth_tables_missing',
      )
    } finally {
      await pgConnection.close()
    }
  })

  it('passes on database errors it does not recognise', async () => {
    const broken: FirstAdminConnection = {
      grammar: mysqlGrammar,
      run: async () => {
        throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })
      },
      transaction: async (fn) => fn(),
    } as FirstAdminConnection
    await expect(createFirstAdmin(broken, { email: 'a@acme.test' }, { hasher })).rejects.toThrow(
      /ECONNREFUSED/,
    )
  })
})

/** A connection that renders every statement with a real framework grammar and answers from a script. */
function recording(
  grammar: typeof mysqlGrammar,
  answer: (sql: string) => Record<string, unknown>[],
) {
  const statements: { sql: string; params: readonly unknown[] }[] = []
  const connection = {
    grammar,
    run: async (fragment: SqlFragment) => {
      const rendered = grammar.render(fragment)
      statements.push(rendered)
      return { rows: answer(rendered.sql), rowsAffected: 1 }
    },
    transaction: async <T>(fn: () => Promise<T>) => fn(),
  } as unknown as FirstAdminConnection
  return { connection, statements }
}

describe.each([
  ['mysql', mysqlGrammar],
  ['mariadb', mariadbGrammar],
] as const)('createFirstAdmin on %s (rendered SQL)', (_name, grammar) => {
  it('locks the role rows, writes MySQL DATETIME text and reads the id back', async () => {
    const { connection, statements } = recording(grammar, (sql) =>
      sql.startsWith('SELECT `id` FROM `users`') &&
      statements.some((s) => s.sql.startsWith('INSERT INTO `users`'))
        ? [{ id: 41 }]
        : [],
    )
    const admin = await createFirstAdmin(connection, { email: 'a@acme.test' }, { hasher })
    expect(admin.userId).toBe('41')
    const select = statements.find((s) => s.sql.includes('FROM `user_roles` WHERE `role` ='))
    expect(select?.sql).toMatch(/FOR UPDATE$/)
    const insert = statements.find((s) => s.sql.startsWith('INSERT INTO `users`'))
    const [, , hash, verified, created, updated] = insert?.params ?? []
    expect(String(hash)).toMatch(/^\$scrypt\$/)
    for (const value of [verified, created, updated])
      expect(String(value)).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$/)
    const role = statements.find((s) => s.sql.startsWith('INSERT INTO `user_roles`'))
    expect(role?.params).toEqual([41, 'admin'])
    // Every value is bound: the password never appears in SQL text.
    for (const s of statements) expect(s.sql).not.toContain(admin.oneTimePassword ?? '-')
  })

  it('reports an existing admin as first_admin_exists', async () => {
    const { connection } = recording(grammar, (sql) =>
      sql.includes('FROM `user_roles` WHERE') ? [{ user_id: 1 }] : [],
    )
    await refused(
      () => createFirstAdmin(connection, { email: 'a@acme.test' }, { hasher }),
      'first_admin_exists',
    )
  })

  it("maps MySQL's missing-table error to auth_tables_missing", async () => {
    const connection = {
      grammar,
      run: async () => {
        throw Object.assign(new Error("Table 'app.user_roles' doesn't exist"), {
          code: 'ER_NO_SUCH_TABLE',
        })
      },
      transaction: async <T>(fn: () => Promise<T>) => fn(),
    } as unknown as FirstAdminConnection
    await refused(
      () => createFirstAdmin(connection, { email: 'a@acme.test' }, { hasher }),
      'auth_tables_missing',
    )
  })
})
