/**
 * Decision #2: the app owns its `users` table; auth ships its own tables (and the columns it adds
 * to `users`) as ordinary, driver-neutral migrations, and never creates or alters a table at
 * runtime.
 *
 * These tests run the shipped migrations through the framework itself (its replay sandbox, its
 * migrator, its offline SQL compiler) on top of a pinned copy of the skeleton's users migration.
 */
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { PGlite } from '@electric-sql/pglite'
import commands from '@strutvane/framework/commands'
import {
  Connection,
  pgliteDriver,
  replayInSandbox,
  rollbackMigrations,
  runMigrations,
  sqliteDriver,
} from '@strutvane/framework/database'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { pgliteClient, postgresAuthStore } from '../../src/engine/store/postgres.ts'
import { sqliteAuthStore } from '../../src/engine/store/sqlite.ts'
import { AUTH_MIGRATIONS, authMigrationsDirectory } from '../../src/migrations.ts'
import { appMigrationsFolder } from '../support/compile-auth-schema.ts'

type Replay = Awaited<ReturnType<typeof replayInSandbox>>

const USERS_MIGRATION = '0001_01_01_000000_create_users_table'
const AUTH_TABLES = [
  'user_roles',
  'auth_sessions',
  'auth_one_time_tokens',
  'two_factor_recovery_codes',
  'passkeys',
  'personal_access_tokens',
  'teams',
  'team_members',
  'team_invitations',
  'auth_counters',
]
const SKELETON_USER_COLUMNS = [
  'id',
  'name',
  'email',
  'email_verified_at',
  'password',
  'remember_token',
  'created_at',
  'updated_at',
]
const AUTH_USER_COLUMNS = [
  'two_factor_secret',
  'two_factor_confirmed_at',
  'two_factor_last_step',
  'current_team_id',
]

let folder = ''
let replay: Replay
beforeAll(async () => {
  folder = appMigrationsFolder()
  replay = await replayInSandbox(folder, { timeoutMs: 120_000 })
})
afterAll(() => rmSync(folder, { recursive: true, force: true }))

interface SyncCommand {
  readonly name: string
  run(ctx: unknown): Promise<unknown>
}

/** Run the framework's offline `node strut sync` on a project with these migrations. */
async function compileOffline(root: string): Promise<void> {
  const migrations = join(root, 'database', 'migrations')
  mkdirSync(migrations, { recursive: true })
  for (const file of readdirSync(folder)) copyFileSync(join(folder, file), join(migrations, file))
  const sync = (commands as readonly SyncCommand[]).find((c) => c.name === 'sync')
  const quiet = { line() {}, success() {}, info() {}, warn() {}, error() {} }
  await sync?.run({
    flags: {},
    requireProject: () => ({ root }),
    out: quiet,
    services: { env: {} },
  })
}

describe('shipped migrations', () => {
  it('migrations/ holds exactly the listed Schema-builder migrations, nothing else', () => {
    expect(readdirSync(authMigrationsDirectory()).sort()).toEqual([...AUTH_MIGRATIONS])
    for (const file of AUTH_MIGRATIONS)
      expect(file).toMatch(/^\d{4}_\d{2}_\d{2}_\d{6}_[a-z0-9_]+\.ts$/)
  })

  it('run after the skeleton users migration (names sort after it)', () => {
    expect(replay.migrations.map((m) => m.name)).toEqual([
      USERS_MIGRATION,
      ...AUTH_MIGRATIONS.map((f) => f.replace(/\.ts$/, '')),
    ])
  })

  it('compile for MySQL, MariaDB, PostgreSQL and SQLite; never create, drop or rename users', async () => {
    const root = mkdtempSync(join(tmpdir(), 'sv-auth-sync-'))
    try {
      await compileOffline(root)
      const sqlOf = (dialect: string) =>
        readFileSync(join(root, '.strutvane', 'sql', `migrations.${dialect}.sql`), 'utf8')
      for (const dialect of ['mysql', 'mariadb', 'postgres', 'sqlite']) {
        const text = sqlOf(dialect)
        const auth = text.slice(text.indexOf(`-- ${AUTH_MIGRATIONS[0]?.replace(/\.ts$/, '')}: up`))
        expect(auth.length, dialect).toBeGreaterThan(1000)
        const q = dialect === 'mysql' || dialect === 'mariadb' ? '`' : '"'
        expect(auth, dialect).not.toMatch(
          new RegExp(`(CREATE|DROP) TABLE (IF EXISTS )?${q}users${q}`),
        )
        expect(auth, dialect).not.toMatch(/RENAME/i)
        const touchingUsers = auth
          .split('\n')
          .filter((line) => line.includes(`${q}users${q}`) && !line.includes('REFERENCES'))
        expect(touchingUsers.length, dialect).toBe(AUTH_USER_COLUMNS.length * 2) // up and down
        for (const line of touchingUsers)
          expect(line, dialect).toMatch(
            new RegExp(
              `^ALTER TABLE ${q}users${q} (ADD|DROP) COLUMN ${q}(${AUTH_USER_COLUMNS.join('|')})${q}`,
            ),
          )
      }
      // MySQL indexes a key of at most 3072 bytes (768 utf8mb4 characters): no index may cover
      // TEXT/JSON or exceed it, or the migration would fail on MySQL only.
      const mysql = sqlOf('mysql')
      const columns = new Map<string, string>()
      let table = ''
      for (const line of mysql.split('\n')) {
        const create = /^CREATE TABLE `(\w+)`/.exec(line)
        if (create) table = create[1] ?? ''
        const column = /^\s+`(\w+)` (\w+(?:\(\d+\))?)/.exec(line)
        if (column && table) columns.set(`${table}.${column[1]}`, column[2] ?? '')
      }
      const indexes = [...mysql.matchAll(/CREATE (?:UNIQUE )?INDEX `\w+` ON `(\w+)` \(([^)]+)\)/g)]
      expect(indexes.length).toBeGreaterThan(15)
      for (const [, on, cols] of indexes) {
        let bytes = 0
        for (const col of (cols ?? '').split(',')) {
          const type = columns.get(`${on}.${col.trim().replaceAll('`', '')}`) ?? ''
          expect(type, `${on} (${cols})`).not.toMatch(/TEXT|JSON|^$/)
          const varchar = /^VARCHAR\((\d+)\)$/.exec(type)
          bytes += varchar ? Number(varchar[1]) * 4 : 8
        }
        expect(bytes, `${on} (${cols})`).toBeLessThanOrEqual(3072)
      }
      // Every auth table is internal: no generic CRUD API, no sidebar entry (F-01).
      const resources = JSON.parse(
        readFileSync(join(root, '.strutvane', 'resources.json'), 'utf8'),
      ) as { internal: readonly string[] }
      for (const name of AUTH_TABLES) expect(resources.internal).toContain(name)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})

/** Columns of `table` on SQLite. */
const sqliteColumns = (db: DatabaseSync, table: string): string[] =>
  (db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[]).map((c) => c.name)

describe('migrate and roll back', () => {
  it('sqlite: migrate adds the columns and tables; rolling back auth leaves users as the app made it', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sv-auth-db-'))
    const file = join(dir, 'app.sqlite')
    const connection = new Connection(sqliteDriver(file))
    try {
      await runMigrations(connection, replay, { step: true })
      const db = new DatabaseSync(file)
      try {
        expect(sqliteColumns(db, 'users')).toEqual([...SKELETON_USER_COLUMNS, ...AUTH_USER_COLUMNS])
        expect(await sqliteAuthStore(db).findUserByEmail('nobody@acme.test')).toBeUndefined()
      } finally {
        db.close()
      }
      expect((await runMigrations(connection, replay)).ran).toEqual([]) // a second run: no-op
      await rollbackMigrations(connection, replay, { step: AUTH_MIGRATIONS.length })
      const after = new DatabaseSync(file)
      try {
        expect(sqliteColumns(after, 'users')).toEqual(SKELETON_USER_COLUMNS)
        const tables = (
          after.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as {
            name: string
          }[]
        ).map((t) => t.name)
        for (const name of AUTH_TABLES) expect(tables).not.toContain(name)
      } finally {
        after.close()
      }
    } finally {
      await connection.close()
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('postgres: the same, on PGlite', async () => {
    const pg = await PGlite.create()
    const connection = new Connection(pgliteDriver(pg))
    const columns = async (): Promise<string[]> =>
      (
        await pg.query<{ column_name: string }>(
          "SELECT column_name FROM information_schema.columns WHERE table_name = 'users' ORDER BY ordinal_position",
        )
      ).rows.map((r) => r.column_name)
    try {
      await runMigrations(connection, replay, { step: true })
      expect(await columns()).toEqual([...SKELETON_USER_COLUMNS, ...AUTH_USER_COLUMNS])
      expect(
        await postgresAuthStore(pgliteClient(pg)).findUserByEmail('nobody@acme.test'),
      ).toBeUndefined()
      await rollbackMigrations(connection, replay, { step: AUTH_MIGRATIONS.length })
      expect(await columns()).toEqual(SKELETON_USER_COLUMNS)
      const tables = await pg.query<{ table_name: string }>(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
      )
      for (const name of AUTH_TABLES)
        expect(tables.rows.map((r) => r.table_name)).not.toContain(name)
    } finally {
      await connection.close()
    }
  })
})

describe('no runtime DDL (decision #2)', () => {
  it('the stores never create a table: on an empty database they fail and leave it empty', async () => {
    const db = new DatabaseSync(':memory:')
    const store = sqliteAuthStore(db)
    await expect(store.findUserByEmail('a@acme.test')).rejects.toThrow(/no such table: users/)
    expect(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all()).toEqual([])
    const pg = await PGlite.create()
    try {
      await expect(
        postgresAuthStore(pgliteClient(pg)).findUserByEmail('a@acme.test'),
      ).rejects.toThrow(/relation "users" does not exist/)
      const tables = await pg.query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
      )
      expect(tables.rows).toEqual([])
    } finally {
      await pg.close()
    }
  })

  it('no source file creates, drops or alters the users table', () => {
    const src = new URL('../../src/', import.meta.url)
    const files = readdirSync(src, { recursive: true, encoding: 'utf8' }).filter((f) =>
      f.endsWith('.ts'),
    )
    expect(files.length).toBeGreaterThan(50)
    const ddl =
      /\b(?:create|alter|drop)\s+table\s+(?:if\s+(?:not\s+)?exists\s+)?["`]?users["`]?(?:\s|\(|$)/im
    for (const file of files) {
      const text = readFileSync(new URL(file.replaceAll('\\', '/'), src), 'utf8')
      expect(text, file).not.toMatch(ddl)
    }
    // The pattern does catch what it guards against.
    expect('CREATE TABLE IF NOT EXISTS users (').toMatch(ddl)
    expect('ALTER TABLE "users" ADD COLUMN x').toMatch(ddl)
  })
})
