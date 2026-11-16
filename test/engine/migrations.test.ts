/**
 * The identity tables ship as ordinary migrations (blueprint §6), one per dialect, in the
 * framework's file format. They must be exactly the DDL the stores are tested on, and must apply
 * cleanly to an empty database (and again, idempotently).
 */
import { readFileSync } from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import { PGlite } from '@electric-sql/pglite'
import { describe, expect, it } from 'vitest'
import { pgliteClient, postgresAuthStore } from '../../src/engine/store/postgres.ts'
import { POSTGRES_AUTH_STATEMENTS } from '../../src/engine/store/postgres-schema.ts'
import { sqliteAuthStore } from '../../src/engine/store/sqlite.ts'
import { SQLITE_SCHEMA } from '../../src/engine/store/sqlite-schema.ts'

const BREAKPOINT = '--> statement-breakpoint'
const file = (dialect: string) =>
  readFileSync(
    new URL(`../../migrations/${dialect}/20261116000000_create_auth_tables.sql`, import.meta.url),
    'utf8',
  )
/** The framework's reading of a migration: header comments, then statements between breakpoints. */
const statements = (text: string): string[] =>
  text
    .split(BREAKPOINT)
    .map((part) =>
      part
        .split('\n')
        .filter((line) => !line.startsWith('-- '))
        .join('\n')
        .trim()
        .replace(/;$/, ''),
    )
    .filter(Boolean)
const norm = (s: string) => s.replace(/\s+/g, ' ').trim()

describe('shipped migrations', () => {
  it('carry the framework header (name and dialect)', () => {
    for (const dialect of ['postgres', 'sqlite']) {
      const text = file(dialect)
      expect(text.startsWith('-- strutvane:migration\n-- name: create_auth_tables\n')).toBe(true)
      expect(text).toContain(`-- dialect: ${dialect}\n`)
    }
  })

  it('postgres: the same statements the store is tested on; applies twice on an empty database', async () => {
    const shipped = statements(file('postgres'))
    expect(shipped.map(norm)).toEqual(POSTGRES_AUTH_STATEMENTS.map(norm))
    const db = await PGlite.create()
    try {
      for (let run = 0; run < 2; run++) for (const s of shipped) await db.query(s)
      const store = postgresAuthStore(pgliteClient(db))
      expect(await store.findUserByEmail('nobody@acme.test')).toBeUndefined()
      const tables = await db.query<{ table_name: string }>(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1",
      )
      expect(tables.rows.map((r) => r.table_name)).toEqual([
        'auth_counters',
        'auth_one_time_tokens',
        'passkeys',
        'personal_access_tokens',
        'sessions',
        'team_invitations',
        'team_members',
        'teams',
        'two_factor_recovery_codes',
        'user_roles',
        'users',
      ])
    } finally {
      await db.close()
    }
  })

  it('sqlite: the same statements the store is tested on; applies twice on an empty database', async () => {
    const shipped = statements(file('sqlite'))
    const own = SQLITE_SCHEMA.split(';')
      .map((s) => s.trim())
      .filter(Boolean)
    expect(shipped.map(norm)).toEqual(own.map(norm))
    const db = new DatabaseSync(':memory:')
    try {
      for (let run = 0; run < 2; run++) for (const s of shipped) db.exec(s)
      expect(await sqliteAuthStore(db).findUserByEmail('nobody@acme.test')).toBeUndefined()
    } finally {
      db.close()
    }
  })
})
