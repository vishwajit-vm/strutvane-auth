/**
 * The PostgreSQL identity store on a REAL PostgreSQL 18 server (throwaway container), where
 * connections genuinely run in parallel. PGlite (the unit suites) runs one statement at a time,
 * so the races of CONSISTENCY #117 can only be shown here.
 */
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { manualClock } from '../../src/engine/ports/clock.ts'
import type { AuthStore, UserRecord } from '../../src/engine/ports/store.ts'
import {
  type PostgresClient,
  pgPoolClient,
  postgresAuthStore,
  postgresCounterStore,
} from '../../src/engine/store/postgres.ts'
import { Browser, harness, PASSWORD, rejectsWith, START } from '../engine/helpers/harness.ts'
import { authSchema } from '../support/auth-schema.ts'
import { createDatabase, ignoreForcedDrop, type TestDatabase } from './helpers.ts'

let db: TestDatabase
let client: PostgresClient
let store: AuthStore
const pools: pg.Pool[] = []

const user = (id: string): UserRecord => ({
  id,
  email: `${id}@acme.test`,
  name: id,
  passwordHash: null,
  emailVerifiedAt: null,
  twoFactorSecret: null,
  twoFactorConfirmedAt: null,
  twoFactorLastStep: null,
  currentTeamId: null,
  createdAt: START,
})

/** A second, independent pool on the same database: another app instance. */
function instance(): AuthStore {
  const pool = new pg.Pool({ connectionString: db.url(), max: 4 })
  pool.on('error', ignoreForcedDrop)
  pools.push(pool)
  return postgresAuthStore(pgPoolClient(pool))
}

beforeAll(async () => {
  db = await createDatabase()
  // What `node strut migrate` runs: the skeleton's users table, then auth's migrations.
  for (const statement of authSchema('postgres')) await db.admin.query(statement)
  client = pgPoolClient(db.admin)
  store = postgresAuthStore(client)
})

afterAll(async () => {
  for (const pool of pools) await pool.end().catch(() => undefined)
  await db?.drop()
})

async function teamWithTwoAdmins(id: string): Promise<void> {
  expect(
    await store.createTeam(
      { id, name: id, slug: null, personal: false, createdAt: START },
      { teamId: id, userId: `${id}-a`, role: 'admin' },
    ),
  ).toBe(true)
  await store.putMember({ teamId: id, userId: `${id}-b`, role: 'admin' })
}

const admins = async (teamId: string) =>
  (await store.listMembers(teamId)).filter((m) => m.role === 'admin').length

describe('PostgreSQL store on a real server: races (#117)', () => {
  it('last-admin guard: a change that waits on another instance sees its commit', async () => {
    await teamWithTwoAdmins('t-lock')
    // Another instance is mid-way through demoting admin A: it holds the team lock and has
    // written, but not committed.
    const other = await db.admin.connect()
    try {
      await other.query('BEGIN')
      await other.query('SELECT 1 FROM teams WHERE id = $1 FOR UPDATE', ['t-lock'])
      await other.query(
        "UPDATE team_members SET role = 'member' WHERE team_id = $1 AND user_id = $2",
        ['t-lock', 't-lock-a'],
      )
      // Demoting B now must wait for that commit, then see that A is no longer an admin.
      const pending = instance().changeMemberRole('t-lock', 't-lock-b', 'member')
      await new Promise((r) => setTimeout(r, 200))
      await other.query('COMMIT')
      expect(await pending).toBe('last-admin')
    } finally {
      other.release()
    }
    expect(await admins('t-lock')).toBe(1)
  })

  it('last-admin guard: two instances demoting (or removing) each other never leave zero admins', async () => {
    const [one, two] = [instance(), instance()]
    for (let i = 0; i < 25; i++) {
      const id = `t-race-${i}`
      await teamWithTwoAdmins(id)
      const remove = i % 2 === 0 ? null : 'member'
      const results = await Promise.all([
        one.changeMemberRole(id, `${id}-a`, remove),
        two.changeMemberRole(id, `${id}-b`, remove),
      ])
      expect(results.sort()).toEqual(['last-admin', 'ok'])
      expect(await admins(id)).toBe(1)
    }
  })

  it('single-use records, recovery codes and invitations: of many parallel takers exactly one wins', async () => {
    const takers = Array.from({ length: 6 }, () => instance())
    await store.createUser(user('u-race'))
    await store.putOneTime({
      digest: 'race',
      purpose: 'password-reset',
      userId: 'u-race',
      payload: {},
      createdAt: START,
      expiresAt: START + 1,
    })
    const consumed = await Promise.all(
      takers.map((s) => s.consumeOneTime('race', 'password-reset')),
    )
    expect(consumed.filter((r) => r !== undefined)).toHaveLength(1)

    await store.replaceRecoveryCodes('u-race', ['c1', 'c2'])
    const codes = await Promise.all(takers.map((s) => s.consumeRecoveryCode('u-race', 'c1')))
    expect(codes.filter(Boolean)).toHaveLength(1)
    expect(await store.countRecoveryCodes('u-race')).toBe(1)

    await store.createTeam(
      { id: 't-inv', name: 'Inv', slug: 'inv', personal: false, createdAt: START },
      { teamId: 't-inv', userId: 'u-race', role: 'admin' },
    )
    await store.addInvitation({
      id: 'inv-1',
      teamId: 't-inv',
      email: 'x@acme.test',
      role: 'member',
      digest: 'inv-digest',
      invitedBy: 'u-race',
      createdAt: START,
      expiresAt: START + 1,
    })
    const invitations = await Promise.all(takers.map((s) => s.consumeInvitation('inv-1')))
    expect(invitations.filter((r) => r !== undefined)).toHaveLength(1)
  })

  it('TOTP steps and passkey counters move once under parallel use (replay and clone detection)', async () => {
    const takers = Array.from({ length: 6 }, () => instance())
    const totpUser = (await store.createUser(user('u-totp')))?.id ?? ''
    const steps = await Promise.all(takers.map((s) => s.advanceTotpStep(totpUser, 100)))
    expect(steps.filter(Boolean)).toHaveLength(1)
    await store.addPasskey({
      id: 'pk',
      userId: 'u-totp',
      name: 'key',
      credentialId: 'cred',
      publicKey: 'pub',
      counter: 5,
      transports: ['usb'],
      backedUp: false,
      createdAt: START,
      lastUsedAt: null,
    })
    const moved = await Promise.all(
      takers.map((s) =>
        s.advancePasskeyCounter('pk', 5, { counter: 6, lastUsedAt: START, backedUp: true }),
      ),
    )
    expect(moved.filter(Boolean)).toHaveLength(1)
    expect((await store.findPasskeyByCredentialId('cred'))?.counter).toBe(6)
  })

  it('counters are shared and atomic across instances', async () => {
    const clock = manualClock(START)
    const counters = Array.from({ length: 4 }, () => {
      const pool = new pg.Pool({ connectionString: db.url(), max: 4 })
      pools.push(pool)
      return postgresCounterStore(pgPoolClient(pool), clock)
    })
    const values = await Promise.all(
      Array.from({ length: 40 }, (_, i) => counters[i % 4]?.increment('shared', 60_000)),
    )
    expect(new Set(values).size).toBe(40)
    expect(Math.max(...values.map((v) => v ?? 0))).toBe(40)
  })
})

describe('PostgreSQL store on a real server: failure handling', () => {
  it('a failed transaction rolls back and returns its connection to the pool', async () => {
    const pool = new pg.Pool({ connectionString: db.url(), max: 1 })
    pools.push(pool)
    const tx = pgPoolClient(pool)
    await expect(
      tx.transaction(async (t) => {
        await t.query(
          "INSERT INTO teams (id, name, personal, created_at) VALUES ('rb', 'x', false, 1)",
        )
        throw new Error('boom')
      }),
    ).rejects.toThrow('boom')
    expect((await tx.query("SELECT 1 FROM teams WHERE id = 'rb'")).rows).toHaveLength(0)
    // With max: 1, a leaked client would make this wait forever.
    expect((await tx.query('SELECT 1 AS ok')).rows).toEqual([{ ok: 1 }])
    expect(pool.totalCount).toBe(1)
  })

  it('a database that is down fails the call (closed), never a silent success', async () => {
    const pool = new pg.Pool({
      connectionString: 'postgres://nobody:wrong@127.0.0.1:1/none',
      connectionTimeoutMillis: 2000,
    })
    pools.push(pool)
    const down = postgresAuthStore(pgPoolClient(pool))
    await expect(down.findUserByEmail('a@acme.test')).rejects.toThrow()
    await expect(down.consumeOneTime('d', 'email-link')).rejects.toThrow()
  })
})

describe('the engine end to end on a real server', () => {
  it('signs up, signs in, rotates sessions and limits across instances', async () => {
    const pool = new pg.Pool({ connectionString: db.url(), max: 4 })
    pools.push(pool)
    const shared = pgPoolClient(pool)
    const clock = manualClock(START)
    const one = harness({ pg: shared, clock, config: { features: { registration: true } } })
    const two = harness({ pg: shared, clock, config: { features: { registration: true } } })
    const b = new Browser()
    await one.auth.passwords.register(b.req, {
      name: 'Ada',
      email: 'ada@e2e.test',
      password: PASSWORD,
    })
    const first = b.get('strutvane_session')
    expect(first).toBeDefined()
    // The other instance sees the same session…
    expect((await two.auth.state(b.req))?.user.email).toBe('ada@e2e.test')
    // …and a fresh sign-in there issues a new one and revokes the presented one.
    const result = await two.auth.passwords.login(b.req, {
      email: 'ada@e2e.test',
      password: PASSWORD,
    })
    expect(result.status).toBe('signed-in')
    expect(b.get('strutvane_session')).not.toBe(first)
    const stolen = new Browser()
    stolen.jar.set('strutvane_session', first ?? '')
    expect(await one.auth.state(stolen.req)).toBeNull()
    // Raw session ids never reach the table: only keyed digests.
    const raw = await pool.query('SELECT id FROM auth_sessions')
    expect(raw.rows.map((r: { id: string }) => r.id)).not.toContain(b.get('strutvane_session'))
    await rejectsWith(
      () =>
        one.auth.passwords.login(new Browser().req, {
          email: 'ada@e2e.test',
          password: 'wrong wrong!',
        }),
      'invalid_credentials',
    )
    await one.auth.idle()
    await two.auth.idle()
  })
})
