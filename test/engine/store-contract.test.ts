import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { afterAll, describe, expect, it } from 'vitest'
import { manualClock } from '../../src/engine/ports/clock.ts'
import type { AuthStore, UserRecord } from '../../src/engine/ports/store.ts'
import { memoryAuthStore, memoryCounterStore } from '../../src/engine/store/memory.ts'
import { postgresAuthStore, postgresCounterStore } from '../../src/engine/store/postgres.ts'
import { sqliteAuthStore, sqliteCounterStore } from '../../src/engine/store/sqlite.ts'
import { isUserId } from '../../src/engine/tokens/formats.ts'
import { sqliteWithAuthSchema } from '../support/auth-schema.ts'
import { Browser, harness, rejectsWith, START } from './helpers/harness.ts'
import { pgliteSchemaClient } from './helpers/pg.ts'

const dir = mkdtempSync(join(tmpdir(), 'sv-auth-'))
/** Every file-backed connection, closed before the folder is removed (Windows keeps open files locked). */
const opened: DatabaseSync[] = []
/** A connection to `file`; the first one migrates it (as `node strut migrate` would). */
const openFile = (file: string): DatabaseSync => {
  const db = existsSync(file) ? new DatabaseSync(file) : sqliteWithAuthSchema(file)
  opened.push(db)
  return db
}
afterAll(() => {
  for (const db of opened) db.close()
  rmSync(dir, { recursive: true, force: true })
})

const UUID_1 = '00000000-0000-4000-8000-000000000001'

const user = (id: string, email: string): UserRecord => ({
  id,
  email,
  name: 'n',
  passwordHash: null,
  emailVerifiedAt: null,
  twoFactorSecret: null,
  twoFactorConfirmedAt: null,
  twoFactorLastStep: null,
  currentTeamId: null,
  createdAt: START,
})

const STORES: [string, () => AuthStore][] = [
  ['memory', () => memoryAuthStore()],
  ['sqlite', () => sqliteAuthStore(sqliteWithAuthSchema())],
  ['postgres', () => postgresAuthStore(pgliteSchemaClient())],
]

describe.each(STORES)('store contract (%s)', (_name, make) => {
  it('emails are unique; createUser reports a conflict instead of throwing', async () => {
    const s = make()
    expect(await s.createUser(user('u1', 'a@b.io'))).toBeDefined()
    expect(await s.createUser(user('u2', 'a@b.io'))).toBeUndefined()
  })

  it('advanceTotpStep only moves forward', async () => {
    const s = make()
    const id = (await s.createUser(user(UUID_1, 'a@b.io')))?.id ?? ''
    expect(await s.advanceTotpStep(id, 10)).toBe(true)
    expect(await s.advanceTotpStep(id, 10)).toBe(false)
    expect(await s.advanceTotpStep(id, 9)).toBe(false)
    expect(await s.advanceTotpStep(id, 11)).toBe(true)
    expect(await s.advanceTotpStep('missing', 1)).toBe(false)
  })

  it('user ids are the store\'s (the users table key); malformed ids are "not found", never an error', async () => {
    const s = make()
    const created = await s.createUser(user(UUID_1, 'a@b.io'))
    expect(created !== undefined && isUserId(created.id)).toBe(true)
    expect((await s.findUserById(created?.id ?? ''))?.email).toBe('a@b.io')
    for (const bad of ['abc', '1; DROP TABLE users', '01', '-1', '1.5', '9223372036854775808', ''])
      expect(await s.findUserById(bad), bad).toBeUndefined()
    expect(await s.listUserRoles('abc')).toEqual([])
    await s.updateUser('abc', { name: 'x' })
    expect(await s.advanceTotpStep('abc', 1)).toBe(false)
  })

  it('user times round-trip to the millisecond (stored as the framework\'s timestamps)', async () => {
    const s = make()
    const created = await s.createUser({ ...user(UUID_1, 'a@b.io'), emailVerifiedAt: START + 7 })
    const id = created?.id ?? ''
    expect(created?.createdAt).toBe(START)
    expect(created?.emailVerifiedAt).toBe(START + 7)
    await s.updateUser(id, { twoFactorConfirmedAt: START + 9, emailVerifiedAt: null, name: 'Ada' })
    const after = await s.findUserById(id)
    expect(after?.twoFactorConfirmedAt).toBe(START + 9)
    expect(after?.emailVerifiedAt).toBeNull()
    expect(after?.name).toBe('Ada')
  })

  it('roles belong to the user row', async () => {
    const s = make()
    const id = (await s.createUser(user(UUID_1, 'a@b.io')))?.id ?? ''
    await s.setUserRoles(id, ['admin', 'admin', 'member'])
    expect(await s.listUserRoles(id)).toEqual(['admin', 'member'])
    await s.setUserRoles(id, [])
    expect(await s.listUserRoles(id)).toEqual([])
  })

  it('a passkey with a 1024-character credential id (the WebAuthn maximum) is stored and found', async () => {
    const s = make()
    const credentialId = 'A'.repeat(1024)
    await s.addPasskey({
      id: 'p-long',
      userId: 'u1',
      name: 'x',
      credentialId,
      publicKey: 'k',
      counter: 0,
      transports: ['usb'],
      backedUp: true,
      createdAt: 1,
      lastUsedAt: null,
    })
    expect((await s.findPasskeyByCredentialId(credentialId))?.id).toBe('p-long')
    expect(await s.findPasskeyByCredentialId(`${credentialId.slice(1)}B`)).toBeUndefined()
  })

  it('one-time records are single-use and separated by purpose', async () => {
    const s = make()
    await s.putOneTime({
      digest: 'd',
      purpose: 'password-reset',
      userId: 'u1',
      payload: { a: 'b' },
      createdAt: 1,
      expiresAt: 2,
    })
    expect(await s.findOneTime('d', 'email-link')).toBeUndefined()
    expect((await s.findOneTime('d', 'password-reset'))?.payload).toEqual({ a: 'b' })
    expect(await s.consumeOneTime('d', 'password-reset')).toBeDefined()
    expect(await s.consumeOneTime('d', 'password-reset')).toBeUndefined()
  })

  it('recovery codes, tokens and passkeys are owner-scoped', async () => {
    const s = make()
    await s.replaceRecoveryCodes('u1', ['c1', 'c2'])
    expect(await s.consumeRecoveryCode('u2', 'c1')).toBe(false)
    expect(await s.consumeRecoveryCode('u1', 'c1')).toBe(true)
    expect(await s.consumeRecoveryCode('u1', 'c1')).toBe(false)
    expect(await s.countRecoveryCodes('u1')).toBe(1)
    await s.addToken({
      id: 't1',
      userId: 'u1',
      name: 'x',
      digest: 'td',
      abilities: ['*'],
      createdAt: 1,
      lastUsedAt: null,
      expiresAt: null,
    })
    expect(await s.deleteToken('u2', 't1')).toBe(false)
    expect(await s.findTokenByDigest('td')).toBeDefined()
    expect(await s.deleteToken('u1', 't1')).toBe(true)
    await s.addPasskey({
      id: 'p1',
      userId: 'u1',
      name: 'x',
      credentialId: 'c',
      publicKey: 'k',
      counter: 0,
      transports: [],
      backedUp: false,
      createdAt: 1,
      lastUsedAt: null,
    })
    expect(await s.deletePasskey('u2', 'p1')).toBe(false)
    expect(await s.deletePasskey('u1', 'p1')).toBe(true)
  })

  it('team slugs are unique: a taken slug creates nothing and resolves false', async () => {
    const s = make()
    const owner = (teamId: string) => ({ teamId, userId: 'u1', role: 'admin' })
    expect(
      await s.createTeam(
        { id: 'a', name: 'A', slug: 'acme', personal: false, createdAt: 1 },
        owner('a'),
      ),
    ).toBe(true)
    expect(
      await s.createTeam(
        { id: 'b', name: 'B', slug: 'acme', personal: false, createdAt: 1 },
        owner('b'),
      ),
    ).toBe(false)
    expect(await s.findTeam('b')).toBeUndefined()
    expect(await s.findMember('b', 'u1')).toBeUndefined()
    expect((await s.findTeamBySlug('acme'))?.id).toBe('a')
    expect(await s.findTeamBySlug('ACME')).toBeUndefined()
    // Slug-less teams never collide with each other.
    for (const id of ['c', 'd'])
      expect(
        await s.createTeam({ id, name: id, slug: null, personal: true, createdAt: 1 }, owner(id)),
      ).toBe(true)
  })

  it('invitations are consumed once', async () => {
    const s = make()
    await s.createTeam(
      { id: 't', name: 'T', slug: null, personal: false, createdAt: 1 },
      { teamId: 't', userId: 'u1', role: 'admin' },
    )
    await s.addInvitation({
      id: 'i',
      teamId: 't',
      email: 'x@y.io',
      role: 'member',
      digest: 'g',
      invitedBy: 'u1',
      createdAt: 1,
      expiresAt: 2,
    })
    expect(await s.consumeInvitation('i')).toBeDefined()
    expect(await s.consumeInvitation('i')).toBeUndefined()
  })
})

describe('PostgreSQL: several app instances on one database, rows that fail closed', () => {
  it('bypass attempt: spreading attempts over two app instances does not double the limit', async () => {
    const shared = pgliteSchemaClient()
    const clock = manualClock(START)
    const config = { lockout: { threshold: 1000 } }
    const one = harness({ store: 'postgres', pg: shared, clock, config })
    const two = harness({ store: 'postgres', pg: shared, clock, config })
    for (let i = 0; i < 10; i++)
      await rejectsWith(
        () =>
          (i % 2 === 0 ? one : two).auth.passwords.login(new Browser('198.51.100.1').req, {
            email: `x${i}@acme.test`,
            password: 'wrong password!',
          }),
        'invalid_credentials',
      )
    for (const instance of [one, two])
      await rejectsWith(
        () =>
          instance.auth.passwords.login(new Browser('198.51.100.1').req, {
            email: 'y@acme.test',
            password: 'wrong password!',
          }),
        'rate_limited',
      )
  })

  it('a single-use record is consumed once across two instances', async () => {
    const shared = pgliteSchemaClient()
    const [a, b] = [postgresAuthStore(shared), postgresAuthStore(shared)]
    await a.putOneTime({
      digest: 'd',
      purpose: 'email-link',
      userId: null,
      payload: { nonce: 'n' },
      createdAt: 1,
      expiresAt: 2,
    })
    const results = await Promise.all([
      a.consumeOneTime('d', 'email-link'),
      b.consumeOneTime('d', 'email-link'),
    ])
    expect(results.filter((r) => r !== undefined)).toHaveLength(1)
    expect(results.find((r) => r !== undefined)?.payload).toEqual({ nonce: 'n' })
  })

  it('unknown session states, methods and one-time purposes fail closed', async () => {
    const client = pgliteSchemaClient()
    const store = postgresAuthStore(client)
    for (const [state, method] of [
      ['Two-Factor', 'password'],
      ['pending', 'password'],
      ['active', 'sso'],
    ] as const) {
      await client.query(
        `INSERT INTO auth_sessions (id, user_id, state, method, created_at, last_activity, expires_at, idle_ms, remember)
         VALUES ($1, 'u', $2, $3, 1, 1, 9999999999999, 1000, false)`,
        [`${state}|${method}`, state, method],
      )
      await expect(store.findSession(`${state}|${method}`), `${state} ${method}`).rejects.toThrow(
        TypeError,
      )
    }
    await client.query(
      `INSERT INTO auth_one_time_tokens (digest, purpose, user_id, payload, created_at, expires_at)
       VALUES ('x', 'magic', NULL, '{}', 1, 2)`,
    )
    await expect(store.findOneTime('x', 'magic' as never)).rejects.toThrow(TypeError)
  })

  it('a corrupt number column fails closed instead of reading as NaN', async () => {
    const client = pgliteSchemaClient()
    const store = postgresAuthStore(client)
    const id = (await store.createUser(user(UUID_1, 'a@b.io')))?.id ?? ''
    await client.query("ALTER TABLE users ALTER COLUMN two_factor_last_step TYPE text USING 'soon'")
    await expect(store.findUserById(id)).rejects.toThrow(TypeError)
  })

  it('a corrupt timestamp in the users table fails closed instead of reading as NaN', async () => {
    const client = pgliteSchemaClient()
    const store = postgresAuthStore(client)
    const id = (await store.createUser(user(UUID_1, 'a@b.io')))?.id ?? ''
    await client.query(
      "ALTER TABLE users ALTER COLUMN email_verified_at TYPE text USING 'yesterday-ish'",
    )
    await expect(store.findUserById(id)).rejects.toThrow(TypeError)
  })
})

describe('SQLite across connections (several app processes on one database)', () => {
  it('single-use holds across two connections to the same file', async () => {
    const file = join(dir, 'shared.sqlite')
    const a = sqliteAuthStore(openFile(file))
    const b = sqliteAuthStore(openFile(file))
    await a.putOneTime({
      digest: 'd',
      purpose: 'email-link',
      userId: 'u',
      payload: {},
      createdAt: 1,
      expiresAt: 2,
    })
    const id = (await a.createUser(user(UUID_1, 'a@b.io')))?.id ?? ''
    expect(await b.consumeOneTime('d', 'email-link')).toBeDefined()
    expect(await a.consumeOneTime('d', 'email-link')).toBeUndefined()
    expect(await b.advanceTotpStep(id, 5)).toBe(true)
    expect(await a.advanceTotpStep(id, 5)).toBe(false)
  })

  it('an unknown session state or method in a row fails closed (never read as an active session)', async () => {
    // An ORM store or a hand-edited row may hold values the schema CHECK would refuse (a
    // case-insensitive column, a new state from a later version). Mapping "anything else" to
    // 'active' would turn a pending two-factor session into a signed-in one.
    const db = sqliteWithAuthSchema()
    const store = sqliteAuthStore(db)
    for (const [state, method] of [
      ['Two-Factor', 'password'],
      ['pending', 'password'],
      ['two-factor ', 'password'],
      ['active', 'sso'],
    ] as const) {
      db.prepare(
        `INSERT INTO auth_sessions (id, user_id, state, method, created_at, last_activity, expires_at, idle_ms, remember)
         VALUES (?, 'u', ?, ?, 1, 1, 9999999999999, 1000, 0)`,
      ).run(`${state}|${method}`, state, method)
      await expect(store.findSession(`${state}|${method}`), `${state} ${method}`).rejects.toThrow(
        TypeError,
      )
    }
  })

  it('the last-admin guard and the passkey counter are atomic across two connections', async () => {
    const file = join(dir, 'guards.sqlite')
    const a = sqliteAuthStore(openFile(file))
    const b = sqliteAuthStore(openFile(file))
    await a.createTeam(
      { id: 't', name: 'T', slug: null, personal: false, createdAt: 1 },
      { teamId: 't', userId: 'u1', role: 'admin' },
    )
    await a.putMember({ teamId: 't', userId: 'u2', role: 'admin' })
    // Each connection removes the OTHER admin: the second must see the first's write.
    expect(await a.changeMemberRole('t', 'u2', 'member')).toBe('ok')
    expect(await b.changeMemberRole('t', 'u1', null)).toBe('last-admin')
    expect(await b.changeMemberRole('t', 'nobody', null)).toBe('not-found')
    await a.addPasskey({
      id: 'p',
      userId: 'u1',
      name: 'k',
      credentialId: 'c',
      publicKey: 'x',
      counter: 5,
      transports: [],
      backedUp: false,
      createdAt: 1,
      lastUsedAt: null,
    })
    expect(
      await a.advancePasskeyCounter('p', 5, { counter: 6, lastUsedAt: 2, backedUp: false }),
    ).toBe(true)
    expect(
      await b.advancePasskeyCounter('p', 5, { counter: 6, lastUsedAt: 3, backedUp: false }),
    ).toBe(false)
  })

  it('bypass attempt: spreading attempts over two app instances does not double the limit', async () => {
    const file = join(dir, 'limits.sqlite')
    const clock = manualClock(START)
    const one = harness({
      store: 'sqlite',
      db: openFile(file),
      clock,
      config: { lockout: { threshold: 1000 } },
    })
    const two = harness({
      store: 'sqlite',
      db: openFile(file),
      clock,
      config: { lockout: { threshold: 1000 } },
    })
    for (let i = 0; i < 10; i++) {
      const instance = i % 2 === 0 ? one : two
      await rejectsWith(
        () =>
          instance.auth.passwords.login(new Browser('198.51.100.1').req, {
            email: `x${i}@acme.test`,
            password: 'wrong password!',
          }),
        'invalid_credentials',
      )
    }
    await rejectsWith(
      () =>
        one.auth.passwords.login(new Browser('198.51.100.1').req, {
          email: 'y@acme.test',
          password: 'wrong password!',
        }),
      'rate_limited',
    )
    await rejectsWith(
      () =>
        two.auth.passwords.login(new Browser('198.51.100.1').req, {
          email: 'y@acme.test',
          password: 'wrong password!',
        }),
      'rate_limited',
    )
  })

  it('counter stores expire values and restart from 1', async () => {
    for (const [name, make] of [
      ['memory', (c: ReturnType<typeof manualClock>) => memoryCounterStore(c)],
      [
        'sqlite',
        (c: ReturnType<typeof manualClock>) => sqliteCounterStore(sqliteWithAuthSchema(), c),
      ],
      [
        'postgres',
        (c: ReturnType<typeof manualClock>) => postgresCounterStore(pgliteSchemaClient(), c),
      ],
    ] as const) {
      const clock = manualClock(START)
      const counters = make(clock)
      expect(await counters.increment('k', 1000), name).toBe(1)
      expect(await counters.increment('k', 1000)).toBe(2)
      expect(await counters.get('k')).toBe(2)
      clock.advance(1000)
      expect(await counters.get('k')).toBeUndefined()
      expect(await counters.increment('k', 1000)).toBe(1)
      await counters.set('k', 42, 500)
      expect(await counters.get('k')).toBe(42)
      await counters.delete('k')
      expect(await counters.get('k')).toBeUndefined()
    }
  })
})
