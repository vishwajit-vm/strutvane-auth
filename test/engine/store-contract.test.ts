import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { afterAll, describe, expect, it } from 'vitest'
import { manualClock } from '../../src/engine/ports/clock.ts'
import type { AuthStore, UserRecord } from '../../src/engine/ports/store.ts'
import { memoryAuthStore, memoryCounterStore } from '../../src/engine/store/memory.ts'
import { sqliteAuthStore, sqliteCounterStore } from '../../src/engine/store/sqlite.ts'
import { Browser, harness, rejectsWith, START } from './helpers/harness.ts'

const dir = mkdtempSync(join(tmpdir(), 'sv-auth-'))
/** Every file-backed connection, closed before the folder is removed (Windows keeps open files locked). */
const opened: DatabaseSync[] = []
const openFile = (file: string): DatabaseSync => {
  const db = new DatabaseSync(file)
  opened.push(db)
  return db
}
afterAll(() => {
  for (const db of opened) db.close()
  rmSync(dir, { recursive: true, force: true })
})

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
  ['sqlite', () => sqliteAuthStore(new DatabaseSync(':memory:'))],
]

describe.each(STORES)('store contract (%s)', (_name, make) => {
  it('emails are unique; createUser reports a conflict instead of throwing', async () => {
    const s = make()
    expect(await s.createUser(user('u1', 'a@b.io'))).toBeDefined()
    expect(await s.createUser(user('u2', 'a@b.io'))).toBeUndefined()
  })

  it('advanceTotpStep only moves forward', async () => {
    const s = make()
    await s.createUser(user('u1', 'a@b.io'))
    expect(await s.advanceTotpStep('u1', 10)).toBe(true)
    expect(await s.advanceTotpStep('u1', 10)).toBe(false)
    expect(await s.advanceTotpStep('u1', 9)).toBe(false)
    expect(await s.advanceTotpStep('u1', 11)).toBe(true)
    expect(await s.advanceTotpStep('missing', 1)).toBe(false)
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
    await a.createUser(user('u', 'a@b.io'))
    expect(await b.consumeOneTime('d', 'email-link')).toBeDefined()
    expect(await a.consumeOneTime('d', 'email-link')).toBeUndefined()
    expect(await b.advanceTotpStep('u', 5)).toBe(true)
    expect(await a.advanceTotpStep('u', 5)).toBe(false)
  })

  it('an unknown session state or method in a row fails closed (never read as an active session)', async () => {
    // An ORM store or a hand-edited row may hold values the schema CHECK would refuse (a
    // case-insensitive column, a new state from a later version). Mapping "anything else" to
    // 'active' would turn a pending two-factor session into a signed-in one.
    const db = new DatabaseSync(':memory:')
    const store = sqliteAuthStore(db)
    db.exec('PRAGMA ignore_check_constraints = ON')
    for (const [state, method] of [
      ['Two-Factor', 'password'],
      ['pending', 'password'],
      ['two-factor ', 'password'],
      ['active', 'sso'],
    ] as const) {
      db.prepare(
        `INSERT INTO sessions (id, user_id, state, method, created_at, last_activity, expires_at, idle_ms, remember)
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
        (c: ReturnType<typeof manualClock>) => sqliteCounterStore(new DatabaseSync(':memory:'), c),
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
