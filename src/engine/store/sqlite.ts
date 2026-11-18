/**
 * A real SQLite {@link AuthStore} and {@link CounterStore} on Node's built-in `node:sqlite`.
 *
 * It shows how an ORM-backed store must implement the atomic operations: single-use secrets are
 * `DELETE … RETURNING`, the TOTP replay guard is a conditional `UPDATE`, counters are one
 * `INSERT … ON conflict DO UPDATE … RETURNING`. Every value is bound, never interpolated.
 *
 * The tables come from migrations the app runs, never from this store (decision #2): the app's
 * own `users` table (see `users-table.ts` for how its integer ids and timestamps are mapped) plus
 * auth's columns and tables from `migrations/` in this package.
 *
 * @module
 */
import type { DatabaseSync, SQLInputValue } from 'node:sqlite'
import type { Clock } from '../ports/clock.ts'
import { systemClock } from '../ports/clock.ts'
import type { CounterStore } from '../ports/counter-store.ts'
import type {
  AuthStore,
  InvitationRecord,
  MemberRecord,
  OneTimeRecord,
  PasskeyRecord,
  SessionRecord,
  TeamRecord,
  TokenRecord,
  UserRecord,
} from '../ports/store.ts'
import { credentialKey } from './credential-key.ts'
import { fromTimestamp, toTimestamp, userIdFrom, userKey } from './users-table.ts'

type Row = Record<string, unknown>

function str(row: Row, key: string): string {
  const v = row[key]
  if (typeof v !== 'string') throw new TypeError(`sqlite store: column ${key} is not text`)
  return v
}
function strOrNull(row: Row, key: string): string | null {
  const v = row[key]
  return v === null || v === undefined ? null : str(row, key)
}
function num(row: Row, key: string): number {
  const v = row[key]
  if (typeof v === 'number') return v
  if (typeof v === 'bigint') return Number(v)
  throw new TypeError(`sqlite store: column ${key} is not a number`)
}
function numOrNull(row: Row, key: string): number | null {
  const v = row[key]
  return v === null || v === undefined ? null : num(row, key)
}
function strings(row: Row, key: string): readonly string[] {
  const parsed: unknown = JSON.parse(str(row, key))
  return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : []
}
function record(row: Row, key: string): Readonly<Record<string, string>> {
  const parsed: unknown = JSON.parse(str(row, key))
  const out: Record<string, string> = {}
  if (typeof parsed === 'object' && parsed !== null)
    for (const [k, v] of Object.entries(parsed)) if (typeof v === 'string') out[k] = v
  return out
}

const toUser = (r: Row): UserRecord => ({
  id: userIdFrom(r['id'], 'id'),
  email: str(r, 'email'),
  name: str(r, 'name'),
  passwordHash: strOrNull(r, 'password'),
  emailVerifiedAt: fromTimestamp(r['email_verified_at'], 'email_verified_at'),
  twoFactorSecret: strOrNull(r, 'two_factor_secret'),
  twoFactorConfirmedAt: fromTimestamp(r['two_factor_confirmed_at'], 'two_factor_confirmed_at'),
  twoFactorLastStep: numOrNull(r, 'two_factor_last_step'),
  currentTeamId: strOrNull(r, 'current_team_id'),
  // Rows the app inserted without timestamps have none; the engine only displays it.
  createdAt: fromTimestamp(r['created_at'], 'created_at') ?? 0,
})

const SESSION_STATES: readonly SessionRecord['state'][] = ['active', 'two-factor']
const SESSION_METHODS: readonly SessionRecord['method'][] = ['password', 'email-link', 'passkey']

/** Exactly one of `allowed`, or a TypeError: an unknown value is never mapped to a default. */
function oneOf<T extends string>(row: Row, key: string, allowed: readonly T[]): T {
  const v = str(row, key)
  const found = allowed.find((a) => a === v)
  if (found === undefined) throw new TypeError(`sqlite store: column ${key} has an unknown value`)
  return found
}

const toSession = (r: Row): SessionRecord => {
  return {
    digest: str(r, 'id'),
    userId: str(r, 'user_id'),
    // Fail closed: mapping "anything else" to 'active' would sign in a pending 2FA session.
    state: oneOf(r, 'state', SESSION_STATES),
    method: oneOf(r, 'method', SESSION_METHODS),
    createdAt: num(r, 'created_at'),
    lastSeenAt: num(r, 'last_activity'),
    expiresAt: num(r, 'expires_at'),
    idleMs: num(r, 'idle_ms'),
    remember: num(r, 'remember') === 1,
    passwordConfirmedAt: numOrNull(r, 'password_confirmed_at'),
    impersonatorId: strOrNull(r, 'impersonator_id'),
    ip: strOrNull(r, 'ip_address'),
    userAgent: strOrNull(r, 'user_agent'),
  }
}

const toOneTime = (r: Row): OneTimeRecord => ({
  digest: str(r, 'digest'),
  purpose: str(r, 'purpose') as OneTimeRecord['purpose'],
  userId: strOrNull(r, 'user_id'),
  payload: record(r, 'payload'),
  createdAt: num(r, 'created_at'),
  expiresAt: num(r, 'expires_at'),
})

const toPasskey = (r: Row): PasskeyRecord => ({
  id: str(r, 'id'),
  userId: str(r, 'user_id'),
  name: str(r, 'name'),
  credentialId: str(r, 'credential_id'),
  publicKey: str(r, 'public_key'),
  counter: num(r, 'counter'),
  transports: strings(r, 'transports'),
  backedUp: num(r, 'backed_up') === 1,
  createdAt: num(r, 'created_at'),
  lastUsedAt: numOrNull(r, 'last_used_at'),
})

const toToken = (r: Row): TokenRecord => ({
  id: str(r, 'id'),
  userId: str(r, 'user_id'),
  name: str(r, 'name'),
  digest: str(r, 'token'),
  abilities: strings(r, 'abilities'),
  createdAt: num(r, 'created_at'),
  lastUsedAt: numOrNull(r, 'last_used_at'),
  expiresAt: numOrNull(r, 'expires_at'),
})

const toTeam = (r: Row): TeamRecord => ({
  id: str(r, 'id'),
  name: str(r, 'name'),
  slug: strOrNull(r, 'slug'),
  personal: num(r, 'personal') === 1,
  createdAt: num(r, 'created_at'),
})

const toMember = (r: Row): MemberRecord => ({
  teamId: str(r, 'team_id'),
  userId: str(r, 'user_id'),
  role: str(r, 'role'),
})

const toInvitation = (r: Row): InvitationRecord => ({
  id: str(r, 'id'),
  teamId: str(r, 'team_id'),
  email: str(r, 'email'),
  role: str(r, 'role'),
  digest: str(r, 'code'),
  invitedBy: str(r, 'invited_by'),
  createdAt: num(r, 'created_at'),
  expiresAt: num(r, 'expires_at'),
})

/** Column names `updateUser` / `updateSession` / `updatePasskey` may write, by patch key. */
const USER_COLUMNS = {
  name: 'name',
  passwordHash: 'password',
  emailVerifiedAt: 'email_verified_at',
  twoFactorSecret: 'two_factor_secret',
  twoFactorConfirmedAt: 'two_factor_confirmed_at',
  twoFactorLastStep: 'two_factor_last_step',
  currentTeamId: 'current_team_id',
} as const
/** Patch keys whose users-table column is a timestamp (written as ISO 8601, like the ORM). */
const USER_TIMESTAMPS: ReadonlySet<string> = new Set(['emailVerifiedAt', 'twoFactorConfirmedAt'])

/** A user patch with its timestamps converted to what the users table stores. */
function userPatch(patch: object): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(patch))
    out[key] =
      USER_TIMESTAMPS.has(key) && (typeof value === 'number' || value === null)
        ? toTimestamp(value)
        : value
  return out
}
const SESSION_COLUMNS = {
  lastSeenAt: 'last_activity',
  passwordConfirmedAt: 'password_confirmed_at',
} as const
const PASSKEY_COLUMNS = {
  name: 'name',
  counter: 'counter',
  lastUsedAt: 'last_used_at',
  backedUp: 'backed_up',
} as const

/** Build `SET a = ?, b = ?` from a patch through a fixed column map (keys never come from input). */
function setClause(
  patch: object,
  columns: Readonly<Record<string, string>>,
): { sql: string; values: SQLInputValue[] } {
  const parts: string[] = []
  const values: SQLInputValue[] = []
  for (const [key, value] of Object.entries(patch)) {
    const column = columns[key]
    if (column === undefined || value === undefined) continue
    parts.push(`${column} = ?`)
    values.push(typeof value === 'boolean' ? (value ? 1 : 0) : (value as SQLInputValue))
  }
  return { sql: parts.join(', '), values }
}

/**
 * An {@link AuthStore} on a `node:sqlite` database. The tables must exist: the app's migrations
 * create them (`node strut migrate`); this store never creates or alters one.
 *
 * @example
 * ```ts
 * import { DatabaseSync } from 'node:sqlite'
 * const store = sqliteAuthStore(new DatabaseSync('database/database.sqlite'))
 * ```
 */
export function sqliteAuthStore(db: DatabaseSync): AuthStore {
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;')
  const get = (sql: string, ...params: SQLInputValue[]): Row | undefined =>
    db.prepare(sql).get(...params) as Row | undefined
  const all = (sql: string, ...params: SQLInputValue[]): Row[] =>
    db.prepare(sql).all(...params) as Row[]
  const run = (sql: string, ...params: SQLInputValue[]): number =>
    Number(db.prepare(sql).run(...params).changes)
  const tx = (fn: () => void): void => {
    db.exec('BEGIN IMMEDIATE')
    try {
      fn()
      db.exec('COMMIT')
    } catch (error) {
      db.exec('ROLLBACK')
      throw error
    }
  }

  return {
    async createUser(u) {
      // The id is the users table's own (auto-increment): `u.id` is the engine's proposal, used
      // only by the in-memory store. The email's unique index makes a taken address a no-op.
      const createdAt = toTimestamp(u.createdAt)
      const row = get(
        `INSERT INTO users (email, name, password, email_verified_at, two_factor_secret, two_factor_confirmed_at,
           two_factor_last_step, current_team_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON conflict(email) DO NOTHING RETURNING *`,
        u.email,
        u.name,
        u.passwordHash,
        toTimestamp(u.emailVerifiedAt),
        u.twoFactorSecret,
        toTimestamp(u.twoFactorConfirmedAt),
        u.twoFactorLastStep,
        u.currentTeamId,
        createdAt,
        createdAt,
      )
      return row ? toUser(row) : undefined
    },
    async findUserById(id) {
      const key = userKey(id)
      if (key === undefined) return undefined
      const row = get('SELECT * FROM users WHERE id = ?', key)
      return row ? toUser(row) : undefined
    },
    async findUserByEmail(email) {
      const row = get('SELECT * FROM users WHERE email = ?', email)
      return row ? toUser(row) : undefined
    },
    async updateUser(id, patch) {
      const key = userKey(id)
      const set = setClause(userPatch(patch), USER_COLUMNS)
      if (key === undefined || !set.sql) return
      run(
        `UPDATE users SET ${set.sql}, updated_at = ? WHERE id = ?`,
        ...set.values,
        new Date().toISOString(),
        key,
      )
    },
    async advanceTotpStep(userId, step) {
      const key = userKey(userId)
      if (key === undefined) return false
      return (
        run(
          'UPDATE users SET two_factor_last_step = ? WHERE id = ? AND (two_factor_last_step IS NULL OR two_factor_last_step < ?)',
          step,
          key,
          step,
        ) === 1
      )
    },
    async listUserRoles(userId) {
      const key = userKey(userId)
      if (key === undefined) return []
      return all('SELECT role FROM user_roles WHERE user_id = ? ORDER BY role', key).map((r) =>
        str(r, 'role'),
      )
    },
    async setUserRoles(userId, roles) {
      const key = userKey(userId)
      if (key === undefined) throw new TypeError('sqlite store: not a users table id')
      tx(() => {
        run('DELETE FROM user_roles WHERE user_id = ?', key)
        for (const role of new Set(roles))
          run('INSERT INTO user_roles (user_id, role) VALUES (?, ?)', key, role)
      })
    },

    async createSession(s) {
      run(
        `INSERT INTO auth_sessions (id, user_id, state, method, created_at, last_activity, expires_at, idle_ms, remember,
           password_confirmed_at, impersonator_id, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        s.digest,
        s.userId,
        s.state,
        s.method,
        s.createdAt,
        s.lastSeenAt,
        s.expiresAt,
        s.idleMs,
        s.remember ? 1 : 0,
        s.passwordConfirmedAt,
        s.impersonatorId,
        s.ip,
        s.userAgent,
      )
    },
    async findSession(digest) {
      const row = get('SELECT * FROM auth_sessions WHERE id = ?', digest)
      return row ? toSession(row) : undefined
    },
    async updateSession(digest, patch) {
      const set = setClause(patch, SESSION_COLUMNS)
      if (set.sql) run(`UPDATE auth_sessions SET ${set.sql} WHERE id = ?`, ...set.values, digest)
    },
    async deleteSession(digest) {
      run('DELETE FROM auth_sessions WHERE id = ?', digest)
    },
    async deleteUserSessions(userId, exceptDigest) {
      return exceptDigest === undefined
        ? run('DELETE FROM auth_sessions WHERE user_id = ?', userId)
        : run('DELETE FROM auth_sessions WHERE user_id = ? AND id <> ?', userId, exceptDigest)
    },
    async listUserSessions(userId) {
      return all('SELECT * FROM auth_sessions WHERE user_id = ?', userId).map(toSession)
    },

    async putOneTime(r) {
      run(
        'INSERT OR REPLACE INTO auth_one_time_tokens (digest, purpose, user_id, payload, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
        r.digest,
        r.purpose,
        r.userId,
        JSON.stringify(r.payload),
        r.createdAt,
        r.expiresAt,
      )
    },
    async findOneTime(digest, purpose) {
      const row = get(
        'SELECT * FROM auth_one_time_tokens WHERE digest = ? AND purpose = ?',
        digest,
        purpose,
      )
      return row ? toOneTime(row) : undefined
    },
    async consumeOneTime(digest, purpose) {
      const row = get(
        'DELETE FROM auth_one_time_tokens WHERE digest = ? AND purpose = ? RETURNING *',
        digest,
        purpose,
      )
      return row ? toOneTime(row) : undefined
    },
    async deleteUserOneTime(userId, purpose) {
      run('DELETE FROM auth_one_time_tokens WHERE user_id = ? AND purpose = ?', userId, purpose)
    },

    async replaceRecoveryCodes(userId, digests) {
      tx(() => {
        run('DELETE FROM two_factor_recovery_codes WHERE user_id = ?', userId)
        for (const d of digests)
          run('INSERT INTO two_factor_recovery_codes (user_id, digest) VALUES (?, ?)', userId, d)
      })
    },
    async consumeRecoveryCode(userId, digest) {
      return (
        run(
          'DELETE FROM two_factor_recovery_codes WHERE user_id = ? AND digest = ?',
          userId,
          digest,
        ) === 1
      )
    },
    async countRecoveryCodes(userId) {
      return num(
        get('SELECT COUNT(*) AS n FROM two_factor_recovery_codes WHERE user_id = ?', userId) ?? {
          n: 0,
        },
        'n',
      )
    },

    async addPasskey(p) {
      run(
        `INSERT INTO passkeys (id, user_id, name, credential_id, credential_key, public_key, counter, transports, backed_up, created_at, last_used_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        p.id,
        p.userId,
        p.name,
        p.credentialId,
        credentialKey(p.credentialId),
        p.publicKey,
        p.counter,
        JSON.stringify(p.transports),
        p.backedUp ? 1 : 0,
        p.createdAt,
        p.lastUsedAt,
      )
    },
    async findPasskeyByCredentialId(credentialId) {
      const row = get(
        'SELECT * FROM passkeys WHERE credential_key = ? AND credential_id = ?',
        credentialKey(credentialId),
        credentialId,
      )
      return row ? toPasskey(row) : undefined
    },
    async listPasskeys(userId) {
      return all('SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at, rowid', userId).map(
        toPasskey,
      )
    },
    async updatePasskey(id, patch) {
      const set = setClause(patch, PASSKEY_COLUMNS)
      if (set.sql) run(`UPDATE passkeys SET ${set.sql} WHERE id = ?`, ...set.values, id)
    },
    async advancePasskeyCounter(id, expected, patch) {
      return (
        run(
          'UPDATE passkeys SET counter = ?, last_used_at = ?, backed_up = ? WHERE id = ? AND counter = ?',
          patch.counter,
          patch.lastUsedAt,
          patch.backedUp ? 1 : 0,
          id,
          expected,
        ) === 1
      )
    },
    async deletePasskey(userId, id) {
      return run('DELETE FROM passkeys WHERE id = ? AND user_id = ?', id, userId) === 1
    },

    async addToken(t) {
      run(
        `INSERT INTO personal_access_tokens (id, user_id, name, token, abilities, created_at, last_used_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        t.id,
        t.userId,
        t.name,
        t.digest,
        JSON.stringify(t.abilities),
        t.createdAt,
        t.lastUsedAt,
        t.expiresAt,
      )
    },
    async findTokenByDigest(digest) {
      const row = get('SELECT * FROM personal_access_tokens WHERE token = ?', digest)
      return row ? toToken(row) : undefined
    },
    async listTokens(userId) {
      return all(
        'SELECT * FROM personal_access_tokens WHERE user_id = ? ORDER BY created_at, rowid',
        userId,
      ).map(toToken)
    },
    async touchToken(id, at) {
      run('UPDATE personal_access_tokens SET last_used_at = ? WHERE id = ?', at, id)
    },
    async deleteToken(userId, id) {
      return (
        run('DELETE FROM personal_access_tokens WHERE id = ? AND user_id = ?', id, userId) === 1
      )
    },
    async deleteUserTokens(userId) {
      return run('DELETE FROM personal_access_tokens WHERE user_id = ?', userId)
    },

    async createTeam(team, owner) {
      let created = false
      tx(() => {
        created =
          run(
            'INSERT INTO teams (id, name, slug, personal, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING',
            team.id,
            team.name,
            team.slug,
            team.personal ? 1 : 0,
            team.createdAt,
          ) === 1
        if (created)
          run(
            'INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, ?)',
            owner.teamId,
            owner.userId,
            owner.role,
          )
      })
      return created
    },
    async findTeam(id) {
      const row = get('SELECT * FROM teams WHERE id = ?', id)
      return row ? toTeam(row) : undefined
    },
    async findTeamBySlug(slug) {
      const row = get('SELECT * FROM teams WHERE slug = ?', slug)
      return row ? toTeam(row) : undefined
    },
    async findMember(teamId, userId) {
      const row = get(
        'SELECT * FROM team_members WHERE team_id = ? AND user_id = ?',
        teamId,
        userId,
      )
      return row ? toMember(row) : undefined
    },
    async listMembers(teamId) {
      return all('SELECT * FROM team_members WHERE team_id = ? ORDER BY user_id', teamId).map(
        toMember,
      )
    },
    async listUserTeams(userId) {
      return all('SELECT * FROM team_members WHERE user_id = ? ORDER BY team_id', userId).map(
        toMember,
      )
    },
    async putMember(m) {
      run(
        'INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, ?) ON conflict(team_id, user_id) DO UPDATE SET role = excluded.role',
        m.teamId,
        m.userId,
        m.role,
      )
    },
    async removeMember(teamId, userId) {
      run('DELETE FROM team_members WHERE team_id = ? AND user_id = ?', teamId, userId)
    },
    async changeMemberRole(teamId, userId, role) {
      // The "another admin remains" check is part of the write: SQLite runs the statement under the
      // database write lock, so two connections demoting each other cannot both pass it.
      const keepsAdmin = `(role <> 'admin' OR EXISTS (SELECT 1 FROM team_members o
        WHERE o.team_id = team_members.team_id AND o.user_id <> team_members.user_id AND o.role = 'admin'))`
      const changed =
        role === null
          ? run(
              `DELETE FROM team_members WHERE team_id = ? AND user_id = ? AND ${keepsAdmin}`,
              teamId,
              userId,
            )
          : run(
              `UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ? AND (? = 'admin' OR ${keepsAdmin})`,
              role,
              teamId,
              userId,
              role,
            )
      if (changed === 1) return 'ok'
      return get(
        'SELECT 1 AS x FROM team_members WHERE team_id = ? AND user_id = ?',
        teamId,
        userId,
      )
        ? 'last-admin'
        : 'not-found'
    },
    async addInvitation(i) {
      run(
        'INSERT INTO team_invitations (id, team_id, email, role, code, invited_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        i.id,
        i.teamId,
        i.email,
        i.role,
        i.digest,
        i.invitedBy,
        i.createdAt,
        i.expiresAt,
      )
    },
    async findInvitationByDigest(digest) {
      const row = get('SELECT * FROM team_invitations WHERE code = ?', digest)
      return row ? toInvitation(row) : undefined
    },
    async listInvitations(teamId) {
      return all(
        'SELECT * FROM team_invitations WHERE team_id = ? ORDER BY created_at, rowid',
        teamId,
      ).map(toInvitation)
    },
    async consumeInvitation(id) {
      const row = get('DELETE FROM team_invitations WHERE id = ? RETURNING *', id)
      return row ? toInvitation(row) : undefined
    },
  }
}

/**
 * A shared {@link CounterStore} on SQLite: several processes on one database file share limits
 * (the stand-in for the framework's `cache` table). `auth_counters` comes from auth's migration.
 */
export function sqliteCounterStore(db: DatabaseSync, clock: Clock = systemClock): CounterStore {
  const increment = db.prepare(
    `INSERT INTO auth_counters (key, value, expires_at) VALUES (?, 1, ?)
     ON conflict(key) DO UPDATE SET
       value = CASE WHEN auth_counters.expires_at <= ? THEN 1 ELSE auth_counters.value + 1 END,
       expires_at = CASE WHEN auth_counters.expires_at <= ? THEN excluded.expires_at ELSE auth_counters.expires_at END
     RETURNING value`,
  )
  return {
    async increment(key, ttlMs) {
      const now = clock.now()
      const row = increment.get(key, now + ttlMs, now, now) as Row | undefined
      return row ? num(row, 'value') : 1
    },
    async get(key) {
      const row = db
        .prepare('SELECT value FROM auth_counters WHERE key = ? AND expires_at > ?')
        .get(key, clock.now()) as Row | undefined
      return row ? num(row, 'value') : undefined
    },
    async set(key, value, ttlMs) {
      db.prepare(
        'INSERT INTO auth_counters (key, value, expires_at) VALUES (?, ?, ?) ON conflict(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at',
      ).run(key, value, clock.now() + ttlMs)
    },
    async delete(key) {
      db.prepare('DELETE FROM auth_counters WHERE key = ?').run(key)
    },
  }
}
