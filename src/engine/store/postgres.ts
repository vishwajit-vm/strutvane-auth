/**
 * A PostgreSQL {@link AuthStore} and {@link CounterStore}.
 *
 * It runs on anything that can send a parameterised query and run a transaction: a node-postgres
 * pool (v1's database approach, {@link pgPoolClient}), PGlite in tests ({@link pgliteClient}) or the
 * framework's `Database` ({@link frameworkDatabaseClient}), so v2 works on today's framework.
 *
 * **Where the ORM plugs in.** ADR-0023 puts identity storage on the framework ORM once it lands.
 * The seam is the store port (`ports/store.ts`), not this file: an ORM-backed store implements
 * the same 46 methods over the same tables and must pass the same store contract
 * (`test/engine/store-contract.test.ts`, which runs every store). Until then this store is the
 * persistent default for PostgreSQL apps.
 *
 * How it keeps the port's atomicity rules (every one is raced in the store contract):
 * - single use (`consumeOneTime`, `consumeRecoveryCode`, `consumeInvitation`) is one
 *   `DELETE … RETURNING`: of two concurrent callers, exactly one gets the row;
 * - the TOTP replay guard and the passkey counter are conditional `UPDATE … RETURNING`s;
 * - the last-admin guard runs in a transaction that first locks the team row (`FOR UPDATE`), so
 *   role changes on one team are serialised and each check sees the committed result of the
 *   previous change (READ COMMITTED takes a new snapshot per statement);
 * - multi-statement writes (team + first member, replacing roles or recovery codes) are
 *   transactions.
 *
 * Every value is bound (`$1`), never interpolated. Column names in `UPDATE … SET` come from fixed
 * maps, never from input. Unknown enum values in a row fail closed (they throw).
 *
 * @module
 */
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
import { POSTGRES_AUTH_STATEMENTS } from './postgres-schema.ts'

/** A row as a driver returns it. */
export type PostgresRow = Readonly<Record<string, unknown>>

/**
 * The little the store needs from a PostgreSQL connection: parameterised queries and
 * transactions on one connection.
 *
 * @example
 * const client: PostgresClient = pgPoolClient(new pg.Pool({ connectionString }))
 */
export interface PostgresClient {
  query(
    text: string,
    values?: readonly unknown[],
  ): Promise<{ readonly rows: readonly PostgresRow[] }>
  /** Run `fn` in ONE transaction on ONE connection; commit when it resolves, roll back otherwise. */
  transaction<T>(fn: (tx: PostgresClient) => Promise<T>): Promise<T>
}

/** The subset of a node-postgres `Pool` (and `PoolClient`) the adapter uses. */
export interface PgPoolLike {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>
  connect(): Promise<{
    query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>
    release(error?: Error | boolean): void
  }>
}

const asRows = (rows: unknown[]): readonly PostgresRow[] => rows as PostgresRow[]

/**
 * Adapt a node-postgres `Pool`. Transactions take a dedicated client and always release it; a
 * client whose rollback failed is destroyed instead of returned to the pool.
 *
 * @example
 * const store = postgresAuthStore(pgPoolClient(new pg.Pool({ connectionString: process.env.DB_URL })))
 */
export function pgPoolClient(pool: PgPoolLike): PostgresClient {
  return {
    async query(text, values) {
      return { rows: asRows((await pool.query(text, values ? [...values] : undefined)).rows) }
    },
    async transaction(fn) {
      const client = await pool.connect()
      const tx: PostgresClient = {
        async query(text, values) {
          return { rows: asRows((await client.query(text, values ? [...values] : undefined)).rows) }
        },
        transaction: (inner) => inner(tx),
      }
      let broken: Error | undefined
      try {
        await client.query('BEGIN')
        const result = await fn(tx)
        await client.query('COMMIT')
        return result
      } catch (error) {
        try {
          await client.query('ROLLBACK')
        } catch (rollback) {
          broken = rollback instanceof Error ? rollback : new Error(String(rollback))
        }
        throw error
      } finally {
        client.release(broken)
      }
    },
  }
}

/** The subset of PGlite (`@electric-sql/pglite`) the adapter uses. */
export interface PGliteLike {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>
  transaction<T>(
    fn: (tx: {
      query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>
    }) => Promise<T>,
  ): Promise<T>
}

/**
 * Adapt PGlite (in-process PostgreSQL; tests and demos).
 *
 * @example
 * const store = postgresAuthStore(pgliteClient(await PGlite.create()))
 */
export function pgliteClient(db: PGliteLike): PostgresClient {
  const wrap =
    (q: PGliteLike['query']): PostgresClient['query'] =>
    async (text, values) => ({
      rows: asRows((await q(text, values ? [...values] : undefined)).rows),
    })
  return {
    query: wrap((t, v) => db.query(t, v)),
    transaction: (fn) =>
      db.transaction((raw) => {
        const tx: PostgresClient = {
          query: wrap((t, v) => raw.query(t, v)),
          transaction: (inner) => inner(tx),
        }
        return fn(tx)
      }),
  }
}

/** The subset of the framework's `Database` (`@strutvane/framework/database`) the adapter uses. */
export interface FrameworkDatabaseLike {
  readonly dialect: string
  query(sql: string, params?: readonly unknown[]): Promise<Record<string, unknown>[]>
  transaction<T>(fn: (tx: FrameworkDatabaseLike) => Promise<T>): Promise<T>
}

/**
 * Adapt the framework's `Database` (bound as `DatabaseToken`), so auth shares the app's pool.
 * Throws for a non-PostgreSQL database: use the SQLite store there.
 *
 * @example
 * const store = postgresAuthStore(frameworkDatabaseClient(app.make(DatabaseToken)))
 */
export function frameworkDatabaseClient(db: FrameworkDatabaseLike): PostgresClient {
  if (db.dialect !== 'postgres')
    throw new TypeError(
      `postgres auth store: the app database is ${db.dialect}, not postgres (use the SQLite store)`,
    )
  const wrap = (d: FrameworkDatabaseLike): PostgresClient => ({
    async query(text, values) {
      return { rows: await d.query(text, values) }
    },
    transaction: (fn) => d.transaction((tx) => fn(wrap(tx))),
  })
  return wrap(db)
}

/**
 * Create the identity tables if they are missing (idempotent). Apps normally get them from the
 * shipped migration through `migrate`; this is for tests, demos and scripts.
 *
 * @example
 * await ensurePostgresAuthSchema(client)
 */
export async function ensurePostgresAuthSchema(db: PostgresClient): Promise<void> {
  await db.transaction(async (tx) => {
    for (const statement of POSTGRES_AUTH_STATEMENTS) await tx.query(statement)
  })
}

function str(row: PostgresRow, key: string): string {
  const v = row[key]
  if (typeof v !== 'string') throw new TypeError(`postgres store: column ${key} is not text`)
  return v
}
function strOrNull(row: PostgresRow, key: string): string | null {
  const v = row[key]
  return v === null || v === undefined ? null : str(row, key)
}
/** `bigint` arrives as a string (node-postgres) or a number/bigint (PGlite); all become numbers. */
function num(row: PostgresRow, key: string): number {
  const v = row[key]
  const n =
    typeof v === 'number' ? v : typeof v === 'bigint' || typeof v === 'string' ? Number(v) : NaN
  if (!Number.isSafeInteger(n))
    throw new TypeError(`postgres store: column ${key} is not an integer`)
  return n
}
function numOrNull(row: PostgresRow, key: string): number | null {
  const v = row[key]
  return v === null || v === undefined ? null : num(row, key)
}
function bool(row: PostgresRow, key: string): boolean {
  const v = row[key]
  if (typeof v !== 'boolean') throw new TypeError(`postgres store: column ${key} is not boolean`)
  return v
}
/** A `jsonb` value (drivers parse it; a string is parsed here for drivers that do not). */
function json(row: PostgresRow, key: string): unknown {
  const v = row[key]
  return typeof v === 'string' ? (JSON.parse(v) as unknown) : v
}
function strings(row: PostgresRow, key: string): readonly string[] {
  const v = json(row, key)
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
}
function record(row: PostgresRow, key: string): Readonly<Record<string, string>> {
  const v = json(row, key)
  const out: Record<string, string> = {}
  if (typeof v === 'object' && v !== null && !Array.isArray(v))
    for (const [k, value] of Object.entries(v)) if (typeof value === 'string') out[k] = value
  return out
}

const SESSION_STATES: readonly SessionRecord['state'][] = ['active', 'two-factor']
const SESSION_METHODS: readonly SessionRecord['method'][] = ['password', 'email-link', 'passkey']
const ONE_TIME_PURPOSES: readonly OneTimeRecord['purpose'][] = [
  'password-reset',
  'email-link',
  'trusted-device',
  'webauthn-registration',
  'webauthn-authentication',
  'registration',
]

/** Exactly one of `allowed`, or a TypeError: an unknown value is never mapped to a default. */
function oneOf<T extends string>(row: PostgresRow, key: string, allowed: readonly T[]): T {
  const v = str(row, key)
  const found = allowed.find((a) => a === v)
  if (found === undefined) throw new TypeError(`postgres store: column ${key} has an unknown value`)
  return found
}

const toUser = (r: PostgresRow): UserRecord => ({
  id: str(r, 'id'),
  email: str(r, 'email'),
  name: str(r, 'name'),
  passwordHash: strOrNull(r, 'password'),
  emailVerifiedAt: numOrNull(r, 'email_verified_at'),
  twoFactorSecret: strOrNull(r, 'two_factor_secret'),
  twoFactorConfirmedAt: numOrNull(r, 'two_factor_confirmed_at'),
  twoFactorLastStep: numOrNull(r, 'two_factor_last_step'),
  currentTeamId: strOrNull(r, 'current_team_id'),
  createdAt: num(r, 'created_at'),
})

const toSession = (r: PostgresRow): SessionRecord => ({
  digest: str(r, 'id'),
  userId: str(r, 'user_id'),
  // Fail closed: mapping "anything else" to 'active' would sign in a pending 2FA session.
  state: oneOf(r, 'state', SESSION_STATES),
  method: oneOf(r, 'method', SESSION_METHODS),
  createdAt: num(r, 'created_at'),
  lastSeenAt: num(r, 'last_activity'),
  expiresAt: num(r, 'expires_at'),
  idleMs: num(r, 'idle_ms'),
  remember: bool(r, 'remember'),
  passwordConfirmedAt: numOrNull(r, 'password_confirmed_at'),
  impersonatorId: strOrNull(r, 'impersonator_id'),
  ip: strOrNull(r, 'ip_address'),
  userAgent: strOrNull(r, 'user_agent'),
})

const toOneTime = (r: PostgresRow): OneTimeRecord => ({
  digest: str(r, 'digest'),
  purpose: oneOf(r, 'purpose', ONE_TIME_PURPOSES),
  userId: strOrNull(r, 'user_id'),
  payload: record(r, 'payload'),
  createdAt: num(r, 'created_at'),
  expiresAt: num(r, 'expires_at'),
})

const toPasskey = (r: PostgresRow): PasskeyRecord => ({
  id: str(r, 'id'),
  userId: str(r, 'user_id'),
  name: str(r, 'name'),
  credentialId: str(r, 'credential_id'),
  publicKey: str(r, 'public_key'),
  counter: num(r, 'counter'),
  transports: strings(r, 'transports'),
  backedUp: bool(r, 'backed_up'),
  createdAt: num(r, 'created_at'),
  lastUsedAt: numOrNull(r, 'last_used_at'),
})

const toToken = (r: PostgresRow): TokenRecord => ({
  id: str(r, 'id'),
  userId: str(r, 'user_id'),
  name: str(r, 'name'),
  digest: str(r, 'token'),
  abilities: strings(r, 'abilities'),
  createdAt: num(r, 'created_at'),
  lastUsedAt: numOrNull(r, 'last_used_at'),
  expiresAt: numOrNull(r, 'expires_at'),
})

const toTeam = (r: PostgresRow): TeamRecord => ({
  id: str(r, 'id'),
  name: str(r, 'name'),
  slug: strOrNull(r, 'slug'),
  personal: bool(r, 'personal'),
  createdAt: num(r, 'created_at'),
})

const toMember = (r: PostgresRow): MemberRecord => ({
  teamId: str(r, 'team_id'),
  userId: str(r, 'user_id'),
  role: str(r, 'role'),
})

const toInvitation = (r: PostgresRow): InvitationRecord => ({
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
const USER_COLUMNS: Readonly<Record<string, string>> = {
  name: 'name',
  passwordHash: 'password',
  emailVerifiedAt: 'email_verified_at',
  twoFactorSecret: 'two_factor_secret',
  twoFactorConfirmedAt: 'two_factor_confirmed_at',
  twoFactorLastStep: 'two_factor_last_step',
  currentTeamId: 'current_team_id',
}
const SESSION_COLUMNS: Readonly<Record<string, string>> = {
  lastSeenAt: 'last_activity',
  passwordConfirmedAt: 'password_confirmed_at',
}
const PASSKEY_COLUMNS: Readonly<Record<string, string>> = {
  name: 'name',
  counter: 'counter',
  lastUsedAt: 'last_used_at',
  backedUp: 'backed_up',
}

/** `SET a = $1, b = $2` from a patch through a fixed column map (keys never come from input). */
function setClause(
  patch: object,
  columns: Readonly<Record<string, string>>,
): { readonly sql: string; readonly values: unknown[] } {
  const parts: string[] = []
  const values: unknown[] = []
  for (const [key, value] of Object.entries(patch)) {
    const column = columns[key]
    if (column === undefined || value === undefined) continue
    values.push(value)
    parts.push(`${column} = $${values.length}`)
  }
  return { sql: parts.join(', '), values }
}

/**
 * An {@link AuthStore} on PostgreSQL. The tables come from the shipped migration (`migrate`), or
 * from {@link ensurePostgresAuthSchema} in tests.
 *
 * @example
 * ```ts
 * import pg from 'pg'
 * const store = postgresAuthStore(pgPoolClient(new pg.Pool({ connectionString: process.env.DB_URL })))
 * ```
 */
export function postgresAuthStore(db: PostgresClient): AuthStore {
  const one = async (sql: string, values: readonly unknown[]): Promise<PostgresRow | undefined> =>
    (await db.query(sql, values)).rows[0]
  const all = async (sql: string, values: readonly unknown[]): Promise<readonly PostgresRow[]> =>
    (await db.query(sql, values)).rows
  /** Rows a write touched (every write here says `RETURNING 1`). */
  const count = async (sql: string, values: readonly unknown[]): Promise<number> =>
    (await db.query(sql, values)).rows.length

  return {
    async createUser(u) {
      const row = await one(
        `INSERT INTO users (id, email, name, password, email_verified_at, two_factor_secret,
           two_factor_confirmed_at, two_factor_last_step, current_team_id, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING RETURNING *`,
        [
          u.id,
          u.email,
          u.name,
          u.passwordHash,
          u.emailVerifiedAt,
          u.twoFactorSecret,
          u.twoFactorConfirmedAt,
          u.twoFactorLastStep,
          u.currentTeamId,
          u.createdAt,
        ],
      )
      return row ? toUser(row) : undefined
    },
    async findUserById(id) {
      const row = await one('SELECT * FROM users WHERE id = $1', [id])
      return row ? toUser(row) : undefined
    },
    async findUserByEmail(email) {
      const row = await one('SELECT * FROM users WHERE email = $1', [email])
      return row ? toUser(row) : undefined
    },
    async updateUser(id, patch) {
      const set = setClause(patch, USER_COLUMNS)
      if (set.sql)
        await db.query(`UPDATE users SET ${set.sql} WHERE id = $${set.values.length + 1}`, [
          ...set.values,
          id,
        ])
    },
    async advanceTotpStep(userId, step) {
      return (
        (await count(
          `UPDATE users SET two_factor_last_step = $1
           WHERE id = $2 AND (two_factor_last_step IS NULL OR two_factor_last_step < $1) RETURNING 1`,
          [step, userId],
        )) === 1
      )
    },
    async listUserRoles(userId) {
      return (
        await all('SELECT role FROM user_roles WHERE user_id = $1 ORDER BY role', [userId])
      ).map((r) => str(r, 'role'))
    },
    async setUserRoles(userId, roles) {
      await db.transaction(async (tx) => {
        await tx.query('DELETE FROM user_roles WHERE user_id = $1', [userId])
        for (const role of new Set(roles))
          await tx.query('INSERT INTO user_roles (user_id, role) VALUES ($1, $2)', [userId, role])
      })
    },

    async createSession(s) {
      await db.query(
        `INSERT INTO sessions (id, user_id, state, method, created_at, last_activity, expires_at,
           idle_ms, remember, password_confirmed_at, impersonator_id, ip_address, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
        [
          s.digest,
          s.userId,
          s.state,
          s.method,
          s.createdAt,
          s.lastSeenAt,
          s.expiresAt,
          s.idleMs,
          s.remember,
          s.passwordConfirmedAt,
          s.impersonatorId,
          s.ip,
          s.userAgent,
        ],
      )
    },
    async findSession(digest) {
      const row = await one('SELECT * FROM sessions WHERE id = $1', [digest])
      return row ? toSession(row) : undefined
    },
    async updateSession(digest, patch) {
      const set = setClause(patch, SESSION_COLUMNS)
      if (set.sql)
        await db.query(`UPDATE sessions SET ${set.sql} WHERE id = $${set.values.length + 1}`, [
          ...set.values,
          digest,
        ])
    },
    async deleteSession(digest) {
      await db.query('DELETE FROM sessions WHERE id = $1', [digest])
    },
    async deleteUserSessions(userId, exceptDigest) {
      return exceptDigest === undefined
        ? count('DELETE FROM sessions WHERE user_id = $1 RETURNING 1', [userId])
        : count('DELETE FROM sessions WHERE user_id = $1 AND id <> $2 RETURNING 1', [
            userId,
            exceptDigest,
          ])
    },
    async listUserSessions(userId) {
      return (await all('SELECT * FROM sessions WHERE user_id = $1', [userId])).map(toSession)
    },

    async putOneTime(r) {
      await db.query(
        `INSERT INTO auth_one_time_tokens (digest, purpose, user_id, payload, created_at, expires_at)
         VALUES ($1, $2, $3, $4::jsonb, $5, $6)
         ON CONFLICT (purpose, digest) DO UPDATE SET user_id = EXCLUDED.user_id,
           payload = EXCLUDED.payload, created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at`,
        [r.digest, r.purpose, r.userId, JSON.stringify(r.payload), r.createdAt, r.expiresAt],
      )
    },
    async findOneTime(digest, purpose) {
      const row = await one(
        'SELECT * FROM auth_one_time_tokens WHERE digest = $1 AND purpose = $2',
        [digest, purpose],
      )
      return row ? toOneTime(row) : undefined
    },
    async consumeOneTime(digest, purpose) {
      const row = await one(
        'DELETE FROM auth_one_time_tokens WHERE digest = $1 AND purpose = $2 RETURNING *',
        [digest, purpose],
      )
      return row ? toOneTime(row) : undefined
    },
    async deleteUserOneTime(userId, purpose) {
      await db.query('DELETE FROM auth_one_time_tokens WHERE user_id = $1 AND purpose = $2', [
        userId,
        purpose,
      ])
    },

    async replaceRecoveryCodes(userId, digests) {
      await db.transaction(async (tx) => {
        await tx.query('DELETE FROM two_factor_recovery_codes WHERE user_id = $1', [userId])
        for (const d of digests)
          await tx.query(
            'INSERT INTO two_factor_recovery_codes (user_id, digest) VALUES ($1, $2)',
            [userId, d],
          )
      })
    },
    async consumeRecoveryCode(userId, digest) {
      return (
        (await count(
          'DELETE FROM two_factor_recovery_codes WHERE user_id = $1 AND digest = $2 RETURNING 1',
          [userId, digest],
        )) === 1
      )
    },
    async countRecoveryCodes(userId) {
      const row = await one(
        'SELECT COUNT(*) AS n FROM two_factor_recovery_codes WHERE user_id = $1',
        [userId],
      )
      return row ? num(row, 'n') : 0
    },

    async addPasskey(p) {
      await db.query(
        `INSERT INTO passkeys (id, user_id, name, credential_id, public_key, counter, transports,
           backed_up, created_at, last_used_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10)`,
        [
          p.id,
          p.userId,
          p.name,
          p.credentialId,
          p.publicKey,
          p.counter,
          JSON.stringify(p.transports),
          p.backedUp,
          p.createdAt,
          p.lastUsedAt,
        ],
      )
    },
    async findPasskeyByCredentialId(credentialId) {
      const row = await one('SELECT * FROM passkeys WHERE credential_id = $1', [credentialId])
      return row ? toPasskey(row) : undefined
    },
    async listPasskeys(userId) {
      return (
        await all('SELECT * FROM passkeys WHERE user_id = $1 ORDER BY created_at, seq', [userId])
      ).map(toPasskey)
    },
    async updatePasskey(id, patch) {
      const set = setClause(patch, PASSKEY_COLUMNS)
      if (set.sql)
        await db.query(`UPDATE passkeys SET ${set.sql} WHERE id = $${set.values.length + 1}`, [
          ...set.values,
          id,
        ])
    },
    async advancePasskeyCounter(id, expected, patch) {
      return (
        (await count(
          `UPDATE passkeys SET counter = $1, last_used_at = $2, backed_up = $3
           WHERE id = $4 AND counter = $5 RETURNING 1`,
          [patch.counter, patch.lastUsedAt, patch.backedUp, id, expected],
        )) === 1
      )
    },
    async deletePasskey(userId, id) {
      return (
        (await count('DELETE FROM passkeys WHERE id = $1 AND user_id = $2 RETURNING 1', [
          id,
          userId,
        ])) === 1
      )
    },

    async addToken(t) {
      await db.query(
        `INSERT INTO personal_access_tokens (id, user_id, name, token, abilities, created_at,
           last_used_at, expires_at)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)`,
        [
          t.id,
          t.userId,
          t.name,
          t.digest,
          JSON.stringify(t.abilities),
          t.createdAt,
          t.lastUsedAt,
          t.expiresAt,
        ],
      )
    },
    async findTokenByDigest(digest) {
      const row = await one('SELECT * FROM personal_access_tokens WHERE token = $1', [digest])
      return row ? toToken(row) : undefined
    },
    async listTokens(userId) {
      return (
        await all(
          'SELECT * FROM personal_access_tokens WHERE user_id = $1 ORDER BY created_at, seq',
          [userId],
        )
      ).map(toToken)
    },
    async touchToken(id, at) {
      await db.query('UPDATE personal_access_tokens SET last_used_at = $1 WHERE id = $2', [at, id])
    },
    async deleteToken(userId, id) {
      return (
        (await count(
          'DELETE FROM personal_access_tokens WHERE id = $1 AND user_id = $2 RETURNING 1',
          [id, userId],
        )) === 1
      )
    },
    async deleteUserTokens(userId) {
      return count('DELETE FROM personal_access_tokens WHERE user_id = $1 RETURNING 1', [userId])
    },

    async createTeam(team, owner) {
      return db.transaction(async (tx) => {
        const inserted = await tx.query(
          `INSERT INTO teams (id, name, slug, personal, created_at) VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT DO NOTHING RETURNING 1`,
          [team.id, team.name, team.slug, team.personal, team.createdAt],
        )
        if (inserted.rows.length !== 1) return false
        await tx.query('INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3)', [
          owner.teamId,
          owner.userId,
          owner.role,
        ])
        return true
      })
    },
    async findTeam(id) {
      const row = await one('SELECT * FROM teams WHERE id = $1', [id])
      return row ? toTeam(row) : undefined
    },
    async findTeamBySlug(slug) {
      const row = await one('SELECT * FROM teams WHERE slug = $1', [slug])
      return row ? toTeam(row) : undefined
    },
    async findMember(teamId, userId) {
      const row = await one('SELECT * FROM team_members WHERE team_id = $1 AND user_id = $2', [
        teamId,
        userId,
      ])
      return row ? toMember(row) : undefined
    },
    async listMembers(teamId) {
      return (
        await all('SELECT * FROM team_members WHERE team_id = $1 ORDER BY user_id', [teamId])
      ).map(toMember)
    },
    async listUserTeams(userId) {
      return (
        await all('SELECT * FROM team_members WHERE user_id = $1 ORDER BY team_id', [userId])
      ).map(toMember)
    },
    async putMember(m) {
      await db.query(
        `INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3)
         ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
        [m.teamId, m.userId, m.role],
      )
    },
    async removeMember(teamId, userId) {
      await db.query('DELETE FROM team_members WHERE team_id = $1 AND user_id = $2', [
        teamId,
        userId,
      ])
    },
    async changeMemberRole(teamId, userId, role) {
      return db.transaction(async (tx) => {
        // Serialise role changes per team: a second change waits here until the first commits,
        // and its next statement (a new snapshot) sees that commit. Without the lock, two admins
        // demoting each other would each still see the other as admin (CONSISTENCY #117).
        const team = await tx.query('SELECT 1 FROM teams WHERE id = $1 FOR UPDATE', [teamId])
        if (team.rows.length === 0) return 'not-found'
        const keepsAdmin = `(role <> 'admin' OR EXISTS (SELECT 1 FROM team_members o
          WHERE o.team_id = $1 AND o.user_id <> $2 AND o.role = 'admin'))`
        const changed =
          role === null
            ? await tx.query(
                `DELETE FROM team_members WHERE team_id = $1 AND user_id = $2 AND ${keepsAdmin} RETURNING 1`,
                [teamId, userId],
              )
            : await tx.query(
                `UPDATE team_members SET role = $3 WHERE team_id = $1 AND user_id = $2
                 AND ($3 = 'admin' OR ${keepsAdmin}) RETURNING 1`,
                [teamId, userId, role],
              )
        if (changed.rows.length === 1) return 'ok'
        const exists = await tx.query(
          'SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2',
          [teamId, userId],
        )
        return exists.rows.length === 1 ? 'last-admin' : 'not-found'
      })
    },
    async addInvitation(i) {
      await db.query(
        `INSERT INTO team_invitations (id, team_id, email, role, code, invited_by, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [i.id, i.teamId, i.email, i.role, i.digest, i.invitedBy, i.createdAt, i.expiresAt],
      )
    },
    async findInvitationByDigest(digest) {
      const row = await one('SELECT * FROM team_invitations WHERE code = $1', [digest])
      return row ? toInvitation(row) : undefined
    },
    async listInvitations(teamId) {
      return (
        await all('SELECT * FROM team_invitations WHERE team_id = $1 ORDER BY created_at, seq', [
          teamId,
        ])
      ).map(toInvitation)
    },
    async consumeInvitation(id) {
      const row = await one('DELETE FROM team_invitations WHERE id = $1 RETURNING *', [id])
      return row ? toInvitation(row) : undefined
    },
  }
}

/**
 * A shared {@link CounterStore} on PostgreSQL (`auth_counters`): every app instance on one
 * database shares the rate limits and lockouts. `increment` is one atomic upsert.
 *
 * @example
 * const counters = postgresCounterStore(client)
 */
export function postgresCounterStore(db: PostgresClient, clock: Clock = systemClock): CounterStore {
  return {
    async increment(key, ttlMs) {
      const now = clock.now()
      const row = (
        await db.query(
          `INSERT INTO auth_counters (key, value, expires_at) VALUES ($1, 1, $2)
           ON CONFLICT (key) DO UPDATE SET
             value = CASE WHEN auth_counters.expires_at <= $3 THEN 1 ELSE auth_counters.value + 1 END,
             expires_at = CASE WHEN auth_counters.expires_at <= $3 THEN EXCLUDED.expires_at
                               ELSE auth_counters.expires_at END
           RETURNING value`,
          [key, now + ttlMs, now],
        )
      ).rows[0]
      return row ? num(row, 'value') : 1
    },
    async get(key) {
      const row = (
        await db.query('SELECT value FROM auth_counters WHERE key = $1 AND expires_at > $2', [
          key,
          clock.now(),
        ])
      ).rows[0]
      return row ? num(row, 'value') : undefined
    },
    async set(key, value, ttlMs) {
      await db.query(
        `INSERT INTO auth_counters (key, value, expires_at) VALUES ($1, $2, $3)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`,
        [key, value, clock.now() + ttlMs],
      )
    },
    async delete(key) {
      await db.query('DELETE FROM auth_counters WHERE key = $1', [key])
    },
  }
}
