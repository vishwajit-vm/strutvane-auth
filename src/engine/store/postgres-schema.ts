/**
 * The PostgreSQL schema of the identity tables: the same tables and columns as the SQLite store
 * (`sqlite-schema.ts`), with PostgreSQL types. Shipped to apps as an ordinary migration
 * (`migrations/postgres/`, applied by `migrate`; blueprint §6). `test/engine/migrations.test.ts`
 * checks the migration file and this DDL are the same statements.
 *
 * Choices, and why:
 * - **Ids are `text`, not `uuid`.** Services look rows up by ids that arrive from requests; a
 *   malformed id must be "not found", and a `uuid` column would turn it into a query error
 *   (a 500). Ids are still random UUIDs (`crypto.randomUUID()`).
 * - **Times are `bigint` epoch milliseconds**, like the store port, so no time zone or precision
 *   conversion happens between the core and the database.
 * - **No row-level security on these tables.** They are global (a user exists across teams);
 *   the auth core decides membership. App tables keep the tenant RLS of ADR-0007.
 * - Emails compare byte for byte (the default deterministic collation): the core normalises them
 *   before every query (review F-08).
 *
 * @module
 */

/** Every DDL statement, in order. Each is idempotent (`IF NOT EXISTS`). */
export const POSTGRES_AUTH_STATEMENTS: readonly string[] = Object.freeze([
  `CREATE TABLE IF NOT EXISTS users (
  id text PRIMARY KEY,
  email text NOT NULL UNIQUE,
  name text NOT NULL,
  password text,
  email_verified_at bigint,
  two_factor_secret text,
  two_factor_confirmed_at bigint,
  two_factor_last_step bigint,
  current_team_id text,
  created_at bigint NOT NULL
)`,
  `CREATE TABLE IF NOT EXISTS user_roles (
  user_id text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role text NOT NULL,
  PRIMARY KEY (user_id, role)
)`,
  `CREATE TABLE IF NOT EXISTS sessions (
  id text PRIMARY KEY,
  user_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('active', 'two-factor')),
  method text NOT NULL,
  created_at bigint NOT NULL,
  last_activity bigint NOT NULL,
  expires_at bigint NOT NULL,
  idle_ms bigint NOT NULL,
  remember boolean NOT NULL,
  password_confirmed_at bigint,
  impersonator_id text,
  ip_address text,
  user_agent text
)`,
  'CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions (user_id)',
  `CREATE TABLE IF NOT EXISTS auth_one_time_tokens (
  digest text NOT NULL,
  purpose text NOT NULL,
  user_id text,
  payload jsonb NOT NULL,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  PRIMARY KEY (purpose, digest)
)`,
  'CREATE INDEX IF NOT EXISTS auth_one_time_tokens_user ON auth_one_time_tokens (user_id, purpose)',
  `CREATE TABLE IF NOT EXISTS two_factor_recovery_codes (
  user_id text NOT NULL,
  digest text NOT NULL,
  PRIMARY KEY (user_id, digest)
)`,
  `CREATE TABLE IF NOT EXISTS passkeys (
  id text PRIMARY KEY,
  user_id text NOT NULL,
  name text NOT NULL,
  credential_id text NOT NULL UNIQUE,
  public_key text NOT NULL,
  counter bigint NOT NULL,
  transports jsonb NOT NULL,
  backed_up boolean NOT NULL,
  created_at bigint NOT NULL,
  last_used_at bigint,
  seq bigserial NOT NULL
)`,
  'CREATE INDEX IF NOT EXISTS passkeys_user_id ON passkeys (user_id)',
  `CREATE TABLE IF NOT EXISTS personal_access_tokens (
  id text PRIMARY KEY,
  user_id text NOT NULL,
  name text NOT NULL,
  token text NOT NULL UNIQUE,
  abilities jsonb NOT NULL,
  created_at bigint NOT NULL,
  last_used_at bigint,
  expires_at bigint,
  seq bigserial NOT NULL
)`,
  'CREATE INDEX IF NOT EXISTS personal_access_tokens_user_id ON personal_access_tokens (user_id)',
  `CREATE TABLE IF NOT EXISTS teams (
  id text PRIMARY KEY,
  name text NOT NULL,
  slug text UNIQUE,
  personal boolean NOT NULL,
  created_at bigint NOT NULL
)`,
  `CREATE TABLE IF NOT EXISTS team_members (
  team_id text NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
  user_id text NOT NULL,
  role text NOT NULL,
  PRIMARY KEY (team_id, user_id)
)`,
  'CREATE INDEX IF NOT EXISTS team_members_user_id ON team_members (user_id)',
  `CREATE TABLE IF NOT EXISTS team_invitations (
  id text PRIMARY KEY,
  team_id text NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
  email text NOT NULL,
  role text NOT NULL,
  code text NOT NULL UNIQUE,
  invited_by text NOT NULL,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  seq bigserial NOT NULL
)`,
  `CREATE TABLE IF NOT EXISTS auth_counters (
  key text PRIMARY KEY,
  value bigint NOT NULL,
  expires_at bigint NOT NULL
)`,
])
