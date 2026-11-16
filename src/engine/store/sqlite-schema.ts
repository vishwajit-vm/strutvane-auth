/**
 * The SQLite schema for the spike's real store. Table and column names follow Laravel where it has
 * one (`users`, `sessions`, `personal_access_tokens`, `passkeys`, `teams`, `team_members`,
 * `team_invitations`); in the framework these become ordinary app migrations (spike 10 format)
 * marked `internal: true` (review F-01), so the auto API never exposes them.
 *
 * Every token-like column holds a keyed digest; `two_factor_secret` holds AES-GCM ciphertext.
 *
 * @module
 */

/** DDL applied by `sqliteAuthStore` (idempotent). */
export const SQLITE_SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password TEXT,
  email_verified_at INTEGER,
  two_factor_secret TEXT,
  two_factor_confirmed_at INTEGER,
  two_factor_last_step INTEGER,
  current_team_id TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS user_roles (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  PRIMARY KEY (user_id, role)
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active', 'two-factor')),
  method TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_activity INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  idle_ms INTEGER NOT NULL,
  remember INTEGER NOT NULL,
  password_confirmed_at INTEGER,
  impersonator_id TEXT,
  ip_address TEXT,
  user_agent TEXT
);
CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id);
CREATE TABLE IF NOT EXISTS auth_one_time_tokens (
  digest TEXT NOT NULL,
  purpose TEXT NOT NULL,
  user_id TEXT,
  payload TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (purpose, digest)
);
CREATE INDEX IF NOT EXISTS auth_one_time_tokens_user ON auth_one_time_tokens(user_id, purpose);
CREATE TABLE IF NOT EXISTS two_factor_recovery_codes (
  user_id TEXT NOT NULL,
  digest TEXT NOT NULL,
  PRIMARY KEY (user_id, digest)
);
CREATE TABLE IF NOT EXISTS passkeys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  credential_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL,
  transports TEXT NOT NULL,
  backed_up INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE INDEX IF NOT EXISTS passkeys_user_id ON passkeys(user_id);
CREATE TABLE IF NOT EXISTS personal_access_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  abilities TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  expires_at INTEGER
);
CREATE INDEX IF NOT EXISTS personal_access_tokens_user_id ON personal_access_tokens(user_id);
CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  personal INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS team_members (
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL,
  role TEXT NOT NULL,
  PRIMARY KEY (team_id, user_id)
);
CREATE INDEX IF NOT EXISTS team_members_user_id ON team_members(user_id);
CREATE TABLE IF NOT EXISTS team_invitations (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT NOT NULL,
  code TEXT NOT NULL UNIQUE,
  invited_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_counters (
  key TEXT PRIMARY KEY,
  value INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
`
