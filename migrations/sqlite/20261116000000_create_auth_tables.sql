-- strutvane:migration
-- name: create_auth_tables
-- dialect: sqlite
-- The identity tables of @strutvane/auth (native engine, ADR-0023): users, global roles,
-- sessions, single-use secrets, recovery codes, passkeys, personal access tokens, teams,
-- members, invitations and the shared rate-limit counters. Secrets are stored as keyed
-- digests only. Generated from src/engine/store/*-schema.ts; a test keeps them equal.
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
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS user_roles (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  PRIMARY KEY (user_id, role)
);
--> statement-breakpoint
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
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS auth_one_time_tokens (
  digest TEXT NOT NULL,
  purpose TEXT NOT NULL,
  user_id TEXT,
  payload TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (purpose, digest)
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS auth_one_time_tokens_user ON auth_one_time_tokens(user_id, purpose);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS two_factor_recovery_codes (
  user_id TEXT NOT NULL,
  digest TEXT NOT NULL,
  PRIMARY KEY (user_id, digest)
);
--> statement-breakpoint
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
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS passkeys_user_id ON passkeys(user_id);
--> statement-breakpoint
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
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS personal_access_tokens_user_id ON personal_access_tokens(user_id);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE,
  personal INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS team_members (
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL,
  role TEXT NOT NULL,
  PRIMARY KEY (team_id, user_id)
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS team_members_user_id ON team_members(user_id);
--> statement-breakpoint
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
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS auth_counters (
  key TEXT PRIMARY KEY,
  value INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
