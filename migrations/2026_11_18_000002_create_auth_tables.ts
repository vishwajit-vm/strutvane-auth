import { type Migration, migration } from '@strutvane/framework/schema'

// @strutvane/auth: its own tables (native engine, ADR-0023), as an ordinary migration that runs
// on MySQL, MariaDB, PostgreSQL and SQLite. `node strut auth:migration` copies it into
// database/migrations; `node strut migrate` runs it. The `users` table stays the app's: see the
// add_auth_columns_to_users_table migration that runs just before this one.
//
// Why the columns look like this:
// - Every table is `internal`: framework bookkeeping, never exposed by the generic CRUD API or the
//   sidebar (security review F-01). Auth reads and writes them itself.
// - Every token-like column holds a keyed digest (HMAC-SHA-256, hex), never the raw secret.
// - `user_id` columns are text: they hold the users table's id as a decimal string (and a UUID in
//   the in-memory store), so a malformed id from a request is "not found", never a SQL error.
// - Times in auth's own tables are epoch milliseconds (`bigInteger`), the unit the engine uses.
// - `seq` is an auto-increment primary key on every table: some managed MySQL servers refuse
//   tables without one (`sql_require_primary_key`), and lists are ordered by it.
// - A passkey's credential id can be up to 1024 characters, longer than MySQL can index, so its
//   uniqueness is enforced on `credential_key` (the credential id's SHA-256, hex).
export default migration({
  up(schema) {
    const internal = { internal: true } as const

    // Global roles (`admin`, …) of an account. Deleted with the user.
    schema.create(
      'user_roles',
      (t) => {
        t.id('seq')
        t.foreignId('user_id').constrained('users').cascadeOnDelete()
        t.string('role', 64)
        t.unique(['user_id', 'role'])
      },
      internal,
    )

    // Signed-in sessions. `id` is the keyed digest of the cookie value.
    schema.create(
      'auth_sessions',
      (t) => {
        t.id('seq')
        t.string('id', 64).unique()
        t.string('user_id', 36).index()
        t.string('state', 20)
        t.string('method', 20)
        t.bigInteger('created_at')
        t.bigInteger('last_activity')
        t.bigInteger('expires_at')
        t.bigInteger('idle_ms')
        t.boolean('remember')
        t.bigInteger('password_confirmed_at').nullable()
        t.string('impersonator_id', 36).nullable()
        t.string('ip_address', 45).nullable()
        t.text('user_agent').nullable()
      },
      internal,
    )

    // Single-use secrets: password reset, email link, trusted device, WebAuthn challenges.
    schema.create(
      'auth_one_time_tokens',
      (t) => {
        t.id('seq')
        t.string('digest', 64)
        t.string('purpose', 40)
        t.string('user_id', 36).nullable()
        t.json('payload')
        t.bigInteger('created_at')
        t.bigInteger('expires_at')
        t.unique(['purpose', 'digest'])
        t.index(['user_id', 'purpose'])
      },
      internal,
    )

    schema.create(
      'two_factor_recovery_codes',
      (t) => {
        t.id('seq')
        t.string('user_id', 36)
        t.string('digest', 64)
        t.unique(['user_id', 'digest'])
      },
      internal,
    )

    schema.create(
      'passkeys',
      (t) => {
        t.id('seq')
        t.string('id', 36).unique()
        t.string('user_id', 36).index()
        t.string('name', 100)
        t.text('credential_id')
        t.string('credential_key', 64).unique()
        t.text('public_key')
        t.bigInteger('counter')
        t.json('transports')
        t.boolean('backed_up')
        t.bigInteger('created_at')
        t.bigInteger('last_used_at').nullable()
      },
      internal,
    )

    // Sanctum-style API tokens. `token` is the keyed digest of the secret part.
    schema.create(
      'personal_access_tokens',
      (t) => {
        t.id('seq')
        t.string('id', 36).unique()
        t.string('user_id', 36).index()
        t.string('name', 100)
        t.string('token', 64).unique()
        t.json('abilities')
        t.bigInteger('created_at')
        t.bigInteger('last_used_at').nullable()
        t.bigInteger('expires_at').nullable()
      },
      internal,
    )

    schema.create(
      'teams',
      (t) => {
        t.id('seq')
        t.string('id', 36).unique()
        t.string('name', 100)
        t.string('slug', 63).nullable().unique()
        t.boolean('personal')
        t.bigInteger('created_at')
      },
      internal,
    )

    schema.create(
      'team_members',
      (t) => {
        t.id('seq')
        t.string('team_id', 36)
        t.string('user_id', 36).index()
        t.string('role', 64)
        t.unique(['team_id', 'user_id'])
      },
      internal,
    )

    schema.create(
      'team_invitations',
      (t) => {
        t.id('seq')
        t.string('id', 36).unique()
        t.string('team_id', 36).index()
        t.string('email', 255)
        t.string('role', 64)
        t.string('code', 64).unique()
        t.string('invited_by', 36)
        t.bigInteger('created_at')
        t.bigInteger('expires_at')
      },
      internal,
    )

    // Rate-limit and lockout counters shared by every app instance.
    schema.create(
      'auth_counters',
      (t) => {
        t.id('seq')
        t.string('key', 255).unique()
        t.bigInteger('value')
        t.bigInteger('expires_at')
      },
      internal,
    )
  },
  down(schema) {
    for (const table of [
      'auth_counters',
      'team_invitations',
      'team_members',
      'teams',
      'personal_access_tokens',
      'passkeys',
      'two_factor_recovery_codes',
      'auth_one_time_tokens',
      'auth_sessions',
      'user_roles',
    ])
      schema.dropIfExists(table)
  },
}) as Migration
