---
"@strutvane/auth": minor
---

**The app owns its `users` table; auth ships ordinary migrations and never creates or alters a table at runtime (decision #2).** Breaking, pre-1.0 (a minor bump).

- New: `migrations/2026_11_18_000001_add_auth_columns_to_users_table.ts` (adds `two_factor_secret`, `two_factor_confirmed_at`, `two_factor_last_step`, `current_team_id` to the skeleton's `users`) and `migrations/2026_11_18_000002_create_auth_tables.ts` (auth's own tables, all `internal`). Both are Schema-builder migrations, so they run on MySQL, MariaDB, PostgreSQL and SQLite and roll back cleanly.
- `node strut auth:migration` now copies these files into `database/migrations` (never overwriting a file the app already has) instead of writing SQL; it no longer needs a database. New exports `copyAuthMigrations`, `AUTH_MIGRATIONS`, `authMigrationsDirectory`.
- The SQLite and PostgreSQL stores no longer run DDL: `sqliteAuthStore` / `sqliteCounterStore` stop creating tables, and `SQLITE_SCHEMA`, `POSTGRES_AUTH_STATEMENTS` and `ensurePostgresAuthSchema` are removed, as are the v1 SQL files in `migrations/{postgres,sqlite}/`.
- The stores read and write the skeleton's columns: user ids are the table's integer key (decimal strings such as `'42'`), and `email_verified_at`, `two_factor_confirmed_at`, `created_at` and `updated_at` are timestamps written like the ORM writes them. A malformed user id is "not found" before it reaches SQL. Email-verification links and system operations accept integer user ids.
- The sessions table is now `auth_sessions` (the framework reserves `sessions`). Passkey uniqueness moves to `credential_key` (the credential id's SHA-256), so a 1024-character WebAuthn credential id fits every engine's index limit.
- Boot checks the auth columns of `users` too, and `config/database.ts` may use the skeleton's flat shape (`pgsql`, `database` as the SQLite file; the default SQLite file is now `database/database.sqlite`).
