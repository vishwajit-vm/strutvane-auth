# NEXT: `v2/native-engine` (@strutvane/auth 0.2 core train)

Branch progress for the next session (HANDOFF §2 rule 5). Status of the whole ecosystem is in the hub's `STATE.md`.

## Done (2026-11-19): ready to stage 0.2.0-next.1

- **Version 0.2.0-next.1** (`changeset version`, pre mode `next`). Dev dependency `@strutvane/framework` `0.2.0-next.1` from npm (the lockfile has its integrity); the peer stays `^0.2.0-next.0`. Plain `npm ci` passes (the pinned `allowScripts` were already in place).
- **Decision #2: the app owns `users`.** Auth ships `migrations/2026_11_18_000001_add_auth_columns_to_users_table.ts` and `migrations/2026_11_18_000002_create_auth_tables.ts` (Schema builder, every auth table `internal`), copied by `node strut auth:migration` / `copyAuthMigrations(dir)` (never overwriting). No runtime DDL: the SQLite/PostgreSQL stores stopped creating tables; `SQLITE_SCHEMA`, `POSTGRES_AUTH_STATEMENTS`, `ensurePostgresAuthSchema` and the v1 SQL files are gone. The stores map the skeleton's integer `users.id` (decimal strings) and timestamp columns (`engine/store/users-table.ts`); the sessions table is `auth_sessions`; passkeys are unique on `credential_key` (SHA-256 of the credential id, fits MySQL's 3072-byte index limit). Boot also checks auth's `users` columns; `config/database.ts` may use the skeleton's flat shape (`pgsql`, `database` = the SQLite file, default `database/database.sqlite`).
- **Decision #13: `createFirstAdmin(db, { email, name?, password?, role? })`**, exported from the root `@strutvane/auth` (with `FirstAdminError`, codes `first_admin_exists`, `email_taken`, `validation_failed`, `auth_tables_missing`). Runs on the seeder's framework `Connection` on every engine; returns `{ userId, email, role, oneTimePassword? }`.
- **Tests:** store suites run on the DDL the framework compiles from the real migrations (global setup); `test/engine/migrations.test.ts` (offline compile for MySQL/MariaDB/PG/SQLite, MySQL index-size check, migrate + rollback on SQLite and PGlite, no runtime DDL); `test/first-admin.test.ts` (SQLite file + PGlite end to end with the native engine signing in; MySQL/MariaDB rendered SQL); integration: the framework migrator on real PostgreSQL 18 and a real parallel-connection first-admin race.
- **Verified locally (Windows, Node 24.21):** see `RELEASE-READINESS.md` R2/R5 (3 gate runs, integration, publint, attw, audit).

## Not done / waiting

- **Not pushed** (the coordinator pushes).
- **The installer must change** (create-strutvane `src/templates/app-files.ts`, `ADMIN_SEEDER`):
  - import `createFirstAdmin` and `FirstAdminError` from `@strutvane/auth` (the root); the call `createFirstAdmin(db, { name, email })` already matches;
  - catch `FirstAdminError` with `code === 'first_admin_exists'` (re-seeding) and skip; let other codes fail the seed;
  - print the returned `oneTimePassword` once (it is stored nowhere else);
  - put auth's migrations into the app before `migrate` (`copyAuthMigrations(join(root, 'database/migrations'))` from `@strutvane/auth`, or `node strut auth:migration`).
- **MySQL/MariaDB sign-in** still keeps sessions in memory (no MySQL store yet); the migrations and `createFirstAdmin` already work there.
- Forced change of the one-time password (#29) is not built.
- R2 matrix (Linux/macOS, Node 26), R3 `security-reviewer` pass on this change (schema + first admin), R4 soak, R6–R8: see `RELEASE-READINESS.md`.

## How to verify

```bash
npm ci
npm run ci                      # 3x in a row
npm run test:integration        # needs Docker; starts and removes its own postgres:18.7-alpine container
```
