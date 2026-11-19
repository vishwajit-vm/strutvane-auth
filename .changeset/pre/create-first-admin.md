---
"@strutvane/auth": minor
---

**`createFirstAdmin()`: the app's first administrator from a seeder, on every engine (decision #13).**

`createFirstAdmin(db, { email, name?, password?, role? })` (from `@strutvane/auth`) runs on the seeder's framework connection (`SeedContext.db`), so it works on MySQL, MariaDB, PostgreSQL and SQLite without a running app. It creates the account once (email verified, scrypt hash, role `admin` by default) in one locked transaction. Without `password` it returns a generated 24-character `oneTimePassword` to show once; the password is never logged. It refuses, changing nothing, with `FirstAdminError` and a stable code: `first_admin_exists` (re-seeding is safe), `email_taken` (an existing account is never promoted), `validation_failed`, `auth_tables_missing`.
