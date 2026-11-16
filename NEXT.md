# auth v2 (native engine): paused work, branch v2/native-engine

Paused on the project lead's instruction (usage limit). Nothing is pushed or merged.

## Done (committed, green at each step)
- 05719e6 tooling sync (npm CI, .npmrc, code rules, package check); retired workspace-packages.mjs removed
- 81dcbb0 one kernel on @strutvane/framework (peer ^0.1.0-next.1 + dev 0.1.0-next.1), npm only, engines >=24.3, @simplewebauthn/server 14.1.0
- 82436a9 spike 20 engine ported to src/engine with all 279 tests (test/engine)
- b216caf #25/#107 feature names, #68 snake_case codes, #69 issue shape, #67 403 link answers
- e6ad2ac team slugs + optional personal team
- f1ba439 PostgreSQL store (pg Pool / PGlite / framework Database adapters), app migrations in migrations/{postgres,sqlite}; BA migration moved to migrations-better-auth/; real-PG race tests (test/integration/postgres-store.test.ts, 8 green)
- 1bd341c system operations (seeders, commands, identity adapter)

## In this WIP commit (NOT fully green yet)
- src/identity/native.ts: native IdentityEngine over the engine (contract passes: test/native-engine.test.ts 34/34)
- contract kit: lowercase codes, ownerRole per engine; new codes two_factor_required, email_not_verified
- src/identity/app-identity.ts: engine/store selection (postgres via framework Database or own pool, sqlite file, memory; Better Auth only with identity: 'better-auth')
- Better Auth: one-line DeprecationWarning (BETTER_AUTH_DEPRECATION) on use; subpath stays @strutvane/auth/better-auth
- provider: binds SessionCookieToken in register() (one cookie-name source, #105; boot fails on mismatch), mounts engine routes under {api}/auth, AuthMailerToken, domain events via src/events.ts (auth.user.registered, auth.login.failed, auth.role.assigned, tenant.created, ...)
- new exports: engine API in index, postgres store in ./postgres, sqlite store in new ./sqlite subpath
- engine config: custom role lists, sessionCookie base

## Test state at pause
- tsc clean, biome clean
- test/engine: 422 green (last full run before the adapter); native-engine + security-regressions green
- STILL FAILING (from last v1-suite run): test/app-identity.test.ts (4: selection rules/messages changed, admin/commands memory checks), test/app-provider.test.ts (4: seed admin role, tenancy endpoints with owner->admin, clientAddress limit)
- integration suite (better-auth, app-identity) not re-run since the contract change

## Next
1. Fix the 8 failing v1 tests above (owner->admin for native tenants; APP_KEY for database driver; provider expectations), add tests for events.ts, engine-config.ts, tokens, SessionCookieToken mismatch, engine routes via provider, deprecation warning.
2. Run integration suite (Docker): BA contract with lowercase codes, app-identity.
3. Coverage 90/90/85/90; check-code-rules, check-package, publint --strict, attw (npm pack).
4. README + migration guide (v1 Better Auth -> native), major/minor changeset (note: in pre mode a `major` would version to 1.0.0-next.0; ADR-0020 says breaking pre-1.0 = minor -> needs a decision), `npx changeset version`, CHANGELOG check.
5. Gate 3x under load; report.
Not done/decisions: #29 forced password change, #23 APP_PREVIOUS_KEYS, #70 ability-based impersonation, framework Hash/keyring (#63-66) not in framework yet, framework core codes still UPPERCASE (#68), MySQL store waits for ORM, lockfile framework entry has no integrity until 0.1.0-next.1 is published.
