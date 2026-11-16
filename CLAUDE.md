# CLAUDE.md: Strutvane Auth (`@strutvane/auth`)

Project memory for Claude Code in this repository. Keep this file short, accurate and current.

## Ecosystem memory (shared by every Strutvane repo)

The file below is synced from strutvane-tooling and is identical in every repo. It covers how the whole ecosystem fits together: repo map, decisions, connection rules, standards, workflow and current status. Read it before changing anything.

@.claude/ECOSYSTEM.md

## What this repo is

Enterprise authentication and authorization for TypeScript apps: Strutvane's own identity engine (ADR-0023), RBAC/ABAC compiled to SQL, multi-tenancy with row-level security and audit.

It is one repo of the **Strutvane** polyrepo ecosystem (one GitHub repo per package; see ADR-0002). The hub with the full blueprint is https://github.com/vishwajit-vm/strutvane. Locally it is the umbrella folder two levels up: `../../docs/`.

## Status

- **v2 (`0.2.0-next`, branch `v2/native-engine`): the native identity engine is the default (ADR-0023); not yet released to npm.** One concept per file in `src/`:
  - `engine/`: the identity core ported from spike 20 (`auth.ts` createAuth, `config.ts` features/limits, `core/`, `crypto/`, `password/`, `totp/`, `tokens/`, `limits/`, `services/` incl. `system.ts`, `ports/` = the store/counter/mailer/events/cookies ports, `http/routes.ts` Fortify-style handler, `store/` memory, SQLite (`/sqlite`), PostgreSQL (`/postgres`)). Tests: `test/engine/` (every behaviour suite runs on memory, SQLite and PGlite).
  - `policy/`: `schema.ts` (model metadata, identifier safety), `filter.ts` (contracts `QueryFilter` constructors + folding), `bind.ts` (actor refs, null-never-matches), `validate.ts` (the shared gate + limits), `evaluate.ts` (in-memory), `builder.ts` (typed `row`/`actor` proxies), `policy.ts` (`definePolicy`, field rules, explain, extra grants), `roles.ts` (`compileRoleMap`: the `config/auth.ts` role map → grants), `provider.ts` (`createPermissionProvider`, role-only resources, `filterableFields`)
  - `sql/`: the Postgres compiler (subpath `@strutvane/auth/sql`)
  - `tenancy/resolver.ts`; `postgres/`: `withTenant`, RLS/role SQL, `tenancyAudit`, `findSessionSet`, Postgres rate-limit store (subpath `/postgres`)
  - `identity/`: `engine.ts` (the `IdentityEngine` contract, lowercase codes), `native.ts` (the native engine as an `IdentityEngine`), `engine-config.ts` (`config/auth.ts` → engine settings), `app-identity.ts` (engine + store selection), `better-auth.ts` (**deprecated** adapter, subpath `/better-auth`, one DeprecationWarning), `rate-limit.ts`, `limiter.ts` (used by the deprecated adapter)
  - `events.ts` (engine events → framework event bus, `auth.*` / `tenant.*`), `tokens.ts` (`AuthMailerToken`)
  - `http/`: request meta (socket peer, unforgeable) and trusted-proxy client IP
  - `audit/audit.ts`; `middleware/`: `core.ts`, `hono.ts`, `node.ts`; `testing/`: contract suite + helpers (subpath `/testing`)
- Attack-class regression tests live in `test/security-regressions.test.ts` (plus provider-level ones in `test/app-provider.test.ts`).
- Tests are in `test/`: unit, fast-check property (SQL ≡ in-memory on PGlite, plus mutation checks), RLS on PGlite, the identity contract on the native engine, VAPT (`vapt.test.ts`), type-level (`*.test-d.ts`) and README examples (`readme.test.ts`: update both together). `test/integration/` needs Docker: real PostgreSQL 18 (the identity store's races, the provider with persistent identity, pooling, session leaks, bypasses, the deprecated Better Auth contract + TRIPWIRE tests).
- Gates: `npm run ci` (lint → typecheck → tests + coverage 90/90/85/90 → build) and `npm run test:integration`. `src/identity/better-auth.ts` is excluded from unit coverage; the integration suite covers it.
- `config.ts`: `defineAuthConfig` / `AuthConfig` (typed `config/auth.ts`). Role names: the role map's keys plus `admin` (the team-managing role; a tenant's creator), else `rolePreset`. The deprecated Better Auth adapter keeps v1's `owner`. Role-map tests: `test/roles.test.ts` (incl. PGlite SQL ≡ in-memory).
- `provider.ts`: the Strutvane app provider (`@strutvane/auth/provider`; policies + role map → `PermissionProviderToken`, `auth.identity` hook, auth + tenant member endpoints, field rules via `field-rules.ts`). Engine selection: `identity/app-identity.ts` (native on PostgreSQL via the framework `Database`, or SQLite, or memory; Better Auth only with `identity: 'better-auth'`). The provider binds `SessionCookieToken` in `register()` (one cookie-name source, #105). `admin.ts` (`/admin`: seeders and scripts) and `commands.ts` (`sv auth:migration`, `auth:user:create`, `tenant:create`, `tenant:member:add`). Tests: `test/app-provider.test.ts`, `test/app-identity.test.ts`, `test/field-rules.test.ts`, `test/integration/app-identity.test.ts`.
- **Deferred** (see README "Not built yet"): screens and installer; framework `Hash`/keyring and `APP_PREVIOUS_KEYS`; forced admin password change (#29); ability-based impersonation (#70); the ORM-backed and MySQL stores; SSO/SCIM; schema- and database-per-tenant.
- **`@strutvane/framework` 0.1.0-next.1 is not on npm yet:** its lockfile entry has no integrity hash until it is published (then `npm install` fills it in). Locally, install it from a tarball packed from framework main, and pin the registry version again before committing.
- Changesets is in pre mode (`next` tag, `.changeset/pre.json`).
- **Upgrading Better Auth:** the peer is pinned exactly, because the adapter uses the semi-internal `$context.adapter`. Re-run `test:integration`; a failing TRIPWIRE test means Better Auth changed behaviour the adapter relies on (ADR-0013).
- Design first: read this package's spec and the ADRs (0007, 0008, 0023), and write or extend an RFC before changing any public API.
- The source of truth for decisions is `../../docs/00-executive-summary.md`. If anything here conflicts with it, that file wins.
- The package spec is `../../docs/07-package-auth.md` (online: https://github.com/vishwajit-vm/strutvane/blob/main/docs/07-package-auth.md).

## Boundaries (non-negotiable)

- `@strutvane/framework` is a **peer** (one kernel): import it only through `@strutvane/framework/core`, `/contracts` and the root entry's tokens. Never import another product package (`@strutvane/ui`, `files`, `logs`). Optional engines (Better Auth, openid-client, SAML) are optional peers behind adapters.
- Cooperation with other Strutvane packages happens **only through the six connections** of hub docs/17 (contracts, container tokens, hooks, domain events, installer `enhances`, HTTP).
- Public API changes need a changeset, docs and tests. Contract changes need an RFC.

## Conventions

- TypeScript strict, ESM only, Node 24.3+ (Node 26 LTS is the target). No decorators or reflection.
- Validation uses Standard Schema with Zod 4 as the default. Errors are RFC 9457 problem+json.
- Tooling: npm, tsdown (build), Biome (lint/format), Vitest (tests), Playwright (UI e2e), Testcontainers (DB).
- Code generation and AST work pin the TypeScript 6 compiler API (`@typescript/typescript6`), because TypeScript 7 has no compiler API.
- Releases: Changesets, npm trusted publishing (OIDC) with provenance. Core packages share a major release train.
- **Docker is local-only and never committed** (ADR-0006). Never commit `.env`; keep `.env.example` complete and documented.
- Windows, macOS and Linux are all first-class. Use no bash-only scripts.

## Definition of done (for any change)

Code, tests, docs and a changeset ship together. Security implications are noted. The CLI help or reference is updated if commands changed.

## Where things are

- `.claude/skills/`: task playbooks for this package (invoke by name)
- `.claude/agents/`: specialised reviewer subagents
- `.claude/commands/`: slash commands (`/spec`, `/pre-pr`)
