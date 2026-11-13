# CLAUDE.md: Strutvane Auth (`@strutvane/auth`)

Project memory for Claude Code in this repository. Keep this file short, accurate and current.

## Ecosystem memory (shared by every Strutvane repo)

The file below is synced from strutvane-tooling and is identical in every repo. It covers how the whole ecosystem fits together: repo map, decisions, connection rules, standards, workflow and current status. Read it before changing anything.

@.claude/ECOSYSTEM.md

## What this repo is

Enterprise authentication and authorization for TypeScript apps: identity adapters, RBAC/ABAC compiled to SQL, multi-tenancy with row-level security, audit logs, SSO/SCIM, plus ready-made auth API and screens.

It is one repo of the **Strutvane** polyrepo ecosystem (one GitHub repo per package; see ADR-0002). The hub with the full blueprint is https://github.com/vishwajit-vm/strutvane. Locally it is the umbrella folder two levels up: `../../docs/`.

## Status

- **Implemented: `0.1.0-next.0` (Phase 1/2 core), not yet released to npm.** One concept per file in `src/`:
  - `policy/`: `schema.ts` (model metadata, identifier safety), `filter.ts` (contracts `QueryFilter` constructors + folding), `bind.ts` (actor refs, null-never-matches), `validate.ts` (the shared gate + limits), `evaluate.ts` (in-memory), `builder.ts` (typed `row`/`actor` proxies), `policy.ts` (`definePolicy`, field rules, explain), `provider.ts` (`createPermissionProvider`)
  - `sql/`: the Postgres compiler (subpath `@strutvane/auth/sql`)
  - `tenancy/resolver.ts`; `postgres/`: `withTenant`, RLS/role SQL, `tenancyAudit`, `findSessionSet`, Postgres rate-limit store (subpath `/postgres`)
  - `identity/`: `engine.ts` (interface), `native.ts` (in-memory engine), `better-auth.ts` (hardened adapter, subpath `/better-auth`), `rate-limit.ts`
  - `http/`: request meta (socket peer, unforgeable) and trusted-proxy client IP
  - `audit/audit.ts`; `middleware/`: `core.ts`, `hono.ts`, `node.ts`; `testing/`: contract suite + helpers (subpath `/testing`)
- Tests are in `test/`: unit, fast-check property (SQL ≡ in-memory on PGlite, plus mutation checks), RLS on PGlite, the identity contract on the native engine, VAPT (`vapt.test.ts`), type-level (`*.test-d.ts`) and README examples (`readme.test.ts`: update both together). `test/integration/` needs Docker: real PostgreSQL 18 (pooling, session leaks, bypasses, Better Auth contract + TRIPWIRE tests).
- Gates: `corepack pnpm@12.18.0 run ci` (lint → typecheck → tests + coverage 90/90/85/90 → build) and `corepack pnpm@12.18.0 run test:integration`. `src/identity/better-auth.ts` is excluded from unit coverage; the integration suite covers it.
- `provider.ts`: the Strutvane app provider (`@strutvane/auth/provider`; policies → `PermissionProviderToken`, `auth.identity` hook, auth endpoints on the native engine). Tests: `test/app-provider.test.ts`.
- **Deferred** (see README "Not built yet"): persistent identity in the app provider, reset/tenant endpoints, screens and installer; CLI commands; SSO/SCIM/MFA/API keys; schema- and database-per-tenant; a Postgres audit sink; Express/Fastify/Nest-specific adapters; policies emitted as permissive RLS.
- **Temporary:** `pnpm-workspace.yaml` overrides `@strutvane/contracts` and `@strutvane/core` with `link:../contracts` / `link:../core` until both are published. **Never commit it**; the CI `check-deps` guard rejects it.
- Changesets is in pre mode (`next` tag, `.changeset/pre.json`).
- **Upgrading Better Auth:** the peer is pinned exactly, because the adapter uses the semi-internal `$context.adapter`. Re-run `test:integration`; a failing TRIPWIRE test means Better Auth changed behaviour the adapter relies on (ADR-0013).
- Design first: read this package's spec and the ADRs (0007, 0008, 0013), and write or extend an RFC before changing any public API.
- The source of truth for decisions is `../../docs/00-executive-summary.md`. If anything here conflicts with it, that file wins.
- The package spec is `../../docs/07-package-auth.md` (online: https://github.com/vishwajit-vm/strutvane/blob/main/docs/07-package-auth.md).

## Boundaries (non-negotiable)

- Allowed dependencies: `@strutvane/core`, `@strutvane/contracts`. It must never import `@strutvane/framework` or `@strutvane/ui`. Identity engines (Better Auth, openid-client, SAML) are optional peer dependencies behind adapters.
- Cooperation with other Strutvane packages happens **only through `@strutvane/contracts`**, resolved at runtime via the core container.
- Public API changes need a changeset, docs and tests. Contract changes need an RFC.

## Conventions

- TypeScript strict, ESM only, Node 24+ (Node 26 LTS is the target). No decorators or reflection.
- Validation uses Standard Schema with Zod 4 as the default. Errors are RFC 9457 problem+json.
- Tooling: pnpm, tsdown (build), Biome (lint/format), Vitest (tests), Playwright (UI e2e), Testcontainers (DB).
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
