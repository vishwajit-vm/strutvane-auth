<div align="center">

# Strutvane Auth

**Enterprise authentication and authorization for TypeScript apps: identity adapters, RBAC/ABAC compiled to SQL, multi-tenancy with row-level security, audit logs, SSO/SCIM, plus ready-made auth API and screens.**

[![Status: 0.1.0-next](https://img.shields.io/badge/status-0.1.0--next-orange)](https://github.com/vishwajit-vm/strutvane/blob/main/docs/14-roadmap.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Part of Strutvane](https://img.shields.io/badge/ecosystem-Strutvane-1f3a5f)](https://github.com/vishwajit-vm/strutvane)

</div>

> [!NOTE]
> **Status: `0.1.0-next.0`, the authorization, tenancy, identity and audit core is implemented and tested, but not yet released to npm.** It follows [ADR-0007](https://github.com/vishwajit-vm/strutvane/blob/main/docs/adr/0007-tenancy-rls-enforcement-rules.md) (tenancy), [ADR-0008](https://github.com/vishwajit-vm/strutvane/blob/main/docs/adr/0008-policy-predicates-two-valued-semantics.md) (policy semantics) and [ADR-0013](https://github.com/vishwajit-vm/strutvane/blob/main/docs/adr/0013-better-auth-hardened-adapter.md) (Better Auth). The API may still change before `0.1.0`. See [what's not built yet](#not-built-yet).

## What it is

Strutvane Auth is part of **[Strutvane](https://github.com/vishwajit-vm/strutvane)**, a TypeScript framework and package ecosystem for building enterprise B2B applications. It works **standalone** in any Node app, or **integrated** with `@strutvane/framework`, which talks to it only through the contracts `PermissionProvider` (so the two never import each other).

It depends only on [`@strutvane/core`](https://github.com/vishwajit-vm/strutvane-core) and [`@strutvane/contracts`](https://github.com/vishwajit-vm/strutvane-contracts). Better Auth, Hono, `pg` and Vitest are optional peers, used only by the subpaths that need them.

## What's inside

| Entry point | What you get |
|---|---|
| `@strutvane/auth` | `definePolicy` (typed predicate builder, allow/deny, deny wins, deny by default, field rules, `explain()`), `createPermissionProvider`, the tenant resolver chain, `recordAudit`, the native identity engine, rate limiting and the framework-agnostic middleware core. |
| `@strutvane/auth/sql` | `compileToSql`: a policy or UI filter → a parameterised, two-valued, NULL-safe Postgres `WHERE` fragment. |
| `@strutvane/auth/postgres` | `withTenant`, RESTRICTIVE row-level-security and role migration SQL, `tenancyAudit`, the `findSessionSet` lint, and a shared Postgres rate-limit store. |
| `@strutvane/auth/better-auth` | The hardened Better Auth adapter (needs `better-auth` and `pg`). |
| `@strutvane/auth/hono`, `@strutvane/auth/node` | Auth middleware for Hono, and for `node:http` / Express (connect-style). |
| `@strutvane/auth/testing` | The identity-engine contract suite (run it against any adapter) and test helpers. |

## Quick start: policies that compile to SQL

```ts
import { createPermissionProvider, definePolicy, defineSchema } from '@strutvane/auth'
import { compileToSql } from '@strutvane/auth/sql'

const invoice = defineSchema({
  table: 'invoices',
  columns: {
    ownerId: { column: 'owner_id', type: 'uuid' },
    amount: { column: 'amount', type: 'int4' },
    status: { column: 'status', type: 'text' },
    internalNotes: { column: 'internal_notes', type: 'text' },
  },
})

export const invoicePolicy = definePolicy('invoice', { schema: invoice }, ({ allow, deny, field }) => {
  allow(['viewAny', 'view'], { role: ['accountant', 'manager'] })
  allow(['view', 'update'], { when: ({ actor, row }) => row.ownerId.eq(actor.id) }) // compiles to SQL
  allow('approve', { role: 'manager', when: ({ row }) => row.amount.lte(10_000) })
  deny('delete', { when: ({ row }) => row.status.eq('paid'), name: 'paid-is-final' }) // deny wins
  field('internalNotes').readable({ role: 'manager' })
})

const permissions = createPermissionProvider([invoicePolicy]) // register under PermissionProviderToken

// One record, in memory:
await permissions.can(actor, 'invoice.update', { type: 'invoice', record })
// → { allowed: true, reason: 'allow:view|update:signed-in+when' }

// A list, in SQL (pagination counts stay correct; nothing is filtered after the fact):
const filter = await permissions.filterFor(actor, 'invoice.view', 'invoice')
const where = compileToSql(filter, invoice, { alias: 'i' })
await pool.query(`SELECT * FROM invoices i WHERE ${where.sql} LIMIT 50`, where.params)
```

`row.amout` or `row.amount.eq('x')` don't compile, and every condition is validated against the schema when the policy is defined, so mistakes surface at boot. The in-memory check and the SQL select exactly the same rows: property-based tests compare them against real Postgres.

## Roles: the role map

Policies say what each model allows. The role map (the `roles` block of `config/auth.ts`, docs/07 §4.4) adds the broad, app-wide grants, so you don't repeat "admins may do everything" in every policy:

```ts
import { compileRoleMap, createPermissionProvider } from '@strutvane/auth'

const roles = compileRoleMap({
  roles: {
    admin: { permissions: ['*', { action: 'user.update', scope: 'global' }] },
    member: { permissions: ['*.viewAny', '*.view', '*.create', { action: '*.update', own: true }] },
    viewer: { permissions: ['*.viewAny', '*.view'] },
    owner: { scope: 'tenant', permissions: ['*'] }, // a tenant's creator
  },
  wildcardExclude: ['user', 'session', 'role', 'membership', 'auditEvent'],
  newModelDefaults: 'inherit-role-patterns',
})
const permissions = createPermissionProvider([invoicePolicy], { roles })
```

- `'<resource>.<action>'` patterns, with `*` for either part, are allows for actors holding the role.
- `{ action, own: true }` only covers records whose `ownerId` is the actor's id. It compiles to SQL, so lists stay filtered, and it never matches on a model without a text/uuid `ownerId` field.
- `allowed = (policy allows OR role grants) AND NOT policy denies`: a policy `deny` always wins.
- Wildcards never match `wildcardExclude` resources (grant those by exact name), and inside a tenant they only reach models with a `tenantId` column, so a tenant role can never touch platform-wide data through a pattern.
- `scope: 'global'` grants count only outside tenants (platform admins); `'tenant'` only inside one.
- `newModelDefaults: 'admin-only'` limits models nobody names to the full `'*'` grant (partial patterns such as `'*.view'` are then a boot error).
- No roles configured: exactly the policies, deny by default. Every mistake (unknown option, malformed pattern, `own` typo) fails at boot.

In an app, write `config/auth.ts` with `defineAuthConfig` (typed, unknown keys are compile errors); the provider compiles its role map at boot. `permissions.filterableFields(actor, type)` returns the fields a client may filter and sort on (the readable fields; an unknown resource gets none).

## Tenancy with row-level security

```ts
import { tenantRlsSql, withTenant } from '@strutvane/auth/postgres'

// In a migration: ENABLE + FORCE RLS and a RESTRICTIVE policy with USING and WITH CHECK.
const { up } = tenantRlsSql({ table: 'app.invoices', runtimeRole: 'app_user' })

// At runtime: one transaction, tenant set with set_config(…, true), never leaked by the pool.
const rows = await withTenant(pool, tenantId, async (client) => (await client.query('SELECT * FROM app.invoices')).rows)
```

Tenants are resolved per request by a chain: `subdomainResolver`, `pathResolver`, `headerResolver` (only for callers you trust) and `sessionResolver`. The middleware refuses a request for a tenant the actor isn't a member of with 403, and Postgres RLS enforces the boundary in the database. Anonymous requests get no tenant unless you set `tenancy.allowAnonymousTenant` (`true` admits the `subdomain` and `path` resolvers; a list of resolver names is an explicit opt-in).

Run `tenancyAudit(pool)` in CI or `sv doctor`. It flags:
- tables without RLS, or without a RESTRICTIVE `FOR ALL` policy for every role that checks the tenant column against the tenant setting in both USING and WITH CHECK;
- runtime roles that bypass RLS or own tables, directly or through role membership;
- role- or database-level defaults for the tenant setting;
- definer views and `SECURITY DEFINER` functions.

`relationKeyAudit(pool, schemas)` checks that every policy relation points at a unique key (relation fields compile to scalar subqueries). `withTenant` rejects with `TransactionAbortedError` when Postgres rolled the transaction back because a statement inside it failed and the error was caught.

## Identity and middleware

```ts
import { Hono } from 'hono'
import { sessionResolver } from '@strutvane/auth'
import { createBetterAuthEngine } from '@strutvane/auth/better-auth'
import { type AuthVariables, authMiddleware } from '@strutvane/auth/hono'
import { postgresRateLimitStore } from '@strutvane/auth/postgres'

const engine = createBetterAuthEngine({
  pool,
  baseURL: 'https://app.example.com',
  secret: env.AUTH_SECRET, // ≥ 32 random characters, from your secret store
  rateLimitStore: postgresRateLimitStore(pool), // shared by every process
  trustedProxies: ['10.0.0.0/8'], // X-Forwarded-For is honoured only from these
  deliverPasswordReset: ({ email, token }) => mailer.sendReset(email, token),
  onUnexpectedError: (context, error) => logger.error(context, { err: error }),
})

const app = new Hono<{ Variables: AuthVariables }>()
app.use(authMiddleware({ engine, tenancy: { resolvers: [sessionResolver()] } }))
app.get('/me', (c) => c.json(c.get('actor')))
```

Every engine implements `IdentityEngine` and returns results, never throws: stable error codes, cookies as headers, and `authenticate(request) → { actor, headers }` that fails closed. The **native engine** (`createNativeEngine`) is in-memory and meant for development and tests.

Per-IP rate limits need the socket peer address (`attachRequestMeta`, done by the `/node` and `/hono` adapters, or `clientAddress` on the `http.onRequest` hook). A request without one counts against a single shared fallback bucket, and the engine warns once through its `logger`. Set `allowMissingPeer: true` only for hosts that knowingly have no socket; the per-account limit applies either way.

## In a Strutvane app

`create-strutvane` registers `@strutvane/auth/provider` in `strutvane.config.ts`. It plugs into the app only
through core (container token + hooks), never by importing the framework:

- **Permissions:** loads `app/policies/*.policy.ts` at boot, combines them with the role map of
  `config/auth.ts` (`roles`, `wildcardExclude`, `newModelDefaults`; see "Roles" above) and binds
  `PermissionProviderToken` (deny-by-default). A policy gets its schema from the model:
  `definePolicy('invoice', { schema: policySchema(Invoice) }, ({ allow }) => { … })`
  (`policySchema` comes from `@strutvane/framework`).
- **Field rules:** a policy's `field('amount').readable({ role })` and `.writable({ role })` are
  enforced on every API record: the framework's `resource.serialize` hook drops fields the actor may
  not read (lists, show, write responses and included relations), and `resource.beforeWrite` refuses
  (403) a create or update that sends a field the actor may not write. Filters, sorts and search on
  unreadable fields are refused through `filterableFields`.
- **Identity:** an `http.onRequest` hook (`auth.identity`) resolves the actor (and, with
  `config/tenancy.ts` `enabled: true`, the tenant from the session). `X-Tenant-Id` is honoured only
  for tenant-less service actors, and anonymous requests are never scoped to a tenant. The hook's
  `clientAddress` (socket peer) keys the per-IP rate limits; set `auth.trustedProxies` when the app
  runs behind a reverse proxy.
- **Endpoints** under the API base path: `POST /auth/sign-up` (only with `registration: true`;
  public sign-up is off by default),
  `POST /auth/sign-in`, `POST /auth/sign-out`, `GET /auth/me`, and for tenancy `POST|GET /auth/tenants`
  and `POST /auth/switch-tenant` (members only; the creator becomes `owner`, and the session token
  rotates). `POST` endpoints refuse cross-site requests (`Sec-Fetch-Site: cross-site`, or an `Origin`
  other than the app URL, the request's own origin or `auth.trustedOrigins`) and require
  `application/json`. Bodies are read as a stream and cut off at 16 KiB. Failures are RFC 9457 problems.
- **Role names** (docs/07 §2.7): `admin`, `member`, `viewer`, and with tenancy `owner` (the tenant's
  creator, held inside that tenant only).
- **Roles outside tenants:** the `seedAdmin` account from `config/auth.ts` is created at boot with
  `seedAdmin.role`. The role is bound to that account's id, never to the email, and boot fails if the
  account cannot be created. Self-registered users get `defaultRoles` (none unless configured). Engines
  can supply them through the `globalRoles` option of `createNativeEngine`.

The provider uses the native engine: accounts and sessions live in memory and are lost on restart,
so it is for development and tests. Persistent identity (Better Auth on Postgres) is wired by hand
for now (`@strutvane/auth/better-auth`).

## Security notes

- **Deny by default, deny wins, fail closed.** No matching rule denies. A record missing a field the policy needs throws instead of guessing. Without a record, record-dependent actions are denied (`record-required:<rule>`).
- **NULL-safe, two-valued semantics (ADR-0008).** `ne` matches rows with no value, so `deny … when status ne 'draft'` also protects rows without a status. A null actor attribute never matches null rows, and in allow rules it never widens access either: under `ne`, `nin` or `not` the condition part binds to "no match".
- **Records must be well-typed.** A loaded value that doesn't fit its column type (a `bigint` read as a string, `0`/`1` for a boolean, a non-canonical uuid) makes `can()` throw instead of guessing.
- **Hidden fields stay hidden.** `maskRecord` copies only readable schema fields. Validate untrusted filters and sorts with `validateFilter(filter, schema, { allowedFields: policy.filterableFields(actor) })`, so a field the actor can't read can't be probed one comparison at a time. Pass `maskFor: policy` to `diffChanges` / `recordAudit` to redact those fields in audit diffs.
- **Role lists are explicit.** `role: []` is a definition error, never "everyone". Use `scope: 'global'` on platform-admin rules so a tenant's own `admin` role can't match them (`'tenant'` for the reverse).
- **Text compares bytewise in SQL** (`COLLATE "C"`), so case- or accent-insensitive column collations can't make SQL disagree with in-memory checks. Build indexes used by policy filters `COLLATE "C"`, or set `textCollation: 'database'` if every text column is deterministic.
- **No value ever reaches SQL text.** Values are typed parameters, identifiers come only from the schema and are pattern-checked, and text search never uses `LIKE`.
- **Untrusted filters are bounded**: node count, depth, list length and string length are capped before any work is done.
- **Rate limits can't be bypassed with a forged `X-Forwarded-For`.** The client IP comes from the socket peer and only trusted proxies are believed. Sign-in is limited per IP (IPv6 per `/64`) and per account. Requests without a known IP share one fallback bucket instead of skipping the limit. The in-memory store evicts expired windows first and never evicts per-account counters before per-IP ones.
- **Sessions:** a new session on every sign-in (no fixation), token rotation when privileges change (tenant creation and switch), server-side revocation, all sessions and outstanding reset links revoked on password reset, constant-time reset start (no user enumeration), `HttpOnly; SameSite=Lax` cookies that are `Secure` on https.
- **Audit records redact** passwords, tokens and secrets (plus any fields you name), keeping only the fact that they changed.
- Attack-style tests (IDOR, role tampering, cross-tenant CRUD, header spoofing, SQL injection, session fixation, hostile filters) run on every CI build. See [`test/vapt.test.ts`](test/vapt.test.ts) and [`test/security-regressions.test.ts`](test/security-regressions.test.ts).

## Not built yet

These parts of the [package spec](https://github.com/vishwajit-vm/strutvane/blob/main/docs/07-package-auth.md) come in later phases:

- A persistent identity engine in the app provider (it uses the in-memory native engine), password-reset endpoints, screens and the `sv add auth` installer; CLI commands (`sv auth:*`, `sv tenant:*`, `sv audit:*`).
- OIDC/SAML SSO, SCIM, MFA (TOTP, passkeys), magic links, social login, API keys and service-account tokens, JWT refresh rotation.
- Schema-per-tenant and database-per-tenant strategies (only `shared` + RLS is implemented); custom DB-stored roles, teams and record-scoped assignments.
- A Postgres audit sink with a transactional outbox and hash chain (the `AuditSink` interface and an in-memory sink exist).
- Express-specific, Fastify and NestJS adapters (Express already works with the connect-style `@strutvane/auth/node` middleware).
- Generating RBAC/ABAC policies as Postgres permissive RLS policies (today: `filterFor` + `compileToSql` in the query, plus the tenant RLS boundary).

## Installation (once released)

```bash
npm i @strutvane/auth
# optional, per feature: better-auth pg hono
```

## Development

```bash
corepack pnpm@12.18.0 install
corepack pnpm@12.18.0 run ci                # lint → typecheck → unit, property, PGlite and type tests + coverage → build
corepack pnpm@12.18.0 run test:integration  # real PostgreSQL 18 in a throwaway Docker container
```

| Script | What it does |
|---|---|
| `lint` / `format` | Biome check / auto-fix |
| `typecheck` | `tsc --noEmit` with the strictest settings |
| `test` / `test:coverage` | Vitest: unit, fast-check property tests, Postgres-equivalence and RLS tests on [PGlite](https://pglite.dev) (in-process Postgres), the identity contract on the native engine, VAPT tests and type-level tests. Coverage thresholds: 90/90/85/90. |
| `test:integration` | Starts `postgres:18.7-alpine` with `docker run --rm` (removed afterwards, no Docker files written) and runs pooling/leak/bypass tests and the Better Auth contract + tripwires. |
| `build` | tsdown → one `dist/<entry>.mjs` + `.d.mts` per entry point |

Until `@strutvane/contracts` and `@strutvane/core` are published, local development links them from `../contracts` and `../core` through a temporary `overrides` entry in `pnpm-workspace.yaml`. That entry must not be committed (the CI `check-deps` guard rejects it).

Shared configs (`tsconfig.base.json`, `biome.base.json`, `vitest.shared.ts`, CI workflows) are synced from [strutvane-tooling](https://github.com/vishwajit-vm/strutvane-tooling). Don't edit them here.

## Works alone, better together

| Package | Role |
|---------|------|
| [`@strutvane/framework`](https://github.com/vishwajit-vm/strutvane-framework) | Backend & database core |
| [`@strutvane/auth`](https://github.com/vishwajit-vm/strutvane-auth) | Authentication, authorization, tenancy, audit (this repo) |
| [`@strutvane/ui`](https://github.com/vishwajit-vm/strutvane-ui) | Metadata-driven frontend |
| [`@strutvane/core`](https://github.com/vishwajit-vm/strutvane-core) | Kernel: container, providers, config, context |
| [`@strutvane/contracts`](https://github.com/vishwajit-vm/strutvane-contracts) | Shared types and wire protocols |
| [`strutvane` / `@strutvane/cli`](https://github.com/vishwajit-vm/strutvane-cli) | Unified CLI |
| [`@strutvane/devkit`](https://github.com/vishwajit-vm/strutvane-devkit) | SDK for installers, generators and plugins |
| [`@strutvane/logs`](https://github.com/vishwajit-vm/strutvane-logs) | Zero-config logging + built-in log viewer (default) |
| [`create-strutvane`](https://github.com/vishwajit-vm/create-strutvane) | Project starter |

## Documentation

- **Package specification:** [07-package-auth.md](https://github.com/vishwajit-vm/strutvane/blob/main/docs/07-package-auth.md)
- **Decisions:** [ADR-0007](https://github.com/vishwajit-vm/strutvane/blob/main/docs/adr/0007-tenancy-rls-enforcement-rules.md) (tenancy), [ADR-0008](https://github.com/vishwajit-vm/strutvane/blob/main/docs/adr/0008-policy-predicates-two-valued-semantics.md) (policy semantics), [ADR-0013](https://github.com/vishwajit-vm/strutvane/blob/main/docs/adr/0013-better-auth-hardened-adapter.md) (Better Auth)
- **Ecosystem blueprint:** [strutvane/docs](https://github.com/vishwajit-vm/strutvane/tree/main/docs), starting with the [executive summary](https://github.com/vishwajit-vm/strutvane/blob/main/docs/00-executive-summary.md)

## Contributing

Issues, ideas and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Public API changes need an RFC, tests, docs and a changeset.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 The Strutvane Authors
