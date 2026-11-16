<div align="center">

# Strutvane Auth

**Enterprise authentication and authorization for TypeScript apps: Strutvane's own identity engine (passwords, email links, 2FA, passkeys, API tokens, teams, impersonation), RBAC/ABAC compiled to SQL, multi-tenancy with row-level security and audit.**

[![Status: 0.2.0-next](https://img.shields.io/badge/status-0.2.0--next-orange)](https://github.com/vishwajit-vm/strutvane/blob/main/docs/14-roadmap.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Part of Strutvane](https://img.shields.io/badge/ecosystem-Strutvane-1f3a5f)](https://github.com/vishwajit-vm/strutvane)

</div>

> [!NOTE]
> **Status: `0.2.0-next`: the native identity engine ([ADR-0023](https://github.com/vishwajit-vm/strutvane/blob/main/docs/adr/0023-native-identity-engine-default.md)), authorization, tenancy and audit are implemented and tested, and not released to npm yet.** It follows [ADR-0007](https://github.com/vishwajit-vm/strutvane/blob/main/docs/adr/0007-tenancy-rls-enforcement-rules.md) (tenancy) and [ADR-0008](https://github.com/vishwajit-vm/strutvane/blob/main/docs/adr/0008-policy-predicates-two-valued-semantics.md) (policy semantics). Coming from v1? See [Migrating from v1](#migrating-from-v1-better-auth--native).

## What it is

Strutvane Auth is part of **[Strutvane](https://github.com/vishwajit-vm/strutvane)**, a TypeScript framework and package ecosystem for building enterprise B2B applications. It works **standalone** in any Node app, or **integrated** with `@strutvane/framework`, which talks to it only through the contracts `PermissionProvider` (so the two never import each other).

It peer-depends on [`@strutvane/framework`](https://github.com/vishwajit-vm/strutvane-framework) (`^0.1.0-next.1 || ^0.2.0-next.0`), so an app has exactly one kernel. Its one runtime dependency is `@simplewebauthn/server` (MIT), for passkeys. `pg`, Hono, Vitest and `better-auth` (for the deprecated adapter) are optional peers, used only by the subpaths that need them. It needs Node.js 24.3 or newer.

## What's inside

| Entry point | What you get |
|---|---|
| `@strutvane/auth` | The native identity engine (`createNativeEngine`, `createAuth`, the in-memory store, `createAuthHandler`), `definePolicy` (typed predicate builder, allow/deny, deny wins, deny by default, field rules, `explain()`), `createPermissionProvider`, the tenant resolver chain, `recordAudit`, `AuthMailerToken`, the domain-event names and the framework-agnostic middleware core. |
| `@strutvane/auth/sql` | `compileToSql`: a policy or UI filter → a parameterised, two-valued, NULL-safe Postgres `WHERE` fragment. |
| `@strutvane/auth/postgres` | The PostgreSQL identity store (`postgresAuthStore`, `postgresCounterStore`, `pgPoolClient`, `pgliteClient`, `frameworkDatabaseClient`), `withTenant`, RESTRICTIVE row-level-security and role migration SQL, `tenancyAudit` and the `findSessionSet` lint. |
| `@strutvane/auth/sqlite` | The SQLite identity store on `node:sqlite`. |
| `@strutvane/auth/better-auth` | **Deprecated** (ADR-0023): the v1 Better Auth adapter (needs `better-auth` and `pg`), removed no earlier than 0.3. |
| `@strutvane/auth/hono`, `@strutvane/auth/node` | Auth middleware for Hono, and for `node:http` / Express (connect-style). |
| `@strutvane/auth/testing` | The identity-engine contract suite (run it against any engine) and test helpers. |
| `@strutvane/auth/provider`, `/admin`, `/commands` | The Strutvane app provider, the seeder API and the CLI commands. |

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

## Identity: Strutvane's own engine

The default identity engine is Strutvane's own ([ADR-0023](https://github.com/vishwajit-vm/strutvane/blob/main/docs/adr/0023-native-identity-engine-default.md)). It covers every sign-in option the installer offers, and its only runtime dependency is `@simplewebauthn/server` for passkeys; everything else uses `node:crypto`.

| Feature (`config/auth.ts` `features`) | Default | What you get |
|---|---|---|
| `password` | on | Email + password sign-in (scrypt `ln=17`, rehash on login, timing-safe, one `invalid_credentials` for every failure), per-IP (IPv6 `/64`) and per-account limits, lockout with backoff |
| `passwordReset` | follows `password` | 60-minute single-use links, stored as keyed digests; a reset signs out everywhere |
| `passwordConfirmation` | on | "Confirm your password" (3 h) before 2FA, token, passkey and session changes and impersonation |
| `registration` | off | Public sign-up (B2B apps are invite-only by default) |
| `emailVerification` | off | Signed links (`403 invalid_signature` / `signature_expired` when edited or late); password sign-in waits for the proof (account pre-hijacking protection) |
| `emailLink` | off | Passwordless links bound to the requesting browser (`__Host-` nonce; https outside local) |
| `twoFactor` | off | TOTP (RFC 6238) with 8–10 recovery codes, replay protection, "remember this device" |
| `passkeys` | off | WebAuthn: passwordless sign-in, second factor, several per user |
| `apiTokens` | off | Personal access tokens (`svp_…`, shown once, keyed digest, abilities, expiry) |
| `teams` | off (on with tenancy) | Teams as tenants: invitations, roles, last-admin guard, switching rotates the session |
| `impersonation` | off | Global `admin` only, after confirmation, never another admin, audited with actor and subject |

A switched-off feature has no routes (the same 404 as an unknown path) and its services refuse too. Every secret (session ids, reset and email-link tokens, recovery codes, PATs, invitations) is stored only as an HMAC under `APP_KEY`. Cookies are `__Host-` on https. Error codes are lowercase `snake_case`, and field issues are `{ path, field, code, message }`.

```ts
import { createNativeEngine } from '@strutvane/auth'
import { pgPoolClient, postgresAuthStore, postgresCounterStore } from '@strutvane/auth/postgres'

const db = pgPoolClient(pool) // a node-postgres Pool; the tables come from the shipped migration
const engine = createNativeEngine({
  baseURL: 'https://app.example.com',
  appKey: process.env.APP_KEY, // required with a persistent store
  store: postgresAuthStore(db),
  counters: postgresCounterStore(db), // rate limits shared by every instance
  config: { features: { twoFactor: true, emailVerification: true } },
  mailer: { send: (mail) => queue.push('auth-mail', mail) }, // every mail carries one secret link
})

const { actor } = await engine.authenticate(request) // never throws; anonymous on any doubt
await engine.auth.twoFactor.enable(req) // the full engine, for your own routes and screens
```

**Stores.** The engine reads and writes only through a store port with atomic single-use and guard operations:

| Store | Entry point | Use |
|---|---|---|
| PostgreSQL | `@strutvane/auth/postgres`: `postgresAuthStore`, `postgresCounterStore` over `pgPoolClient(pool)`, `pgliteClient(db)` or `frameworkDatabaseClient(app.make(DatabaseToken))` | Production. In an app it shares the framework's `Database` |
| SQLite | `@strutvane/auth/sqlite`: `sqliteAuthStore`, `sqliteCounterStore` on `node:sqlite` | SQLite apps (the app's own database file) |
| Memory | `memoryAuthStore`, `memoryCounterStore` | Tests and demos |

The ORM-backed store plugs in at the same port once the framework ORM lands: it implements the 46 store methods over the same tables and passes the same store contract (`test/engine/store-contract.test.ts`).

**Tables** ship as ordinary migrations in the framework's format, `migrations/{postgres,sqlite}/…_create_auth_tables.sql`. `migrate` applies them, and `auth:migration` copies them into your app's `database/migrations`.

Every engine implements `IdentityEngine`, so the provider, the middleware and the tenancy layer don't care which one runs. `@strutvane/auth/testing` holds the contract suite, which runs against the native engine and the deprecated Better Auth adapter.

### Middleware outside a Strutvane app

```ts
import { Hono } from 'hono'
import { sessionResolver } from '@strutvane/auth'
import { type AuthVariables, authMiddleware } from '@strutvane/auth/hono'

const app = new Hono<{ Variables: AuthVariables }>()
app.use(authMiddleware({ engine, tenancy: { resolvers: [sessionResolver()] } }))
app.get('/me', (c) => c.json(c.get('actor')))
```

Per-IP rate limits need the socket peer address (`attachRequestMeta`, done by the `/node` and `/hono` adapters, or `clientAddress` on the `http.onRequest` hook). A request without one counts against a single shared fallback bucket, and the engine warns once through its `logger`.

## In a Strutvane app

`create-strutvane` registers `@strutvane/auth/provider` in `strutvane.config.ts`. It connects to the app only through the framework kernel (container tokens, hooks, events), never by importing another product package:

- **Engine and store:** the native engine on the app's database. On PostgreSQL it uses the framework's `Database` (`DatabaseToken`), so there is one pool. On SQLite it uses the same database file. It needs `APP_KEY` and the migrated tables, and boot fails with the fix named when either is missing. Use `session: { driver: 'memory' }` for development and tests. MySQL waits for the framework ORM: until then the identity is kept in memory, with a warning.
- **One cookie-name source (#105):** in `register()` the provider binds `SessionCookieToken` from `config/session.ts` `cookie` (default `strutvane_session`, `__Host-` on https). The engine names its session cookie from that same value, and the framework's CSRF check reads the token. A token bound elsewhere is followed, and a name the engine can't set fails the boot.
- **Permissions:** loads `app/policies/*.policy.ts` at boot, combines them with the role map of `config/auth.ts` (`roles`, `wildcardExclude`, `newModelDefaults`; see "Roles") and binds `PermissionProviderToken` (deny-by-default). Role names come from the role map's keys (plus `admin`, the role that manages a team) or from `rolePreset` (`admin-member`, `admin-manager-member-viewer`).
- **Field rules:** `field('amount').readable({ role })` and `.writable({ role })` are enforced on every API record through the framework's `resource.serialize` and `resource.beforeWrite` hooks; filters, sorts and search on unreadable fields are refused through `filterableFields`.
- **Identity on every request:** an `http.onRequest` hook (`auth.identity`) resolves the actor (and, with `config/tenancy.ts` `enabled: true`, the tenant from the session). `X-Tenant-Id` is honoured only for tenant-less service actors. The hook's `clientAddress` keys the per-IP limits; set `auth.trustedProxies` behind a reverse proxy.
- **Routes** under `{api}/auth` (by default `/api/v1/auth`):
  - the engine's own routes, under Laravel Fortify's names: `POST /login`, `/logout`, `/register`, `/forgot-password`, `/reset-password`, `/two-factor-challenge`, `/email-link`, `GET /email/verify/:id/:hash`, `/user`, `/user/sessions`, `/user/password`, `/user/confirm-password`, `/user/two-factor-authentication`, `/user/passkeys`, `/user/api-tokens`, `/teams/…`, `/impersonate/…`. Each exists only while its feature is on;
  - the v1 endpoints, kept so existing clients keep working: `POST /sign-up` (only with `registration`), `/sign-in`, `/sign-out`, `GET /me`, and with tenancy `POST|GET /tenants`, `POST /switch-tenant` and the member endpoints `GET|POST /tenants/:id/members`, `DELETE /tenants/:id/members/:userId`.

  Unsafe requests must come from the app's own origin (on top of the framework's CSRF check), bodies must be `application/json` and are cut off at 16 KiB, and failures are RFC 9457 problems.
- **Tenants are teams.** A tenant's creator is its `admin`, held inside that tenant only. The last admin can be neither removed nor demoted: the guard is one atomic store operation.
- **Seed admin:** the `seedAdmin` account is created once at boot, and its role (`seedAdmin.role`, default `admin`) is stored with the account (`user_roles`). Self-registered users get `defaultRoles`.
- **Mail:** bind a mailer under `AuthMailerToken` (`{ send(mail) }`). Without one, mails are dropped with a warning that names only the mail kind, never the link.
- **Domain events** on the framework event bus: `auth.user.registered`, `auth.login.succeeded`, `auth.login.failed`, `auth.lockout`, `auth.logout`, `auth.password.changed`, `auth.email.verified`, `auth.two_factor.enabled|disabled`, `auth.passkey.added|removed`, `auth.token.created|revoked`, `auth.session.revoked`, `auth.role.assigned`, `auth.impersonation.started|stopped`, and `tenant.created`, `tenant.switched`, `tenant.invitation.created|accepted`, `tenant.member.changed` (`AUTH_DOMAIN_EVENTS`). Payloads carry ids and enums only, with no IP address. The actor is the user (or the impersonating admin), and `tenant.*` events carry the tenant.
- **Scripts and seeders:** `openIdentityAdmin()` from `@strutvane/auth/admin` builds the same engine from the project's `.env` and `config/`, and offers idempotent `ensureUser`, `ensureTenant` and `setMember`:

  ```ts
  const idp = await openIdentityAdmin()
  try {
    await idp.ensureTenant({ name: 'Acme', slug: 'acme', ownerEmail: 'olivia@acme.test' })
    await idp.setMember({ tenant: 'acme', email: 'vic@acme.test', role: 'member' })
  } finally {
    await idp.close()
  }
  ```
- **Commands:** `auth:migration`, `auth:user:create --email --name --password-env VAR` (the password comes from that environment variable, never a flag), `tenant:create --name --slug --owner <email>` and `tenant:member:add --tenant <slug> --email --role`.

## Migrating from v1 (Better Auth → native)

Version 0.2 makes the native engine the default ([ADR-0023](https://github.com/vishwajit-vm/strutvane/blob/main/docs/adr/0023-native-identity-engine-default.md)). The Better Auth adapter still exists, deprecated, at `@strutvane/auth/better-auth`. It prints one `DeprecationWarning` (code `STRUTVANE_AUTH_BETTER_AUTH`) and will be removed no earlier than 0.3. These v1 findings remain open on it: raw session and reset tokens in the database, a `__Secure-` (not `__Host-`) cookie, no session rotation on tenant switch, `trustedOrigins` not passed through, and `session.idleMinutes` ignored.

To move an app:

1. **Set `APP_KEY`** (`node strut key:generate`). `AUTH_SECRET` and `secret` are no longer used by the native engine.
2. **Create the tables:** `node strut migrate` applies `create_auth_tables` (or run `node strut auth:migration` to copy it into `database/migrations`). The Better Auth tables (`"user"`, `"session"`, `"organization"`, …) are not touched; the v1 package migration now lives in `migrations-better-auth/`.
3. **Move the accounts.** Password hashes are not carried over automatically (no `LegacyVerifier` for Better Auth's scrypt format ships), so every user sets a new password through `forgot-password`. Create the accounts with `openIdentityAdmin().ensureUser` or `auth:user:create`, and teams with `ensureTenant` / `setMember`.
4. **Roles:** a tenant's creator is now `admin` (was `owner`). Rename `owner` to `admin` in your role map and policies, or keep both.
5. **Codes:** identity error codes are lowercase (`invalid_credentials`, `validation_failed`, …), and two are new: `two_factor_required` and `email_not_verified`.
6. **Cookies:** the session cookie is `strutvane_session` (`__Host-strutvane_session` on https). Everyone signs in again once.
7. **Features:** switch sign-in options on in `config/auth.ts` `features`. Public `registration` stays off unless it is `true`.
8. **Keeping Better Auth for now:** set `identity: 'better-auth'` (with `session.driver: 'database'`, PostgreSQL, `secret`). The deprecation notice reminds you.

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
- **Sessions:** the cookie holds a random id and the database holds only its keyed digest. A new session on every sign-in (no fixation) and on every privilege change (team creation and switch). Idle (2 h) and absolute (12 h) timeouts, and server-side revocation. A password reset revokes every session, token and outstanding link. Reset and email-link requests answer the same for unknown accounts. On https, cookies are `__Host-`, `Secure`, `HttpOnly` and `SameSite=Lax`.
- **Audit records redact** passwords, tokens and secrets (plus any fields you name), keeping only the fact that they changed.
- Attack-style tests (IDOR, role tampering, cross-tenant CRUD, header spoofing, SQL injection, session fixation, hostile filters) run on every CI build. See [`test/vapt.test.ts`](test/vapt.test.ts) and [`test/security-regressions.test.ts`](test/security-regressions.test.ts).

## Not built yet

- Screens (login, 2FA challenge, settings) and the `add auth` installer. Also: email change, and the `tokens:prune` and `auth:clear-resets` commands.
- Hashing and signing through the framework's `Hash` and keyring, and `APP_PREVIOUS_KEYS` (key rotation without signing everyone out). The framework doesn't provide these yet, so the engine uses its own scrypt hasher and HKDF key ring behind the same ports.
- A forced password change for generated admin passwords (CONSISTENCY #29), and impersonation by the `impersonate` ability instead of the `admin` role (#70).
- The ORM-backed store and a MySQL store (both wait for the framework ORM).
- OIDC/SAML SSO, SCIM and social login (the `sso` and `social-login` add-ons).
- Schema-per-tenant and database-per-tenant strategies (only `shared` + RLS is implemented).

## Installation

```bash
npm install @strutvane/auth @strutvane/framework
# optional: pg (PostgreSQL), hono (the Hono middleware)
```

## Development

```bash
npm install
npm run ci                 # lint, typecheck, unit/property/PGlite/type tests with coverage, build
npm run test:integration   # real PostgreSQL 18 in a throwaway Docker container
```

| Script | What it does |
|---|---|
| `lint` / `format` | Biome check / auto-fix |
| `typecheck` | `tsc --noEmit` with the strictest settings |
| `test` / `test:coverage` | Vitest: the engine's behaviour and attack suites on the memory, SQLite and PostgreSQL ([PGlite](https://pglite.dev)) stores, fast-check property tests, Postgres-equivalence and RLS tests, the identity contract on the native engine, VAPT tests and type-level tests. Coverage thresholds: 90/90/85/90. |
| `test:integration` | Starts `postgres:18.7-alpine` with `docker run --rm` (removed afterwards, no Docker files written). Runs the identity store's races on a real server, the app provider with persistent identity, pooling/leak/bypass tests, and the deprecated Better Auth adapter's contract and tripwires. |
| `build` | tsdown → one `dist/<entry>.mjs` + `.d.mts` per entry point |

Shared configs (`tsconfig.base.json`, `biome.base.json`, `vitest.shared.ts`, CI workflows) are synced from [strutvane-tooling](https://github.com/vishwajit-vm/strutvane-tooling). Don't edit them here.

## Works alone, better together

| Package | Role |
|---------|------|
| [`@strutvane/framework`](https://github.com/vishwajit-vm/strutvane-framework) | Backend & database core, kernel, contracts, CLI and devkit |
| [`@strutvane/auth`](https://github.com/vishwajit-vm/strutvane-auth) | Authentication, authorization, tenancy, audit (this repo) |
| [`@strutvane/ui`](https://github.com/vishwajit-vm/strutvane-ui) | Metadata-driven frontend |
| [`@strutvane/logs`](https://github.com/vishwajit-vm/strutvane-logs) | Zero-config logging + built-in log viewer (default) |
| [`create-strutvane`](https://github.com/vishwajit-vm/create-strutvane) | Project starter |

## Documentation

- **Package specification:** [07-package-auth.md](https://github.com/vishwajit-vm/strutvane/blob/main/docs/07-package-auth.md)
- **Decisions:** [ADR-0007](https://github.com/vishwajit-vm/strutvane/blob/main/docs/adr/0007-tenancy-rls-enforcement-rules.md) (tenancy), [ADR-0008](https://github.com/vishwajit-vm/strutvane/blob/main/docs/adr/0008-policy-predicates-two-valued-semantics.md) (policy semantics), [ADR-0023](https://github.com/vishwajit-vm/strutvane/blob/main/docs/adr/0023-native-identity-engine-default.md) (native identity engine)
- **Ecosystem blueprint:** [strutvane/docs](https://github.com/vishwajit-vm/strutvane/tree/main/docs), starting with the [executive summary](https://github.com/vishwajit-vm/strutvane/blob/main/docs/00-executive-summary.md)

## Contributing

Issues, ideas and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Public API changes need an RFC, tests, docs and a changeset.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 The Strutvane Authors
