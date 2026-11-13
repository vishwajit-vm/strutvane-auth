---
"@strutvane/auth": minor
---

First implementation of `@strutvane/auth` (Phase 1/2 core):

- Policy engine: `definePolicy` with a typed predicate builder, allow/deny with deny-wins and deny-by-default, field rules (`readableFields`, `maskRecord`, `unwritableFields`), `explain()` and `Decision.reason` strings; actor binding with the null-never-matches rule; one shared validation gate; in-memory evaluation (`can`) and bound contracts `QueryFilter`s for lists (`filterFor`), proven equivalent on Postgres with property-based tests.
- `createPermissionProvider(policies)`: the contracts `PermissionProvider`, deny by default.
- `@strutvane/auth/sql`: parameterised, two-valued, NULL-safe Postgres compiler (strpos/starts_with/right, ASCII-only case folding, correlated scalar subqueries for to-one relations).
- Tenancy: resolver chain (subdomain, path, trusted-only header, session); `@strutvane/auth/postgres` with `withTenant`, RESTRICTIVE RLS and role migration SQL (ADR-0007), `tenancyAudit`, the `findSessionSet` lint and a shared Postgres rate-limit store.
- Identity: the `IdentityEngine` interface with `authenticate(request) → { actor, headers }`; a native in-memory engine; the hardened Better Auth adapter (`@strutvane/auth/better-auth`, ADR-0013) with per-IP and per-account limits, trusted proxies only and per-request membership resolution; the contract suite as `@strutvane/auth/testing`.
- Audit: `recordAudit` with field-level diffs and redaction, the `AuditSink` interface and an in-memory sink.
- Middleware: framework-agnostic core with Hono (`@strutvane/auth/hono`) and node:http/connect (`@strutvane/auth/node`) adapters.
