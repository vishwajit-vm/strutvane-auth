---
"@strutvane/auth": minor
---

Harden tenant resolution for anonymous requests, rate limiting and policy evaluation defaults.

- Anonymous requests are no longer scoped to a tenant unless `tenancy.allowAnonymousTenant` allows it; the app provider honours `X-Tenant-Id` only for tenant-less service actors. `requireAuth` is now checked before tenant resolution.
- Identity engines count requests without a peer address against a shared fallback bucket (new `allowMissingPeer` and `logger` options); IPv6 clients are limited per `/64`; the memory store evicts expired and per-IP keys before per-account keys. The app provider reads the `clientAddress` of the `http.onRequest` payload and accepts `auth.trustedProxies`.
- The app provider binds the seed admin role to the seeded account and fails boot if it cannot be created; its `POST` endpoints require `application/json`, refuse cross-site requests (new `auth.trustedOrigins`) and stream-limit bodies to 16 KiB.
- Policies: mistyped record values make checks throw; `role: []` is a definition error; null actor values never widen allow rules under negation; new rule/field option `scope` (`'any' | 'global' | 'tenant'`); combined rule limits are checked at definition time; new `filterableFields()` and `restrictedFields`; `maskRecord` keeps only readable schema fields and `unwritableFields` reports non-schema keys.
- `validateFilter` accepts `allowedFields`; error reasons are escaped and truncated and no longer name tables; new `safeLabel`.
- `diffChanges` / `recordAudit` accept `maskFor` to redact fields with read rules.
- SQL: text comparisons use `COLLATE "C"` by default (`textCollation: 'database'` to opt out).
- Postgres: `tenancyAudit` follows role membership, requires tenant policies to apply to every role and read the tenant setting, and flags role/database defaults for it (new `setting` option, code `TENANT_SETTING_DEFAULT`); `findSessionSet` recognises `ALTER ROLE/DATABASE … SET`, `RESET` and quoted names; `withTenant` rejects with `TransactionAbortedError` when Postgres rolled the transaction back; new `relationKeyAudit`.
- Native engine: tenant creation rotates the session token; a completed password reset invalidates the user's other reset tokens. Better Auth adapter: error-code mapping only reads own keys.
