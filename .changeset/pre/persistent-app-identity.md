---
"@strutvane/auth": minor
---

Persistent identity for apps: with `session.driver: 'database'` on PostgreSQL the provider runs the Better Auth engine on the app's database (accounts, sessions, tenants and memberships survive restarts), with the tables written by the new `sv auth:migration` command. The seed admin is created once and never overwritten. Tenant owners manage members over `/auth/tenants/:id/members`. New `@strutvane/auth/admin` (`openIdentityAdmin`: idempotent `ensureUser`, `ensureTenant`, `setMember` for seeders) and commands `auth:user:create`, `tenant:create`, `tenant:member:add`. `IdentityEngine` gains system operations (`findUserAsSystem`, `createUserAsSystem`, `createTenantAsSystem`, `findTenantAsSystem`, `listMembersAsSystem`), `addMemberAsSystem` accepts any configured role and replaces an existing one, and `createBetterAuthEngine` takes `globalRoles`.
