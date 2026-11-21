---
"@strutvane/auth": minor
---

Features default to off unless set, and tenant roles are separate from platform roles.

- **Every feature switch is explicit.** The engine no longer turns anything on by itself: `registration` is on only with `registration: true`, `teams` only with tenancy on (`config/tenancy.ts` `enabled`) or `features.teams: true`; every other optional feature stays off unless `config/auth.ts` sets it. Without tenancy the engine's `/teams…` routes do not exist (the same 404 as an unknown path). `createNativeEngine` no longer defaults `registration` and `teams` to on: pass them in `config.features` when you build the engine yourself.
- **A team's creator is its `owner`.** `owner` is the reserved tenant role (it manages members and invitations); `admin` is the platform role only. Role map entries without a `scope` are platform roles (`'global'`); give tenant roles `scope: 'tenant'` (or `'any'` for both places, where inside a tenant the grants reach only resources with a `tenantId` column). Actors inside a tenant match only tenant grants. Invitations, `POST /tenants/:id/members` and the admin API accept only tenant roles. The boot refuses `owner` as a platform role, `admin` as a tenant role, and a platform role with a tenant permission (set the role's scope instead). Grant names (`Decision.reason`) drop the `@global` suffix and spell out `@tenant` and `@any`.
- **Existing data moves on boot.** On SQLite and PostgreSQL, team memberships and pending invitations that still say `admin` become `owner` (idempotent; a warning says how many rows moved). `createFirstAdmin` refuses `owner`.
