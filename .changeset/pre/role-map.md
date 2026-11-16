---
"@strutvane/auth": minor
---

Enforce the role map of `config/auth.ts` and add `defineAuthConfig`.

- New `compileRoleMap({ roles, wildcardExclude, newModelDefaults })`. Role permissions (`'<resource>.<action>'` with `*` wildcards, and `{ action, own: true }` for records whose `ownerId` is the actor) become allow grants combined with the policies: `(policy allows OR role grants) AND NOT policy denies`. `own` grants compile to SQL and never match on a model without a text/uuid `ownerId`. Resource wildcards skip `wildcardExclude` resources and, inside a tenant, reach only models with a `tenantId` column. `scope` (`'any' | 'global' | 'tenant'`) works per role or per permission. `newModelDefaults: 'admin-only'` limits unnamed models to the full `'*'` grant. Malformed role maps throw `PolicyDefinitionError` at boot. Without roles, behaviour is unchanged.
- `createPermissionProvider(policies, { roles, schemas })`: resources without a policy are decided by the role map alone; the provider exposes `roles` and implements `filterableFields(actor, resourceType)` (the readable fields; an unknown resource gets an empty set).
- Policies accept extra grants: `decide`/`can`/`explain(actor, action, record?, grants?)` and `filterFor(actor, action, grants?)` (new `ExtraGrant` type).
- The app provider compiles `roles`, `wildcardExclude` and `newModelDefaults` from `config/auth.ts`; a malformed role map fails the boot.
- New `defineAuthConfig` and `AuthConfig`: a typed `config/auth.ts` (unknown keys are compile errors), deep-frozen like core's `defineConfig`. `AppAuthConfig` is now an alias of `AuthConfig`.
