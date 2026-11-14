---
"@strutvane/auth": patch
---

The app provider now answers `POST|GET /auth/tenants` and `POST /auth/switch-tenant` only when tenancy is on (`config/tenancy.ts` `enabled: true`), as documented; otherwise they are 404. Before, any signed-in user of an app without tenancy could create a tenant and act as its `owner`.
