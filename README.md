<div align="center">

# Strutvane Auth

**Enterprise authentication and authorization for TypeScript apps: identity adapters, RBAC/ABAC compiled to SQL, multi-tenancy with row-level security, audit logs, SSO/SCIM, plus ready-made auth API and screens.**

[![Status: planning](https://img.shields.io/badge/status-planning-blueviolet)](https://github.com/vishwajit-vm/strutvane/blob/main/docs/14-roadmap.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Part of Strutvane](https://img.shields.io/badge/ecosystem-Strutvane-1f3a5f)](https://github.com/vishwajit-vm/strutvane)

</div>

> [!NOTE]
> **Strutvane Auth is in the design phase.** The specification is written and implementation has not started. Nothing is published to npm yet, and the package name `@strutvane/auth` is reserved for this project. Follow [the roadmap](https://github.com/vishwajit-vm/strutvane/blob/main/docs/14-roadmap.md) for progress.

## What it is

Strutvane Auth is part of **[Strutvane](https://github.com/vishwajit-vm/strutvane)**, a TypeScript framework and package ecosystem for building enterprise B2B applications. You declare models as fields and types, and get migrations, a secured CRUD API, auth/RBAC/tenancy and a complete UI. Every line stays owned, overridable TypeScript.

## Planned capabilities

- **Identity** through adapters: Better Auth by default, OIDC/SAML enterprise IdPs (Entra ID, Okta, Keycloak), and an optional native engine
- Email/password, magic links, social login, **MFA** (TOTP, passkeys), sessions, JWT with refresh rotation, API keys, service accounts
- **Authorization**: roles, permissions and policies with conditions that **compile to SQL filters**, field-level rules, explainable decisions
- **Multi-tenancy**: shared schema with Postgres RLS, schema-per-tenant or database-per-tenant, plus a tenant resolver chain
- **Audit log**: transactional outbox, redaction, optional hash-chain tamper evidence
- Works **standalone** in Hono, Express, Fastify, NestJS and Next.js apps, or **integrated** with `@strutvane/framework` and `@strutvane/ui`

## A taste of the API (design preview)

```ts
import { definePolicy } from '@strutvane/auth'

export default definePolicy('invoice', ({ allow, deny, field }) => {
  allow('read',    { role: ['accountant', 'manager'] })
  allow('read',    { when: ({ actor, row }) => row.ownerId.eq(actor.id) }) // compiles to SQL
  allow('approve', { role: 'manager', when: ({ row }) => row.amount.lte(10_000) })
  deny('delete',   { when: ({ row }) => row.status.eq('paid') })           // deny wins
  field('internalNotes').readable({ role: ['manager'] })
})

// pnpm sv add auth → config, migrations, /api/v1/auth/*, login/register/MFA screens, roles, admin seed
```

## Installation (once released)

```bash
pnpm sv add auth   # or, in any Node app: npx strutvane add auth
```

## Works alone, better together

| Package | Role |
|---------|------|
| [`@strutvane/framework`](https://github.com/vishwajit-vm/strutvane-framework) | Backend & database core |
| [`@strutvane/auth`](https://github.com/vishwajit-vm/strutvane-auth) | Authentication, authorization, tenancy, audit |
| [`@strutvane/ui`](https://github.com/vishwajit-vm/strutvane-ui) | Metadata-driven frontend |
| [`@strutvane/core`](https://github.com/vishwajit-vm/strutvane-core) | Kernel: container, providers, config, context |
| [`@strutvane/contracts`](https://github.com/vishwajit-vm/strutvane-contracts) | Shared types and wire protocols |
| [`strutvane` / `@strutvane/cli`](https://github.com/vishwajit-vm/strutvane-cli) | Unified CLI |
| [`@strutvane/devkit`](https://github.com/vishwajit-vm/strutvane-devkit) | SDK for installers, generators and plugins |
| [`@strutvane/logs`](https://github.com/vishwajit-vm/strutvane-logs) | Zero-config logging + built-in log viewer (default) |
| [`create-strutvane`](https://github.com/vishwajit-vm/create-strutvane) | Project starter |

## Documentation

- **Package specification:** [07-package-auth.md](https://github.com/vishwajit-vm/strutvane/blob/main/docs/07-package-auth.md)
- **Ecosystem blueprint:** [strutvane/docs](https://github.com/vishwajit-vm/strutvane/tree/main/docs), starting with the [executive summary](https://github.com/vishwajit-vm/strutvane/blob/main/docs/00-executive-summary.md) and the [developer experience](https://github.com/vishwajit-vm/strutvane/blob/main/docs/05-developer-experience.md)

## Contributing

Ideas and design feedback are welcome while the project is in the design phase. Open an issue or discussion, and see [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 The Strutvane Authors
