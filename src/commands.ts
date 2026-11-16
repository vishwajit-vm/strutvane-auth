/**
 * CLI commands contributed by `@strutvane/auth` (package.json `strutvane.commands`), loaded by the
 * project-local CLI from the app's `node_modules`. Plain objects in the CLI's command shape; auth
 * never imports the CLI.
 *
 * - `auth:migration`: writes `database/migrations/<timestamp>_auth_identity.sql` with the identity
 *   tables (native engine: the shipped migration, for apps that keep migrations in the app; the
 *   deprecated Better Auth adapter: only what is missing), applied by `migrate`.
 * - `auth:user:create --email --name --password-env VAR`: an account (the password is read from an
 *   environment variable so it never lands in shell history or process listings).
 * - `tenant:create --name --slug --owner <email>` and
 *   `tenant:member:add --tenant <slug|id> --email --role`.
 *
 * Exit codes follow the CLI: 0 success, 2 usage, 3 validation, 4 conflict, 5 database.
 *
 * @module
 */
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import {
  IdentityAdminError,
  IdentitySetupError,
  loadAuthProject,
  openIdentityAdmin,
} from './admin.ts'
import { createAppIdentity, RATE_LIMIT_TABLE } from './identity/app-identity.ts'
import { engineConfigFrom } from './identity/engine-config.ts'
import { rateLimitTableSql } from './postgres/rate-limit-store.ts'

/** The parts of the CLI's command context these commands use. */
export interface AuthCommandContext {
  readonly flags: Readonly<Record<string, string | boolean | string[] | undefined>>
  requireProject(): { readonly root: string }
  readonly out: {
    line(text?: string): void
    success(text: string): void
    info(text: string): void
    warn(text: string): void
  }
}

/** A contributed command, in the CLI's shape. */
export interface AuthCommand {
  readonly name: string
  readonly description: string
  readonly details?: string
  readonly flags?: Readonly<
    Record<string, { readonly type: 'boolean' | 'string'; readonly description?: string }>
  >
  run(
    ctx: AuthCommandContext,
  ): Promise<{ readonly exitCode?: number; readonly data?: unknown } | undefined>
}

const BREAKPOINT = '--> statement-breakpoint'
const str = (v: unknown): string | undefined =>
  typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined

/** `20261114083000` for a Date (UTC), the framework's migration name prefix. */
export function migrationStamp(date: Date): string {
  return date.toISOString().replace(/[-:T]/g, '').slice(0, 14)
}

/** Split Better Auth's compiled SQL into statements joined by the framework's breakpoint. */
export function toMigrationFile(
  sql: string,
  created: Date,
  dialect: 'postgres' | 'sqlite' = 'postgres',
): string | undefined {
  const statements = sql
    .split(/;\s*(?:\r?\n|$)/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    // Idempotent, like the package migration: either file may run first on a fresh database.
    .map((s) =>
      s
        .replace(/^create table "/i, 'create table if not exists "')
        .replace(
          /^create (unique )?index "/i,
          (_m, unique: string | undefined) => `create ${unique ?? ''}index if not exists "`,
        ),
    )
  if (statements.length === 0) return undefined
  return [
    '-- strutvane:migration',
    '-- name: auth_identity',
    `-- dialect: ${dialect}`,
    `-- created: ${created.toISOString()}`,
    '-- Tables of the persistent identity (@strutvane/auth). Written by auth:migration.',
    statements.join(`;\n${BREAKPOINT}\n`) + ';',
    '',
  ].join('\n')
}

/** Turn an expected failure into a message and an exit code. */
async function guarded(
  ctx: AuthCommandContext,
  run: () => Promise<{ readonly exitCode?: number; readonly data?: unknown } | undefined>,
): Promise<{ readonly exitCode?: number; readonly data?: unknown } | undefined> {
  try {
    return await run()
  } catch (error) {
    if (error instanceof IdentityAdminError) {
      ctx.out.warn(error.message)
      return { exitCode: error.code === 'email_unavailable' ? 4 : 3 }
    }
    if (error instanceof IdentitySetupError) {
      ctx.out.warn(error.message)
      return { exitCode: 3 }
    }
    const code = (error as { code?: unknown }).code
    if (typeof code === 'string' && /^(?:ECONNREFUSED|ENOTFOUND|28P01|3D000|57P03)$/.test(code)) {
      ctx.out.warn(
        `Cannot reach the database (${code}). Check DB_* in .env and that it is running.`,
      )
      return { exitCode: 5 }
    }
    throw error
  }
}

const usage = (ctx: AuthCommandContext, message: string) => {
  ctx.out.warn(message)
  return { exitCode: 2 }
}

const migrationCommand: AuthCommand = {
  name: 'auth:migration',
  description: 'Write the migration that creates the auth tables (then run sv migrate)',
  details:
    'Compares the database with the tables persistent sign-in needs (accounts, sessions, tenants, memberships, rate limits) and writes only what is missing to database/migrations. Needs session.driver "database" on PostgreSQL.',
  async run(ctx) {
    return guarded(ctx, async () => {
      const project = await loadAuthProject(ctx.requireProject().root)
      if (project.auth.session?.driver === 'memory' || !project.database)
        throw new IdentitySetupError(
          'config/auth.ts: the identity is kept in memory (session.driver "memory" or no config/database.ts); it needs no tables.',
        )
      const identity = await createAppIdentity({
        auth: project.auth,
        appUrl: project.appUrl,
        root: project.root,
        engineConfig: engineConfigFrom(project.auth, { tenancy: true }),
        database: project.database,
        logger: { warn: (m: string) => ctx.out.warn(m), error: () => undefined },
        deliverPasswordReset: async () => undefined,
        verifyTables: false,
      })
      try {
        if (identity.driver !== 'database' || !identity.compileMigrations)
          throw new IdentitySetupError(
            'Persistent identity needs PostgreSQL or SQLite (config/database.ts).',
          )
        const dir = project.migrationsDirectory
        const written = existsSync(dir)
          ? readdirSync(dir).filter((f) => /_auth_identity\.sql$/.test(f))
          : []
        const missing = (await identity.tablesMissing?.()) ?? true
        // Written but not applied yet: a second file would create the same tables twice.
        if (written.length > 0 && missing) {
          ctx.out.info(`${written.at(-1)} is already written. Run: node strut migrate`)
          return { data: { written: null } }
        }
        // Better Auth answers ";" when nothing is missing.
        const sql = (await identity.compileMigrations()).replace(/^[\s;]+|[\s;]+$/g, '')
        // The native engine compiles its whole schema (idempotent), the adapter only what is
        // missing: either way, nothing to write once the tables exist.
        if (!missing && (sql === '' || identity.native !== undefined)) {
          ctx.out.success('The auth tables are up to date.')
          return { data: { written: null } }
        }
        const now = new Date()
        // The rate-limit table is ours, not Better Auth's; IF NOT EXISTS keeps it idempotent.
        const rateLimits =
          identity.native === undefined ? `${rateLimitTableSql({ table: RATE_LIMIT_TABLE })};` : ''
        const file = toMigrationFile(
          sql === '' ? rateLimits : `${sql};\n${rateLimits}`,
          now,
          identity.dialect ?? 'postgres',
        )
        if (!file) return { data: { written: null } }
        mkdirSync(dir, { recursive: true })
        const path = join(dir, `${migrationStamp(now)}_auth_identity.sql`)
        writeFileSync(path, file, { flag: 'wx' })
        const rel = relative(project.root, path).replaceAll('\\', '/')
        ctx.out.success(`Created ${rel}. Run: node strut migrate`)
        return { data: { written: rel } }
      } finally {
        await identity.close()
      }
    })
  },
}

const userCreateCommand: AuthCommand = {
  name: 'auth:user:create',
  description: 'Create an account (the password comes from an environment variable)',
  flags: {
    email: { type: 'string', description: 'Email address' },
    name: { type: 'string', description: 'Display name' },
    'password-env': {
      type: 'string',
      description:
        'Name of the environment variable holding the password (never pass it as a flag)',
    },
  },
  async run(ctx) {
    const email = str(ctx.flags['email'])
    const name = str(ctx.flags['name'])
    const envName = str(ctx.flags['password-env'])
    if (!email || !name || !envName)
      return usage(
        ctx,
        'Usage: sv auth:user:create --email <email> --name <name> --password-env <VAR>',
      )
    const password = process.env[envName]
    if (!password) return usage(ctx, `Environment variable ${envName} is empty or not set.`)
    return guarded(ctx, async () => {
      const idp = await openIdentityAdmin({ root: ctx.requireProject().root })
      try {
        const existing = await idp.engine.findUserAsSystem({ email })
        if (existing.ok && existing.value)
          throw new IdentityAdminError('email_unavailable', `${email} already has an account`)
        const user = await idp.ensureUser({ email, name, password })
        ctx.out.success(`Created ${user.email} (${user.id})`)
        return { data: { id: user.id, email: user.email } }
      } finally {
        await idp.close()
      }
    })
  },
}

const tenantCreateCommand: AuthCommand = {
  name: 'tenant:create',
  description: 'Create a tenant (workspace) owned by an existing account',
  flags: {
    name: { type: 'string', description: 'Tenant name' },
    slug: { type: 'string', description: 'URL-safe unique id, e.g. acme' },
    owner: { type: 'string', description: 'Email of the owner (must have an account)' },
  },
  async run(ctx) {
    const name = str(ctx.flags['name'])
    const slug = str(ctx.flags['slug'])
    const owner = str(ctx.flags['owner'])
    if (!name || !slug || !owner)
      return usage(ctx, 'Usage: sv tenant:create --name <name> --slug <slug> --owner <email>')
    return guarded(ctx, async () => {
      const idp = await openIdentityAdmin({ root: ctx.requireProject().root })
      try {
        const tenant = await idp.ensureTenant({ name, slug, ownerEmail: owner })
        ctx.out.success(`Tenant ${tenant.slug} (${tenant.tenantId})`)
        return { data: tenant }
      } finally {
        await idp.close()
      }
    })
  },
}

const memberAddCommand: AuthCommand = {
  name: 'tenant:member:add',
  description: 'Give an account a role in a tenant (replaces its previous role there)',
  flags: {
    tenant: { type: 'string', description: 'Tenant slug or id' },
    email: { type: 'string', description: 'Email of the account' },
    role: { type: 'string', description: 'A role from config/auth.ts, e.g. member or viewer' },
  },
  async run(ctx) {
    const tenant = str(ctx.flags['tenant'])
    const email = str(ctx.flags['email'])
    const role = str(ctx.flags['role'])
    if (!tenant || !email || !role)
      return usage(ctx, 'Usage: sv tenant:member:add --tenant <slug> --email <email> --role <role>')
    return guarded(ctx, async () => {
      const idp = await openIdentityAdmin({ root: ctx.requireProject().root })
      try {
        await idp.setMember({ tenant, email, role })
        ctx.out.success(`${email} is now ${role} in ${tenant}`)
        return { data: { tenant, email, role } }
      } finally {
        await idp.close()
      }
    })
  },
}

/** Every command auth contributes. */
const commands: readonly AuthCommand[] = Object.freeze([
  migrationCommand,
  userCreateCommand,
  tenantCreateCommand,
  memberAddCommand,
])
export default commands
