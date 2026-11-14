/**
 * `@strutvane/auth/admin`: manage accounts, tenants and memberships from scripts that run outside
 * the HTTP server (seeders, the `sv auth:*` / `sv tenant:*` commands, one-off maintenance).
 *
 * ```ts
 * // database/seeders/demo.seeder.ts
 * import { openIdentityAdmin } from '@strutvane/auth/admin'
 * const idp = await openIdentityAdmin()                 // reads .env and config/ from the project
 * try {
 *   const acme = await idp.ensureTenant({ name: 'Acme', slug: 'acme', ownerEmail: 'olivia@acme.test' })
 *   await idp.setMember({ tenant: 'acme', email: 'vic@acme.test', role: 'viewer' })
 *   await create(DealFactory, 20, { tenantId: acme.tenantId })
 * } finally {
 *   await idp.close()
 * }
 * ```
 *
 * It builds the same engine as the app provider (see identity/app-identity.ts), so what it writes
 * is what the running app reads. Every `ensure*` call is idempotent: re-running a seeder never
 * duplicates accounts or tenants and never changes an existing password.
 *
 * Failure scenarios:
 * - the app keeps identity in memory (`session.driver` is not `database`, or no PostgreSQL): the
 *   writes would vanish with this process, so {@link openIdentityAdmin} refuses unless
 *   `allowMemory` is set (tests);
 * - an engine refusal (weak password, taken slug, unknown role…) throws {@link IdentityAdminError}
 *   carrying the stable code.
 *
 * @module
 */
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import type { AuthConfig } from './config.ts'
import {
  type AppDatabaseSection,
  createAppIdentity,
  IdentitySetupError,
} from './identity/app-identity.ts'
import type {
  IdentityEngine,
  IdentityErrorCode,
  IdentityResult,
  IdentityUser,
  TenantInfo,
} from './identity/engine.ts'

export { IdentitySetupError } from './identity/app-identity.ts'

/** An engine refusal, with its stable code. */
export class IdentityAdminError extends Error {
  override readonly name = 'IdentityAdminError'
  readonly code: IdentityErrorCode
  constructor(code: IdentityErrorCode, message: string) {
    super(`${message} (${code})`)
    this.code = code
  }
}

/** The project settings auth needs, read from `.env` and `config/`. */
export interface AuthProject {
  readonly root: string
  readonly appUrl: string
  readonly auth: AuthConfig
  readonly database?: AppDatabaseSection | undefined
  readonly migrationsDirectory: string
}

async function importDefault<T>(file: string): Promise<T | undefined> {
  if (!existsSync(file)) return undefined
  const mod = (await import(pathToFileURL(file).href)) as { default?: T }
  return mod.default
}

/**
 * Read a project's auth settings. `.env` is loaded first without overriding variables that are
 * already set (the same rule as the app runtime), then `config/app.ts`, `config/auth.ts` and
 * `config/database.ts`.
 */
export async function loadAuthProject(root: string = process.cwd()): Promise<AuthProject> {
  const envFile = join(root, '.env')
  if (existsSync(envFile)) process.loadEnvFile(envFile)
  const app = await importDefault<{ url?: string }>(join(root, 'config', 'app.ts'))
  const auth = (await importDefault<AuthConfig>(join(root, 'config', 'auth.ts'))) ?? {}
  const database = await importDefault<
    AppDatabaseSection & { migrations?: { directory?: string } }
  >(join(root, 'config', 'database.ts'))
  return {
    root,
    appUrl: app?.url ?? 'http://localhost:3000',
    auth,
    database,
    migrationsDirectory: join(root, database?.migrations?.directory ?? 'database/migrations'),
  }
}

/** Options for {@link openIdentityAdmin}. */
export interface IdentityAdminOptions {
  /** Project root. Default: the working directory (what `sv` and seeders run in). */
  readonly root?: string
  /** Allow an in-memory engine (tests only: nothing outlives the process). */
  readonly allowMemory?: boolean
}

/** What {@link openIdentityAdmin} returns. */
export interface IdentityAdmin {
  readonly engine: IdentityEngine
  readonly driver: 'database' | 'memory'
  /** The account with this email, created (with `password`) when it does not exist yet. */
  ensureUser(input: {
    readonly email: string
    readonly name: string
    readonly password: string
  }): Promise<IdentityUser>
  /** The tenant with this slug, created with `ownerEmail`'s account as owner when missing. */
  ensureTenant(input: {
    readonly name: string
    readonly slug: string
    readonly ownerEmail: string
  }): Promise<TenantInfo>
  /** Give an existing account a role in a tenant (slug or id); replaces a previous role. */
  setMember(input: {
    readonly tenant: string
    readonly email: string
    readonly role: string
  }): Promise<void>
  close(): Promise<void>
}

const unwrap = <T>(result: IdentityResult<T>, what: string): T => {
  if (!result.ok) throw new IdentityAdminError(result.error.code, what)
  return result.value
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** Open the project's identity store for administration. Always `close()` it. */
export async function openIdentityAdmin(
  options: IdentityAdminOptions = {},
): Promise<IdentityAdmin> {
  const project = await loadAuthProject(options.root)
  const warnings: string[] = []
  const identity = await createAppIdentity({
    auth: project.auth,
    appUrl: project.appUrl,
    database: project.database,
    logger: {
      warn: (message: string) => {
        warnings.push(message)
      },
      error: () => undefined,
    },
    deliverPasswordReset: async () => undefined,
  })
  if (identity.driver === 'memory' && options.allowMemory !== true) {
    await identity.close()
    throw new IdentitySetupError(
      `This app keeps accounts in memory, so changes made here would be lost. Use session.driver "database" with PostgreSQL in config/auth.ts.${warnings.length ? ` (${warnings.join('; ')})` : ''}`,
    )
  }
  const engine = identity.engine
  const userByEmail = async (email: string): Promise<IdentityUser> => {
    const found = unwrap(await engine.findUserAsSystem({ email }), `looking up ${email}`)
    if (!found) throw new IdentityAdminError('VALIDATION_FAILED', `no account with email ${email}`)
    return found
  }
  const tenantOf = async (tenant: string): Promise<string> => {
    if (UUID.test(tenant)) return tenant.toLowerCase()
    const found = unwrap(await engine.findTenantAsSystem({ slug: tenant }), `looking up ${tenant}`)
    if (!found) throw new IdentityAdminError('VALIDATION_FAILED', `no tenant with slug ${tenant}`)
    return found.tenantId
  }
  return {
    engine,
    driver: identity.driver,
    async ensureUser(input) {
      const found = unwrap(await engine.findUserAsSystem({ email: input.email }), 'lookup')
      if (found) return found
      return unwrap(await engine.createUserAsSystem(input), `creating ${input.email}`)
    },
    async ensureTenant(input) {
      const found = unwrap(await engine.findTenantAsSystem({ slug: input.slug }), 'lookup')
      if (found) return found
      const owner = await userByEmail(input.ownerEmail)
      const created = unwrap(
        await engine.createTenantAsSystem({
          name: input.name,
          slug: input.slug,
          ownerUserId: owner.id,
        }),
        `creating tenant ${input.slug}`,
      )
      return { tenantId: created.tenantId, name: created.name, slug: created.slug }
    },
    async setMember(input) {
      const roles = project.auth.roles
        ? Object.keys(project.auth.roles)
        : ['owner', 'member', 'viewer']
      if (!roles.includes(input.role))
        throw new IdentityAdminError(
          'VALIDATION_FAILED',
          `role "${input.role}" is not defined in config/auth.ts (roles: ${roles.join(', ')})`,
        )
      const tenantId = await tenantOf(input.tenant)
      const user = await userByEmail(input.email)
      unwrap(
        await engine.addMemberAsSystem({ tenantId, userId: user.id, role: input.role }),
        `adding ${input.email} to ${input.tenant} as ${input.role}`,
      )
    },
    close: () => identity.close(),
  }
}
