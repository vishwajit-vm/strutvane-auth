/**
 * `@strutvane/auth/provider`: the provider `strutvane.config.ts` registers in a Strutvane app.
 *
 * It connects auth to the app only through core (integration map: container tokens + hooks):
 * - binds `PermissionProviderToken` to a provider built from `app/policies/*.policy.ts`
 *   (deny-by-default: an action without a matching rule is refused);
 * - on `http.onRequest` (handler `auth.identity`), resolves the actor (and tenant, with
 *   tenancy on) for every request, and answers the auth endpoints itself:
 *   `POST {api}/auth/sign-up`, `POST {api}/auth/sign-in`, `POST {api}/auth/sign-out`,
 *   `GET {api}/auth/me`, and for tenancy `POST|GET {api}/auth/tenants` and
 *   `POST {api}/auth/switch-tenant` (members only; the creator becomes `owner`).
 *
 * Identity uses the native engine (in memory, single process): accounts and sessions are lost on
 * restart, so it is for development and tests. On boot it creates the `seedAdmin` account from
 * `config/auth.ts` (role `seedAdmin.role`) so there is always a way in; new sign-ups get
 * `defaultRoles` (none unless configured). The persistent Better Auth engine needs Postgres and is
 * wired by hand (`@strutvane/auth/better-auth`).
 *
 * @module
 */
import { existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import type { Actor } from '@strutvane/contracts'
import {
  type Application,
  defineProvider,
  ErrorRegistryToken,
  HooksToken,
  LoggerToken,
  PermissionProviderToken,
  type Provider,
  StrutvaneError,
  UnauthenticatedError,
} from '@strutvane/core'
import { AUTH_ERRORS } from './errors.ts'
import type { IdentityResult } from './identity/engine.ts'
import { createNativeEngine } from './identity/native.ts'
import { authenticateRequest, problemResponse } from './middleware/core.ts'
import type { Policy } from './policy/policy.ts'
import { createPermissionProvider, type StrutvanePermissionProvider } from './policy/provider.ts'
import { headerResolver, sessionResolver } from './tenancy/resolver.ts'

/** `config/auth.ts`, as far as the provider reads it. */
export interface AppAuthConfig {
  readonly registration?: boolean
  readonly seedAdmin?: {
    readonly email?: string
    readonly password?: string
    readonly role?: string
  }
  /** Roles every self-registered user gets outside tenants. Default: none. */
  readonly defaultRoles?: readonly string[]
  readonly session?: { readonly idleMinutes?: number }
}

/** `config/tenancy.ts`. */
export interface AppTenancyConfig {
  readonly enabled?: boolean
  readonly strategy?: 'shared' | 'schema' | 'database'
  readonly resolve?: string
}

const MAX_BODY_BYTES = 16 * 1024

const section = <T>(app: Application, name: string): T | undefined =>
  (app.settings as Readonly<Record<string, unknown>>)[name] as T | undefined

/** `/api` + `v1` → `/api/v1` (the same rule the framework uses for its routes). */
export function apiBase(api: { prefix?: string; version?: string } | undefined): string {
  const prefix = (api?.prefix ?? '/api').replace(/\/+$/, '')
  const version = (api?.version ?? 'v1').replace(/^\/+|\/+$/g, '')
  return `/${prefix}/${version}`.replace(/\/{2,}/g, '/')
}

/** Load the default exports of `app/policies/*.policy.ts`. */
export async function loadPolicies(root: string): Promise<Policy[]> {
  const dir = join(root, 'app', 'policies')
  if (!existsSync(dir)) return []
  const files = readdirSync(dir)
    .filter((f) => f.endsWith('.policy.ts'))
    .sort()
  const out: Policy[] = []
  for (const file of files) {
    const mod = (await import(pathToFileURL(join(dir, file)).href)) as { default?: unknown }
    const policy = mod.default as Partial<Policy> | undefined
    if (!policy || typeof policy.resource !== 'string' || typeof policy.filterFor !== 'function')
      throw new Error(`app/policies/${file} must default-export definePolicy(...)`)
    out.push(policy as Policy)
  }
  return out
}

/** Read a JSON body of at most 16 KiB (the framework body limit doesn't cover hook answers). */
async function readJson(request: Request): Promise<Record<string, unknown>> {
  const length = Number(request.headers.get('content-length') ?? '0')
  if (length > MAX_BODY_BYTES) throw new StrutvaneError('PAYLOAD_TOO_LARGE', { status: 413 })
  const text = await request.text()
  if (text.length > MAX_BODY_BYTES) throw new StrutvaneError('PAYLOAD_TOO_LARGE', { status: 413 })
  try {
    const value: unknown = JSON.parse(text)
    if (typeof value === 'object' && value !== null && !Array.isArray(value))
      return value as Record<string, unknown>
  } catch {
    // fall through
  }
  throw new StrutvaneError('MALFORMED_REQUEST', { status: 400 })
}

const json = (body: unknown, status: number, headers: Headers): Response => {
  const out = new Headers(headers)
  out.set('content-type', 'application/json')
  out.set('cache-control', 'no-store')
  return new Response(JSON.stringify(body), { status, headers: out })
}

const publicActor = (actor: Actor) => ({
  id: actor.id,
  type: actor.type,
  roles: actor.roles,
  ...(actor.tenantId ? { tenantId: actor.tenantId } : {}),
})

const toResponse = (result: IdentityResult<{ readonly actor: Actor } | null>, status = 200) => {
  if (!result.ok) {
    const error = new StrutvaneError(result.error.code, { status: result.error.status })
    const headers = new Headers(result.headers)
    if (result.error.retryAfterSeconds !== undefined)
      headers.set('retry-after', String(result.error.retryAfterSeconds))
    return problemResponse(error, headers)
  }
  return result.value === null
    ? new Response(null, { status: 204, headers: result.headers })
    : json({ actor: publicActor(result.value.actor) }, status, result.headers)
}

const text = (v: unknown): string => (typeof v === 'string' ? v : '')

/** Create the auth provider (a factory so every app and test gets fresh state). */
export function createAuthProvider(): Provider {
  let permissions: StrutvanePermissionProvider | undefined
  return defineProvider({
    name: '@strutvane/auth',
    register(app) {
      app.container.singleton(PermissionProviderToken, () => {
        if (!permissions)
          throw new Error(
            'Policies are not loaded yet (resolve PermissionProviderToken after boot)',
          )
        return permissions
      })
    },
    async boot(app) {
      for (const definition of AUTH_ERRORS) {
        const registry = app.make(ErrorRegistryToken)
        if (!registry.get(definition.code)) registry.register(definition)
      }
      const root = section<{ root?: string }>(app, 'app')?.root ?? process.cwd()
      const appUrl = section<{ url?: string }>(app, 'app')?.url ?? 'http://localhost:3000'
      const cfg = section<AppAuthConfig>(app, 'auth') ?? {}
      const tenancy = section<AppTenancyConfig>(app, 'tenancy')
      const logger = app.make(LoggerToken)
      permissions = createPermissionProvider(await loadPolicies(root))

      const seedEmail = cfg.seedAdmin?.email?.toLowerCase()
      const seedRole = cfg.seedAdmin?.role ?? 'admin'
      const defaultRoles = [...(cfg.defaultRoles ?? [])]
      const native = createNativeEngine({
        baseURL: appUrl,
        deliverPasswordReset: async () => {
          logger.warn('Password reset requested, but no mailer is configured for @strutvane/auth')
        },
        ...(cfg.session?.idleMinutes ? { sessionTtlSeconds: cfg.session.idleMinutes * 60 } : {}),
        onUnexpectedError: (context, error) =>
          logger.error('auth engine failure', {
            context,
            error: error instanceof Error ? error.message : String(error),
          }),
        globalRoles: ({ email }) => (email === seedEmail ? [seedRole] : defaultRoles),
      })
      if (seedEmail && cfg.seedAdmin?.password) {
        const seeded = await native.signUp(
          { email: seedEmail, password: cfg.seedAdmin.password, name: 'Administrator' },
          new Request(new URL('/_strutvane/seed', appUrl), { method: 'POST' }),
        )
        if (!seeded.ok) logger.warn('Could not create the seed admin', { code: seeded.error.code })
      }

      const base = `${apiBase(section(app, 'api'))}/auth`
      const tenancyOptions =
        tenancy?.enabled === true
          ? {
              tenancy: {
                resolvers: [
                  sessionResolver(),
                  // A tenant header is only honoured for members (checked by authenticateRequest).
                  headerResolver({ trust: () => true }),
                ],
                strategy: tenancy.strategy ?? 'shared',
              },
            }
          : {}
      const hooks = app.make(HooksToken)
      hooks.on(
        'http.onRequest',
        async (payload, control) => {
          const p = payload as { request: Request; actor: Actor | null; tenant: unknown }
          const url = new URL(p.request.url)
          const answer = (response: Response) => {
            control.stop()
            return { ...p, response }
          }
          if (url.pathname.startsWith(`${base}/`)) {
            try {
              const route = `${p.request.method} ${url.pathname.slice(base.length)}`
              switch (route) {
                case 'POST /sign-up': {
                  if (cfg.registration === false)
                    return answer(problemResponse(new StrutvaneError('FORBIDDEN', { status: 403 })))
                  const body = await readJson(p.request)
                  const input = {
                    email: text(body['email']),
                    password: text(body['password']),
                    name: text(body['name']),
                  }
                  return answer(toResponse(await native.signUp(input, p.request), 201))
                }
                case 'POST /sign-in': {
                  const body = await readJson(p.request)
                  const input = { email: text(body['email']), password: text(body['password']) }
                  return answer(toResponse(await native.signIn(input, p.request)))
                }
                case 'POST /tenants': {
                  const body = await readJson(p.request)
                  const input = { name: text(body['name']), slug: text(body['slug']) }
                  const result = await native.createTenant(input, p.request)
                  return answer(
                    result.ok
                      ? json(result.value, 201, result.headers)
                      : toResponse({ ...result, ok: false }),
                  )
                }
                case 'GET /tenants': {
                  const result = await native.listTenants(p.request)
                  return answer(
                    result.ok
                      ? json({ data: result.value }, 200, result.headers)
                      : toResponse({ ...result, ok: false }),
                  )
                }
                case 'POST /switch-tenant': {
                  const body = await readJson(p.request)
                  return answer(
                    toResponse(
                      await native.switchTenant({ tenantId: text(body['tenantId']) }, p.request),
                    ),
                  )
                }
                case 'POST /sign-out':
                  return answer(toResponse(await native.signOut(p.request)))
                case 'GET /me': {
                  const auth = await native.authenticate(p.request)
                  if (!auth.actor)
                    return answer(problemResponse(new UnauthenticatedError(), auth.headers))
                  return answer(json({ actor: publicActor(auth.actor) }, 200, auth.headers))
                }
                default:
                  return answer(problemResponse(new StrutvaneError('NOT_FOUND', { status: 404 })))
              }
            } catch (error) {
              if (error instanceof StrutvaneError) return answer(problemResponse(error))
              throw error
            }
          }
          const outcome = await authenticateRequest(p.request, {
            engine: native,
            ...tenancyOptions,
          })
          if (!outcome.ok) return answer(outcome.response)
          return {
            ...p,
            actor: outcome.state.actor,
            tenant: outcome.state.tenant,
            headers: outcome.state.headers,
          }
        },
        { name: 'auth.identity' },
      )
    },
  })
}

/** The auth provider for `strutvane.config.ts`. */
const provider: Provider = createAuthProvider()
export default provider
