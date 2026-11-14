/**
 * `@strutvane/auth/provider`: the provider `strutvane.config.ts` registers in a Strutvane app.
 *
 * It connects auth to the app only through core (integration map: container tokens + hooks):
 * - binds `PermissionProviderToken` to a provider built from `app/policies/*.policy.ts` plus the
 *   role map of `config/auth.ts` (`roles`, `wildcardExclude`, `newModelDefaults`; see
 *   `compileRoleMap`): `(policy allows OR role grants) AND NOT policy denies`. Deny-by-default:
 *   without roles, an action no policy rule allows is refused;
 * - on `http.onRequest` (handler `auth.identity`), resolves the actor (and tenant, with
 *   tenancy on) for every request, and answers the auth endpoints itself:
 *   `POST {api}/auth/sign-up`, `POST {api}/auth/sign-in`, `POST {api}/auth/sign-out`,
 *   `GET {api}/auth/me`, and for tenancy `POST|GET {api}/auth/tenants` and
 *   `POST {api}/auth/switch-tenant` (members only; the creator becomes `owner`);
 * - enforces policy field rules: `resource.serialize` drops fields the actor may not read and
 *   `resource.beforeWrite` refuses writes to fields the actor may not write (see field-rules.ts).
 *
 * Identity uses the native engine (in memory, single process): accounts and sessions are lost on
 * restart, so it is for development and tests. On boot it creates the `seedAdmin` account from
 * `config/auth.ts` (role `seedAdmin.role`) so there is always a way in. The role is bound to the
 * created account's id (never to the email), and boot fails if the account cannot be created. New
 * sign-ups get `defaultRoles` (none unless configured). The persistent Better Auth engine needs
 * Postgres and is wired by hand (`@strutvane/auth/better-auth`).
 *
 * Request hardening on the auth endpoints:
 * - state-changing endpoints (`POST`) refuse cross-site requests (`Sec-Fetch-Site: cross-site`, or
 *   an `Origin` other than the app URL, the request's own origin or `auth.trustedOrigins`);
 * - JSON bodies must be sent as `application/json` and are read as a stream, aborted past 16 KiB;
 * - the socket peer address from the hook payload (`clientAddress`) keys the per-IP rate limits;
 * - with tenancy on, the `X-Tenant-Id` header is honoured only for tenant-less service actors, and
 *   anonymous requests are never scoped to a tenant.
 *
 * @module
 */
import { existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { type Actor, HTTP_HOOKS, type HttpRequestHookPayload } from '@strutvane/contracts'
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
import type { AuthConfig } from './config.ts'
import { AUTH_ERRORS } from './errors.ts'
import { registerFieldRules } from './field-rules.ts'
import { attachRequestMeta } from './http/request-meta.ts'
import type { IdentityResult } from './identity/engine.ts'
import { createNativeEngine } from './identity/native.ts'
import { authenticateRequest, problemResponse } from './middleware/core.ts'
import type { Policy } from './policy/policy.ts'
import { createPermissionProvider, type StrutvanePermissionProvider } from './policy/provider.ts'
import { compileRoleMap } from './policy/roles.ts'
import { headerResolver, sessionResolver } from './tenancy/resolver.ts'

/**
 * `config/auth.ts`, as the provider reads it (the full shape is {@link AuthConfig}; write it with
 * `defineAuthConfig`).
 */
export type AppAuthConfig = AuthConfig

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

const tooLarge = () => new StrutvaneError('PAYLOAD_TOO_LARGE', { status: 413 })

/**
 * Read a request body of at most 16 KiB, counting bytes as they stream in and aborting the stream
 * as soon as the limit is passed (the framework body limit doesn't cover hook answers, and
 * `request.text()` would buffer an unbounded chunked body first).
 */
async function readBody(request: Request): Promise<string> {
  const declared = request.headers.get('content-length')
  if (declared !== null && Number(declared) > MAX_BODY_BYTES) throw tooLarge()
  if (!request.body) return ''
  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > MAX_BODY_BYTES) {
        await reader.cancel().catch(() => undefined)
        throw tooLarge()
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw new StrutvaneError('MALFORMED_REQUEST', { status: 400 })
  }
}

/**
 * Read a JSON object body. The content type must be `application/json`: a cross-site HTML form can
 * only send `text/plain`, `multipart/form-data` or `application/x-www-form-urlencoded` without a
 * CORS preflight, so this also closes the "form posts JSON as text/plain" route.
 */
async function readJson(request: Request): Promise<Record<string, unknown>> {
  const type = (request.headers.get('content-type') ?? '').split(';')[0]?.trim().toLowerCase()
  if (type !== 'application/json')
    throw new StrutvaneError('UNSUPPORTED_MEDIA_TYPE', { status: 415 })
  const text = await readBody(request)
  try {
    const value: unknown = JSON.parse(text)
    if (typeof value === 'object' && value !== null && !Array.isArray(value))
      return value as Record<string, unknown>
  } catch {
    // fall through
  }
  throw new StrutvaneError('MALFORMED_REQUEST', { status: 400 })
}

const originOf = (url: string): string | undefined => {
  try {
    return new URL(url).origin
  } catch {
    return undefined
  }
}

/**
 * Refuse cross-site calls to state-changing endpoints (defence in depth, on top of `SameSite=Lax`
 * cookies and the JSON content type). Requests without `Origin` and `Sec-Fetch-Site` (non-browser
 * clients) pass: they carry no ambient browser credentials.
 */
function assertSameSite(request: Request, trusted: ReadonlySet<string>): void {
  if (request.headers.get('sec-fetch-site')?.toLowerCase() === 'cross-site')
    throw new StrutvaneError('FORBIDDEN', { status: 403 })
  const origin = request.headers.get('origin')
  if (origin === null) return
  if (origin === originOf(request.url) || trusted.has(origin)) return
  throw new StrutvaneError('FORBIDDEN', { status: 403 })
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
      // The role map is compiled (and validated) before the policies load, so a typo in
      // config/auth.ts fails the boot with a clear message.
      const roles = compileRoleMap({
        ...(cfg.roles ? { roles: cfg.roles } : {}),
        ...(cfg.wildcardExclude ? { wildcardExclude: cfg.wildcardExclude } : {}),
        ...(cfg.newModelDefaults ? { newModelDefaults: cfg.newModelDefaults } : {}),
      })
      permissions = createPermissionProvider(await loadPolicies(root), { roles })
      // Field-level read/write rules ride on the framework's resource hooks (integration map §4).
      registerFieldRules(app.make(HooksToken), permissions)

      const seedEmail = cfg.seedAdmin?.email?.toLowerCase()
      const seedRole = cfg.seedAdmin?.role ?? 'admin'
      const defaultRoles = [...(cfg.defaultRoles ?? [])]
      // The admin role belongs to the seeded ACCOUNT (by id), never to whoever registers the email.
      let seedUserId: string | undefined
      const trustedOrigins = new Set<string>()
      for (const o of [appUrl, ...(cfg.trustedOrigins ?? [])]) {
        const origin = originOf(o)
        if (origin === undefined) throw new TypeError(`Invalid trusted origin ${JSON.stringify(o)}`)
        trustedOrigins.add(origin)
      }
      const native = createNativeEngine({
        baseURL: appUrl,
        logger,
        ...(cfg.trustedProxies ? { trustedProxies: cfg.trustedProxies } : {}),
        deliverPasswordReset: async () => {
          logger.warn('Password reset requested, but no mailer is configured for @strutvane/auth')
        },
        ...(cfg.session?.idleMinutes ? { sessionTtlSeconds: cfg.session.idleMinutes * 60 } : {}),
        onUnexpectedError: (context, error) =>
          logger.error('auth engine failure', {
            context,
            error: error instanceof Error ? error.message : String(error),
          }),
        globalRoles: ({ userId }) =>
          seedUserId !== undefined && userId === seedUserId ? [seedRole] : defaultRoles,
      })
      if (seedEmail && cfg.seedAdmin?.password) {
        // An in-process call: the server itself is the peer.
        const seedRequest = attachRequestMeta(
          new Request(new URL('/_strutvane/seed', appUrl), { method: 'POST' }),
          { remoteAddress: '127.0.0.1' },
        )
        const seeded = await native.signUp(
          { email: seedEmail, password: cfg.seedAdmin.password, name: 'Administrator' },
          seedRequest,
        )
        // Fail the boot: otherwise operators are locked out without noticing.
        if (!seeded.ok)
          throw new Error(
            `@strutvane/auth: could not create the seed admin (${seeded.error.code}); check seedAdmin in config/auth.ts`,
          )
        seedUserId = seeded.value.actor.id
      } else if (seedEmail) {
        logger.warn('seedAdmin.email is set without a password; no seed admin was created')
      }

      const base = `${apiBase(section(app, 'api'))}/auth`
      const tenancyOptions =
        tenancy?.enabled === true
          ? {
              tenancy: {
                resolvers: [
                  sessionResolver(),
                  // Only tenant-less service actors (internal callers) may pick a tenant by header;
                  // anonymous and user requests never can.
                  headerResolver({
                    trust: ({ actor }) => actor?.type === 'service' && actor.tenantId === undefined,
                  }),
                ],
                strategy: tenancy.strategy ?? 'shared',
              },
            }
          : {}
      const hooks = app.make(HooksToken)
      hooks.on(
        HTTP_HOOKS.request,
        async (payload, control) => {
          const p = payload as HttpRequestHookPayload
          // The socket peer (never a header) keys the per-IP limits. Without it the engine falls
          // back to a shared bucket (fail closed) and warns once.
          if (p.clientAddress !== undefined)
            attachRequestMeta(p.request, { remoteAddress: p.clientAddress })
          const url = new URL(p.request.url)
          const answer = (response: Response) => {
            control.stop()
            return { ...p, response }
          }
          if (url.pathname.startsWith(`${base}/`)) {
            try {
              const route = `${p.request.method} ${url.pathname.slice(base.length)}`
              if (p.request.method !== 'GET' && p.request.method !== 'HEAD')
                assertSameSite(p.request, trustedOrigins)
              switch (route) {
                case 'POST /sign-up': {
                  // Deny by default: only an explicit `registration: true` opens public sign-up.
                  if (cfg.registration !== true)
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
