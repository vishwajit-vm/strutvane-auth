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
 * Identity: Strutvane's own engine (ADR-0023) on the app's database: PostgreSQL (on the
 * framework's `Database` when it is bound) or SQLite, with the tables from the shipped migration
 * (`migrate`); in memory with `session.driver: 'memory'` (development and tests). The deprecated
 * Better Auth adapter runs only with `identity: 'better-auth'`. See identity/app-identity.ts.
 *
 * Besides the v1 endpoints below, the engine's own routes (Fortify's names: `POST /login`,
 * `/register`, `/forgot-password`, `/reset-password`, `/two-factor-challenge`, `/user/…` for
 * sessions, two-factor, passkeys and API tokens, `/teams/…`, `/impersonate/…`) are served under
 * the same `{api}/auth` prefix, each only while its feature is on (`config/auth.ts` `features`).
 *
 * One source for cookie names (CONSISTENCY #105): in `register()` the provider binds
 * `SessionCookieToken` from `config/session.ts` `cookie` and the app URL, the engine names its
 * session cookie from the same value, and the framework's CSRF check reads the token; boot fails
 * if anything bound a different name first.
 *
 * Domain events: every auth event is published on the framework event bus as `auth.*` or
 * `tenant.*` (integration map §5; see events.ts). Mail goes to the mailer bound under
 * `AuthMailerToken`; without one, mails are dropped with a warning (never with their links).
 * On boot it makes sure the `seedAdmin` account from `config/auth.ts` exists (created once,
 * never overwritten), so there is always a way in. The role is bound to that account's id (never
 * to the email), and boot fails if the account cannot be found or created. New sign-ups get
 * `defaultRoles` (none unless configured).
 *
 * With tenancy, a tenant's owners manage its members: `GET|POST {api}/auth/tenants/:id/members`
 * (`{ email, role }`, an existing account and a role from `config/auth.ts`) and
 * `DELETE {api}/auth/tenants/:id/members/:userId` (the last owner cannot be removed).
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
import { DatabaseToken, SessionCookieToken, sessionCookieName } from '@strutvane/framework'
import { type Actor, HTTP_HOOKS, type HttpRequestHookPayload } from '@strutvane/framework/contracts'
import {
  type Application,
  defineProvider,
  ErrorRegistryToken,
  EventBusToken,
  HooksToken,
  LoggerToken,
  PermissionProviderToken,
  type Provider,
  StrutvaneError,
  UnauthenticatedError,
} from '@strutvane/framework/core'
import type { AuthConfig } from './config.ts'
import { createAuthHandler } from './engine/http/routes.ts'
import type { AuthMailer } from './engine/ports/mailer.ts'
import { AUTH_ERRORS } from './errors.ts'
import { domainEventSink } from './events.ts'
import { registerFieldRules } from './field-rules.ts'
import { resolveClientIp, trustedProxies } from './http/client-ip.ts'
import { attachRequestMeta } from './http/request-meta.ts'
import {
  type AppDatabaseSection,
  type AppIdentity,
  createAppIdentity,
} from './identity/app-identity.ts'
import type { IdentityEngine, IdentityResult } from './identity/engine.ts'
import { engineConfigFrom } from './identity/engine-config.ts'
import { authenticateRequest, problemResponse } from './middleware/core.ts'
import { loadPolicies } from './policy/discover.ts'
import { createPermissionProvider, type StrutvanePermissionProvider } from './policy/provider.ts'
import { compileRoleMap } from './policy/roles.ts'
import { headerResolver, sessionResolver } from './tenancy/resolver.ts'
import { AuthMailerToken } from './tokens.ts'

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

/** A prefix that already ends in an API version (`/api/v1`, `/api/v2`). */
const VERSIONED = /\/v\d+$/

/**
 * Where the API lives: `config/api.ts` `prefix` + `version`, by default `/api/v1` (the URL contract,
 * docs/05: the API under `/api/v1`, auth under `/api/v1/auth`). A prefix that already carries a
 * version (`prefix: '/api/v1'`) is used as it is, never `/api/v1/v1`; `version: ''` means none.
 *
 * @example
 * apiBase(undefined) // '/api/v1'
 * apiBase({ prefix: '/api/v1' }) // '/api/v1'
 * apiBase({ prefix: '/api', version: '' }) // '/api'
 */
export function apiBase(api: { prefix?: string; version?: string } | undefined): string {
  const prefix = (api?.prefix ?? '/api').replace(/\/+$/, '')
  const version = (api?.version ?? (VERSIONED.test(prefix) ? '' : 'v1')).replace(/^\/+|\/+$/g, '')
  return `/${prefix}/${version}`.replace(/\/{2,}/g, '/').replace(/(.)\/$/, '$1')
}

export { loadPolicies } from './policy/discover.ts'

/** The peer address of an in-process request in the testing environment (no socket). */
const TEST_PEER_ADDRESS = '127.0.0.1'

const tooLarge = () => new StrutvaneError('payload_too_large', { status: 413 })
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const MEMBERS = /^\/tenants\/([^/]+)\/members(?:\/([^/]+))?$/
/** v1 tenant roles of the deprecated Better Auth adapter (its creator role is `owner`). */
const BETTER_AUTH_TENANT_ROLES = ['owner', 'member', 'viewer'] as const
/** Routes that exist only with tenancy on (`config/tenancy.ts` `enabled: true`). */
const TENANT_ROUTES: ReadonlySet<string> = new Set([
  'POST /tenants',
  'GET /tenants',
  'POST /switch-tenant',
])

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
    throw new StrutvaneError('malformed_request', { status: 400 })
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
    throw new StrutvaneError('unsupported_media_type', { status: 415 })
  const text = await readBody(request)
  try {
    const value: unknown = JSON.parse(text)
    if (typeof value === 'object' && value !== null && !Array.isArray(value))
      return value as Record<string, unknown>
  } catch {
    // fall through
  }
  throw new StrutvaneError('malformed_request', { status: 400 })
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
    throw new StrutvaneError('forbidden', { status: 403 })
  const origin = request.headers.get('origin')
  if (origin === null) return
  if (origin === originOf(request.url) || trusted.has(origin)) return
  throw new StrutvaneError('forbidden', { status: 403 })
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

/**
 * The tenant member endpoints, for the tenant's owners only. A non-owner, a non-member and an
 * unknown tenant all get the same 403, so tenants cannot be probed.
 */
async function handleMembers(
  request: Request,
  tenantId: string,
  userId: string | undefined,
  deps: {
    readonly engine: IdentityEngine
    readonly roles: readonly string[]
    /** The role that manages a tenant: `admin` (native) or `owner` (Better Auth). */
    readonly ownerRole: string
  },
): Promise<Response> {
  const auth = await deps.engine.authenticate(request)
  const actor = auth.actor
  if (!actor) return problemResponse(new UnauthenticatedError(), auth.headers)
  const forbidden = () => problemResponse(new StrutvaneError('forbidden', { status: 403 }))
  const invalid = () => problemResponse(new StrutvaneError('validation_failed', { status: 422 }))
  if (
    !UUID.test(tenantId) ||
    actor.tenantId?.toLowerCase() !== tenantId.toLowerCase() ||
    !actor.roles.includes(deps.ownerRole)
  )
    return forbidden()
  const fromResult = <T>(r: IdentityResult<T>): T | Response =>
    r.ok ? r.value : toResponse({ ...r, ok: false })
  const roster = fromResult(await deps.engine.listMembersAsSystem({ tenantId }))
  if (roster instanceof Response) return roster
  const method = request.method
  if (method === 'GET' && userId === undefined) return json({ data: roster }, 200, auth.headers)
  if (method === 'POST' && userId === undefined) {
    const body = await readJson(request)
    const email = text(body['email'])
    const role = text(body['role'])
    if (!deps.roles.includes(role)) return invalid()
    const found = fromResult(await deps.engine.findUserAsSystem({ email }))
    if (found instanceof Response) return found
    // An unknown email is the same 422 as a bad role (invitations are a separate, planned flow).
    if (!found) return invalid()
    const isLastOwner =
      role !== deps.ownerRole &&
      roster.filter((m) => m.roles.includes(deps.ownerRole)).every((m) => m.userId === found.id) &&
      roster.some((m) => m.userId === found.id && m.roles.includes(deps.ownerRole))
    if (isLastOwner) return invalid()
    const added = await deps.engine.addMemberAsSystem({ tenantId, userId: found.id, role })
    if (!added.ok) return toResponse({ ...added, ok: false })
    return json(
      { userId: found.id, email: found.email, name: found.name, roles: [role] },
      201,
      auth.headers,
    )
  }
  if (method === 'DELETE' && userId !== undefined) {
    const target = roster.find((m) => m.userId.toLowerCase() === userId.toLowerCase())
    if (!target) return problemResponse(new StrutvaneError('not_found', { status: 404 }))
    const owners = roster.filter((m) => m.roles.includes(deps.ownerRole))
    if (target.roles.includes(deps.ownerRole) && owners.length <= 1) return invalid()
    const removed = await deps.engine.removeMemberAsSystem({ tenantId, userId: target.userId })
    if (!removed.ok) return toResponse({ ...removed, ok: false })
    return new Response(null, { status: 204, headers: auth.headers })
  }
  return problemResponse(new StrutvaneError('not_found', { status: 404 }))
}

/** Create the auth provider (a factory so every app and test gets fresh state). */
export function createAuthProvider(): Provider {
  let permissions: StrutvanePermissionProvider | undefined
  let identity: AppIdentity | undefined
  return defineProvider({
    name: '@strutvane/auth',
    register(app) {
      // One source for the session cookie's name (#105): bound here, before the framework builds
      // its HTTP app, so its CSRF check reads exactly the name the engine sets. A binding that
      // already exists is checked against the engine's name at boot.
      if (!app.container.has(SessionCookieToken)) {
        const appUrl = section<{ url?: string }>(app, 'app')?.url ?? 'http://localhost:3000'
        const base = section<{ cookie?: string }>(app, 'session')?.cookie
        app.container.value(
          SessionCookieToken,
          sessionCookieName({
            ...(base !== undefined ? { base } : {}),
            secure: new URL(appUrl).protocol === 'https:',
          }),
        )
      }
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
      // Framework (class) policies stay with the framework's PolicyRegistry; auth compiles only
      // definePolicy(...) files (AUTH-3: both styles live in app/policies).
      const policies = await loadPolicies(root, {
        onFrameworkPolicy: (file) =>
          logger.debug('auth: a framework policy is left to the framework gate', { file }),
      })
      permissions = createPermissionProvider(policies, { roles })
      // Field-level read/write rules ride on the framework's resource hooks (integration map §4).
      registerFieldRules(app.make(HooksToken), permissions)

      const seedEmail = cfg.seedAdmin?.email?.toLowerCase()
      const seedRole = cfg.seedAdmin?.role ?? 'admin'
      const defaultRoles = [...(cfg.defaultRoles ?? [])]
      // The admin role belongs to the seeded ACCOUNT (by id), never to whoever registers the email.
      let seedUserId: string | undefined
      const cookie = app.make(SessionCookieToken)
      const tenancyOn = tenancy?.enabled === true
      const testing = section<{ env?: string }>(app, 'app')?.env === 'testing'
      const mailer: AuthMailer = app.container.has(AuthMailerToken)
        ? app.make(AuthMailerToken)
        : {
            // Never log the mail itself: it carries a secret link.
            send: async (mail) =>
              logger.warn(
                'auth: a mail was not sent because no mailer is bound (AuthMailerToken)',
                {
                  kind: mail.kind,
                },
              ),
          }
      const trustedOrigins = new Set<string>()
      for (const o of [appUrl, ...(cfg.trustedOrigins ?? [])]) {
        const origin = originOf(o)
        if (origin === undefined) throw new TypeError(`Invalid trusted origin ${JSON.stringify(o)}`)
        trustedOrigins.add(origin)
      }
      const betterAuth = cfg.identity === 'better-auth'
      identity = await createAppIdentity({
        auth: cfg,
        appUrl,
        root,
        database: section<AppDatabaseSection>(app, 'database'),
        frameworkDatabase: app.container.has(DatabaseToken) ? app.make(DatabaseToken) : undefined,
        appKey: section<{ key?: string }>(app, 'app')?.key || process.env['APP_KEY'],
        logger,
        engineConfig: engineConfigFrom(cfg, { tenancy: tenancyOn, sessionCookie: cookie.base }),
        mailer,
        events: domainEventSink(app.make(EventBusToken), logger),
        defaultRoles,
        deliverPasswordReset: async () => undefined,
        // The deprecated adapter has no stored global roles: v1's rule, bound to the account id.
        ...(betterAuth
          ? {
              globalRoles: ({ userId }: { readonly userId: string }) =>
                seedUserId !== undefined && userId === seedUserId ? [seedRole] : defaultRoles,
            }
          : {}),
      })
      // #105: the engine and the framework's CSRF check must agree on the session cookie name.
      if (identity.native && identity.native.auth.cookieNames.session !== cookie.name) {
        await identity.close()
        throw new Error(
          `@strutvane/auth: the session cookie is "${identity.native.auth.cookieNames.session}" but SessionCookieToken says "${cookie.name}"; bind SessionCookieToken from config/session.ts only`,
        )
      }
      const native = identity.engine
      if (seedEmail && cfg.seedAdmin?.password) {
        // Idempotent: a persistent store already holds the account after the first boot. An
        // existing account is never modified (its password may have been changed since).
        const existing = await native.findUserAsSystem({ email: seedEmail })
        const seeded =
          existing.ok && existing.value
            ? { ok: true as const, value: existing.value }
            : existing.ok
              ? await native.createUserAsSystem({
                  email: seedEmail,
                  password: cfg.seedAdmin.password,
                  name: 'Administrator',
                })
              : existing
        // Fail the boot: otherwise operators are locked out without noticing.
        if (!seeded.ok) {
          await identity.close()
          throw new Error(
            `@strutvane/auth: could not create the seed admin (${seeded.error.code}); check seedAdmin in config/auth.ts`,
          )
        }
        seedUserId = seeded.value.id
        // Native engine: the role is stored with the account (user_roles), once; an operator may
        // change it afterwards. A role the engine does not know fails the boot (fail closed).
        const engineAuth = identity.native?.auth
        if (engineAuth) {
          const held = await engineAuth.system.rolesOf(seeded.value.id)
          if (!held.includes(seedRole))
            await engineAuth.system
              .setRoles(seeded.value.id, [...held, seedRole])
              .catch(async () => {
                await identity?.close()
                throw new Error(
                  `@strutvane/auth: seedAdmin.role "${seedRole}" is not a role of this app (config/auth.ts roles)`,
                )
              })
        }
      } else if (seedEmail) {
        logger.warn('seedAdmin.email is set without a password; no seed admin was created')
      }

      const base = `${apiBase(section(app, 'api'))}/auth`
      const proxies = trustedProxies(cfg.trustedProxies)
      const engineHandler = identity.native
        ? createAuthHandler(identity.native.auth, {
            onError: (route, error) =>
              logger.error('auth route failure', {
                route,
                error: error instanceof Error ? error.message : String(error),
              }),
          })
        : undefined
      /** Serve one engine route: the body is read with the 16 KiB streaming cap first. */
      const engineRoutes = engineHandler
        ? async (request: Request, path: string): Promise<Response> => {
            const url = new URL(request.url)
            url.pathname = path
            const hasBody = request.method !== 'GET' && request.method !== 'HEAD'
            const body = hasBody ? await readBody(request) : undefined
            const inner = new Request(url, {
              method: request.method,
              headers: request.headers,
              ...(body !== undefined && body !== '' ? { body } : {}),
            })
            return engineHandler(inner, { ip: resolveClientIp(request, proxies) })
          }
        : undefined
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
          // back to a shared bucket (fail closed) and warns once. In-process test requests
          // (`app.handle()` under APP_ENV=testing) have no socket: they count as loopback, the
          // same single bucket, without the warning (AUTH-6).
          const peer = p.clientAddress ?? (testing ? TEST_PEER_ADDRESS : undefined)
          if (peer !== undefined) attachRequestMeta(p.request, { remoteAddress: peer })
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
              const members =
                tenancy?.enabled === true ? MEMBERS.exec(url.pathname.slice(base.length)) : null
              if (members)
                return answer(
                  await handleMembers(p.request, members[1] ?? '', members[2], {
                    engine: native,
                    roles: identity?.native
                      ? identity.native.auth.config.roles
                      : cfg.roles
                        ? Object.keys(cfg.roles)
                        : BETTER_AUTH_TENANT_ROLES,
                    ownerRole: identity?.native ? identity.native.ownerRole : 'owner',
                  }),
                )
              // Without tenancy the tenant endpoints do not exist: otherwise any signed-in user
              // could create a tenant and act as its `owner` in an app that never scopes by tenant.
              if (tenancy?.enabled !== true && TENANT_ROUTES.has(route))
                return answer(problemResponse(new StrutvaneError('not_found', { status: 404 })))
              switch (route) {
                case 'POST /sign-up': {
                  // Deny by default: only an explicit `registration: true` opens public sign-up.
                  if (cfg.registration !== true && cfg.features?.registration !== true)
                    return answer(problemResponse(new StrutvaneError('forbidden', { status: 403 })))
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
                  // The engine's own routes (Fortify's names), each only while its feature is on;
                  // anything else is the engine's plain 404.
                  if (engineRoutes)
                    return answer(await engineRoutes(p.request, url.pathname.slice(base.length)))
                  return answer(problemResponse(new StrutvaneError('not_found', { status: 404 })))
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
    async shutdown() {
      await identity?.close()
      identity = undefined
    },
  })
}

/** The auth provider for `strutvane.config.ts`. */
const provider: Provider = createAuthProvider()
export default provider
