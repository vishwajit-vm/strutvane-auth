/**
 * The example HTTP adapter: Fortify-style routes on Fetch `Request`/`Response`, so it runs under
 * `node:http` (see `node.ts`), Hono or any Fetch server.
 *
 * It is deliberately thin: parse JSON, call one service method, map `AuthError` to an RFC 9457
 * problem. The framework replaces it with its router, its CSRF middleware (spike 12) and its
 * problem renderer; the services do not change.
 *
 * Rules shown here that the framework must keep:
 * - **A disabled feature has no routes.** Its paths fall through to the same 404 as an unknown
 *   path, byte for byte (`test/features.test.ts` compares them).
 * - **Unsafe cookie requests must come from the app's own origin** (`Sec-Fetch-Site: same-origin`
 *   or an exact `Origin`; never `same-site` or `null`). The framework adds the token fallback for
 *   plain-http and form posts (review F-07).
 * - **JSON bodies need `application/json`** and are capped at 16 KiB.
 * - **A bearer token never falls back to the cookie.**
 *
 * @module
 */
import type { Auth } from '../auth.ts'
import type { AuthFeatures } from '../config.ts'
import { AUTH_MESSAGES, AuthError } from '../errors.ts'
import type { AuthRequest } from '../ports/cookies.ts'
import { fetchCookieJar } from './cookies.ts'

type Json = Record<string, unknown>

/** What a route handler receives. */
interface RouteContext {
  readonly req: AuthRequest
  readonly body: Json
  readonly params: Readonly<Record<string, string>>
  readonly query: URLSearchParams
  readonly request: Request
}

interface Route {
  readonly method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  readonly path: string
  readonly feature?: keyof AuthFeatures
  /** Bearer-authenticated API route: cookies are ignored and no origin check applies. */
  readonly bearer?: boolean
  readonly handle: (ctx: RouteContext) => Promise<unknown>
}

const MAX_BODY = 16 * 1024

function problem(error: AuthError): Response {
  const body: Json = {
    type: 'about:blank',
    title: AUTH_MESSAGES[error.code],
    status: error.status,
    code: error.code,
  }
  if (error.issues.length > 0) body['issues'] = error.issues
  const headers = new Headers({
    'content-type': 'application/problem+json',
    'cache-control': 'no-store',
  })
  if (error.retryAfterSeconds !== undefined)
    headers.set('retry-after', String(error.retryAfterSeconds))
  return new Response(JSON.stringify(body), { status: error.status, headers })
}

/** The one 404 every unknown or disabled path gets. */
function notFound(): Response {
  return problem(new AuthError('not_found'))
}

function routes(auth: Auth): readonly Route[] {
  return [
    {
      method: 'GET',
      path: '/user',
      handle: async ({ req }) =>
        (await auth.state(req)) ?? Promise.reject(new AuthError('unauthenticated')),
    },
    {
      method: 'POST',
      path: '/login',
      feature: 'password',
      handle: ({ req, body }) =>
        auth.passwords.login(req, body as { email: unknown; password: unknown }),
    },
    {
      method: 'POST',
      path: '/logout',
      handle: async ({ req }) => await auth.passwords.logout(req),
    },
    {
      method: 'POST',
      path: '/register',
      feature: 'registration',
      handle: ({ req, body }) =>
        auth.passwords.register(req, body as { name: unknown; email: unknown }),
    },
    {
      method: 'POST',
      path: '/forgot-password',
      feature: 'passwordReset',
      handle: ({ req, body }) => auth.passwordReset.request(req, { email: body['email'] }),
    },
    {
      method: 'POST',
      path: '/reset-password',
      feature: 'passwordReset',
      handle: async ({ req, body }) =>
        await auth.passwordReset.reset(req, { token: body['token'], password: body['password'] }),
    },
    {
      method: 'PUT',
      path: '/user/password',
      feature: 'password',
      handle: async ({ req, body }) =>
        await auth.passwords.change(req, { current: body['current'], password: body['password'] }),
    },
    {
      method: 'POST',
      path: '/user/confirm-password',
      feature: 'passwordConfirmation',
      handle: async ({ req, body }) =>
        await auth.passwords.confirm(req, { password: body['password'] }),
    },
    {
      method: 'POST',
      path: '/email/verification-notification',
      feature: 'emailVerification',
      handle: ({ req }) => auth.verification.resend(req),
    },
    {
      method: 'GET',
      path: '/email/verify/:id/:hash',
      feature: 'emailVerification',
      handle: async ({ req, params, query }) =>
        await auth.verification.verify(req, {
          id: params['id'],
          hash: params['hash'],
          expires: query.get('expires') ?? undefined,
          signature: query.get('signature') ?? undefined,
        }),
    },
    {
      method: 'POST',
      path: '/email-link',
      feature: 'emailLink',
      handle: ({ req, body }) => auth.emailLink.request(req, { email: body['email'] }),
    },
    {
      method: 'POST',
      path: '/email-link/:token',
      feature: 'emailLink',
      handle: ({ req, params, body }) =>
        auth.emailLink.consume(req, { token: params['token'], remember: body['remember'] }),
    },
    {
      method: 'POST',
      path: '/two-factor-challenge',
      feature: 'twoFactor',
      handle: ({ req, body }) => auth.twoFactor.challenge(req, body),
    },
    {
      method: 'POST',
      path: '/user/two-factor-authentication',
      feature: 'twoFactor',
      handle: ({ req }) => auth.twoFactor.enable(req),
    },
    {
      method: 'DELETE',
      path: '/user/two-factor-authentication',
      feature: 'twoFactor',
      handle: async ({ req }) => await auth.twoFactor.disable(req),
    },
    {
      method: 'POST',
      path: '/user/confirmed-two-factor-authentication',
      feature: 'twoFactor',
      handle: ({ req, body }) => auth.twoFactor.confirm(req, { code: body['code'] }),
    },
    {
      method: 'POST',
      path: '/user/two-factor-recovery-codes',
      feature: 'twoFactor',
      handle: ({ req }) => auth.twoFactor.regenerateRecoveryCodes(req),
    },
    { method: 'GET', path: '/user/sessions', handle: ({ req }) => auth.sessions.list(req) },
    {
      method: 'DELETE',
      path: '/user/sessions/:handle',
      handle: async ({ req, params }) =>
        await auth.sessions.revoke(req, { handle: params['handle'] }),
    },
    {
      method: 'DELETE',
      path: '/user/other-sessions',
      handle: async ({ req }) => ({ revoked: await auth.sessions.revokeOthers(req) }),
    },
    {
      method: 'GET',
      path: '/user/api-tokens',
      feature: 'apiTokens',
      handle: ({ req }) => auth.tokens.list(req),
    },
    {
      method: 'POST',
      path: '/user/api-tokens',
      feature: 'apiTokens',
      handle: ({ req, body }) =>
        auth.tokens.create(req, {
          name: body['name'],
          abilities: body['abilities'],
          expiresInDays: body['expiresInDays'],
        }),
    },
    {
      method: 'DELETE',
      path: '/user/api-tokens/:id',
      feature: 'apiTokens',
      handle: async ({ req, params }) => await auth.tokens.revoke(req, { id: params['id'] }),
    },
    {
      method: 'GET',
      path: '/api/me',
      feature: 'apiTokens',
      bearer: true,
      handle: async ({ request }) => {
        const token = await auth.tokens.authenticate(request.headers.get('authorization'))
        if (!token) throw new AuthError('unauthenticated')
        return { id: token.user.id, abilities: token.token.abilities }
      },
    },
    {
      method: 'POST',
      path: '/user/passkeys/options',
      feature: 'passkeys',
      handle: ({ req }) => auth.passkeys.registrationOptions(req),
    },
    {
      method: 'POST',
      path: '/user/passkeys',
      feature: 'passkeys',
      handle: ({ req, body }) =>
        auth.passkeys.register(req, { response: body['response'], name: body['name'] }),
    },
    {
      method: 'GET',
      path: '/user/passkeys',
      feature: 'passkeys',
      handle: ({ req }) => auth.passkeys.list(req),
    },
    {
      method: 'PATCH',
      path: '/user/passkeys/:id',
      feature: 'passkeys',
      handle: async ({ req, params, body }) =>
        await auth.passkeys.rename(req, { id: params['id'], name: body['name'] }),
    },
    {
      method: 'DELETE',
      path: '/user/passkeys/:id',
      feature: 'passkeys',
      handle: async ({ req, params }) => await auth.passkeys.remove(req, { id: params['id'] }),
    },
    {
      method: 'POST',
      path: '/passkeys/options',
      feature: 'passkeys',
      handle: ({ req, body }) => {
        const mode = body['mode']
        if (mode !== 'passwordless' && mode !== 'second-factor' && mode !== 'confirm')
          throw new AuthError('validation_failed', { issues: [{ field: 'mode', code: 'invalid' }] })
        return auth.passkeys.authenticationOptions(req, { mode })
      },
    },
    {
      method: 'POST',
      path: '/passkeys/authenticate',
      feature: 'passkeys',
      handle: ({ req, body }) =>
        auth.passkeys.authenticate(req, { response: body['response'], remember: body['remember'] }),
    },
    { method: 'GET', path: '/teams', feature: 'teams', handle: ({ req }) => auth.teams.list(req) },
    {
      method: 'POST',
      path: '/teams',
      feature: 'teams',
      handle: ({ req, body }) => auth.teams.create(req, { name: body['name'] }),
    },
    {
      method: 'POST',
      path: '/teams/:team/switch',
      feature: 'teams',
      handle: ({ req, params }) => auth.teams.switch(req, { teamId: params['team'] }),
    },
    {
      method: 'POST',
      path: '/teams/:team/invitations',
      feature: 'teams',
      handle: ({ req, params, body }) =>
        auth.teams.invite(req, {
          teamId: params['team'],
          email: body['email'],
          role: body['role'],
        }),
    },
    {
      method: 'POST',
      path: '/team-invitations/accept',
      feature: 'teams',
      handle: ({ req, body }) => auth.teams.accept(req, { token: body['token'] }),
    },
    {
      method: 'GET',
      path: '/teams/:team/members',
      feature: 'teams',
      handle: ({ req, params }) => auth.teams.members(req, { teamId: params['team'] }),
    },
    {
      method: 'PUT',
      path: '/teams/:team/members/:user',
      feature: 'teams',
      handle: async ({ req, params, body }) =>
        await auth.teams.changeRole(req, {
          teamId: params['team'],
          userId: params['user'],
          role: body['role'],
        }),
    },
    {
      method: 'DELETE',
      path: '/teams/:team/members/:user',
      feature: 'teams',
      handle: async ({ req, params }) =>
        await auth.teams.removeMember(req, { teamId: params['team'], userId: params['user'] }),
    },
    {
      method: 'POST',
      path: '/impersonate/:user',
      feature: 'impersonation',
      handle: async ({ req, params }) =>
        await auth.impersonation.start(req, { userId: params['user'] }),
    },
    {
      method: 'DELETE',
      path: '/impersonate',
      feature: 'impersonation',
      handle: async ({ req }) => await auth.impersonation.stop(req),
    },
  ]
}

function match(pattern: string, path: string): Record<string, string> | undefined {
  const a = pattern.split('/')
  const b = path.split('/')
  if (a.length !== b.length) return undefined
  const params: Record<string, string> = {}
  for (let i = 0; i < a.length; i++) {
    const p = a[i] ?? ''
    const v = b[i] ?? ''
    if (p.startsWith(':')) {
      if (v.length === 0 || v.length > 200) return undefined
      // Malformed percent-encoding (`%E0%A4%A`, a bare `%`) makes decodeURIComponent THROW, and
      // matching runs before the handler's try block: treat it as "no route" (the plain 404).
      try {
        params[p.slice(1)] = decodeURIComponent(v)
      } catch {
        return undefined
      }
    } else if (p !== v) return undefined
  }
  return params
}

async function readJson(request: Request): Promise<Json> {
  if (request.method === 'GET') return {}
  const length = Number(request.headers.get('content-length') ?? '0')
  if (length > MAX_BODY)
    throw new AuthError('validation_failed', { issues: [{ field: 'body', code: 'too_large' }] })
  const text = await request.text()
  if (text.length === 0) return {}
  if (text.length > MAX_BODY)
    throw new AuthError('validation_failed', { issues: [{ field: 'body', code: 'too_large' }] })
  if (!(request.headers.get('content-type') ?? '').toLowerCase().startsWith('application/json'))
    throw new AuthError('validation_failed', { issues: [{ field: 'body', code: 'json_required' }] })
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new AuthError('validation_failed', { issues: [{ field: 'body', code: 'invalid_json' }] })
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed))
    throw new AuthError('validation_failed', {
      issues: [{ field: 'body', code: 'object_required' }],
    })
  return parsed as Json
}

/** Unsafe cookie requests must come from the app itself (exact origin; never `same-site`/`null`). */
function sameOrigin(request: Request, appUrl: string): boolean {
  const site = request.headers.get('sec-fetch-site')
  if (site === 'same-origin') return true
  if (site !== null && site !== 'none') return false
  return request.headers.get('origin') === appUrl
}

/** Options for {@link createAuthHandler}. */
export interface AuthHandlerOptions {
  /** Called for every unexpected (non-`AuthError`) failure, with the route path only. */
  readonly onError?: (route: string, error: unknown) => void
}

/**
 * Build the Fetch handler. `ip` must be the client address resolved by the server from the socket
 * peer and trusted proxies (`node.ts` does this).
 *
 * @example
 * ```ts
 * const handle = createAuthHandler(auth)
 * const response = await handle(request, { ip: '203.0.113.7' })
 * ```
 */
export function createAuthHandler(
  auth: Auth,
  options: AuthHandlerOptions = {},
): (request: Request, info: { readonly ip: string | undefined }) => Promise<Response> {
  const table = routes(auth).filter(
    (r) => r.feature === undefined || auth.config.features[r.feature],
  )
  const secure = auth.config.secureCookies
  return async (request, info) => {
    const url = new URL(request.url)
    let route: Route | undefined
    let params: Record<string, string> | undefined
    for (const r of table) {
      if (r.method !== request.method) continue
      params = match(r.path, url.pathname)
      if (params) {
        route = r
        break
      }
    }
    if (!route || !params) return notFound()
    const jar = fetchCookieJar(request, { secure })
    const req: AuthRequest = {
      cookies: jar,
      ip: info.ip,
      userAgent: request.headers.get('user-agent') ?? undefined,
    }
    let response: Response
    try {
      if (
        route.bearer !== true &&
        route.method !== 'GET' &&
        !sameOrigin(request, auth.config.appUrl)
      )
        throw new AuthError('forbidden')
      const body = await readJson(request)
      const result = await route.handle({ req, body, params, query: url.searchParams, request })
      response = new Response(result === undefined ? null : JSON.stringify(result), {
        status: result === undefined ? 204 : 200,
        headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
      })
    } catch (error) {
      if (error instanceof AuthError) response = problem(error)
      else {
        options.onError?.(route.path, error)
        response = problem(new AuthError('internal_error'))
      }
    }
    jar.applyTo(response.headers)
    return response
  }
}
