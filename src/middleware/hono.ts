/**
 * `@strutvane/auth/hono`: the auth middleware for Hono.
 *
 * ```ts
 * const app = new Hono<{ Variables: AuthVariables }>()
 * app.use(authMiddleware({ engine, tenancy: { resolvers: [subdomainResolver({…}), sessionResolver()] } }))
 * app.get('/me', (c) => c.json({ actor: c.get('actor') }))
 * ```
 *
 * The TCP peer address (for rate limiting) is read from `@hono/node-server`'s `c.env.incoming`
 * when present, or from your `remoteAddress` option on other runtimes. It is never read from
 * headers.
 *
 * @module
 */
import type { Actor, TenantContext } from '@strutvane/contracts'
import type { Context, MiddlewareHandler } from 'hono'
import { attachRequestMeta } from '../http/request-meta.ts'
import { type AuthMiddlewareOptions, authenticateRequest, runWithAuth } from './core.ts'

/** Variables the middleware sets on the Hono context. */
export interface AuthVariables {
  actor: Actor | null
  tenant: TenantContext | undefined
}

/** Options for the Hono middleware. */
export interface HonoAuthOptions extends AuthMiddlewareOptions {
  /** The TCP peer address. Default: `c.env.incoming.socket.remoteAddress` (`@hono/node-server`). */
  readonly remoteAddress?: (c: Context) => string | undefined
}

function nodeServerPeer(c: Context): string | undefined {
  const env = c.env as { incoming?: { socket?: { remoteAddress?: unknown } } } | undefined
  const address = env?.incoming?.socket?.remoteAddress
  return typeof address === 'string' ? address : undefined
}

/** Create the middleware. */
export function authMiddleware(
  options: HonoAuthOptions,
): MiddlewareHandler<{ Variables: AuthVariables }> {
  const peer = options.remoteAddress ?? nodeServerPeer
  return async (c, next) => {
    const request = c.req.raw
    const remoteAddress = peer(c)
    attachRequestMeta(request, remoteAddress !== undefined ? { remoteAddress } : {})
    const outcome = await authenticateRequest(request, options)
    if (!outcome.ok) return outcome.response
    c.set('actor', outcome.state.actor)
    c.set('tenant', outcome.state.tenant)
    await runWithAuth(outcome.state, () => next())
    for (const [name, value] of outcome.state.headers) {
      if (name !== 'set-cookie') c.res.headers.set(name, value)
    }
    for (const cookie of outcome.state.headers.getSetCookie())
      c.res.headers.append('set-cookie', cookie)
    return undefined
  }
}
