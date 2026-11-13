/**
 * `@strutvane/auth/node`: the auth middleware for `node:http` and any connect-style framework
 * (Express works as is: `app.use(authMiddleware({ engine }))`).
 *
 * The TCP peer address (`req.socket.remoteAddress`) is attached to the Web `Request` used for
 * authentication, so rate limits key on a value clients cannot forge (see `attachRequestMeta`).
 *
 * @module
 */
import type { IncomingMessage, ServerResponse } from 'node:http'
import { attachRequestMeta } from '../http/request-meta.ts'
import {
  type AuthMiddlewareOptions,
  type AuthState,
  authenticateRequest,
  runWithAuth,
} from './core.ts'

const HOST = /^[A-Za-z0-9.-]{1,253}(:\d{1,5})?$|^\[[0-9A-Fa-f:.]{2,45}\](:\d{1,5})?$/
const FORBIDDEN_METHODS = new Set(['CONNECT', 'TRACE', 'TRACK'])

function parseUrl(value: string): URL | undefined {
  try {
    return new URL(value)
  } catch {
    return undefined
  }
}

/**
 * Convert a Node request to a Web `Request` (headers and URL only; the body is never read, so the
 * stream stays available to your handler). A malformed `Host` header becomes `invalid.invalid`,
 * so it can never match a tenant subdomain.
 */
export function toWebRequest(req: IncomingMessage): Request {
  const rawHost = typeof req.headers.host === 'string' ? req.headers.host : ''
  const host = HOST.test(rawHost) ? rawHost : 'invalid.invalid'
  const secure = (req.socket as { encrypted?: boolean } | undefined)?.encrypted === true
  const path = typeof req.url === 'string' && req.url.startsWith('/') ? req.url : '/'
  const url =
    parseUrl(`${secure ? 'https' : 'http'}://${host}${path}`) ??
    parseUrl(`http://invalid.invalid${path}`) ??
    new URL('http://invalid.invalid/')
  const headers = new Headers()
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue
    try {
      if (Array.isArray(value)) for (const v of value) headers.append(name, v)
      else headers.set(name, value)
    } catch {
      // Header values Node accepted but the Fetch spec rejects are dropped, never fatal.
    }
  }
  const method = (req.method ?? 'GET').toUpperCase()
  const request = new Request(url, {
    method: FORBIDDEN_METHODS.has(method) ? 'GET' : method,
    headers,
  })
  const remoteAddress = req.socket?.remoteAddress
  return attachRequestMeta(request, remoteAddress !== undefined ? { remoteAddress } : {})
}

const states = new WeakMap<IncomingMessage, AuthState>()

/** The auth state for a request that passed the middleware, or `undefined`. */
export function getAuth(req: IncomingMessage): AuthState | undefined {
  return states.get(req)
}

/** A connect-style `next`. */
export type Next = (error?: unknown) => void

async function send(res: ServerResponse, response: Response): Promise<void> {
  res.statusCode = response.status
  for (const [name, value] of response.headers) {
    if (name !== 'set-cookie') res.setHeader(name, value)
  }
  const cookies = response.headers.getSetCookie()
  if (cookies.length > 0) res.setHeader('set-cookie', cookies)
  res.end(await response.text())
}

/** Create a connect-style middleware: `(req, res, next) => void`. */
export function authMiddleware(
  options: AuthMiddlewareOptions,
): (req: IncomingMessage, res: ServerResponse, next: Next) => void {
  return (req, res, next) => {
    authenticateRequest(toWebRequest(req), options).then(
      async (outcome) => {
        if (!outcome.ok) return send(res, outcome.response)
        states.set(req, outcome.state)
        const cookies = outcome.state.headers.getSetCookie()
        if (cookies.length > 0) res.appendHeader('set-cookie', cookies)
        for (const [name, value] of outcome.state.headers) {
          if (name !== 'set-cookie') res.setHeader(name, value)
        }
        runWithAuth(outcome.state, () => next())
      },
      (error: unknown) => next(error),
    )
  }
}

/** Wrap a plain `node:http` handler: `createServer(withAuth({ engine }, (req, res) => …))`. */
export function withAuth(
  options: AuthMiddlewareOptions,
  handler: (req: IncomingMessage, res: ServerResponse, auth: AuthState) => void | Promise<void>,
): (req: IncomingMessage, res: ServerResponse) => void {
  const middleware = authMiddleware(options)
  return (req, res) => {
    middleware(req, res, (error) => {
      const state = getAuth(req)
      if (error !== undefined || !state) {
        if (!res.headersSent) res.statusCode = 500
        res.end()
        return
      }
      // `.then` also catches a handler that throws synchronously.
      Promise.resolve()
        .then(() => handler(req, res, state))
        .catch(() => {
          if (!res.headersSent) res.statusCode = 500
          res.end()
        })
    })
  }
}
