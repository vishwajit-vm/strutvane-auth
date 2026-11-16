/**
 * Serve the example handler with plain `node:http`, resolving the client IP safely.
 *
 * The client address is the socket peer, unless the peer is a trusted proxy; only then is
 * `X-Forwarded-For` read, right to left, skipping trusted hops (v1 `client-ip.ts`). A forged header
 * from anyone else is ignored, so it cannot rotate the per-IP limit.
 *
 * @module
 */
import { createServer, type IncomingMessage, type Server } from 'node:http'
import { BlockList, isIP } from 'node:net'
import type { Auth } from '../auth.ts'
import { normalizeIp } from '../limits/ip.ts'
import { createAuthHandler } from './routes.ts'

/** Build a trusted-proxy matcher from addresses and CIDRs (`['10.0.0.0/8', '::1']`). */
export function trustedProxies(entries: readonly string[]): (address: string) => boolean {
  const list = new BlockList()
  for (const entry of entries) {
    const [address = '', prefix] = entry.split('/')
    const ip = normalizeIp(address)
    if (!ip) throw new TypeError(`Invalid trusted proxy: ${JSON.stringify(entry)}`)
    const family = isIP(ip) === 4 ? 'ipv4' : 'ipv6'
    if (prefix === undefined) list.addAddress(ip, family)
    else list.addSubnet(ip, Number(prefix), family)
  }
  return (address) => {
    const ip = normalizeIp(address)
    return ip !== undefined && list.check(ip, isIP(ip) === 4 ? 'ipv4' : 'ipv6')
  }
}

/** The client IP for a request: the peer, or the first untrusted `X-Forwarded-For` hop behind trusted proxies. */
export function clientIp(
  peer: string | undefined,
  forwardedFor: string | undefined,
  trusted: (a: string) => boolean,
): string | undefined {
  const ip = normalizeIp(peer)
  if (!ip || !trusted(ip)) return ip
  const hops = (forwardedFor ?? '')
    .split(',')
    .map((h) => h.trim())
    .filter((h) => h.length > 0)
  for (let i = hops.length - 1; i >= 0; i--) {
    const hop = normalizeIp(hops[i])
    if (!hop) return ip
    if (!trusted(hop)) return hop
  }
  return ip
}

async function toRequest(message: IncomingMessage, origin: string): Promise<Request> {
  const headers = new Headers()
  for (const [name, value] of Object.entries(message.headers)) {
    if (Array.isArray(value)) for (const v of value) headers.append(name, v)
    else if (value !== undefined) headers.set(name, value)
  }
  const chunks: Buffer[] = []
  let size = 0
  if (message.method !== 'GET' && message.method !== 'HEAD') {
    for await (const chunk of message) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk))
      size += buf.length
      if (size > 64 * 1024) break // the handler refuses anything over 16 KiB anyway
      chunks.push(buf)
    }
  }
  const init: RequestInit = { method: message.method ?? 'GET', headers }
  if (chunks.length > 0) init.body = Buffer.concat(chunks)
  return new Request(new URL(message.url ?? '/', origin), init)
}

/**
 * Create (not start) a `node:http` server for the auth routes.
 *
 * @example
 * ```ts
 * const server = createAuthServer(auth, { trustedProxies: [] })
 * server.listen(3000, '127.0.0.1')
 * ```
 */
export function createAuthServer(
  auth: Auth,
  options: { readonly trustedProxies?: readonly string[] } = {},
): Server {
  const handle = createAuthHandler(auth)
  const trusted = trustedProxies(options.trustedProxies ?? [])
  return createServer((message, res) => {
    void (async () => {
      const request = await toRequest(message, auth.config.appUrl)
      const forwarded = message.headers['x-forwarded-for']
      const ip = clientIp(
        message.socket.remoteAddress,
        Array.isArray(forwarded) ? forwarded.join(',') : forwarded,
        trusted,
      )
      const response = await handle(request, { ip })
      const setCookies = response.headers.getSetCookie()
      const headers: Record<string, string | string[]> = {}
      response.headers.forEach((value, name) => {
        if (name !== 'set-cookie') headers[name] = value
      })
      if (setCookies.length > 0) headers['set-cookie'] = setCookies
      res.writeHead(response.status, headers)
      res.end(Buffer.from(await response.arrayBuffer()))
    })().catch(() => {
      if (!res.headersSent) res.writeHead(500, { 'content-type': 'application/problem+json' })
      res.end()
    })
  })
}
