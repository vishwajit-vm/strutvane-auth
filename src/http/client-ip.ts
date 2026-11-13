/**
 * Client IP resolution that cannot be spoofed with `X-Forwarded-For`.
 *
 * Spike 07 showed that trusting `X-Forwarded-For` blindly lets an attacker rotate a fake IP on
 * every request and walk straight past a per-IP sign-in limit. The rule implemented here:
 *
 * 1. Start from the TCP peer address (see `request-meta.ts`), which the client cannot forge.
 * 2. Only if that peer is one of YOUR trusted proxies, read `X-Forwarded-For` from right to left,
 *    skipping further trusted proxies; the first untrusted address is the client.
 * 3. Otherwise the peer address IS the client, whatever the headers say.
 *
 * @module
 */
import { BlockList, isIP } from 'node:net'
import { requestMeta } from './request-meta.ts'

/** A set of trusted proxy addresses and CIDR ranges. */
export interface TrustedProxies {
  /** Is this address one of the trusted proxies? */
  has(address: string): boolean
}

/** Normalise `::ffff:1.2.3.4` (IPv4-mapped IPv6) to `1.2.3.4`; return `undefined` for non-IPs. */
export function normalizeIp(value: string | undefined): string | undefined {
  if (value === undefined) return undefined
  let v = value.trim()
  // Strip brackets and a zone id, which some proxies include (`[fe80::1%eth0]`).
  if (v.startsWith('[') && v.endsWith(']')) v = v.slice(1, -1)
  const zone = v.indexOf('%')
  if (zone >= 0) v = v.slice(0, zone)
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(v)
  if (mapped?.[1]) v = mapped[1]
  return isIP(v) === 0 ? undefined : v.toLowerCase()
}

/**
 * Build a trusted-proxy set from addresses and CIDR ranges, e.g.
 * `['10.0.0.0/8', '127.0.0.1', '::1']`. Invalid entries throw at boot.
 */
export function trustedProxies(entries: readonly string[] = []): TrustedProxies {
  const list = new BlockList()
  for (const entry of entries) {
    const [address = '', prefix] = entry.split('/')
    const ip = normalizeIp(address)
    if (!ip) throw new TypeError(`Invalid trusted proxy address: ${JSON.stringify(entry)}`)
    const family = isIP(ip) === 4 ? 'ipv4' : 'ipv6'
    if (prefix === undefined) {
      list.addAddress(ip, family)
      continue
    }
    const bits = Number(prefix)
    const max = family === 'ipv4' ? 32 : 128
    if (!/^\d{1,3}$/.test(prefix) || bits > max)
      throw new TypeError(`Invalid CIDR prefix: ${JSON.stringify(entry)}`)
    list.addSubnet(ip, bits, family)
  }
  return {
    has(address) {
      const ip = normalizeIp(address)
      return ip !== undefined && list.check(ip, isIP(ip) === 4 ? 'ipv4' : 'ipv6')
    },
  }
}

const NONE: TrustedProxies = { has: () => false }

/**
 * The client IP for a request, or `undefined` when the server never attached a peer address
 * (callers must then fall back to limits that don't need an IP, never to a shared bucket).
 */
export function resolveClientIp(
  request: Request,
  proxies: TrustedProxies = NONE,
): string | undefined {
  const peer = normalizeIp(requestMeta(request)?.remoteAddress)
  if (!peer) return undefined
  if (!proxies.has(peer)) return peer
  const hops = (request.headers.get('x-forwarded-for') ?? '')
    .split(',')
    .map((h) => h.trim())
    .filter((h) => h.length > 0)
  for (let i = hops.length - 1; i >= 0; i--) {
    const hop = normalizeIp(hops[i])
    // A malformed hop means the chain can't be trusted beyond this point: use the last good proxy.
    if (!hop) return peer
    if (!proxies.has(hop)) return hop
  }
  return peer
}
