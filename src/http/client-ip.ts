/**
 * Client IP resolution that cannot be spoofed with `X-Forwarded-For`.
 *
 * Spike 07 showed that trusting `X-Forwarded-For` blindly lets an attacker rotate a fake IP on
 * every request and walk straight past a per-IP sign-in limit. The rule implemented here:
 *
 * 1. Start from the TCP peer address (see `request-meta.ts`), which the client cannot forge.
 * 2. Only if that peer is one of YOUR trusted proxies, read `X-Forwarded-For` from right to left,
 *    skipping further trusted proxies; the first untrusted address is the client. A hop may carry
 *    a source port (`203.0.113.7:51234`, `[2001:db8::7]:443`); the port is ignored.
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

const V4_WITH_PORT = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/
const V6_WITH_PORT = /^\[([0-9A-Fa-f:.%a-zA-Z]+)\]:(\d{1,5})$/

/**
 * Drop a source port from one `X-Forwarded-For` hop (`203.0.113.7:51234`, `[2001:db8::7]:443`).
 * Some proxies (e.g. Azure App Service) append it. Without this, such hops were treated as
 * malformed and every client behind the proxy shared the proxy's own rate-limit bucket. Only a
 * valid port (0-65535) is removed; anything else is left for `normalizeIp` to reject.
 */
function withoutPort(hop: string): string {
  const match = V4_WITH_PORT.exec(hop) ?? V6_WITH_PORT.exec(hop)
  if (!match?.[1] || match[2] === undefined || Number(match[2]) > 65_535) return hop
  return match[1]
}

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
    const hop = normalizeIp(withoutPort(hops[i] ?? ''))
    // A malformed hop means the chain can't be trusted beyond this point: use the last good proxy.
    if (!hop) return peer
    if (!proxies.has(hop)) return hop
  }
  return peer
}

/** Expand an IPv6 address (already validated by `isIP`) into its eight 16-bit groups. */
function ipv6Groups(ip: string): number[] {
  let text = ip
  // An embedded IPv4 tail (`64:ff9b::192.0.2.1`) becomes two hex groups.
  const v4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text)
  if (v4) {
    const [a, b, c, d] = v4.slice(1).map(Number) as [number, number, number, number]
    text = `${text.slice(0, v4.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`
  }
  const [head = '', tail] = text.split('::')
  const left = head.length > 0 ? head.split(':') : []
  const right = tail !== undefined && tail.length > 0 ? tail.split(':') : []
  const fill = tail === undefined ? 0 : 8 - left.length - right.length
  return [...left, ...Array<string>(fill).fill('0'), ...right].map((g) => Number.parseInt(g, 16))
}

/**
 * The key a per-IP rate limit should count for an address.
 *
 * IPv4 addresses count individually. IPv6 addresses count per `/64` prefix: a single customer is
 * normally given a whole /64 (or more), so keying on the full /128 would let one client rotate
 * through 2^64 addresses and never hit a limit.
 */
export function rateLimitSubject(ip: string): string {
  const normalized = normalizeIp(ip)
  if (normalized === undefined) return ip
  if (isIP(normalized) === 4) return normalized
  const prefix = ipv6Groups(normalized)
    .slice(0, 4)
    .map((g) => g.toString(16))
    .join(':')
  return `${prefix}::/64`
}
