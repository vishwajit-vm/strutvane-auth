/**
 * The rate-limit subject for a client address (copied from v1 `http/client-ip.ts`).
 *
 * IPv4 addresses count individually. IPv6 addresses count per /64: one customer usually holds a
 * whole /64, so keying on the full /128 would let one client rotate through 2^64 addresses and never
 * hit a limit (review F-22). An unknown address shares ONE bucket (`unknown`), failing closed
 * instead of skipping the per-IP limit.
 *
 * @module
 */
import { isIP } from 'node:net'

/**
 * Normalise an address; `undefined` for anything that is not an IP.
 *
 * Every spelling of an IPv4-mapped IPv6 address (`::ffff:1.2.3.4`, `0:0:0:0:0:ffff:1.2.3.4`,
 * `::ffff:102:304`, upper case, brackets) becomes the plain IPv4 address. Why all of them: a proxy
 * or platform that writes the hex or expanded form would otherwise put EVERY IPv4 client into one
 * shared IPv6 /64 bucket (one client locks out all), and one client seen in two spellings would get
 * two budgets.
 */
export function normalizeIp(value: string | undefined): string | undefined {
  if (value === undefined) return undefined
  let v = value.trim()
  if (v.startsWith('[') && v.endsWith(']')) v = v.slice(1, -1)
  const zone = v.indexOf('%')
  if (zone >= 0) v = v.slice(0, zone)
  const family = isIP(v)
  if (family === 0) return undefined
  if (family === 4) return v
  const groups = ipv6Groups(v.toLowerCase())
  if (groups.length === 8 && groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    const [hi = 0, lo = 0] = groups.slice(6)
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`
  }
  return v.toLowerCase()
}

function ipv6Groups(ip: string): number[] {
  let text = ip
  const v4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text)
  if (v4) {
    const [a = 0, b = 0, c = 0, d = 0] = v4.slice(1).map(Number)
    text = `${text.slice(0, v4.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`
  }
  const [head = '', tail] = text.split('::')
  const left = head.length > 0 ? head.split(':') : []
  const right = tail !== undefined && tail.length > 0 ? tail.split(':') : []
  const fill = tail === undefined ? 0 : 8 - left.length - right.length
  return [...left, ...Array<string>(fill).fill('0'), ...right].map((g) => Number.parseInt(g, 16))
}

/**
 * The key a per-IP limit counts for an address.
 *
 * @example
 * ```ts
 * rateLimitSubject('2001:db8:1:2:aaaa::1') // '2001:db8:1:2::/64'
 * rateLimitSubject(undefined)               // 'unknown' (one shared bucket)
 * ```
 */
export function rateLimitSubject(ip: string | undefined): string {
  const normalized = normalizeIp(ip)
  if (normalized === undefined) return 'unknown'
  if (isIP(normalized) === 4) return normalized
  return `${ipv6Groups(normalized)
    .slice(0, 4)
    .map((g) => g.toString(16))
    .join(':')}::/64`
}
