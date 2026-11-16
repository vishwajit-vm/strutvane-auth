/**
 * A {@link CookieJar} over a Fetch `Request`, collecting `Set-Cookie` headers for the `Response`.
 * In the product the framework's own cookie API implements the port; this is the example's.
 *
 * Every cookie is `HttpOnly; SameSite=Lax; Path=/`, plus `Secure` on https (names starting with
 * `__Host-` are only accepted by browsers with `Secure`, no `Domain` and `Path=/`).
 *
 * @module
 */
import type { CookieJar } from '../ports/cookies.ts'

/** A jar plus the headers it produced. */
export interface FetchCookieJar extends CookieJar {
  /** Append the collected `Set-Cookie` headers. */
  applyTo(headers: Headers): void
}

/** Parse a `Cookie` header (first occurrence of a name wins; malformed pairs are skipped). */
export function parseCookieHeader(header: string | null): Map<string, string> {
  const out = new Map<string, string>()
  for (const pair of (header ?? '').split(';')) {
    const eq = pair.indexOf('=')
    if (eq <= 0) continue
    const name = pair.slice(0, eq).trim()
    if (!out.has(name)) out.set(name, pair.slice(eq + 1).trim())
  }
  return out
}

/**
 * Build a jar for one request.
 *
 * @example
 * ```ts
 * const jar = fetchCookieJar(request, { secure: true })
 * const response = new Response(body); jar.applyTo(response.headers)
 * ```
 */
export function fetchCookieJar(
  request: Request,
  options: { readonly secure: boolean },
): FetchCookieJar {
  const incoming = parseCookieHeader(request.headers.get('cookie'))
  const outgoing = new Map<string, string>()
  const serialize = (name: string, value: string, maxAge: number | undefined): string => {
    const parts = [`${name}=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Lax']
    if (maxAge !== undefined) parts.push(`Max-Age=${maxAge}`)
    if (options.secure) parts.push('Secure')
    return parts.join('; ')
  }
  return {
    get: (name) => incoming.get(name),
    set(name, value, cookieOptions) {
      incoming.set(name, value)
      outgoing.set(name, serialize(name, value, cookieOptions?.maxAgeSeconds))
    },
    clear(name) {
      incoming.delete(name)
      outgoing.set(name, serialize(name, '', 0))
    },
    applyTo(headers) {
      for (const value of outgoing.values()) headers.append('set-cookie', value)
    },
  }
}
