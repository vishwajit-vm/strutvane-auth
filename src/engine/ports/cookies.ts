/**
 * The cookie and request port. The framework owns the HTTP request; auth only needs three things
 * from it: cookies (read and write), the client address and the user agent.
 *
 * Why the IP comes in already resolved: resolving it safely needs the socket peer and the trusted
 * proxy list, which the framework's HTTP layer owns (v1 `client-ip.ts`, kept in this spike's
 * example adapter). Auth never reads `X-Forwarded-For` itself.
 *
 * @module
 */

/** Options for {@link CookieJar.set}. `httpOnly`, `sameSite: 'Lax'` and `path: '/'` are implied. */
export interface CookieOptions {
  /** Lifetime in seconds; omit for a browser-session cookie. */
  readonly maxAgeSeconds?: number
}

/**
 * Read and write cookies for one request. The framework decides the attributes it adds on top
 * (`Secure` and the `__Host-` prefix on https, which this core requests through the cookie name).
 *
 * @example
 * ```ts
 * const jar = fetchCookieJar(request) // the example adapter's implementation
 * jar.get(auth.cookieNames.session) // 'strutvane_session', or '__Host-strutvane_session' on https
 * ```
 */
export interface CookieJar {
  get(name: string): string | undefined
  set(name: string, value: string, options?: CookieOptions): void
  clear(name: string): void
}

/**
 * Everything a service needs to know about the current HTTP request.
 *
 * @example
 * ```ts
 * const req: AuthRequest = { cookies: jar, ip: '203.0.113.7', userAgent: 'Firefox' }
 * await auth.login(req, { email, password })
 * ```
 */
export interface AuthRequest {
  readonly cookies: CookieJar
  /** The client address resolved through trusted proxies, or `undefined` if unknown. */
  readonly ip: string | undefined
  readonly userAgent?: string | undefined
}
