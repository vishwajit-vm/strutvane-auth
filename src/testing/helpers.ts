/**
 * Engine-agnostic test helpers: request builders that behave like a browser behind your proxy,
 * a cookie jar, a mailbox for reset tokens, and actor builders for policy tests.
 *
 * @module
 */
import { randomBytes } from 'node:crypto'
import type { Actor, TenantContext } from '@strutvane/framework/contracts'
import { runWithContext } from '@strutvane/framework/core'
import { attachRequestMeta } from '../http/request-meta.ts'
import type { PasswordResetDelivery } from '../identity/engine.ts'

/** The proxy address the contract suite treats as trusted. Pass it to your engine as `trustedProxies`. */
export const TEST_PROXY = '10.255.0.1'

/** A cookie jar of `name → value`, as a browser keeps them. */
export type Jar = Map<string, string>

export function newJar(): Jar {
  return new Map()
}

/** Apply `Set-Cookie` headers to a jar (`Max-Age=0` or an empty value deletes). */
export function store(jar: Jar, result: { readonly headers: Headers }): Jar {
  for (const cookie of result.headers.getSetCookie()) {
    const [pair = '', ...attrs] = cookie.split(';')
    const eq = pair.indexOf('=')
    const name = pair.slice(0, eq).trim()
    const value = pair.slice(eq + 1).trim()
    if (attrs.some((a) => /^\s*max-age=0\s*$/i.test(a)) || value === '') jar.delete(name)
    else jar.set(name, value)
  }
  return jar
}

/** Options for {@link browserRequest}. */
export interface BrowserRequestOptions {
  readonly jar?: Jar
  /** The client IP. With `viaProxy` (default), it arrives in `X-Forwarded-For` from {@link TEST_PROXY}. */
  readonly ip?: string
  /** `false` = the client connects directly (its IP is the TCP peer). Default `true`. */
  readonly viaProxy?: boolean
  /** A raw `X-Forwarded-For` value (for spoofing tests). */
  readonly forwardedFor?: string
  /** Attach no peer address at all (as if no HTTP adapter ran). */
  readonly noPeer?: boolean
  readonly path?: string
  readonly method?: string
}

/** Build an incoming request as a same-origin browser would send it, with the server-side peer attached. */
export function browserRequest(baseURL: string, options: BrowserRequestOptions = {}): Request {
  const headers = new Headers({ origin: baseURL, 'user-agent': 'strutvane-auth-tests/1.0' })
  const ip = options.ip ?? '203.0.113.10'
  const viaProxy = options.viaProxy !== false
  if (options.forwardedFor !== undefined) headers.set('x-forwarded-for', options.forwardedFor)
  else if (viaProxy) headers.set('x-forwarded-for', ip)
  if (options.jar && options.jar.size > 0) {
    headers.set('cookie', [...options.jar].map(([n, v]) => `${n}=${v}`).join('; '))
  }
  const request = new Request(`${baseURL}${options.path ?? '/'}`, {
    method: options.method ?? 'GET',
    headers,
  })
  if (options.noPeer) return request
  return attachRequestMeta(request, { remoteAddress: viaProxy ? TEST_PROXY : ip })
}

/** A unique, valid email address. */
export function testEmail(label: string): string {
  return `${label}-${randomBytes(5).toString('hex')}@example.com`
}

export const TEST_PASSWORD = 'correct horse battery staple'
export const TEST_NEW_PASSWORD = 'an even longer new passphrase'

/** Parse one `Set-Cookie` header into its name and lower-cased attributes. */
export function cookieAttributes(setCookie: string): { name: string; attrs: Map<string, string> } {
  const [pair = '', ...rest] = setCookie.split(';')
  const attrs = new Map<string, string>()
  for (const part of rest) {
    const [k = '', ...v] = part.trim().split('=')
    attrs.set(k.toLowerCase(), v.join('='))
  }
  return { name: pair.split('=')[0]?.trim() ?? '', attrs }
}

/** Captures password-reset messages. */
export class Mailbox {
  readonly messages: { email: string; token: string }[] = []
  readonly deliver: PasswordResetDelivery = async (m) => {
    this.messages.push({ email: m.email, token: m.token })
  }
  tokenFor(address: string): string | undefined {
    const lower = address.toLowerCase()
    return this.messages.filter((m) => m.email.toLowerCase() === lower).at(-1)?.token
  }
  /** Wait for a token (delivery runs in the background). */
  async waitForToken(address: string, timeoutMs = 5000): Promise<string> {
    const deadline = Date.now() + timeoutMs
    for (;;) {
      const token = this.tokenFor(address)
      if (token) return token
      if (Date.now() > deadline) throw new Error(`no reset token delivered to ${address}`)
      await new Promise((r) => setTimeout(r, 10))
    }
  }
  /** Wait for a token other than `previous` (a second reset request for the same address). */
  async waitForNewToken(address: string, previous: string, timeoutMs = 5000): Promise<string> {
    const deadline = Date.now() + timeoutMs
    for (;;) {
      const token = this.tokenFor(address)
      if (token && token !== previous) return token
      if (Date.now() > deadline) throw new Error(`no new reset token delivered to ${address}`)
      await new Promise((r) => setTimeout(r, 10))
    }
  }
}

let counter = 0
/** A fresh documentation-range client IP, so rate limits never leak between tests. */
export function freshIp(): string {
  counter++
  return `198.51.${Math.floor(counter / 250) % 250}.${(counter % 250) + 1}`
}

/** Build an actor for tests: `actingAs({ roles: ['manager'], tenantId })`. */
export function actingAs(overrides: Partial<Actor> = {}): Actor {
  return Object.freeze({
    id: '00000000-0000-7000-8000-000000000001',
    type: 'user',
    roles: [],
    attrs: {},
    ...overrides,
  })
}

/** Run `fn` with `actor` (and optionally a tenant) in core's request context. */
export function runAs<R>(actor: Actor | null, fn: () => R, tenant?: TenantContext): R {
  return runWithContext(tenant ? { actor, tenant } : { actor }, fn)
}
