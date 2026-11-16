import type { AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import type { AuthFeatures, AuthFeaturesInput } from '../../src/engine/config.ts'
import { parseCookieHeader } from '../../src/engine/http/cookies.ts'
import { clientIp, createAuthServer, trustedProxies } from '../../src/engine/http/node.ts'
import { createAuthHandler } from '../../src/engine/http/routes.ts'
import { harness, PASSWORD, rejectsWith } from './helpers/harness.ts'

const APP = 'http://localhost:3000'
const ALL_OFF: AuthFeaturesInput = { password: false, passwordConfirmation: false }

/** Every feature-owned route (method, path with sample params). */
const FEATURE_ROUTES: Record<keyof AuthFeatures, readonly (readonly [string, string])[]> = {
  password: [
    ['POST', '/login'],
    ['PUT', '/user/password'],
  ],
  // Follows `password` (#25): switching passwords off removes the reset routes too.
  passwordReset: [
    ['POST', '/forgot-password'],
    ['POST', '/reset-password'],
  ],
  passwordConfirmation: [['POST', '/user/confirm-password']],
  registration: [['POST', '/register']],
  emailVerification: [
    ['POST', '/email/verification-notification'],
    ['GET', '/email/verify/x/y'],
  ],
  emailLink: [
    ['POST', '/email-link'],
    ['POST', '/email-link/abc'],
  ],
  twoFactor: [
    ['POST', '/two-factor-challenge'],
    ['POST', '/user/two-factor-authentication'],
    ['DELETE', '/user/two-factor-authentication'],
    ['POST', '/user/confirmed-two-factor-authentication'],
    ['POST', '/user/two-factor-recovery-codes'],
  ],
  passkeys: [
    ['POST', '/user/passkeys/options'],
    ['POST', '/user/passkeys'],
    ['GET', '/user/passkeys'],
    ['PATCH', '/user/passkeys/x'],
    ['DELETE', '/user/passkeys/x'],
    ['POST', '/passkeys/options'],
    ['POST', '/passkeys/authenticate'],
  ],
  apiTokens: [
    ['GET', '/user/api-tokens'],
    ['POST', '/user/api-tokens'],
    ['DELETE', '/user/api-tokens/x'],
    ['GET', '/api/me'],
  ],
  teams: [
    ['GET', '/teams'],
    ['POST', '/teams'],
    ['POST', '/teams/x/switch'],
    ['POST', '/teams/x/invitations'],
    ['POST', '/team-invitations/accept'],
    ['GET', '/teams/x/members'],
    ['PUT', '/teams/x/members/y'],
    ['DELETE', '/teams/x/members/y'],
  ],
  impersonation: [
    ['POST', '/impersonate/x'],
    ['DELETE', '/impersonate'],
  ],
}

function request(
  method: string,
  path: string,
  init: { body?: unknown; cookie?: string; headers?: Record<string, string> } = {},
): Request {
  const headers = new Headers({ 'sec-fetch-site': 'same-origin', ...init.headers })
  if (init.cookie) headers.set('cookie', init.cookie)
  const body = init.body === undefined ? undefined : JSON.stringify(init.body)
  if (body !== undefined && !headers.has('content-type'))
    headers.set('content-type', 'application/json')
  return new Request(`${APP}${path}`, { method, headers, ...(body !== undefined ? { body } : {}) })
}

const cookiesOf = (res: Response): string =>
  res.headers
    .getSetCookie()
    .map((c) => c.split(';')[0] ?? '')
    .filter((c) => !c.endsWith('='))
    .join('; ')

async function snapshot(res: Response): Promise<string> {
  return JSON.stringify({
    status: res.status,
    type: res.headers.get('content-type'),
    body: await res.text(),
    cookies: res.headers.getSetCookie(),
  })
}

describe('feature switches', () => {
  it('a disabled feature is byte-identical to a path that never existed (404, never 403)', async () => {
    const h = harness({ config: { features: ALL_OFF } })
    const handle = createAuthHandler(h.auth)
    const reference = await snapshot(
      await handle(request('GET', '/definitely-not-a-route'), { ip: '192.0.2.1' }),
    )
    expect(JSON.parse(reference).status).toBe(404)
    for (const [feature, routes] of Object.entries(FEATURE_ROUTES)) {
      for (const [method, path] of routes) {
        const res = await handle(request(method, path, method === 'GET' ? {} : { body: {} }), {
          ip: '192.0.2.1',
        })
        expect(await snapshot(res), `${feature} ${method} ${path}`).toBe(reference)
      }
    }
  })

  it('hostile path params (malformed percent-encoding) answer the plain 404, never a thrown error', async () => {
    const h = harness({
      config: {
        features: {
          emailLink: true,
          teams: true,
          apiTokens: true,
          passkeys: true,
          impersonation: true,
        },
        passkeys: { rpId: 'localhost', rpName: 'Test', origins: [APP] },
      },
    })
    const handle = createAuthHandler(h.auth)
    const reference = await snapshot(
      await handle(request('GET', '/definitely-not-a-route'), { ip: '192.0.2.1' }),
    )
    const paths: readonly (readonly [string, string])[] = [
      ['POST', '/email-link/%E0%A4%A'],
      ['DELETE', '/user/sessions/%'],
      ['DELETE', '/user/api-tokens/%ZZ'],
      ['GET', '/email/verify/%E0%A4%A/%'],
      ['POST', '/teams/%C0%AF/switch'],
      ['DELETE', '/user/passkeys/%D8%00'],
      ['POST', '/impersonate/%'],
    ]
    for (const [method, path] of paths) {
      const res = await handle(request(method, path, method === 'GET' ? {} : { body: {} }), {
        ip: '192.0.2.1',
      })
      expect(await snapshot(res), `${method} ${path}`).toBe(reference)
    }
  })

  it('an enabled feature answers (so the 404 above really came from the switch)', async () => {
    const h = harness({
      config: { features: { registration: true, emailLink: true, teams: true, apiTokens: true } },
    })
    const handle = createAuthHandler(h.auth)
    expect(
      (
        await handle(request('POST', '/email-link', { body: { email: 'a@b.io' } }), {
          ip: '192.0.2.1',
        })
      ).status,
    ).toBe(200)
    expect((await handle(request('GET', '/teams'), { ip: '192.0.2.1' })).status).toBe(401)
    expect((await handle(request('GET', '/api/me'), { ip: '192.0.2.1' })).status).toBe(401)
  })

  it('disabled services refuse at the service level too (defence in depth)', async () => {
    const h = harness({ config: { features: ALL_OFF } })
    const req = {
      cookies: { get: () => undefined, set: () => undefined, clear: () => undefined },
      ip: '192.0.2.1',
    }
    const services = {
      passwords: ['register', 'login', 'change'],
      passwordReset: ['request', 'reset'],
      verification: ['resend', 'verify'],
      emailLink: ['request', 'consume'],
      twoFactor: [
        'enable',
        'confirm',
        'disable',
        'regenerateRecoveryCodes',
        'remainingRecoveryCodes',
        'challenge',
      ],
      passkeys: [
        'registrationOptions',
        'register',
        'authenticationOptions',
        'authenticate',
        'list',
        'rename',
        'remove',
      ],
      tokens: ['create', 'list', 'revoke'],
      teams: [
        'create',
        'list',
        'switch',
        'invite',
        'invitations',
        'revokeInvitation',
        'accept',
        'members',
        'changeRole',
        'removeMember',
      ],
      impersonation: ['start', 'stop'],
    } as const
    for (const [service, methods] of Object.entries(services)) {
      const target = h.auth[service as keyof typeof services] as unknown as Record<
        string,
        (r: unknown, i: unknown) => Promise<unknown>
      >
      for (const method of methods) {
        const fn = target[method]
        if (!fn) throw new Error(`${service}.${method} missing`)
        await rejectsWith(() => fn(req, { mode: 'passwordless' }), 'not_found')
      }
    }
    expect(await h.auth.tokens.authenticate('Bearer svp_x')).toBeUndefined()
    expect(await h.auth.teams.current(req)).toBeNull()
  })
})

describe('HTTP adapter', () => {
  it('signs in over HTTP, sets an HttpOnly SameSite=Lax cookie, and serves /user', async () => {
    const h = harness({ config: { appUrl: 'https://app.example.com' } })
    await h.user()
    const handle = createAuthHandler(h.auth)
    const https = (m: string, p: string, init: Parameters<typeof request>[2] = {}) =>
      new Request(`https://app.example.com${p}`, request(m, p, init))
    const login = await handle(
      https('POST', '/login', { body: { email: 'ada@acme.test', password: PASSWORD } }),
      { ip: '192.0.2.1' },
    )
    expect(login.status).toBe(200)
    const setCookie = login.headers.getSetCookie()[0] ?? ''
    expect(setCookie).toMatch(
      /^__Host-strutvane_session=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; SameSite=Lax; Secure$/,
    )
    expect(login.headers.get('cache-control')).toBe('no-store')
    const me = await handle(https('GET', '/user', { cookie: cookiesOf(login) }), {
      ip: '192.0.2.1',
    })
    expect(((await me.json()) as { user: { email: string } }).user.email).toBe('ada@acme.test')
    const out = await handle(https('POST', '/logout', { cookie: cookiesOf(login) }), {
      ip: '192.0.2.1',
    })
    expect(out.status).toBe(204)
    expect(out.headers.getSetCookie()[0]).toMatch(/Max-Age=0/)
  })

  it('maps errors to RFC 9457 problems with Retry-After', async () => {
    const h = harness()
    const handle = createAuthHandler(h.auth)
    let last: Response | undefined
    for (let i = 0; i < 11; i++)
      last = await handle(
        request('POST', '/login', {
          body: { email: `x${i}@acme.test`, password: 'wrong password!' },
        }),
        { ip: '192.0.2.1' },
      )
    expect(last?.status).toBe(429)
    expect(last?.headers.get('content-type')).toBe('application/problem+json')
    expect(Number(last?.headers.get('retry-after'))).toBeGreaterThan(0)
    expect(await last?.json()).toEqual({
      type: 'about:blank',
      title: 'Too many attempts. Please try again later.',
      status: 429,
      code: 'rate_limited',
    })
  })

  it('refuses cross-site unsafe requests (cross-site, same-site, Origin null) and non-JSON bodies', async () => {
    const h = harness()
    await h.user()
    const handle = createAuthHandler(h.auth)
    const body = { email: 'ada@acme.test', password: PASSWORD }
    for (const headers of [
      { 'sec-fetch-site': 'cross-site' },
      { 'sec-fetch-site': 'same-site' },
      { 'sec-fetch-site': '', origin: 'null' },
    ]) {
      const req = request('POST', '/login', { body, headers })
      if (headers['sec-fetch-site'] === '') req.headers.delete('sec-fetch-site')
      expect((await handle(req, { ip: '192.0.2.1' })).status).toBe(403)
    }
    const noHeaders = new Request(`${APP}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: APP },
      body: JSON.stringify(body),
    })
    expect((await handle(noHeaders, { ip: '192.0.2.1' })).status).toBe(200)
    const plain = request('POST', '/login', { body, headers: { 'content-type': 'text/plain' } })
    expect((await handle(plain, { ip: '192.0.2.1' })).status).toBe(422)
    const huge = request('POST', '/login', {
      body: { email: 'a@b.io', password: 'x'.repeat(20_000) },
    })
    expect((await handle(huge, { ip: '192.0.2.1' })).status).toBe(422)
    const array = request('POST', '/login', { body: [body] })
    expect((await handle(array, { ip: '192.0.2.1' })).status).toBe(422)
  })

  it('a bearer route never falls back to the session cookie', async () => {
    const h = harness({ config: { features: { apiTokens: true } } })
    await h.user()
    const handle = createAuthHandler(h.auth)
    const login = await handle(
      request('POST', '/login', { body: { email: 'ada@acme.test', password: PASSWORD } }),
      { ip: '192.0.2.1' },
    )
    const cookie = cookiesOf(login)
    expect((await handle(request('GET', '/api/me', { cookie }), { ip: '192.0.2.1' })).status).toBe(
      401,
    )
    const created = await handle(
      request('POST', '/user/api-tokens', { cookie, body: { name: 'cli' } }),
      { ip: '192.0.2.1' },
    )
    const { plainText } = (await created.json()) as { plainText: string }
    const me = await handle(
      request('GET', '/api/me', { headers: { authorization: `Bearer ${plainText}` } }),
      { ip: '192.0.2.1' },
    )
    expect(me.status).toBe(200)
  })

  it('cookie header parsing keeps the first occurrence (no shadowing by a later duplicate)', () => {
    expect(parseCookieHeader('a=1; a=2; b=3; junk; =x').get('a')).toBe('1')
    expect(parseCookieHeader(null).size).toBe(0)
  })
})

describe('node:http server', () => {
  let close: (() => Promise<void>) | undefined
  afterEach(async () => {
    await close?.()
    close = undefined
  })

  it('serves real requests, and a forged X-Forwarded-For from an untrusted peer cannot rotate the IP limit', async () => {
    const h = harness()
    await h.user()
    const server = createAuthServer(h.auth, { trustedProxies: [] })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    close = () => new Promise<void>((resolve) => server.close(() => resolve()))
    const { port } = server.address() as AddressInfo
    const post = (i: number) =>
      fetch(`http://127.0.0.1:${port}/login`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'sec-fetch-site': 'same-origin',
          'x-forwarded-for': `10.0.${i}.1`,
        },
        body: JSON.stringify({ email: `x${i}@acme.test`, password: 'wrong password!' }),
      })
    for (let i = 0; i < 10; i++) expect((await post(i)).status).toBe(422)
    expect((await post(99)).status).toBe(429)
  })

  it('resolves the client IP through trusted proxies only', () => {
    const trusted = trustedProxies(['10.0.0.0/8', '::1'])
    expect(clientIp('203.0.113.9', '1.2.3.4', trusted)).toBe('203.0.113.9')
    expect(clientIp('10.1.1.1', '198.51.100.7, 10.2.2.2', trusted)).toBe('198.51.100.7')
    expect(clientIp('10.1.1.1', 'garbage, 10.2.2.2', trusted)).toBe('10.1.1.1')
    expect(clientIp('::ffff:10.1.1.1', '', trusted)).toBe('10.1.1.1')
    expect(clientIp(undefined, '1.2.3.4', trusted)).toBeUndefined()
    expect(() => trustedProxies(['not-an-ip'])).toThrow()
  })
})
