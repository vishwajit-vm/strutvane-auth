// The v2 provider: one source for the session cookie name (#105), the engine's own routes under
// {api}/auth, mail through AuthMailerToken, and auth's domain events on the framework event bus.
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SessionCookieToken, sessionCookieName } from '@strutvane/framework'
import { createApp, EventBusToken, HooksToken, LoggerToken } from '@strutvane/framework/core'
import { afterEach, describe, expect, test, vi } from 'vitest'
import type { AuthMail } from '../src/engine/ports/mailer.ts'
import { AUTH_DOMAIN_EVENTS, domainEventSink } from '../src/events.ts'
import { engineConfigFrom } from '../src/identity/engine-config.ts'
import { createAuthProvider } from '../src/provider.ts'
import { AuthMailerToken } from '../src/tokens.ts'

const dirs: string[] = []
afterEach(async () => {
  for (const d of dirs.splice(0)) await rm(d, { recursive: true, force: true })
})

const PASSWORD = 'seed-admin-password-for-tests-only'

async function boot(
  options: {
    url?: string
    session?: Record<string, unknown>
    auth?: Record<string, unknown>
    before?: (app: ReturnType<typeof createApp>) => void
  } = {},
) {
  const root = await mkdtemp(join(tmpdir(), 'sv-auth-v2-'))
  dirs.push(root)
  const url = options.url ?? 'http://localhost:3000'
  const app = createApp({
    config: {
      app: { root, url },
      api: { prefix: '/api', version: 'v1' },
      auth: {
        registration: true,
        seedAdmin: { email: 'admin@app.test', password: PASSWORD },
        ...options.auth,
      },
      ...(options.session ? { session: options.session } : {}),
    },
    providers: [createAuthProvider()],
  })
  options.before?.(app)
  await app.boot()
  const hooks = app.make(HooksToken)
  const send = async (method: string, path: string, body?: unknown, cookie?: string) => {
    const headers = new Headers({ origin: url, 'sec-fetch-site': 'same-origin' })
    if (body !== undefined) headers.set('content-type', 'application/json')
    if (cookie) headers.set('cookie', cookie)
    const request = new Request(`${url}${path}`, {
      method,
      headers,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    })
    const out = (await hooks.run('http.onRequest', {
      request,
      actor: null,
      tenant: undefined,
      clientAddress: '203.0.113.9',
    })) as { response?: Response; actor: { id: string } | null }
    return out
  }
  return { app, send }
}

const cookieOf = (r: Response | undefined): string =>
  (r?.headers.getSetCookie() ?? []).map((c) => c.split(';')[0] ?? '').join('; ')

describe('#105: one source for the session cookie name', () => {
  test('the provider binds SessionCookieToken; the engine sets exactly that cookie', async () => {
    const { app, send } = await boot({ session: { cookie: 'acme_session' } })
    expect(app.make(SessionCookieToken)).toMatchObject({
      name: 'acme_session',
      base: 'acme_session',
    })
    const signIn = await send('POST', '/api/v1/auth/sign-in', {
      email: 'admin@app.test',
      password: PASSWORD,
    })
    expect(signIn.response?.status).toBe(200)
    expect(cookieOf(signIn.response)).toMatch(/^acme_session=/)
  })

  test('on https both sides use the __Host- name', async () => {
    const { app } = await boot({ url: 'https://app.example.com' })
    expect(app.make(SessionCookieToken).name).toBe('__Host-strutvane_session')
  })

  test('a SessionCookieToken bound first is followed by the engine', async () => {
    const { send } = await boot({
      before: (app) =>
        app.container.value(
          SessionCookieToken,
          sessionCookieName({ base: 'other', secure: false }),
        ),
    })
    const signIn = await send('POST', '/api/v1/auth/sign-in', {
      email: 'admin@app.test',
      password: PASSWORD,
    })
    expect(cookieOf(signIn.response)).toMatch(/^other=/)
  })

  test('a bound name the engine cannot set fails the boot (the CSRF check would skip)', async () => {
    // A __Host- name on a plain-http app: the engine would set `other`, the check would look for
    // `__Host-other`.
    await expect(
      boot({
        before: (app) =>
          app.container.value(
            SessionCookieToken,
            sessionCookieName({ base: 'other', secure: true }),
          ),
      }),
    ).rejects.toThrow(/SessionCookieToken says "__Host-other"/)
  })
})

describe('the engine routes under {api}/auth', () => {
  test('Fortify-style routes answer; disabled features are a plain 404', async () => {
    const { send } = await boot()
    const login = await send('POST', '/api/v1/auth/login', {
      email: 'admin@app.test',
      password: PASSWORD,
    })
    expect(login.response?.status).toBe(200)
    expect(await login.response?.json()).toEqual({ status: 'signed-in' })
    const cookie = cookieOf(login.response)
    const user = await send('GET', '/api/v1/auth/user', undefined, cookie)
    expect(await user.response?.json()).toMatchObject({ user: { email: 'admin@app.test' } })
    const sessions = await send('GET', '/api/v1/auth/user/sessions', undefined, cookie)
    expect(sessions.response?.status).toBe(200)
    // Two-factor is off by default: its routes do not exist.
    const twoFactor = await send('POST', '/api/v1/auth/user/two-factor-authentication', {}, cookie)
    const unknown = await send('POST', '/api/v1/auth/no-such-route', {}, cookie)
    expect(twoFactor.response?.status).toBe(404)
    expect(await twoFactor.response?.text()).toBe(await unknown.response?.text())
  })

  test('features from config/auth.ts turn routes on', async () => {
    const { send } = await boot({ auth: { features: { twoFactor: true, apiTokens: true } } })
    const login = await send('POST', '/api/v1/auth/login', {
      email: 'admin@app.test',
      password: PASSWORD,
    })
    const cookie = cookieOf(login.response)
    // Sensitive settings need a fresh password confirmation (passwordConfirmation is on).
    const refused = await send('POST', '/api/v1/auth/user/two-factor-authentication', {}, cookie)
    expect(refused.response?.status).toBe(423)
    const confirmed = await send(
      'POST',
      '/api/v1/auth/user/confirm-password',
      { password: PASSWORD },
      cookie,
    )
    expect(confirmed.response?.status).toBe(204)
    const enable = await send('POST', '/api/v1/auth/user/two-factor-authentication', {}, cookie)
    expect(enable.response?.status).toBe(200)
    const tokens = await send('GET', '/api/v1/auth/user/api-tokens', undefined, cookie)
    expect(await tokens.response?.json()).toEqual([])
  })

  test('a body over 16 KiB is refused before the engine reads it', async () => {
    const { send } = await boot()
    const big = await send('POST', '/api/v1/auth/login', {
      email: 'a@b.test',
      password: 'x'.repeat(20_000),
    })
    expect(big.response?.status).toBe(413)
  })
})

describe('mail and domain events', () => {
  test('mail goes to AuthMailerToken; events reach the bus under their public names', async () => {
    const mails: AuthMail[] = []
    const events: string[] = []
    const { app, send } = await boot({
      before: (app) =>
        app.container.value(AuthMailerToken, { send: async (m) => void mails.push(m) }),
    })
    const bus = app.make(EventBusToken)
    for (const name of ['auth.user.registered', 'auth.login.failed', 'auth.login.succeeded'])
      bus.on(name, (e) => void events.push(`${e.type}:${e.actor ? 'actor' : 'anonymous'}`))
    await send('POST', '/api/v1/auth/sign-up', {
      email: 'ann@app.test',
      password: 'a-long-enough-password',
      name: 'Ann',
    })
    await send('POST', '/api/v1/auth/sign-in', {
      email: 'ann@app.test',
      password: 'wrong-wrong-wrong',
    })
    await send('POST', '/api/v1/auth/forgot-password', { email: 'ann@app.test' })
    await new Promise((r) => setTimeout(r, 50))
    expect(events).toEqual([
      'auth.user.registered:anonymous',
      // The new session's user is the actor of their own sign-in.
      'auth.login.succeeded:actor',
      'auth.login.failed:anonymous',
    ])
    expect(mails.map((m) => m.kind)).toContain('password-reset')
  })

  test('without a mailer, mails are dropped with a warning naming only the kind', async () => {
    const warnings: unknown[][] = []
    const { app, send } = await boot()
    vi.spyOn(app.make(LoggerToken), 'warn').mockImplementation((...args: unknown[]) => {
      warnings.push(args)
    })
    await send('POST', '/api/v1/auth/forgot-password', { email: 'admin@app.test' })
    await new Promise((r) => setTimeout(r, 50))
    const dropped = warnings.find((w) => String(w[0]).includes('no mailer is bound'))
    expect(dropped?.[1]).toEqual({ kind: 'password-reset' })
    expect(JSON.stringify(warnings)).not.toMatch(/reset-password\//)
  })

  test('the sink strips type, time and IP; tenant events carry the tenant; failures are logged', async () => {
    const emitted: { name: string; payload: unknown; options: unknown }[] = []
    const warned: unknown[][] = []
    const sink = domainEventSink(
      {
        emit: async (name, payload, options) => {
          if (name === 'auth.logout') throw new Error('bus down')
          emitted.push({ name, payload, options })
          return { event: {} as never, delivered: 1, errors: [] }
        },
      },
      { warn: (...args: unknown[]) => void warned.push(args) },
    )
    const base = { at: 1, ip: '203.0.113.9', actorId: 'admin-1', subjectId: 'u-1' }
    await sink.emit({ ...base, type: 'team.created', userId: 'u-1', teamId: 't-1' })
    await sink.emit({ ...base, actorId: null, type: 'registered', userId: 'u-1' })
    await sink.emit({ ...base, type: 'logout', userId: 'u-1' })
    expect(emitted).toEqual([
      {
        name: 'tenant.created',
        payload: { actorId: 'admin-1', subjectId: 'u-1', userId: 'u-1', teamId: 't-1' },
        options: { actor: { id: 'admin-1', type: 'user' }, tenantId: 't-1' },
      },
      {
        name: 'auth.user.registered',
        payload: { actorId: null, subjectId: 'u-1', userId: 'u-1' },
        options: {},
      },
    ])
    expect(warned).toEqual([['auth: publishing a domain event failed', { event: 'auth.logout' }]])
    // The integration map's names (§5).
    expect(AUTH_DOMAIN_EVENTS['login.failed']).toBe('auth.login.failed')
    expect(AUTH_DOMAIN_EVENTS['role.assigned']).toBe('auth.role.assigned')
  })
})

describe('engineConfigFrom: config/auth.ts → engine settings', () => {
  test('features, role names, idle minutes, personal teams and the cookie base', () => {
    expect(
      engineConfigFrom(
        {
          registration: true,
          features: { twoFactor: true },
          roles: {
            member: { scope: 'tenant', permissions: [] },
            viewer: { scope: 'any', permissions: [] },
          },
          session: { idleMinutes: 30 },
        },
        { tenancy: true, sessionCookie: 'acme_session' },
      ),
    ).toEqual({
      sessionCookie: 'acme_session',
      features: {
        password: true,
        registration: true,
        emailVerification: false,
        passwordConfirmation: true,
        twoFactor: true,
        passkeys: false,
        emailLink: false,
        apiTokens: false,
        teams: true,
        impersonation: false,
      },
      teams: { personal: false },
      roles: ['admin', 'viewer'],
      tenantRoles: ['owner', 'member', 'viewer'],
      sessions: { idleMinutes: 30 },
    })
    expect(
      engineConfigFrom(
        { rolePreset: 'admin-manager-member-viewer', teams: { personal: true } },
        { tenancy: false },
      ),
    ).toEqual({
      features: {
        password: true,
        registration: false,
        emailVerification: false,
        passwordConfirmation: true,
        twoFactor: false,
        passkeys: false,
        emailLink: false,
        apiTokens: false,
        teams: false,
        impersonation: false,
      },
      teams: { personal: true },
      roles: 'admin-manager-member-viewer',
    })
  })
})
