// Feature switches are explicit: everything optional is off unless config/auth.ts turns it on,
// and a feature that is off (or teams without tenancy) leaves no route behind: its paths answer
// exactly the bytes an unknown path answers.
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, HooksToken } from '@strutvane/framework/core'
import fc from 'fast-check'
import { afterEach, describe, expect, test } from 'vitest'
import type { AuthConfig } from '../src/config.ts'
import { listAuthRoutes } from '../src/engine/http/routes.ts'
import { engineConfigFrom, FEATURE_KEYS, resolveFeatures } from '../src/identity/engine-config.ts'
import { createNativeEngine } from '../src/identity/native.ts'
import { createAuthProvider } from '../src/provider.ts'

const URL_ = 'http://localhost:3000'
const dirs: string[] = []
afterEach(async () => {
  for (const d of dirs.splice(0)) await rm(d, { recursive: true, force: true })
})

/** The defaults when config/auth.ts says nothing: password sign-in and confirmation only. */
const ALL_OFF = Object.freeze({
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
})

/** Every engine route, as the engine knows it (independent of which features are on). */
const ROUTES = listAuthRoutes(
  createNativeEngine({ baseURL: URL_, deliverPasswordReset: async () => undefined }).auth,
)

async function boot(auth: Record<string, unknown>, tenancy = false) {
  const root = await mkdtemp(join(tmpdir(), 'sv-auth-features-'))
  dirs.push(root)
  const app = createApp({
    config: {
      app: { root, url: URL_ },
      api: { prefix: '/api', version: 'v1' },
      auth,
      ...(tenancy ? { tenancy: { enabled: true } } : {}),
    },
    providers: [createAuthProvider()],
  })
  await app.boot()
  const hooks = app.make(HooksToken)
  const send = async (method: string, path: string) => {
    const hasBody = method !== 'GET' && method !== 'DELETE'
    const request = new Request(`${URL_}/api/v1/auth${path}`, {
      method,
      headers: {
        origin: URL_,
        'sec-fetch-site': 'same-origin',
        ...(hasBody ? { 'content-type': 'application/json' } : {}),
      },
      ...(hasBody ? { body: '{}' } : {}),
    })
    const out = (await hooks.run('http.onRequest', {
      request,
      actor: null,
      tenant: undefined,
      clientAddress: '203.0.113.20',
    })) as { response?: Response }
    const response = out.response
    if (!response) throw new Error(`${method} ${path}: no answer from the auth provider`)
    return {
      status: response.status,
      type: response.headers.get('content-type'),
      cookies: response.headers.getSetCookie(),
      body: await response.text(),
    }
  }
  return { app, send }
}

/** `/teams/:team/members/:user` → a concrete path. */
const concrete = (path: string) => path.replace(/:[a-z]+/g, '0190f2a0-0000-7000-8000-00000000000a')

describe('features default to off', () => {
  test.each([
    ['nothing set', {}],
    ['only a role map', { roles: { admin: { permissions: ['*'] } } }],
    ['one feature', { features: { twoFactor: true } }],
    ['teams without tenancy', { features: { teams: true } }],
  ])(
    '%s: every switched-off route answers the unknown-path 404, byte for byte',
    async (_n, auth) => {
      const cfg = auth as AuthConfig
      const { send } = await boot(auth)
      const unknown = await send('POST', '/no-such-route')
      expect(unknown.status).toBe(404)
      const features: Record<string, boolean> = { ...resolveFeatures(cfg, { tenancy: false }) }
      features['passwordReset'] = features['password'] === true
      // Without tenancy the team routes never exist, whatever features.teams says.
      features['teams'] = false
      const off = ROUTES.filter((r) => r.feature !== undefined && features[r.feature] !== true)
      expect(off.some((r) => r.path === '/register')).toBe(true)
      expect(off.some((r) => r.path.startsWith('/teams'))).toBe(true)
      for (const route of off) {
        const got = await send(route.method, concrete(route.path))
        expect(got, `${route.method} ${route.path}`).toEqual(
          await send(route.method, '/no-such-route'),
        )
      }
    },
  )

  test('the engine applies exactly what it is given: no feature is switched on below the config', () => {
    const engine = createNativeEngine({
      baseURL: URL_,
      deliverPasswordReset: async () => undefined,
    })
    expect(engine.auth.config.features).toEqual({ ...ALL_OFF, passwordReset: true })
  })

  test('registration needs an explicit true; teams need tenancy or an explicit true', () => {
    const f = (cfg: Record<string, unknown>, tenancy = false) =>
      resolveFeatures(cfg as AuthConfig, { tenancy })
    expect(f({}).registration).toBe(false)
    expect(f({ registration: true }).registration).toBe(true)
    expect(f({ features: { registration: true } }).registration).toBe(true)
    // A JavaScript config may hold anything: only the boolean true switches a feature on.
    expect(f({ registration: 'true', features: { registration: 1 } }).registration).toBe(false)
    expect(f({ features: { twoFactor: 'yes' } }).twoFactor).toBe(false)
    expect(f({}).teams).toBe(false)
    expect(f({}, true).teams).toBe(true)
    expect(f({ features: { teams: true } }).teams).toBe(true)
    expect(f({ features: { password: false } }).password).toBe(false)
  })

  test('property: the effective features are the all-off defaults plus exactly what was set', () => {
    const optional = FEATURE_KEYS.filter((k) => k !== 'password' && k !== 'passwordConfirmation')
    fc.assert(
      fc.property(
        fc.subarray([...optional]),
        fc.subarray([...optional]),
        fc.boolean(),
        (on, off, tenancy) => {
          const features: Record<string, boolean> = {}
          for (const k of off) features[k] = false
          for (const k of on) features[k] = true
          const cfg = { features } as AuthConfig
          const expected: Record<string, boolean> = { ...ALL_OFF, ...features }
          if (tenancy) expected['teams'] = true
          // Every key is explicit in what the engine receives.
          const given = engineConfigFrom(cfg, { tenancy }).features
          expect(Object.keys(given ?? {}).sort()).toEqual([...FEATURE_KEYS].sort())
          expect(given).toEqual(expected)
          expect(resolveFeatures(cfg, { tenancy })).toEqual(expected)
        },
      ),
      { numRuns: 300 },
    )
  })
})
