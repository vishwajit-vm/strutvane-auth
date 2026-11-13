// The Strutvane provider: policies → PermissionProviderToken, actor resolution and the auth
// endpoints, driven through core hooks exactly as framework's createHttpApp drives them.
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import type { Actor } from '@strutvane/contracts'
import { createApp, HooksToken, PermissionProviderToken } from '@strutvane/core'
import { afterEach, describe, expect, test } from 'vitest'
import { createNativeEngine } from '../src/identity/native.ts'
import provider, { apiBase, createAuthProvider, loadPolicies } from '../src/provider.ts'

const AUTH_SRC = pathToFileURL(resolve(import.meta.dirname, '../src/index.ts')).href
const ADMIN_PASSWORD = 'seed-admin-password-for-tests-only'
const dirs: string[] = []
afterEach(async () => {
  for (const d of dirs.splice(0)) await rm(d, { recursive: true, force: true })
})

const POLICY = `import { definePolicy, defineSchema } from '${AUTH_SRC}'
const schema = defineSchema({ table: 'invoices', columns: { id: { column: 'id', type: 'uuid' } } })
export default definePolicy('invoice', { schema }, ({ allow }) => {
  allow(['viewAny', 'view'], { role: ['member', 'admin'] })
  allow('create', { role: 'admin' })
})
`

async function projectWith(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'sv-auth-'))
  dirs.push(root)
  for (const [path, content] of Object.entries(files)) {
    await mkdir(join(root, path, '..'), { recursive: true })
    await writeFile(join(root, path), content)
  }
  return root
}

async function boot(
  options: { auth?: Record<string, unknown>; tenancy?: Record<string, unknown> } = {},
) {
  const root = await projectWith({ 'app/policies/invoice.policy.ts': POLICY })
  const app = createApp({
    config: {
      app: { root, url: 'http://localhost:3000' },
      api: { prefix: '/api', version: 'v1' },
      auth: {
        registration: true,
        seedAdmin: { email: 'Admin@App.test', password: ADMIN_PASSWORD, role: 'admin' },
        session: { idleMinutes: 60 },
        ...options.auth,
      },
      ...(options.tenancy ? { tenancy: options.tenancy } : {}),
    },
    providers: [createAuthProvider()],
  })
  await app.boot()
  const hooks = app.make(HooksToken)
  const send = async (
    method: string,
    path: string,
    init: { body?: string; cookie?: string; headers?: Record<string, string> } = {},
  ) => {
    const headers = new Headers({ origin: 'http://localhost:3000', ...init.headers })
    if (init.body !== undefined) headers.set('content-type', 'application/json')
    if (init.cookie) headers.set('cookie', init.cookie)
    const request = new Request(`http://localhost:3000${path}`, {
      method,
      headers,
      ...(init.body !== undefined ? { body: init.body } : {}),
    })
    return (await hooks.run('http.onRequest', { request, actor: null, tenant: undefined })) as {
      actor: Actor | null
      response?: Response
      headers?: Headers
      tenant?: { id: string }
    }
  }
  return { app, send }
}

const cookieOf = (r: Response | undefined): string =>
  (r?.headers.get('set-cookie') ?? '').split(';')[0] ?? ''

describe('@strutvane/auth/provider', () => {
  test('exports a ready provider; apiBase mirrors the framework rule', () => {
    expect(provider.name).toBe('@strutvane/auth')
    expect(apiBase(undefined)).toBe('/api/v1')
    expect(apiBase({ prefix: 'api/', version: '/v2' })).toBe('/api/v2')
  })

  test('binds a deny-by-default PermissionProvider from app/policies', async () => {
    const { app } = await boot()
    const permissions = app.make(PermissionProviderToken)
    const member: Actor = { id: 'u', type: 'user', roles: ['member'], attrs: {} }
    expect((await permissions.can(member, 'invoice.viewAny')).allowed).toBe(true)
    expect((await permissions.can(member, 'invoice.create')).allowed).toBe(false)
    expect((await permissions.can(member, 'customer.viewAny')).allowed).toBe(false)
  })

  test('PermissionProviderToken cannot be resolved before boot', () => {
    const app = createApp({ config: {}, providers: [createAuthProvider()] })
    createAuthProvider().register(app)
    expect(() => app.make(PermissionProviderToken)).toThrow(/after boot/)
  })

  test('the seed admin signs in, gets the admin role, and is resolved on later requests', async () => {
    const { send } = await boot()
    const bad = await send('POST', '/api/v1/auth/sign-in', {
      body: JSON.stringify({ email: 'admin@app.test', password: 'wrong-password-123' }),
    })
    expect(bad.response?.status).toBe(401)
    const ok = await send('POST', '/api/v1/auth/sign-in', {
      body: JSON.stringify({ email: 'admin@app.test', password: ADMIN_PASSWORD }),
    })
    expect(ok.response?.status).toBe(200)
    const cookie = cookieOf(ok.response)
    expect(cookie).toMatch(/^sv_session=/)
    expect(await ok.response?.json()).toMatchObject({ actor: { roles: ['admin'] } })

    const me = await send('GET', '/api/v1/auth/me', { cookie })
    expect(await me.response?.json()).toMatchObject({ actor: { roles: ['admin'] } })
    const resolved = await send('GET', '/api/v1/invoices', { cookie })
    expect(resolved.response).toBeUndefined()
    expect(resolved.actor?.roles).toEqual(['admin'])

    const out = await send('POST', '/api/v1/auth/sign-out', { cookie })
    expect(out.response?.status).toBe(204)
    expect((await send('GET', '/api/v1/auth/me', { cookie })).response?.status).toBe(401)
    expect((await send('GET', '/api/v1/invoices', { cookie })).actor).toBeNull()
  })

  test('sign-up gets defaultRoles (none unless configured) and can be turned off', async () => {
    const open = await boot({ auth: { defaultRoles: ['member'] } })
    const up = await open.send('POST', '/api/v1/auth/sign-up', {
      body: JSON.stringify({
        email: 'new@app.test',
        password: 'a-long-enough-password',
        name: 'New',
      }),
    })
    expect(up.response?.status).toBe(201)
    expect(await up.response?.json()).toMatchObject({ actor: { roles: ['member'] } })

    const closed = await boot({ auth: { registration: false } })
    const refused = await closed.send('POST', '/api/v1/auth/sign-up', {
      body: JSON.stringify({ email: 'x@app.test', password: 'a-long-enough-password', name: 'X' }),
    })
    expect(refused.response?.status).toBe(403)
  })

  test('rejects malformed and oversized bodies and unknown auth routes', async () => {
    const { send } = await boot()
    expect((await send('POST', '/api/v1/auth/sign-in', { body: '{' })).response?.status).toBe(400)
    expect((await send('POST', '/api/v1/auth/sign-in', { body: '[1]' })).response?.status).toBe(400)
    const big = JSON.stringify({ email: 'a@b.test', password: 'x'.repeat(20_000) })
    expect((await send('POST', '/api/v1/auth/sign-in', { body: big })).response?.status).toBe(413)
    const lying = await send('POST', '/api/v1/auth/sign-in', {
      body: '{}',
      headers: { 'content-length': '99999' },
    })
    expect(lying.response?.status).toBe(413)
    expect((await send('GET', '/api/v1/auth/nope')).response?.status).toBe(404)
  })

  test('with tenancy on, a tenant header from a non-member is refused', async () => {
    const { send } = await boot({ tenancy: { enabled: true, strategy: 'shared' } })
    const ok = await send('POST', '/api/v1/auth/sign-in', {
      body: JSON.stringify({ email: 'admin@app.test', password: ADMIN_PASSWORD }),
    })
    const cookie = cookieOf(ok.response)
    const other = await send('GET', '/api/v1/invoices', {
      cookie,
      headers: { 'x-tenant-id': '0190a000-0000-7000-8000-00000000000b' },
    })
    expect(other.response?.status).toBe(403)
  })

  test('loadPolicies: no folder means no policies; a wrong export names the file', async () => {
    expect(await loadPolicies(await projectWith({ 'README.md': '' }))).toEqual([])
    const bad = await projectWith({ 'app/policies/x.policy.ts': 'export default {}\n' })
    await expect(loadPolicies(bad)).rejects.toThrow(/x\.policy\.ts/)
  })
})

describe('native engine globalRoles', () => {
  test('applies outside tenants only and drops invalid role names (fail closed)', async () => {
    const engine = createNativeEngine({
      baseURL: 'http://localhost:3000',
      deliverPasswordReset: async () => {},
      scryptCost: 2 ** 14,
      globalRoles: ({ email }) => (email === 'boss@app.test' ? ['admin', 'Bad Role!'] : []),
    })
    const req = new Request('http://localhost:3000/x', {
      method: 'POST',
      headers: { origin: 'http://localhost:3000' },
    })
    const boss = await engine.signUp(
      { email: 'boss@app.test', password: 'a-long-enough-password', name: 'B' },
      req,
    )
    expect(boss.ok && boss.value.actor.roles).toEqual(['admin'])
    const other = await engine.signUp(
      { email: 'o@app.test', password: 'a-long-enough-password', name: 'O' },
      req,
    )
    expect(other.ok && other.value.actor.roles).toEqual([])
  })
})
