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
  // Tests that sign up opt in to public registration (it is off by default). Passing a key as
  // `undefined` removes it, so a test can model a config/auth.ts that omits the key entirely.
  const auth: Record<string, unknown> = {
    registration: true,
    seedAdmin: { email: 'Admin@App.test', password: ADMIN_PASSWORD, role: 'admin' },
    session: { idleMinutes: 60 },
    ...options.auth,
  }
  for (const [key, value] of Object.entries(auth)) if (value === undefined) delete auth[key]
  const app = createApp({
    config: {
      app: { root, url: 'http://localhost:3000' },
      api: { prefix: '/api', version: 'v1' },
      auth,
      ...(options.tenancy ? { tenancy: options.tenancy } : {}),
    },
    providers: [createAuthProvider()],
  })
  await app.boot()
  const hooks = app.make(HooksToken)
  const send = async (
    method: string,
    path: string,
    init: {
      body?: string
      cookie?: string
      headers?: Record<string, string>
      clientAddress?: string
    } = {},
  ) => {
    const headers = new Headers({ origin: 'http://localhost:3000', ...init.headers })
    if (init.body !== undefined) headers.set('content-type', 'application/json')
    if (init.cookie) headers.set('cookie', init.cookie)
    const request = new Request(`http://localhost:3000${path}`, {
      method,
      headers,
      ...(init.body !== undefined ? { body: init.body } : {}),
    })
    return (await hooks.run('http.onRequest', {
      request,
      actor: null,
      tenant: undefined,
      ...(init.clientAddress !== undefined ? { clientAddress: init.clientAddress } : {}),
    })) as {
      actor: Actor | null
      response?: Response
      headers?: Headers
      tenant?: { id: string }
    }
  }
  /** Send a hand-built request (streams, odd headers) through the hook. */
  const raw = async (request: Request) =>
    (await hooks.run('http.onRequest', { request, actor: null, tenant: undefined })) as {
      response?: Response
    }
  return { app, send, raw }
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

  test('refuses sign-up when config/auth.ts omits registration (deny by default)', async () => {
    const { app, send } = await boot({ auth: { registration: undefined } })
    expect(app.config('auth')).not.toHaveProperty('registration')
    const refused = await send('POST', '/api/v1/auth/sign-up', {
      body: JSON.stringify({ email: 'x@app.test', password: 'a-long-enough-password', name: 'X' }),
    })
    expect(refused.response?.status).toBe(403)
    expect(await refused.response?.json()).toMatchObject({ code: 'FORBIDDEN', status: 403 })
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

  test('with tenancy on, a tenant header from a user is ignored; tenant endpoints work', async () => {
    const { send } = await boot({ tenancy: { enabled: true, strategy: 'shared' } })
    const ok = await send('POST', '/api/v1/auth/sign-in', {
      body: JSON.stringify({ email: 'admin@app.test', password: ADMIN_PASSWORD }),
    })
    const cookie = cookieOf(ok.response)
    const other = await send('GET', '/api/v1/invoices', {
      cookie,
      headers: { 'x-tenant-id': '0190a000-0000-7000-8000-00000000000b' },
    })
    expect(other.response).toBeUndefined()
    expect(other.tenant).toBeUndefined()

    const created = await send('POST', '/api/v1/auth/tenants', {
      cookie,
      body: JSON.stringify({ name: 'Acme', slug: 'acme' }),
    })
    expect(created.response?.status).toBe(201)
    const tenant = (await created.response?.json()) as { tenantId: string; roles: string[] }
    expect(tenant.roles).toEqual(['owner'])
    // Creating a tenant changes privileges, so the session token rotates.
    const ownerCookie = cookieOf(created.response)
    expect(ownerCookie).toMatch(/^sv_session=/)
    expect(ownerCookie).not.toBe(cookie)
    expect((await send('GET', '/api/v1/auth/me', { cookie })).response?.status).toBe(401)
    const dup = await send('POST', '/api/v1/auth/tenants', {
      cookie: ownerCookie,
      body: JSON.stringify({ name: 'Acme', slug: 'acme' }),
    })
    expect(dup.response?.status).toBe(422)
    const listed = await send('GET', '/api/v1/auth/tenants', { cookie: ownerCookie })
    expect(await listed.response?.json()).toMatchObject({ data: [{ slug: 'acme' }] })
    expect((await send('GET', '/api/v1/auth/tenants')).response?.status).toBe(401)
    const switched = await send('POST', '/api/v1/auth/switch-tenant', {
      cookie: ownerCookie,
      body: JSON.stringify({ tenantId: tenant.tenantId }),
    })
    expect(await switched.response?.json()).toMatchObject({
      actor: { tenantId: tenant.tenantId, roles: ['owner'] },
    })
    // Switching rotates the session (fixation defence): use the new cookie.
    const rotated = cookieOf(switched.response) || ownerCookie
    const scoped = await send('GET', '/api/v1/invoices', { cookie: rotated })
    expect(scoped.tenant?.id).toBe(tenant.tenantId)
    expect(scoped.actor?.roles).toEqual(['owner'])
    const foreign = await send('POST', '/api/v1/auth/switch-tenant', {
      cookie: rotated,
      body: JSON.stringify({ tenantId: '0190a000-0000-7000-8000-00000000000c' }),
    })
    expect(foreign.response?.status).toBe(403)
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

describe('provider hardening (attack classes)', () => {
  const signIn = (password = 'wrong-password-123') =>
    JSON.stringify({ email: 'admin@app.test', password })

  test('anonymous request cannot select a tenant by header', async () => {
    const { send } = await boot({ tenancy: { enabled: true, strategy: 'shared' } })
    const out = await send('GET', '/api/v1/invoices', {
      headers: { 'x-tenant-id': '0190a000-0000-7000-8000-00000000000b' },
    })
    expect(out.response).toBeUndefined()
    expect(out.actor).toBeNull()
    expect(out.tenant).toBeUndefined()
  })

  test('per-IP sign-in limit is keyed by the hook clientAddress (socket peer), not headers', async () => {
    const { send } = await boot()
    const statuses: number[] = []
    for (let i = 0; i < 11; i++) {
      const r = await send('POST', '/api/v1/auth/sign-in', {
        body: signIn(),
        clientAddress: '203.0.113.50',
        // A forged header must not rotate the key.
        headers: { 'x-forwarded-for': `198.51.100.${i}` },
      })
      statuses.push(r.response?.status ?? 0)
    }
    expect(statuses.slice(0, 10).every((s) => s === 401)).toBe(true)
    expect(statuses[10]).toBe(429)
    const other = await send('POST', '/api/v1/auth/sign-in', {
      body: signIn(),
      clientAddress: '203.0.113.51',
    })
    expect(other.response?.status).toBe(401)
  })

  test('without a clientAddress the per-IP limit is not skipped (shared fallback bucket)', async () => {
    const { send } = await boot()
    let last = 0
    for (let i = 0; i < 11; i++)
      last = (await send('POST', '/api/v1/auth/sign-in', { body: signIn() })).response?.status ?? 0
    expect(last).toBe(429)
  })

  test('the seed admin email alone grants nothing to whoever registers it', async () => {
    const { send } = await boot({
      auth: { seedAdmin: { email: 'boss@app.test', role: 'admin' } },
    })
    const up = await send('POST', '/api/v1/auth/sign-up', {
      body: JSON.stringify({
        email: 'boss@app.test',
        password: 'a-long-enough-password',
        name: 'B',
      }),
    })
    expect(up.response?.status).toBe(201)
    expect(await up.response?.json()).toMatchObject({ actor: { roles: [] } })
  })

  test('a seed admin that cannot be created fails the boot', async () => {
    await expect(
      boot({ auth: { seedAdmin: { email: 'admin@app.test', password: 'short', role: 'admin' } } }),
    ).rejects.toThrow(/seed admin/)
  })

  test('state-changing auth endpoints refuse cross-site requests', async () => {
    const { send } = await boot({ auth: { trustedOrigins: ['https://spa.example.com'] } })
    const crossOrigin = await send('POST', '/api/v1/auth/sign-in', {
      body: signIn(ADMIN_PASSWORD),
      headers: { origin: 'https://evil.example' },
    })
    expect(crossOrigin.response?.status).toBe(403)
    const nullOrigin = await send('POST', '/api/v1/auth/sign-up', {
      body: '{}',
      headers: { origin: 'null' },
    })
    expect(nullOrigin.response?.status).toBe(403)
    const fetchSite = await send('POST', '/api/v1/auth/sign-out', {
      headers: { 'sec-fetch-site': 'cross-site' },
    })
    expect(fetchSite.response?.status).toBe(403)
    const trusted = await send('POST', '/api/v1/auth/sign-in', {
      body: signIn(ADMIN_PASSWORD),
      headers: { origin: 'https://spa.example.com' },
    })
    expect(trusted.response?.status).toBe(200)
    // GET endpoints are not state-changing.
    const me = await send('GET', '/api/v1/auth/me', { headers: { origin: 'https://evil.example' } })
    expect(me.response?.status).toBe(401)
    await expect(boot({ auth: { trustedOrigins: ['not a url'] } })).rejects.toThrow(
      /trusted origin/,
    )
  })

  test('JSON endpoints require application/json (no text/plain form posts)', async () => {
    const { raw } = await boot()
    const form = await raw(
      new Request('http://localhost:3000/api/v1/auth/sign-in', {
        method: 'POST',
        headers: { 'content-type': 'text/plain' },
        body: signIn(ADMIN_PASSWORD),
      }),
    )
    expect(form.response?.status).toBe(415)
    const charset = await raw(
      new Request('http://localhost:3000/api/v1/auth/sign-in', {
        method: 'POST',
        headers: { 'content-type': 'Application/JSON; charset=utf-8' },
        body: signIn(ADMIN_PASSWORD),
      }),
    )
    expect(charset.response?.status).toBe(200)
  })

  test('an unbounded chunked body is aborted at 16 KiB without buffering it', async () => {
    const { raw } = await boot()
    let produced = 0
    let cancelled = false
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        produced += 4096
        controller.enqueue(new Uint8Array(4096).fill(0x20))
      },
      cancel() {
        cancelled = true
      },
    })
    const init = {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
      duplex: 'half',
    } as RequestInit
    const out = await raw(new Request('http://localhost:3000/api/v1/auth/sign-in', init))
    expect(out.response?.status).toBe(413)
    expect(cancelled).toBe(true)
    expect(produced).toBeLessThanOrEqual(16 * 1024 + 2 * 4096)
  })

  test('invalid UTF-8 and empty bodies are malformed requests', async () => {
    const { raw } = await boot()
    const bad = await raw(
      new Request('http://localhost:3000/api/v1/auth/sign-in', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: new Uint8Array([0x7b, 0xff, 0xfe, 0x7d]),
      }),
    )
    expect(bad.response?.status).toBe(400)
    const empty = await raw(
      new Request('http://localhost:3000/api/v1/auth/sign-in', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
      }),
    )
    expect(empty.response?.status).toBe(400)
  })
})

describe('role map from config/auth.ts', () => {
  const roles = {
    admin: { permissions: ['*', { action: 'user.update', scope: 'global' }] },
    member: { permissions: ['*.viewAny', '*.view', { action: '*.update', own: true }] },
    owner: { scope: 'tenant', permissions: ['*', 'customer.viewAny'] },
  }

  test('role grants combine with app/policies (deny-by-default stays for everything else)', async () => {
    const { app } = await boot({ auth: { roles, wildcardExclude: ['user'] } })
    const permissions = app.make(PermissionProviderToken)
    const admin: Actor = { id: 'a', type: 'user', roles: ['admin'], attrs: {} }
    const member: Actor = { id: 'm', type: 'user', roles: ['member'], attrs: {} }
    // The policy alone denies invoice.update to admin; the role map's '*' allows it.
    expect((await permissions.can(admin, 'invoice.update')).allowed).toBe(true)
    // No policy for customer: the role map alone decides.
    expect((await permissions.can(admin, 'customer.export')).allowed).toBe(true)
    expect((await permissions.can(member, 'customer.viewAny')).allowed).toBe(true)
    // invoice's schema has no ownerId: the own grant never matches.
    expect(
      (await permissions.can(member, 'invoice.update', { type: 'invoice', record: { id: 'x' } }))
        .allowed,
    ).toBe(false)
    // user is wildcard-excluded: only the exact, global grant.
    expect((await permissions.can(admin, 'user.delete')).allowed).toBe(false)
    expect((await permissions.can(admin, 'user.update')).allowed).toBe(true)
    expect((await permissions.can({ ...admin, tenantId: 't1' }, 'user.update')).allowed).toBe(false)
    expect(await permissions.filterableFields?.(admin, 'invoice')).toEqual(new Set(['id']))
  })

  test('without roles nothing changes: the seed admin gets nothing the policies do not allow', async () => {
    const { app } = await boot()
    const permissions = app.make(PermissionProviderToken)
    const admin: Actor = { id: 'a', type: 'user', roles: ['admin'], attrs: {} }
    expect((await permissions.can(admin, 'invoice.update')).allowed).toBe(false)
    expect((await permissions.can(admin, 'customer.viewAny')).reason).toBe('default-deny:no-policy')
  })

  test('a tenant creator holds owner, which the role map grants inside that tenant only', async () => {
    const { app, send } = await boot({
      auth: { roles },
      tenancy: { enabled: true, strategy: 'shared' },
    })
    const signUp = await send('POST', '/api/v1/auth/sign-up', {
      body: JSON.stringify({
        email: 'founder@app.test',
        password: 'founder-password-123',
        name: 'F',
      }),
    })
    const cookie = cookieOf(signUp.response)
    const created = await send('POST', '/api/v1/auth/tenants', {
      body: JSON.stringify({ name: 'Acme', slug: 'acme' }),
      cookie,
    })
    expect(created.response?.status).toBe(201)
    const tenant = (await created.response?.json()) as { tenantId: string }
    const tenantId = tenant.tenantId
    const switched = await send('POST', '/api/v1/auth/switch-tenant', {
      body: JSON.stringify({ tenantId }),
      cookie: cookieOf(created.response),
    })
    const body = (await switched.response?.json()) as { actor: Actor }
    const actor = body.actor
    expect(actor).toMatchObject({ roles: ['owner'], tenantId })
    const permissions = app.make(PermissionProviderToken)
    const full: Actor = { ...actor, attrs: {} }
    // invoice's schema has no tenantId column: a tenant wildcard never reaches it.
    expect((await permissions.can(full, 'invoice.viewAny')).allowed).toBe(false)
    // An exact grant is deliberate: it counts inside the tenant, and never outside (scope tenant).
    expect((await permissions.can(full, 'customer.viewAny')).allowed).toBe(true)
    const { tenantId: _t, ...outside } = full
    expect((await permissions.can(outside, 'customer.viewAny')).allowed).toBe(false)
  })

  test.each([
    [{ roles: { member: { permissions: [{ action: '*.update', onw: true }] } } }, /onw/],
    [{ roles: { Admin: { permissions: ['*'] } } }, /invalid role name/],
    [{ newModelDefaults: 'admin-only', roles: { m: { permissions: ['*.view'] } } }, /admin-only/],
    [{ wildcardExclude: ['user'], roles: { a: { permissions: ['user.*'] } } }, /by name/],
  ])('a malformed role map fails the boot (%#)', async (auth, message) => {
    await expect(boot({ auth })).rejects.toThrow(message)
  })
})
