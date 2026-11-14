/** The framework-agnostic core plus the Hono and node:http adapters, over real HTTP where it matters. */
import { createServer, request, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import type { Actor } from '@strutvane/contracts'
import { currentContext } from '@strutvane/core'
import { Hono } from 'hono'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { requestMeta } from '../src/http/request-meta.ts'
import type { Authentication } from '../src/identity/engine.ts'
import { authenticateRequest, problemResponse } from '../src/middleware/core.ts'
import { type AuthVariables, authMiddleware as honoAuth } from '../src/middleware/hono.ts'
import {
  getAuth,
  authMiddleware as nodeAuth,
  toWebRequest,
  withAuth,
} from '../src/middleware/node.ts'
import { headerResolver, sessionResolver, subdomainResolver } from '../src/tenancy/resolver.ts'
import { actor, TENANT_A, TENANT_B } from './fixtures.ts'

/** A fake engine: the cookie value names the actor. */
function fakeEngine(actors: Record<string, Actor>, refresh = false) {
  const seen: Request[] = []
  return {
    seen,
    authenticate: async (request: Request): Promise<Authentication> => {
      seen.push(request)
      const sid = /sid=([^;]+)/.exec(request.headers.get('cookie') ?? '')?.[1]
      const headers = new Headers()
      if (refresh && sid) headers.append('set-cookie', `sid=${sid}; Path=/; HttpOnly`)
      headers.set('x-auth', 'seen')
      return { actor: (sid && actors[sid]) || null, headers }
    },
  }
}

const alice = actor()
const service = actor({
  id: '0190f2a0-0000-7000-8000-0000000000ee',
  type: 'service',
  roles: [],
  tenantId: undefined,
} as never)
const { tenantId: _omit, ...serviceNoTenant } = service
const engine = fakeEngine({ alice, svc: serviceNoTenant as Actor }, true)
const lookup = (slug: string) => ({ acme: TENANT_A, globex: TENANT_B })[slug]
const tenancy = {
  resolvers: [
    subdomainResolver({ baseDomain: 'example.com', lookup }),
    headerResolver({ trust: ({ actor: a }) => a?.type === 'service' }),
    sessionResolver(),
  ],
}

describe('authenticateRequest', () => {
  const run = (url: string, headers: Record<string, string> = {}, extra = {}) =>
    authenticateRequest(new Request(url, { headers }), { engine, tenancy, ...extra })

  it('authenticates, resolves the tenant and passes engine headers through', async () => {
    const out = await run('https://acme.example.com/', { cookie: 'sid=alice' })
    expect(out.ok && out.state.actor?.id).toBe(alice.id)
    expect(out.ok && out.state.tenant).toEqual({ id: TENANT_A, strategy: 'shared' })
    expect(out.ok && out.state.headers.getSetCookie()).toEqual(['sid=alice; Path=/; HttpOnly'])
  })

  it('refuses a session for tenant A acting in tenant B (subdomain switch) with 403', async () => {
    const out = await run('https://globex.example.com/', { cookie: 'sid=alice' })
    expect(out.ok).toBe(false)
    if (out.ok) return
    expect(out.response.status).toBe(403)
    expect(out.response.headers.get('content-type')).toBe('application/problem+json')
    expect(await out.response.json()).toMatchObject({ code: 'FORBIDDEN', status: 403 })
  })

  it('ignores a spoofed X-Tenant-Id from a user, but lets a trusted tenant-less service use it', async () => {
    const spoof = await run('https://x.test/', { cookie: 'sid=alice', 'x-tenant-id': TENANT_B })
    expect(spoof.ok && spoof.state.tenant?.id).toBe(TENANT_A)
    const svc = await run('https://x.test/', { cookie: 'sid=svc', 'x-tenant-id': TENANT_B })
    expect(svc.ok && svc.state.tenant?.id).toBe(TENANT_B)
  })

  it('anonymous requests get a tenant only with allowAnonymousTenant; requireAuth and tenancy.required are enforced', async () => {
    const anon = await run('https://acme.example.com/')
    expect(anon.ok && anon.state).toMatchObject({ actor: null, tenant: undefined })
    const pub = await run(
      'https://acme.example.com/',
      {},
      { tenancy: { ...tenancy, allowAnonymousTenant: true } },
    )
    expect(pub.ok && pub.state).toMatchObject({ actor: null, tenant: { id: TENANT_A } })
    const must = await run('https://acme.example.com/', {}, { requireAuth: true })
    expect(must.ok ? 200 : must.response.status).toBe(401)
    const noTenant = await authenticateRequest(new Request('https://x.test/'), {
      engine,
      tenancy: { ...tenancy, required: true },
    })
    expect(noTenant.ok ? 200 : noTenant.response.status).toBe(400)
    if (!noTenant.ok)
      expect(await noTenant.response.json()).toMatchObject({ code: 'TENANT_REQUIRED' })
    const plain = await authenticateRequest(new Request('https://x.test/'), { engine })
    expect(plain.ok && plain.state.tenant).toBeUndefined()
  })

  it('fails closed if an engine throws despite its contract', async () => {
    const broken = { authenticate: async () => Promise.reject(new Error('boom')) }
    const out = await authenticateRequest(new Request('https://x.test/'), { engine: broken })
    expect(out.ok && out.state.actor).toBeNull()
  })

  it('problem responses are no-store and carry headers', async () => {
    const r = problemResponse(
      new (await import('@strutvane/core')).UnauthenticatedError(),
      new Headers({ 'set-cookie': 'a=; Max-Age=0' }),
    )
    expect(r.headers.get('cache-control')).toBe('no-store')
    expect(r.headers.getSetCookie()).toEqual(['a=; Max-Age=0'])
  })
})

describe('Hono adapter', () => {
  const app = new Hono<{ Variables: AuthVariables }>()
  app.use(honoAuth({ engine, tenancy, remoteAddress: () => '203.0.113.50' }))
  app.get('/me', (c) => {
    const ctx = currentContext()
    return c.json({
      actor: c.get('actor')?.id ?? null,
      tenant: c.get('tenant')?.id ?? null,
      ctxActor: ctx?.actor?.id ?? null,
      ctxTenant: ctx?.tenant?.id ?? null,
    })
  })

  it('sets variables and core context, and appends refreshed cookies', async () => {
    const res = await app.request('https://acme.example.com/me', {
      headers: { cookie: 'sid=alice' },
    })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      actor: alice.id,
      tenant: TENANT_A,
      ctxActor: alice.id,
      ctxTenant: TENANT_A,
    })
    expect(res.headers.getSetCookie()).toEqual(['sid=alice; Path=/; HttpOnly'])
    expect(res.headers.get('x-auth')).toBe('seen')
    expect(requestMeta(engine.seen.at(-1) as Request)).toEqual({ remoteAddress: '203.0.113.50' })
  })

  it('short-circuits with a problem response on cross-tenant access', async () => {
    const res = await app.request('https://globex.example.com/me', {
      headers: { cookie: 'sid=alice' },
    })
    expect(res.status).toBe(403)
  })

  it('reads the peer from @hono/node-server env by default, never from headers', async () => {
    const plain = new Hono<{ Variables: AuthVariables }>()
    plain.use(honoAuth({ engine }))
    plain.get('/', (c) => c.text('ok'))
    await plain.request(
      'http://x.test/',
      { headers: { 'x-forwarded-for': '6.6.6.6' } },
      { incoming: { socket: { remoteAddress: '198.51.100.1' } } },
    )
    expect(requestMeta(engine.seen.at(-1) as Request)).toEqual({ remoteAddress: '198.51.100.1' })
    await plain.request('http://x.test/')
    expect(requestMeta(engine.seen.at(-1) as Request)).toEqual({})
  })
})

describe('node:http adapter', () => {
  let server: Server
  let base: string

  beforeAll(async () => {
    const auth = nodeAuth({ engine, tenancy })
    server = createServer((req, res) => {
      if (req.url === '/wrapped') return
      auth(req, res, (error) => {
        if (error) {
          res.statusCode = 500
          res.end()
          return
        }
        const state = getAuth(req)
        res.setHeader('content-type', 'application/json')
        res.end(
          JSON.stringify({
            actor: state?.actor?.id ?? null,
            tenant: state?.tenant?.id ?? null,
            ctx: currentContext()?.actor?.id ?? null,
          }),
        )
      })
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  })
  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve))
  })

  it('authenticates over real HTTP and attaches the socket peer address', async () => {
    const res = await fetch(`${base}/x`, {
      headers: { cookie: 'sid=alice', 'x-forwarded-for': '6.6.6.6' },
    })
    expect(await res.json()).toEqual({ actor: alice.id, tenant: TENANT_A, ctx: alice.id })
    expect(res.headers.getSetCookie()).toEqual(['sid=alice; Path=/; HttpOnly'])
    expect(requestMeta(engine.seen.at(-1) as Request)?.remoteAddress).toMatch(/127\.0\.0\.1/)
  })

  it('answers cross-tenant attempts (forged Host header) with a 403 problem', async () => {
    // fetch() refuses to set Host, so use node:http directly, as an attacker's script would.
    const { status, type } = await new Promise<{ status: number; type: string | undefined }>(
      (resolve, reject) => {
        const r = request(
          `${base}/x`,
          { headers: { cookie: 'sid=alice', host: 'globex.example.com' } },
          (res) => {
            res.resume()
            resolve({ status: res.statusCode ?? 0, type: res.headers['content-type'] })
          },
        )
        r.on('error', reject)
        r.end()
      },
    )
    expect(status).toBe(403)
    expect(type).toBe('application/problem+json')
  })

  it('withAuth wraps a plain handler; handler errors become 500', async () => {
    const wrapped = createServer(
      withAuth({ engine, requireAuth: true }, (req, res, auth) => {
        if (req.url === '/throw') throw new Error('handler bug')
        res.end(auth.actor?.id ?? 'anon')
      }),
    )
    await new Promise<void>((resolve) => wrapped.listen(0, '127.0.0.1', resolve))
    const url = `http://127.0.0.1:${(wrapped.address() as AddressInfo).port}`
    try {
      expect(await (await fetch(url, { headers: { cookie: 'sid=alice' } })).text()).toBe(alice.id)
      expect((await fetch(url)).status).toBe(401)
      expect((await fetch(`${url}/throw`, { headers: { cookie: 'sid=alice' } })).status).toBe(500)
    } finally {
      await new Promise((resolve) => wrapped.close(resolve))
    }
  })

  it('withAuth turns middleware errors (a failing resolver) into 500', async () => {
    const s = createServer(
      withAuth(
        {
          engine,
          tenancy: {
            resolvers: [{ name: 'x', resolve: () => Promise.reject(new Error('resolver down')) }],
          },
        },
        (_req, res) => {
          res.end('unreachable')
        },
      ),
    )
    await new Promise<void>((resolve) => s.listen(0, '127.0.0.1', resolve))
    try {
      const port = (s.address() as AddressInfo).port
      expect((await fetch(`http://127.0.0.1:${port}/`)).status).toBe(500)
    } finally {
      await new Promise((resolve) => s.close(resolve))
    }
  })

  it('toWebRequest: hostile Host headers, odd methods and paths never break or spoof', () => {
    const fake = (
      headers: Record<string, string | string[] | undefined>,
      method = 'GET',
      url = '/p?q=1',
    ) =>
      ({ headers, method, url, socket: { remoteAddress: '192.0.2.1', encrypted: false } }) as never
    expect(toWebRequest(fake({ host: 'acme.example.com' })).url).toBe(
      'http://acme.example.com/p?q=1',
    )
    expect(toWebRequest(fake({ host: 'evil.com/@acme.example.com' })).url).toBe(
      'http://invalid.invalid/p?q=1',
    )
    expect(toWebRequest(fake({ host: '[::1]:8080' })).url).toBe('http://[::1]:8080/p?q=1')
    expect(toWebRequest(fake({})).url).toBe('http://invalid.invalid/p?q=1')
    expect(toWebRequest(fake({ host: 'a.test' }, 'TRACE')).method).toBe('GET')
    expect(toWebRequest(fake({ host: 'a.test' }, 'POST', 'http://absolute/x')).url).toBe(
      'http://a.test/',
    )
    expect(
      toWebRequest(
        fake({ host: 'a.test', 'x-multi': ['1', '2'], 'x-bad': 'a\u0000b' }),
      ).headers.get('x-multi'),
    ).toBe('1, 2')
    expect(toWebRequest(fake({ host: 'a.test:99999' })).url).toBe('http://invalid.invalid/p?q=1')
    expect(requestMeta(toWebRequest(fake({ host: 'a.test' })))).toEqual({
      remoteAddress: '192.0.2.1',
    })
    const noSocket = { headers: { host: 'a.test' }, method: undefined, url: undefined } as never
    expect(toWebRequest(noSocket).url).toBe('http://a.test/')
    expect(requestMeta(toWebRequest(noSocket))).toEqual({})
    expect(
      toWebRequest({ headers: { host: 'a.test' }, url: '/', socket: { encrypted: true } } as never)
        .url,
    ).toBe('https://a.test/')
  })
})
