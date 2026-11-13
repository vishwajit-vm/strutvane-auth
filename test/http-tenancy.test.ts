/** Client IP resolution (trusted proxies), request meta and the tenant resolver chain. */
import { describe, expect, it } from 'vitest'
import { normalizeIp, resolveClientIp, trustedProxies } from '../src/http/client-ip.ts'
import { attachRequestMeta, requestMeta } from '../src/http/request-meta.ts'
import {
  headerResolver,
  pathResolver,
  resolveTenant,
  sessionResolver,
  subdomainResolver,
} from '../src/tenancy/resolver.ts'
import { actor, TENANT_A, TENANT_B } from './fixtures.ts'

const request = (url: string, headers: Record<string, string> = {}, peer?: string) => {
  const r = new Request(url, { headers })
  return peer === undefined ? r : attachRequestMeta(r, { remoteAddress: peer })
}

describe('request meta', () => {
  it('is attached per Request object and frozen; headers cannot set it', () => {
    const r = request('http://x/', { 'x-remote-address': '1.1.1.1' })
    expect(requestMeta(r)).toBeUndefined()
    attachRequestMeta(r, { remoteAddress: '9.9.9.9' })
    expect(requestMeta(r)).toEqual({ remoteAddress: '9.9.9.9' })
    expect(Object.isFrozen(requestMeta(r))).toBe(true)
    expect(requestMeta(new Request(r))).toBeUndefined()
  })
})

describe('client IP', () => {
  it('normalises addresses and rejects non-IPs', () => {
    expect(normalizeIp('::ffff:192.0.2.1')).toBe('192.0.2.1')
    expect(normalizeIp('[2001:DB8::1]')).toBe('2001:db8::1')
    expect(normalizeIp('fe80::1%eth0')).toBe('fe80::1')
    expect(normalizeIp(' 10.0.0.1 ')).toBe('10.0.0.1')
    expect(normalizeIp('not-an-ip')).toBeUndefined()
    expect(normalizeIp('1.2.3.4, 5.6.7.8')).toBeUndefined()
    expect(normalizeIp(undefined)).toBeUndefined()
  })

  it('uses the TCP peer and ignores X-Forwarded-For from untrusted peers', () => {
    expect(
      resolveClientIp(request('http://x/', { 'x-forwarded-for': '6.6.6.6' }, '203.0.113.5')),
    ).toBe('203.0.113.5')
    expect(resolveClientIp(request('http://x/', { 'x-forwarded-for': '6.6.6.6' }))).toBeUndefined()
  })

  it('walks X-Forwarded-For right-to-left through trusted proxies only', () => {
    const proxies = trustedProxies(['10.0.0.0/8', '::1', '192.168.1.1'])
    // client spoofs a leading entry; the proxy appended the real address
    const r = request(
      'http://x/',
      { 'x-forwarded-for': '6.6.6.6, 198.51.100.7, 10.1.2.3' },
      '10.0.0.1',
    )
    expect(resolveClientIp(r, proxies)).toBe('198.51.100.7')
    expect(resolveClientIp(request('http://x/', {}, '::1'), proxies)).toBe('::1')
    expect(
      resolveClientIp(request('http://x/', { 'x-forwarded-for': '10.9.9.9' }, '10.0.0.1'), proxies),
    ).toBe('10.0.0.1')
    expect(
      resolveClientIp(
        request('http://x/', { 'x-forwarded-for': 'garbage, 10.2.2.2' }, '10.0.0.1'),
        proxies,
      ),
    ).toBe('10.0.0.1')
    expect(
      resolveClientIp(
        request('http://x/', { 'x-forwarded-for': '::ffff:198.51.100.9' }, '::ffff:10.0.0.1'),
        proxies,
      ),
    ).toBe('198.51.100.9')
  })

  it('rejects invalid trusted proxy entries at boot', () => {
    expect(() => trustedProxies(['nope'])).toThrow(TypeError)
    expect(() => trustedProxies(['10.0.0.0/33'])).toThrow(TypeError)
    expect(() => trustedProxies(['10.0.0.0/x'])).toThrow(TypeError)
    expect(trustedProxies(['2001:db8::/32']).has('2001:db8::5')).toBe(true)
    expect(trustedProxies([]).has('not-ip')).toBe(false)
  })
})

describe('tenant resolvers', () => {
  const lookup = (slug: string) => ({ acme: TENANT_A, globex: TENANT_B })[slug]
  const input = (
    url: string,
    headers: Record<string, string> = {},
    a = null as ReturnType<typeof actor> | null,
  ) => ({
    request: request(url, headers),
    actor: a,
  })

  it('subdomain: only direct children of the base domain, reserved names skipped, slugs looked up', async () => {
    const r = subdomainResolver({ baseDomain: 'example.com', lookup })
    expect(await r.resolve(input('https://acme.example.com/x'))).toBe(TENANT_A)
    expect(await r.resolve(input('https://ACME.Example.com/x'))).toBe(TENANT_A)
    expect(await r.resolve(input('https://www.example.com/'))).toBeUndefined()
    expect(await r.resolve(input('https://a.b.example.com/'))).toBeUndefined()
    expect(await r.resolve(input('https://acme.evil.com/'))).toBeUndefined()
    expect(await r.resolve(input('https://example.com/'))).toBeUndefined()
    expect(await r.resolve(input('https://nobody.example.com/'))).toBeUndefined()
    expect(await r.resolve(input(`https://${TENANT_B}.example.com/`))).toBe(TENANT_B)
    expect(
      await r.resolve({
        request: { url: 'not a url', headers: new Headers() } as Request,
        actor: null,
      }),
    ).toBeUndefined()
  })

  it('path: /t/<slug>/…, decoded safely', async () => {
    const r = pathResolver({ lookup })
    expect(await r.resolve(input('https://x/t/acme/invoices'))).toBe(TENANT_A)
    expect(await r.resolve(input('https://x/t/GLOBEX'))).toBe(TENANT_B)
    expect(await r.resolve(input('https://x/invoices'))).toBeUndefined()
    expect(await r.resolve(input('https://x/t/%E0%A4%A/x'))).toBeUndefined()
    expect(await r.resolve(input("https://x/t/acme'--/x"))).toBeUndefined()
    expect(
      await pathResolver({ prefix: '/org/', lookup }).resolve(input('https://x/org/acme')),
    ).toBe(TENANT_A)
    expect(
      await r.resolve({ request: { url: 'bad', headers: new Headers() } as Request, actor: null }),
    ).toBeUndefined()
  })

  it('header: ignored entirely unless the caller is trusted (no spoofing)', async () => {
    const trusted = headerResolver({ trust: ({ actor: a }) => a?.type === 'service' })
    const spoof = input('https://x/', { 'x-tenant-id': TENANT_B }, actor())
    expect(await trusted.resolve(spoof)).toBeUndefined()
    const service = input(
      'https://x/',
      { 'x-tenant-id': TENANT_B },
      actor({ type: 'service', roles: [] }),
    )
    expect(await trusted.resolve(service)).toBe(TENANT_B)
    const malformed = input('https://x/', { 'x-tenant-id': "' OR 1=1" }, actor({ type: 'service' }))
    expect(await trusted.resolve(malformed)).toBeUndefined()
    const custom = headerResolver({ trust: () => true, header: 'X-Org' })
    expect(await custom.resolve(input('https://x/', { 'x-org': TENANT_A }))).toBe(TENANT_A)
    // A trust function returning a truthy non-boolean is not trust.
    expect(
      await headerResolver({ trust: () => 'yes' as never }).resolve(
        input('https://x/', { 'x-tenant-id': TENANT_A }),
      ),
    ).toBeUndefined()
  })

  it('session: the actor’s membership-verified tenant', async () => {
    expect(await sessionResolver().resolve(input('https://x/', {}, actor()))).toBe(TENANT_A)
    expect(await sessionResolver().resolve(input('https://x/'))).toBeUndefined()
  })

  it('the chain takes the first valid UUID and ignores non-UUID answers from custom resolvers', async () => {
    const chain = [
      { name: 'broken', resolve: () => 'not-a-uuid' },
      subdomainResolver({ baseDomain: 'example.com', lookup }),
      sessionResolver(),
    ]
    expect(
      await resolveTenant(
        chain,
        input('https://acme.example.com/', {}, actor({ tenantId: TENANT_B })),
      ),
    ).toEqual({
      tenant: { id: TENANT_A, strategy: 'shared' },
      resolvedBy: 'subdomain',
    })
    expect(
      (
        await resolveTenant(
          chain,
          input('https://x/', {}, actor({ tenantId: TENANT_B.toUpperCase() })),
          { strategy: 'schema' },
        )
      ).tenant,
    ).toEqual({
      id: TENANT_B,
      strategy: 'schema',
    })
    expect(await resolveTenant(chain, input('https://x/'))).toEqual({
      tenant: undefined,
      resolvedBy: undefined,
    })
  })
})
