/**
 * The app provider with persistent identity (`session.driver: 'database'` on PostgreSQL 18): the
 * auth tables come from `sv auth:migration`; accounts, sessions, tenants and memberships survive a
 * restart; the seed admin is created once; seeders and CLI commands write through the admin API;
 * a tenant's owners (and only they) manage its members.
 */
import { randomBytes } from 'node:crypto'
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Actor } from '@strutvane/contracts'
import { createApp, HooksToken } from '@strutvane/core'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { IdentitySetupError, openIdentityAdmin } from '../../src/admin.ts'
import commands, { type AuthCommandContext } from '../../src/commands.ts'
import { createAuthProvider } from '../../src/provider.ts'
import { createDatabase, type TestDatabase } from './helpers.ts'

const APP = 'http://localhost:3000'
const SECRET = randomBytes(32).toString('base64')
const ADMIN_PASSWORD = 'seed-admin-password-for-tests'
const PASSWORD = 'member-password-for-tests'

let db: TestDatabase
let root: string

const authConfig = {
  secret: SECRET,
  session: { driver: 'database', idleMinutes: 60 },
  registration: false,
  seedAdmin: { email: 'admin@app.test', password: ADMIN_PASSWORD, role: 'admin' },
  roles: {
    admin: { permissions: ['*'] },
    member: { permissions: ['*.viewAny'] },
    viewer: { permissions: ['*.viewAny'] },
    owner: { scope: 'tenant', permissions: ['*'] },
  },
}

beforeAll(async () => {
  db = await createDatabase()
  root = await mkdtemp(join(tmpdir(), 'sv-auth-app-'))
  await mkdir(join(root, 'config'), { recursive: true })
  await writeFile(join(root, 'config/app.ts'), `export default { url: '${APP}' }\n`)
  await writeFile(
    join(root, 'config/database.ts'),
    `export default { default: 'postgres', connection: { url: ${JSON.stringify(db.url())} } }\n`,
  )
  await writeFile(join(root, 'config/auth.ts'), `export default ${JSON.stringify(authConfig)}\n`)
  process.env['SV_TEST_PASSWORD'] = PASSWORD
})

afterAll(async () => {
  delete process.env['SV_TEST_PASSWORD']
  await db?.drop()
  if (root) await rm(root, { recursive: true, force: true })
})

function cli(flags: Record<string, string> = {}) {
  const lines: string[] = []
  const ctx: AuthCommandContext = {
    flags,
    requireProject: () => ({ root }),
    out: {
      line: (t = '') => lines.push(t),
      success: (t) => lines.push(`ok ${t}`),
      info: (t) => lines.push(`info ${t}`),
      warn: (t) => lines.push(`warn ${t}`),
    },
  }
  return { ctx, lines }
}
const command = (name: string) => {
  const c = commands.find((x) => x.name === name)
  if (!c) throw new Error(name)
  return c
}

async function applyMigrations(): Promise<void> {
  const dir = join(root, 'database/migrations')
  for (const file of (await readdir(dir)).sort()) {
    const sql = await readFile(join(dir, file), 'utf8')
    for (const statement of sql.split('--> statement-breakpoint')) await db.admin.query(statement)
  }
}

async function boot() {
  const app = createApp({
    config: {
      app: { root, url: APP },
      api: { prefix: '/api', version: 'v1' },
      auth: authConfig,
      tenancy: { enabled: true, strategy: 'shared' },
      database: { default: 'postgres', connection: { url: db.url() } },
    },
    providers: [createAuthProvider()],
  })
  await app.boot()
  const hooks = app.make(HooksToken)
  const send = async (
    method: string,
    path: string,
    init: { body?: unknown; cookie?: string } = {},
  ) => {
    const headers = new Headers({ origin: APP })
    if (init.body !== undefined) headers.set('content-type', 'application/json')
    if (init.cookie) headers.set('cookie', init.cookie)
    const r = (await hooks.run('http.onRequest', {
      request: new Request(`${APP}${path}`, {
        method,
        headers,
        ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
      }),
      actor: null,
      tenant: undefined,
      clientAddress: '127.0.0.1',
    })) as { actor: Actor | null; response?: Response }
    return r
  }
  return { app, send }
}

const cookieOf = (r: Response | undefined): string =>
  (r?.headers.getSetCookie() ?? []).map((c) => c.split(';')[0]).join('; ')

describe('persistent identity in the app provider', () => {
  test('boot refuses before the auth tables exist, naming the fix', async () => {
    await expect(boot()).rejects.toThrow(/sv auth:migration/)
  })

  test('sv auth:migration writes the tables once; sv migrate applies them', async () => {
    const first = cli()
    expect((await command('auth:migration').run(first.ctx))?.exitCode).toBeUndefined()
    const files = await readdir(join(root, 'database/migrations'))
    expect(files).toHaveLength(1)
    expect(files[0]).toMatch(/^\d{14}_auth_identity\.sql$/)
    const sql = await readFile(join(root, 'database/migrations', files[0] as string), 'utf8')
    expect(sql).toContain('-- strutvane:migration')
    expect(sql).toContain('strutvane_rate_limits')
    // Written but not applied: a second run does not write a duplicate.
    const again = cli()
    await command('auth:migration').run(again.ctx)
    expect(again.lines.join('\n')).toMatch(/already written/)
    expect(await readdir(join(root, 'database/migrations'))).toHaveLength(1)
    await applyMigrations()
    const after = cli()
    await command('auth:migration').run(after.ctx)
    expect(after.lines.join('\n')).toMatch(/up to date/)
  })

  test('accounts and sessions survive a restart; the seed admin is created once', async () => {
    const first = await boot()
    const signIn = await first.send('POST', '/api/v1/auth/sign-in', {
      body: { email: 'admin@app.test', password: ADMIN_PASSWORD },
    })
    expect(signIn.response?.status).toBe(200)
    const cookie = cookieOf(signIn.response)
    await first.app.shutdown()

    const second = await boot()
    const me = await second.send('GET', '/api/v1/auth/me', { cookie })
    expect(me.response?.status).toBe(200)
    expect(await me.response?.json()).toMatchObject({ actor: { roles: ['admin'] } })
    const { rows } = await db.admin.query(
      `SELECT count(*)::int AS n FROM "user" WHERE email = $1`,
      ['admin@app.test'],
    )
    expect(rows[0]).toEqual({ n: 1 })
    // Signing out revokes the stored session for good.
    expect((await second.send('POST', '/api/v1/auth/sign-out', { cookie })).response?.status).toBe(
      204,
    )
    expect((await second.send('GET', '/api/v1/auth/me', { cookie })).response?.status).toBe(401)
    await second.app.shutdown()
  })

  test('seeders and CLI commands manage users, tenants and roles idempotently', async () => {
    const idp = await openIdentityAdmin({ root })
    try {
      const owner = await idp.ensureUser({
        email: 'olivia@acme.test',
        name: 'Olivia',
        password: PASSWORD,
      })
      expect(
        await idp.ensureUser({
          email: 'OLIVIA@acme.test',
          name: 'x',
          password: 'other-password-123',
        }),
      ).toEqual(owner)
      const acme = await idp.ensureTenant({ name: 'Acme', slug: 'acme', ownerEmail: owner.email })
      expect(
        await idp.ensureTenant({ name: 'Other', slug: 'acme', ownerEmail: owner.email }),
      ).toEqual(acme)
      await idp.ensureUser({ email: 'vic@acme.test', name: 'Vic', password: PASSWORD })
      await idp.setMember({ tenant: 'acme', email: 'vic@acme.test', role: 'viewer' })
      await idp.setMember({ tenant: 'acme', email: 'vic@acme.test', role: 'viewer' })
      await expect(
        idp.setMember({ tenant: 'acme', email: 'vic@acme.test', role: 'superuser' }),
      ).rejects.toThrow(/not defined/)
      await expect(
        idp.setMember({ tenant: 'nope', email: 'vic@acme.test', role: 'viewer' }),
      ).rejects.toThrow(/no tenant/)
    } finally {
      await idp.close()
    }
    const create = cli({ email: 'mia@acme.test', name: 'Mia', 'password-env': 'SV_TEST_PASSWORD' })
    expect((await command('auth:user:create').run(create.ctx))?.exitCode).toBeUndefined()
    const dup = cli({ email: 'mia@acme.test', name: 'Mia', 'password-env': 'SV_TEST_PASSWORD' })
    expect((await command('auth:user:create').run(dup.ctx))?.exitCode).toBe(4)
    expect((await command('auth:user:create').run(cli({ email: 'x@y.test' }).ctx))?.exitCode).toBe(
      2,
    )
    const member = cli({ tenant: 'acme', email: 'mia@acme.test', role: 'member' })
    expect((await command('tenant:member:add').run(member.ctx))?.exitCode).toBeUndefined()
    const t2 = cli({ name: 'Globex', slug: 'globex', owner: 'mia@acme.test' })
    expect((await command('tenant:create').run(t2.ctx))?.exitCode).toBeUndefined()
    const bad = cli({ name: 'Bad', slug: 'Not A Slug', owner: 'mia@acme.test' })
    expect((await command('tenant:create').run(bad.ctx))?.exitCode).toBe(3)
  })

  test('tenant owners manage members; members, viewers and outsiders cannot (attack-style)', async () => {
    const { app, send } = await boot()
    try {
      const login = async (email: string) => {
        const r = await send('POST', '/api/v1/auth/sign-in', {
          body: { email, password: PASSWORD },
        })
        expect(r.response?.status).toBe(200)
        const cookie = cookieOf(r.response)
        const tenants = (await (
          await send('GET', '/api/v1/auth/tenants', { cookie })
        ).response?.json()) as {
          data: { tenantId: string; slug: string }[]
        }
        const acme = tenants.data.find((t) => t.slug === 'acme')
        if (!acme) return { cookie, tenantId: undefined }
        const s = await send('POST', '/api/v1/auth/switch-tenant', {
          cookie,
          body: { tenantId: acme.tenantId },
        })
        return { cookie: cookieOf(s.response) || cookie, tenantId: acme.tenantId }
      }
      const owner = await login('olivia@acme.test')
      const viewer = await login('vic@acme.test')
      const tenantId = owner.tenantId as string
      const members = `/api/v1/auth/tenants/${tenantId}/members`
      const list = await send('GET', members, { cookie: owner.cookie })
      expect(list.response?.status).toBe(200)
      const roster = (
        (await (list.response as Response).json()) as { data: { email: string; roles: string[] }[] }
      ).data
      expect(roster.map((m) => `${m.email}:${m.roles.join()}`).sort()).toEqual([
        'mia@acme.test:member',
        'olivia@acme.test:owner',
        'vic@acme.test:viewer',
      ])
      // A viewer (and an outsider using a forged tenant id) gets the same 403 as an unknown tenant.
      expect((await send('GET', members, { cookie: viewer.cookie })).response?.status).toBe(403)
      const admin = await send('POST', '/api/v1/auth/sign-in', {
        body: { email: 'admin@app.test', password: ADMIN_PASSWORD },
      })
      // Even the platform admin is not an owner of this tenant.
      expect(
        (await send('GET', members, { cookie: cookieOf(admin.response) })).response?.status,
      ).toBe(403)
      expect((await send('GET', members)).response?.status).toBe(401)
      expect(
        (
          await send('POST', members, {
            cookie: viewer.cookie,
            body: { email: 'vic@acme.test', role: 'owner' },
          })
        ).response?.status,
      ).toBe(403)
      // Owners: unknown roles and unknown emails are the same 422; the last owner stays.
      expect(
        (
          await send('POST', members, {
            cookie: owner.cookie,
            body: { email: 'vic@acme.test', role: 'root' },
          })
        ).response?.status,
      ).toBe(422)
      expect(
        (
          await send('POST', members, {
            cookie: owner.cookie,
            body: { email: 'ghost@acme.test', role: 'member' },
          })
        ).response?.status,
      ).toBe(422)
      expect(
        (
          await send('POST', members, {
            cookie: owner.cookie,
            body: { email: 'olivia@acme.test', role: 'viewer' },
          })
        ).response?.status,
      ).toBe(422)
      const promote = await send('POST', members, {
        cookie: owner.cookie,
        body: { email: 'vic@acme.test', role: 'member' },
      })
      expect(promote.response?.status).toBe(201)
      // The new role applies to the viewer's very next request (re-read from membership).
      const me = await send('GET', '/api/v1/auth/me', { cookie: viewer.cookie })
      expect(((await (me.response as Response).json()) as { actor: Actor }).actor.roles).toEqual([
        'member',
      ])
      const ownerRow = roster.find((m) => m.email === 'olivia@acme.test') as unknown as {
        userId: string
      }
      expect(
        (await send('DELETE', `${members}/${ownerRow.userId}`, { cookie: owner.cookie })).response
          ?.status,
      ).toBe(422)
      const vic = roster.find((m) => m.email === 'vic@acme.test') as unknown as { userId: string }
      expect(
        (await send('DELETE', `${members}/${vic.userId}`, { cookie: owner.cookie })).response
          ?.status,
      ).toBe(204)
      expect(
        (await send('GET', '/api/v1/auth/me', { cookie: viewer.cookie })).actor?.tenantId,
      ).toBeUndefined()
    } finally {
      await app.shutdown()
    }
  })

  test('the admin API refuses an in-memory identity (writes would vanish)', async () => {
    const memRoot = await mkdtemp(join(tmpdir(), 'sv-auth-mem-'))
    try {
      await mkdir(join(memRoot, 'config'))
      await writeFile(
        join(memRoot, 'config/auth.ts'),
        'export default { session: { driver: "memory" } }\n',
      )
      await expect(openIdentityAdmin({ root: memRoot })).rejects.toBeInstanceOf(IdentitySetupError)
      const idp = await openIdentityAdmin({ root: memRoot, allowMemory: true })
      expect(idp.driver).toBe('memory')
      await idp.close()
    } finally {
      await rm(memRoot, { recursive: true, force: true })
    }
  })
})
