// Engine selection for apps, the admin API and the contributed commands, without Docker (the
// PostgreSQL success paths run in test/integration/app-identity.test.ts).
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { type AddressInfo, createServer, type Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Actor } from '@strutvane/contracts'
import { createApp, HooksToken } from '@strutvane/core'
import { afterEach, describe, expect, test } from 'vitest'
import { IdentityAdminError, loadAuthProject, openIdentityAdmin } from '../src/admin.ts'
import commands, {
  type AuthCommandContext,
  migrationStamp,
  toMigrationFile,
} from '../src/commands.ts'
import {
  createAppIdentity,
  IdentitySetupError,
  isPostgres,
  poolOptionsFrom,
} from '../src/identity/app-identity.ts'
import { createAuthProvider } from '../src/provider.ts'

const dirs: string[] = []
afterEach(async () => {
  for (const d of dirs.splice(0)) await rm(d, { recursive: true, force: true })
})

const warnings: string[] = []
const logger = { warn: (m: string) => void warnings.push(m), error: () => undefined }
const base = {
  appUrl: 'http://localhost:3000',
  logger,
  deliverPasswordReset: async () => undefined,
}
const SECRET = 'x'.repeat(40)

async function project(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'sv-auth-id-'))
  dirs.push(root)
  for (const [path, content] of Object.entries(files)) {
    await mkdir(join(root, path, '..'), { recursive: true })
    await writeFile(join(root, path), content)
  }
  return root
}

function cli(root: string, flags: Record<string, string> = {}) {
  const lines: string[] = []
  const ctx: AuthCommandContext = {
    flags,
    requireProject: () => ({ root }),
    out: {
      line: (t = '') => void lines.push(t),
      success: (t) => void lines.push(t),
      info: (t) => void lines.push(t),
      warn: (t) => void lines.push(t),
    },
  }
  return { ctx, lines }
}
const run = (name: string, ctx: AuthCommandContext) => {
  const c = commands.find((x) => x.name === name)
  if (!c) throw new Error(name)
  return c.run(ctx)
}

describe('createAppIdentity: which engine an app runs on', () => {
  test('memory (default) and unknown drivers use the native engine; unbuilt drivers warn', async () => {
    warnings.length = 0
    const plain = await createAppIdentity({ ...base, auth: {} })
    expect(plain.driver).toBe('memory')
    expect(plain.engine.name).toBe('native')
    await plain.close()
    const valkey = await createAppIdentity({ ...base, auth: { session: { driver: 'valkey' } } })
    expect(valkey.driver).toBe('memory')
    expect(warnings.join()).toMatch(/"valkey" is not built yet/)
  })

  test('database on a non-PostgreSQL database warns and stays in memory', async () => {
    warnings.length = 0
    const id = await createAppIdentity({
      ...base,
      auth: { session: { driver: 'database' } },
      database: { default: 'sqlite', connection: { filename: 'x.sqlite' } },
    })
    expect(id.driver).toBe('memory')
    expect(warnings.join()).toMatch(/needs PostgreSQL/)
  })

  test('database on PostgreSQL needs a 32+ character secret and a reachable database', async () => {
    const pg = {
      default: 'postgres',
      connection: { host: '127.0.0.1', port: 1, user: 'u', database: 'd' },
    }
    await expect(
      createAppIdentity({
        ...base,
        auth: { session: { driver: 'database' }, secret: 'short' },
        database: pg,
      }),
    ).rejects.toBeInstanceOf(IdentitySetupError)
    // Nothing listens on port 1: the boot fails (and the pool is closed) instead of hanging.
    await expect(
      createAppIdentity({
        ...base,
        auth: { session: { driver: 'database' }, secret: SECRET },
        database: pg,
      }),
    ).rejects.toMatchObject({ code: 'ECONNREFUSED' })
    // The first import of better-auth in a process can take 20+ s on a cold or busy machine.
  }, 120_000)

  test('a database that accepts connections but never answers fails the boot instead of hanging', async () => {
    // A black-holed or wedged server: TCP connects, the PostgreSQL handshake never completes.
    const sockets = new Set<Socket>()
    const silent = createServer((socket) => {
      sockets.add(socket)
      socket.on('error', () => undefined)
    })
    await new Promise<void>((resolve) => silent.listen(0, '127.0.0.1', resolve))
    const { port } = silent.address() as AddressInfo
    await import('../src/identity/better-auth.ts') // keep the slow first import out of the timing
    try {
      const outcome = await Promise.race([
        createAppIdentity({
          ...base,
          auth: { session: { driver: 'database' }, secret: SECRET },
          database: { default: 'postgres', connection: { host: '127.0.0.1', port, user: 'u' } },
        }).then(
          () => 'booted',
          () => 'failed',
        ),
        new Promise((resolve) => setTimeout(() => resolve('hung'), 30_000)),
      ])
      expect(outcome).toBe('failed')
    } finally {
      for (const socket of sockets) socket.destroy()
      await new Promise((resolve) => silent.close(resolve))
    }
  }, 120_000)

  test('pool options follow config/database.ts; ssl: true verifies certificates', () => {
    expect(isPostgres({ default: 'azure-postgres' })).toBe(true)
    expect(isPostgres({ connection: { driver: 'postgres' } })).toBe(true)
    expect(isPostgres({ default: 'sqlite' })).toBe(false)
    expect(
      poolOptionsFrom({
        connection: {
          host: 'db',
          port: '5433',
          database: 'app',
          user: 'u',
          password: 'p',
          ssl: true,
          pool: { max: 50 },
        },
      }),
    ).toEqual({
      host: 'db',
      port: 5433,
      database: 'app',
      user: 'u',
      password: 'p',
      ssl: { rejectUnauthorized: true },
      max: 5,
      application_name: 'strutvane-auth',
      connectionTimeoutMillis: 10_000,
    })
    expect(
      poolOptionsFrom({
        connection: { url: 'postgres://x/y', ssl: { rejectUnauthorized: false } },
      }),
    ).toMatchObject({
      connectionString: 'postgres://x/y',
      ssl: { rejectUnauthorized: false },
    })
  })
})

describe('admin API and commands without a persistent store', () => {
  test('openIdentityAdmin refuses memory unless allowed; ensure* are idempotent', async () => {
    const root = await project({
      'config/auth.ts': 'export default { roles: { owner: {}, member: {}, viewer: {} } }\n',
    })
    await expect(openIdentityAdmin({ root })).rejects.toBeInstanceOf(IdentitySetupError)
    const idp = await openIdentityAdmin({ root, allowMemory: true })
    try {
      const u = await idp.ensureUser({
        email: 'o@acme.test',
        name: 'O',
        password: 'long-enough-password',
      })
      expect(
        await idp.ensureUser({ email: 'O@ACME.test', name: 'x', password: 'whatever-password' }),
      ).toEqual(u)
      const t = await idp.ensureTenant({ name: 'Acme', slug: 'acme', ownerEmail: 'o@acme.test' })
      expect(
        await idp.ensureTenant({ name: 'Acme', slug: 'acme', ownerEmail: 'o@acme.test' }),
      ).toEqual(t)
      await idp.setMember({ tenant: t.tenantId, email: 'o@acme.test', role: 'member' })
      await expect(
        idp.setMember({ tenant: 'acme', email: 'nobody@acme.test', role: 'member' }),
      ).rejects.toBeInstanceOf(IdentityAdminError)
      await expect(
        idp.ensureTenant({ name: 'B', slug: 'b', ownerEmail: 'nobody@acme.test' }),
      ).rejects.toThrow(/no account/)
      await expect(
        idp.ensureUser({ email: 'w@acme.test', name: 'W', password: 'short' }),
      ).rejects.toMatchObject({ code: 'VALIDATION_FAILED' })
    } finally {
      await idp.close()
    }
  })

  test('loadAuthProject reads .env without overriding, and defaults', async () => {
    const root = await project({ '.env': 'SV_AUTH_TEST_VAR=from-file\n' })
    process.env['SV_AUTH_TEST_VAR'] = 'from-env'
    const p = await loadAuthProject(root)
    expect(process.env['SV_AUTH_TEST_VAR']).toBe('from-env')
    delete process.env['SV_AUTH_TEST_VAR']
    expect(p.appUrl).toBe('http://localhost:3000')
    expect(p.migrationsDirectory).toBe(join(root, 'database/migrations'))
  })

  test('commands: usage errors exit 2, setup problems 3, unreachable databases 5', async () => {
    const memory = await project({ 'config/auth.ts': 'export default {}\n' })
    expect((await run('auth:migration', cli(memory).ctx))?.exitCode).toBe(3)
    expect((await run('auth:user:create', cli(memory).ctx))?.exitCode).toBe(2)
    expect(
      (
        await run(
          'auth:user:create',
          cli(memory, { email: 'a@b.test', name: 'A', 'password-env': 'SV_NOPE_UNSET' }).ctx,
        )
      )?.exitCode,
    ).toBe(2)
    process.env['SV_AUTH_PW'] = 'long-enough-password'
    expect(
      (
        await run(
          'auth:user:create',
          cli(memory, { email: 'a@b.test', name: 'A', 'password-env': 'SV_AUTH_PW' }).ctx,
        )
      )?.exitCode,
    ).toBe(3)
    delete process.env['SV_AUTH_PW']
    expect((await run('tenant:create', cli(memory).ctx))?.exitCode).toBe(2)
    expect(
      (await run('tenant:create', cli(memory, { name: 'A', slug: 'a', owner: 'a@b.test' }).ctx))
        ?.exitCode,
    ).toBe(3)
    expect((await run('tenant:member:add', cli(memory).ctx))?.exitCode).toBe(2)
    expect(
      (
        await run(
          'tenant:member:add',
          cli(memory, { tenant: 'a', email: 'a@b.test', role: 'member' }).ctx,
        )
      )?.exitCode,
    ).toBe(3)
    const down = await project({
      'config/auth.ts': `export default { secret: '${SECRET}', session: { driver: 'database' } }\n`,
      'config/database.ts':
        "export default { default: 'postgres', connection: { host: '127.0.0.1', port: 1, user: 'u', database: 'd' } }\n",
    })
    const r = cli(down)
    expect((await run('auth:migration', r.ctx))?.exitCode).toBe(5)
    expect(r.lines.join()).toMatch(/Cannot reach the database/)
  })

  test('migration files: timestamp names and framework breakpoints', () => {
    expect(migrationStamp(new Date('2026-11-14T08:30:05.123Z'))).toBe('20261114083005')
    expect(toMigrationFile(';\n', new Date())).toBeUndefined()
    const file = toMigrationFile(
      'create table "a" (x int);\n\ncreate index "i" on "a" (x);',
      new Date(0),
    )
    expect(file).toContain('-- strutvane:migration')
    expect(file).toContain(
      'create table if not exists "a" (x int);\n--> statement-breakpoint\ncreate index if not exists "i" on "a" (x);',
    )
  })
})

describe('tenant member endpoints (native engine)', () => {
  test('owners add, change and remove members; others cannot; the last owner stays', async () => {
    const root = await project({})
    const app = createApp({
      config: {
        app: { root, url: 'http://localhost:3000' },
        api: { prefix: '/api', version: 'v1' },
        auth: {
          registration: true,
          roles: {
            owner: { permissions: ['*'] },
            member: { permissions: [] },
            viewer: { permissions: [] },
          },
        },
        tenancy: { enabled: true },
      },
      providers: [createAuthProvider()],
    })
    await app.boot()
    const hooks = app.make(HooksToken)
    const send = async (method: string, path: string, cookie?: string, body?: unknown) =>
      (await hooks.run('http.onRequest', {
        request: new Request(`http://localhost:3000/api/v1/auth${path}`, {
          method,
          headers: {
            origin: 'http://localhost:3000',
            ...(cookie ? { cookie } : {}),
            ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
          },
          ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        }),
        actor: null,
        tenant: undefined,
        clientAddress: '127.0.0.1',
      })) as { actor: Actor | null; response: Response }
    const cookie = (r: Response) => (r.headers.get('set-cookie') ?? '').split(';')[0] ?? ''
    const signUp = async (email: string) =>
      cookie(
        (
          await send('POST', '/sign-up', undefined, {
            email,
            password: 'long-enough-password',
            name: email,
          })
        ).response,
      )
    const owner = await signUp('owner@acme.test')
    const other = await signUp('other@acme.test')
    const created = await send('POST', '/tenants', owner, { name: 'Acme', slug: 'acme' })
    const ownerCookie = cookie(created.response)
    const { tenantId } = (await created.response.json()) as { tenantId: string }
    const path = `/tenants/${tenantId}/members`
    expect(
      (await send('POST', path, ownerCookie, { email: 'other@acme.test', role: 'viewer' })).response
        .status,
    ).toBe(201)
    expect(
      (await send('POST', path, ownerCookie, { email: 'other@acme.test', role: 'nope' })).response
        .status,
    ).toBe(422)
    expect(
      (await send('POST', path, ownerCookie, { email: 'owner@acme.test', role: 'member' })).response
        .status,
    ).toBe(422)
    const roster = (await (await send('GET', path, ownerCookie)).response.json()) as {
      data: { userId: string; email: string }[]
    }
    expect(roster.data).toHaveLength(2)
    // The viewer (no active tenant here) and a malformed tenant id are both refused alike.
    expect((await send('GET', path, other)).response.status).toBe(403)
    expect((await send('GET', '/tenants/not-a-uuid/members', ownerCookie)).response.status).toBe(
      403,
    )
    expect((await send('PATCH', path, ownerCookie, {})).response.status).toBe(404)
    const self = roster.data.find((m) => m.email === 'owner@acme.test')?.userId as string
    const otherId = roster.data.find((m) => m.email === 'other@acme.test')?.userId as string
    expect((await send('DELETE', `${path}/${self}`, ownerCookie)).response.status).toBe(422)
    expect(
      (await send('DELETE', `${path}/00000000-0000-4000-8000-000000000000`, ownerCookie)).response
        .status,
    ).toBe(404)
    expect((await send('DELETE', `${path}/${otherId}`, ownerCookie)).response.status).toBe(204)
    await app.shutdown()
  })
})
