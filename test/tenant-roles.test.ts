// Tenant roles are kept apart from platform roles: a role held through team membership matches
// only tenant-scoped grants, and `any` grants only on tenant data; teams made before the team
// role was `owner` are moved on boot (idempotently) on SQLite and PostgreSQL (PGlite).
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import type { Actor } from '@strutvane/framework/contracts'
import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { defineAuthConfig } from '../src/engine/config.ts'
import type { AuthStore } from '../src/engine/ports/store.ts'
import { memoryAuthStore } from '../src/engine/store/memory.ts'
import { postgresAuthStore } from '../src/engine/store/postgres.ts'
import { sqliteAuthStore } from '../src/engine/store/sqlite.ts'
import { createAppIdentity } from '../src/identity/app-identity.ts'
import { engineConfigFrom } from '../src/identity/engine-config.ts'
import type { RoleScope } from '../src/policy/policy.ts'
import { compileRoleMap, partitionRoles, type RoleDefinition } from '../src/policy/roles.ts'
import { defineSchema } from '../src/policy/schema.ts'
import { pgliteSchemaClient } from './engine/helpers/pg.ts'
import { sqliteWithAuthSchema } from './support/auth-schema.ts'

const TENANT = '0190f2a0-0000-7000-8000-0000000000a1'
const APP_KEY = `base64:${Buffer.alloc(32, 7).toString('base64')}`

/** Platform-wide data (no tenantId) and tenant data. */
const SCHEMAS = {
  country: defineSchema({
    table: 'countries',
    columns: { id: { column: 'id', type: 'uuid' }, name: { column: 'name', type: 'text' } },
  }),
  invoice: defineSchema({
    table: 'invoices',
    columns: {
      id: { column: 'id', type: 'uuid' },
      ownerId: { column: 'owner_id', type: 'uuid' },
      tenantId: { column: 'tenant_id', type: 'uuid' },
    },
  }),
} as const
type Resource = keyof typeof SCHEMAS
const RESOURCES = Object.keys(SCHEMAS) as Resource[]
const ACTIONS = ['viewAny', 'view', 'update', 'delete'] as const

const roleName = fc.constantFrom('admin', 'owner', 'member', 'viewer', 'manager', 'auditor')
const scope = fc.constantFrom<RoleScope | undefined>(undefined, 'global', 'tenant', 'any')
const permission = fc.oneof(
  fc.constant('*'),
  fc.constantFrom(...ACTIONS).map((a) => `*.${a}`),
  fc
    .tuple(fc.constantFrom(...RESOURCES), fc.constantFrom(...ACTIONS, '*'))
    .map(([r, a]) => `${r}.${a}`),
  fc.record({ action: fc.constantFrom(...ACTIONS).map((a) => `*.${a}`), own: fc.boolean() }),
)
const roleMap = fc.dictionary(
  roleName,
  fc.record({ scope, permissions: fc.array(permission, { maxLength: 5 }) }),
)

/** A role map the boot accepts (admin is global only, owner tenant only), or undefined. */
function compiled(map: Record<string, { scope: RoleScope | undefined; permissions: unknown[] }>) {
  const roles: Record<string, RoleDefinition> = {}
  for (const [name, def] of Object.entries(map))
    roles[name] = {
      permissions: def.permissions as RoleDefinition['permissions'],
      ...(def.scope !== undefined ? { scope: def.scope } : {}),
    }
  try {
    return { roles, layer: compileRoleMap({ roles }) }
  } catch {
    return undefined
  }
}

describe('tenant roles are not platform roles', () => {
  it('property: a team member never gets a global or any-scope grant on platform-wide data', () => {
    fc.assert(
      fc.property(
        roleMap,
        fc.subarray(['admin', 'owner', 'member', 'viewer', 'manager', 'auditor']),
        (map, held) => {
          const c = compiled(map)
          fc.pre(c !== undefined)
          if (c === undefined) return
          const member: Actor = { id: 'u', type: 'user', roles: held, attrs: {}, tenantId: TENANT }
          const platform: Actor = { id: 'u', type: 'user', roles: held, attrs: {} }
          for (const resource of RESOURCES)
            for (const action of ACTIONS) {
              const inside = c.layer.grantsFor(member, resource, action, SCHEMAS[resource])
              // Inside a tenant: never a platform grant; an `any` grant only on tenant data.
              for (const g of inside) {
                expect(g.scope).not.toBe('global')
                if (resource === 'country') expect(g.scope).toBe('tenant')
              }
              // Outside a tenant: never a tenant grant.
              for (const g of c.layer.grantsFor(platform, resource, action, SCHEMAS[resource]))
                expect(g.scope).not.toBe('tenant')
            }
          // The engine's tenant roles never include a platform-only role, and vice versa.
          const split = partitionRoles(c.roles)
          expect(split.tenant).toContain('owner')
          expect(split.tenant).not.toContain('admin')
          expect(split.global).toContain('admin')
          expect(split.global).not.toContain('owner')
          for (const [name, def] of Object.entries(c.roles)) {
            if (name === 'admin' || name === 'owner') continue
            const where = def.scope ?? 'global'
            expect(split.tenant.includes(name), name).toBe(where !== 'global')
            expect(split.global.includes(name), name).toBe(where !== 'tenant')
          }
          // ...and the engine refuses them in the wrong place.
          const engine = defineAuthConfig({
            appUrl: 'http://localhost:3000',
            ...engineConfigFrom({ roles: c.roles }, { tenancy: true }),
          })
          expect(engine.tenantRoles).toEqual(split.tenant)
          expect(engine.roles).toEqual(split.global)
        },
      ),
      { numRuns: 400 },
    )
  })

  it('the engine refuses owner as a platform role and admin as a team role', () => {
    const base = { appUrl: 'http://localhost:3000' }
    expect(() => defineAuthConfig({ ...base, roles: ['admin', 'owner'] })).toThrow(
      /reserved team role/,
    )
    expect(() => defineAuthConfig({ ...base, tenantRoles: ['owner', 'admin'] })).toThrow(
      /platform role/,
    )
    expect(() => defineAuthConfig({ ...base, tenantRoles: ['member'] })).toThrow(/include `owner`/)
    expect(defineAuthConfig({ ...base, roles: 'admin-manager-member-viewer' }).tenantRoles).toEqual(
      ['owner', 'manager', 'member', 'viewer'],
    )
  })
})

/** Seed a team made before the rename: its creator and a pending invitation say `admin`. */
async function seedLegacyTeam(store: AuthStore): Promise<void> {
  await store.createTeam(
    { id: 't1', name: 'Acme', slug: 'acme', personal: false, createdAt: 1 },
    { teamId: 't1', userId: 'u1', role: 'admin' },
  )
  await store.putMember({ teamId: 't1', userId: 'u2', role: 'member' })
  await store.addInvitation({
    id: 'i1',
    teamId: 't1',
    email: 'new@acme.test',
    role: 'admin',
    digest: 'd1',
    invitedBy: 'u1',
    createdAt: 1,
    expiresAt: 2,
  })
}

describe.each([
  ['memory', () => memoryAuthStore()],
  ['sqlite', () => sqliteAuthStore(sqliteWithAuthSchema())],
  ['postgres (PGlite)', () => postgresAuthStore(pgliteSchemaClient())],
] as const)('existing teams move from admin to owner (%s)', (_name, make) => {
  it('renames memberships and invitations once; a second run changes nothing', async () => {
    const store = make()
    await seedLegacyTeam(store)
    expect(await store.renameTeamRole('admin', 'owner')).toBe(2)
    expect(await store.renameTeamRole('admin', 'owner')).toBe(0)
    expect((await store.listMembers('t1')).map((m) => [m.userId, m.role]).sort()).toEqual([
      ['u1', 'owner'],
      ['u2', 'member'],
    ])
    expect((await store.listInvitations('t1')).map((i) => i.role)).toEqual(['owner'])
    // The last-owner guard now sees the moved owner.
    expect(await store.changeMemberRole('t1', 'u1', 'member')).toBe('last-admin')
  })
})

describe('the move runs when a persistent store boots', () => {
  it('SQLite: an app booting on an existing database sees owners, every boot', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sv-auth-roles-'))
    const file = join(dir, 'app.sqlite')
    const database = { default: 'sqlite', connection: { filename: 'app.sqlite' } }
    const warnings: string[] = []
    const options = {
      appUrl: 'http://localhost:3000',
      logger: { warn: (m: string) => void warnings.push(m), error: () => undefined },
      deliverPasswordReset: async () => undefined,
      auth: {},
      database,
      root: dir,
      appKey: APP_KEY,
    }
    try {
      const db = sqliteWithAuthSchema(file)
      await seedLegacyTeam(sqliteAuthStore(db))
      db.close()
      // Two boots: the first moves the rows (and says so once), the second finds nothing to do.
      for (let boot = 0; boot < 2; boot++) {
        const id = await createAppIdentity(options)
        await id.close()
      }
      expect(warnings.filter((w) => w.includes('moved from the admin role'))).toHaveLength(1)
      const after = new DatabaseSync(file)
      try {
        const roles = after.prepare('SELECT role FROM team_members ORDER BY user_id').all()
        expect(roles.map((r) => (r as { role: string }).role)).toEqual(['owner', 'member'])
        const invited = after.prepare('SELECT role FROM team_invitations').all()
        expect(invited.map((r) => (r as { role: string }).role)).toEqual(['owner'])
      } finally {
        after.close()
      }
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
