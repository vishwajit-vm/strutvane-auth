/**
 * The role map (`config/auth.ts` roles → allow grants) combined with policies: validation, the
 * semantics of every permission form (patterns, `own`, scope, wildcardExclude, the in-tenant
 * wildcard bound, newModelDefaults), deny-wins, and SQL ≡ in-memory on PGlite so role grants keep
 * lists filtered in the database exactly as single-record checks decide.
 */
import { PGlite } from '@electric-sql/pglite'
import type { Actor, Permission } from '@strutvane/framework/contracts'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { defineAuthConfig } from '../src/config.ts'
import { PolicyDefinitionError } from '../src/errors.ts'
import { definePolicy } from '../src/policy/policy.ts'
import { createPermissionProvider } from '../src/policy/provider.ts'
import { compileRoleMap, type RoleMapConfig } from '../src/policy/roles.ts'
import { defineSchema } from '../src/policy/schema.ts'
import { compileToSql } from '../src/sql/index.ts'

const ALICE = '0190f2a0-0000-7000-8000-00000000000a'
const BOB = '0190f2a0-0000-7000-8000-00000000000b'
const TENANT = '0190f2a0-0000-7000-8000-0000000000a1'

const invoiceSchema = defineSchema({
  table: 'invoices',
  columns: {
    id: { column: 'id', type: 'uuid' },
    ownerId: { column: 'owner_id', type: 'uuid' },
    tenantId: { column: 'tenant_id', type: 'uuid' },
    status: { column: 'status', type: 'text' },
  },
})
/** No ownerId, no tenantId: platform-wide reference data. */
const countrySchema = defineSchema({
  table: 'countries',
  columns: { id: { column: 'id', type: 'uuid' }, name: { column: 'name', type: 'text' } },
})
/** An ownerId that cannot hold an actor id. */
const ticketSchema = defineSchema({
  table: 'tickets',
  columns: { id: { column: 'id', type: 'uuid' }, ownerId: { column: 'owner_id', type: 'int4' } },
})

const invoicePolicy = definePolicy('invoice', { schema: invoiceSchema }, ({ allow, deny }) => {
  allow('approve', { role: 'manager' })
  deny(['update', 'delete'], { when: ({ row }) => row.status.eq('paid') })
})
const countryPolicy = definePolicy('country', { schema: countrySchema }, () => undefined)
const ticketPolicy = definePolicy('ticket', { schema: ticketSchema }, () => undefined)

/** The role map create-strutvane generates (tenancy on), reduced to what the tests need. */
const ROLES: RoleMapConfig = {
  roles: {
    admin: {
      permissions: [
        '*',
        { action: 'user.view', scope: 'global' },
        { action: 'user.update', scope: 'global' },
      ],
    },
    member: {
      permissions: [
        '*.viewAny',
        '*.view',
        '*.create',
        { action: '*.update', own: true },
        { action: '*.delete', own: true },
      ],
    },
    viewer: { permissions: ['*.viewAny', '*.view'] },
    owner: { scope: 'tenant', permissions: ['*', 'membership.viewAny', 'membership.create'] },
  },
  wildcardExclude: ['user', 'membership', 'auditEvent'],
}

const user = (roles: string[], extra: Partial<Actor> = {}): Actor => ({
  id: ALICE,
  type: 'user',
  roles,
  attrs: {},
  ...extra,
})
const provider = createPermissionProvider([invoicePolicy, countryPolicy, ticketPolicy], {
  roles: ROLES,
})
const can = async (
  a: Actor | null,
  p: Permission,
  type?: string,
  record?: Record<string, unknown>,
) =>
  (
    await provider.can(a, p, {
      type: type ?? p.split('.')[0] ?? '',
      ...(record ? { record } : {}),
    })
  ).allowed

describe('compileRoleMap: definition errors fail the boot', () => {
  const bad: [string, unknown, RegExp][] = [
    ['unknown top-level key', { rolse: {} }, /unknown option.*rolse/],
    ['roles not an object', { roles: [] }, /roles must be an object/],
    ['role not an object', { roles: { admin: ['*'] } }, /must be \{ permissions/],
    ['unknown role option', { roles: { admin: { permissions: [], scopes: 'x' } } }, /scopes/],
    ['permissions not a list', { roles: { admin: { permissions: '*' } } }, /must be a list/],
    ['invalid role name', { roles: { Admin: { permissions: [] } } }, /invalid role name/],
    ['malformed pattern', { roles: { a: { permissions: ['invoice'] } } }, /invalid permission/],
    ['injection-ish pattern', { roles: { a: { permissions: ["x.y' OR 1=1"] } } }, /invalid/],
    ['non-string pattern', { roles: { a: { permissions: [42] } } }, /expected a permission/],
    ['typo in own', { roles: { a: { permissions: [{ action: '*.update', onw: true }] } } }, /onw/],
    ['own not boolean', { roles: { a: { permissions: [{ action: '*.x', own: 'yes' }] } } }, /own/],
    ['bad scope', { roles: { a: { scope: 'platform', permissions: [] } } }, /scope must be/],
    [
      'bad permission scope',
      { roles: { a: { permissions: [{ action: '*', scope: 1 }] } } },
      /scope/,
    ],
    ['bad newModelDefaults', { newModelDefaults: 'open' }, /newModelDefaults/],
    [
      'owner as a platform role',
      { roles: { owner: { scope: 'global', permissions: [] } } },
      /reserved tenant role/,
    ],
    [
      'owner in both places',
      { roles: { owner: { scope: 'any', permissions: [] } } },
      /reserved tenant role/,
    ],
    [
      'admin as a tenant role',
      { roles: { admin: { scope: 'tenant', permissions: [] } } },
      /platform role/,
    ],
    [
      'admin in both places',
      { roles: { admin: { scope: 'any', permissions: [] } } },
      /platform role/,
    ],
    [
      'a platform role (no scope) with a tenant permission',
      { roles: { member: { permissions: [{ action: '*.view', scope: 'tenant' }] } } },
      /set the role's scope to 'any'/,
    ],
    [
      'a tenant role with a platform permission',
      {
        roles: {
          member: { scope: 'tenant', permissions: [{ action: '*.view', scope: 'global' }] },
        },
      },
      /never applies to member, a tenant role/,
    ],
    ['wildcardExclude not a list', { wildcardExclude: 'user' }, /wildcardExclude must be/],
    ['bad excluded name', { wildcardExclude: ['*'] }, /invalid resource name/],
    [
      'action wildcard on an excluded resource',
      { wildcardExclude: ['user'], roles: { a: { permissions: ['user.*'] } } },
      /list its actions by name/,
    ],
    [
      'partial wildcard under admin-only',
      { newModelDefaults: 'admin-only', roles: { m: { permissions: ['*.view'] } } },
      /never applies under newModelDefaults 'admin-only'/,
    ],
  ]
  it.each(bad)('rejects: %s', (_name, config, message) => {
    expect(() => compileRoleMap(config as RoleMapConfig)).toThrow(PolicyDefinitionError)
    expect(() => compileRoleMap(config as RoleMapConfig)).toThrow(message)
  })

  it('rejects a non-object role map', () => {
    expect(() => compileRoleMap(null as unknown as RoleMapConfig)).toThrow(/must be an object/)
  })

  it('compiles every form and names grants for Decision.reason', () => {
    const layer = compileRoleMap(ROLES)
    expect(layer.newModelDefaults).toBe('inherit-role-patterns')
    expect(layer.wildcardExclude).toEqual(['user', 'membership', 'auditEvent'])
    expect(layer.grants.map((g) => g.name)).toEqual([
      'role:admin:*',
      'role:admin:user.view',
      'role:admin:user.update',
      'role:member:*.viewAny',
      'role:member:*.view',
      'role:member:*.create',
      'role:member:*.update(own)',
      'role:member:*.delete(own)',
      'role:viewer:*.viewAny',
      'role:viewer:*.view',
      'role:owner:*@tenant',
      'role:owner:membership.viewAny@tenant',
      'role:owner:membership.create@tenant',
    ])
    expect(compileRoleMap({ roles: { a: { permissions: ['*.*'] } } }).grants[0]).toMatchObject({
      resource: '*',
      action: '*',
    })
    expect(Object.isFrozen(layer.grants)).toBe(true)
  })

  it('admin-only accepts the full wildcard and exact grants', () => {
    const layer = compileRoleMap({
      newModelDefaults: 'admin-only',
      roles: {
        admin: { permissions: ['*'] },
        member: { permissions: ['invoice.view', 'invoice.*'] },
      },
    })
    expect(layer.newModelDefaults).toBe('admin-only')
    expect(layer.grantsFor(user(['member']), 'invoice', 'view', invoiceSchema)).toHaveLength(2)
    expect(layer.grantsFor(user(['member']), 'country', 'view', countrySchema)).toHaveLength(0)
    expect(layer.grantsFor(user(['admin']), 'country', 'view', countrySchema)).toHaveLength(1)
  })

  it('no roles configured → no grants, for every actor', () => {
    const layer = compileRoleMap()
    expect(layer.grants).toEqual([])
    expect(layer.grantsFor(user(['admin']), 'invoice', 'view', invoiceSchema)).toEqual([])
  })
})

describe('role grants combined with policies', () => {
  it('without a role map, behaviour is exactly the policies (deny by default)', async () => {
    const bare = createPermissionProvider([invoicePolicy])
    const admin = user(['admin'])
    expect((await bare.can(admin, 'invoice.view')).reason).toBe('default-deny')
    expect((await bare.can(admin, 'country.view')).reason).toBe('default-deny:no-policy')
    expect(await bare.filterFor(admin, 'invoice.view', 'invoice')).toEqual({ op: 'false' })
    expect(bare.roles.grants).toEqual([])
  })

  it("'*' allows every action, including custom ones and resources without a policy", async () => {
    const admin = user(['admin'])
    expect(await can(admin, 'invoice.approve')).toBe(true)
    expect(await can(admin, 'invoice.forceDelete', 'invoice', { status: 'draft' })).toBe(true)
    expect(await can(admin, 'project.export')).toBe(true) // no policy at all
    const decision = await provider.can(admin, 'project.export')
    expect(decision.reason).toBe('allow:role:admin:*')
    expect(await provider.filterFor(admin, 'project.viewAny', 'project')).toEqual({ op: 'true' })
  })

  it('patterns allow only their action; unmatched actions stay denied', async () => {
    const viewer = user(['viewer'])
    expect(await can(viewer, 'invoice.view', 'invoice', { status: 'x' })).toBe(true)
    expect(await can(viewer, 'invoice.viewAny')).toBe(true)
    expect(await can(viewer, 'invoice.create')).toBe(false)
    expect(await can(viewer, 'invoice.approve')).toBe(false)
    expect(await can(user(['unknown-role']), 'invoice.view')).toBe(false)
  })

  it('anonymous requests never get role grants', async () => {
    expect(await can(null, 'invoice.view')).toBe(false)
    expect(await provider.filterFor(null, 'project.viewAny', 'project')).toEqual({ op: 'false' })
    expect(provider.roles.grantsFor(null, 'invoice', 'view', invoiceSchema)).toEqual([])
  })

  it('own: true allows only records whose ownerId is the actor (in memory and as a filter)', async () => {
    const member = user(['member'])
    expect(await can(member, 'invoice.update', 'invoice', { ownerId: ALICE, status: 'x' })).toBe(
      true,
    )
    expect(await can(member, 'invoice.update', 'invoice', { ownerId: BOB, status: 'x' })).toBe(
      false,
    )
    expect(await can(member, 'invoice.update', 'invoice', { ownerId: null, status: 'x' })).toBe(
      false,
    )
    // Without the record, an own grant cannot be decided: fail closed.
    expect((await provider.can(member, 'invoice.update')).reason).toBe(
      'record-required:role:member:*.update(own)',
    )
    // The deny for paid invoices is part of the list filter too.
    expect(await provider.filterFor(member, 'invoice.update', 'invoice')).toEqual({
      op: 'and',
      filters: [
        { op: 'eq', field: 'ownerId', value: ALICE },
        { op: 'not', filter: { op: 'eq', field: 'status', value: 'paid' } },
      ],
    })
  })

  it('own: true fails closed without a usable ownerId (missing, wrong type, unknown schema)', async () => {
    const member = user(['member'])
    expect(await can(member, 'country.update', 'country', { id: ALICE, name: 'x' })).toBe(false)
    expect(await provider.filterFor(member, 'country.update', 'country')).toEqual({ op: 'false' })
    const trace = provider.explain(member, 'country.update', {
      type: 'country',
      record: { id: ALICE, name: 'x' },
    })
    expect(trace.rules.map((r) => [r.rule.name, r.outcome])).toEqual([
      ['role:member:*.update(own):no-ownerId', 'does-not-cover'],
    ])
    expect(await can(member, 'ticket.update', 'ticket', { id: ALICE, ownerId: 1 })).toBe(false)
    expect(await provider.filterFor(member, 'ticket.update', 'ticket')).toEqual({ op: 'false' })
    // No policy and no schema: the owner column is unknown.
    expect(await can(member, 'project.update', 'project', { ownerId: ALICE })).toBe(false)
    expect(await provider.filterFor(member, 'project.update', 'project')).toEqual({ op: 'false' })
  })

  it('options.schemas lets own grants work on a resource without a policy', async () => {
    const projectSchema = defineSchema({
      table: 'projects',
      columns: { ownerId: { column: 'owner_id', type: 'text' } },
    })
    const withSchemas = createPermissionProvider([], {
      roles: compileRoleMap(ROLES),
      schemas: { project: projectSchema },
    })
    const member = user(['member'])
    const ok = await withSchemas.can(member, 'project.update', {
      type: 'project',
      record: { ownerId: ALICE },
    })
    expect(ok).toEqual({ allowed: true, reason: 'allow:role:member:*.update(own)' })
    expect(
      (
        await withSchemas.can(member, 'project.update', {
          type: 'project',
          record: { ownerId: BOB },
        })
      ).allowed,
    ).toBe(false)
    expect(await withSchemas.filterFor(member, 'project.delete', 'project')).toEqual({
      op: 'eq',
      field: 'ownerId',
      value: ALICE,
    })
  })

  it('an explicit policy deny wins over every role grant (admin * included)', async () => {
    for (const roles of [['admin'], ['member'], ['admin', 'member']]) {
      const a = user(roles)
      expect(await can(a, 'invoice.delete', 'invoice', { ownerId: ALICE, status: 'paid' })).toBe(
        false,
      )
      expect(
        (
          await provider.can(a, 'invoice.delete', {
            type: 'invoice',
            record: { ownerId: ALICE, status: 'paid' },
          })
        ).reason,
      ).toBe('deny:update|delete:signed-in+when')
    }
    expect(await provider.filterFor(user(['admin']), 'invoice.delete', 'invoice')).toEqual({
      op: 'not',
      filter: { op: 'eq', field: 'status', value: 'paid' },
    })
  })

  it('wildcards never match wildcardExclude resources; exact grants do', async () => {
    const admin = user(['admin'])
    expect(await can(admin, 'user.view')).toBe(true) // exact, global
    expect(await can(admin, 'user.update')).toBe(true) // exact, global
    expect(await can(admin, 'user.delete')).toBe(false) // only * would cover it: excluded
    expect(await can(admin, 'auditEvent.update')).toBe(false)
    expect(await can(user(['member']), 'user.view')).toBe(false)
    expect(await provider.filterFor(admin, 'auditEvent.viewAny', 'auditEvent')).toEqual({
      op: 'false',
    })
  })

  it("scope 'global' grants never reach a tenant's own admin; 'tenant' grants never leave tenants", async () => {
    const tenantAdmin = user(['admin'], { tenantId: TENANT })
    expect(await can(tenantAdmin, 'user.update')).toBe(false)
    expect(await can(user(['admin']), 'user.update')).toBe(true)
    const owner = user(['owner'], { tenantId: TENANT })
    expect(await can(owner, 'membership.create')).toBe(true)
    expect(await can(owner, 'invoice.approve')).toBe(true) // * inside the tenant
    const ownerOutside = user(['owner'])
    expect(await can(ownerOutside, 'membership.create')).toBe(false)
    expect(await can(ownerOutside, 'invoice.approve')).toBe(false)
  })

  it('inside a tenant, resource wildcards reach only tenant-scoped resources', async () => {
    const owner = user(['owner'], { tenantId: TENANT })
    // invoice has tenantId: covered. country is platform-wide data: never via a tenant wildcard.
    expect(await can(owner, 'invoice.update', 'invoice', { status: 'draft' })).toBe(true)
    expect(await can(owner, 'country.update', 'country', { id: ALICE, name: 'x' })).toBe(false)
    expect(await provider.filterFor(owner, 'country.viewAny', 'country')).toEqual({ op: 'false' })
    // Unknown schema (no policy): not known to be tenant-scoped, so not covered.
    expect(await can(owner, 'project.view')).toBe(false)
    // The same actor outside a tenant (global admin) does reach platform data.
    expect(await can(user(['admin']), 'country.update', 'country', { id: ALICE, name: 'x' })).toBe(
      true,
    )
    // A tenant member of a platform role (no scope = 'global') gets nothing inside the tenant.
    const member = user(['member'], { tenantId: TENANT })
    expect(await can(member, 'invoice.viewAny')).toBe(false)
    expect(await can(member, 'country.viewAny')).toBe(false)
    // An 'any' role inside a tenant reaches tenant data only, exact grants included.
    const anyScope = createPermissionProvider([invoicePolicy, countryPolicy], {
      roles: { roles: { member: { scope: 'any', permissions: ['*.viewAny', 'country.view'] } } },
    })
    expect((await anyScope.can(member, 'invoice.viewAny')).allowed).toBe(true)
    expect((await anyScope.can(member, 'country.viewAny')).allowed).toBe(false)
    expect((await anyScope.can(member, 'country.view')).allowed).toBe(false)
    expect((await anyScope.can(user(['member']), 'country.view')).allowed).toBe(true)
    // An exact grant of a tenant role is deliberate and is not bounded.
    const exact = createPermissionProvider([countryPolicy], {
      roles: { roles: { member: { scope: 'tenant', permissions: ['country.viewAny'] } } },
    })
    expect((await exact.can(member, 'country.viewAny')).allowed).toBe(true)
    expect((await exact.can(user(['member']), 'country.viewAny')).allowed).toBe(false)
  })

  it('explain() lists role grants beside policy rules', () => {
    const e = provider.explain(user(['manager', 'member']), 'invoice.approve')
    expect(e.decision).toEqual({ allowed: true, reason: 'allow:approve:role=manager' })
    const v = provider.explain(user(['viewer']), 'invoice.view', {
      type: 'invoice',
      record: { status: 'x' },
    })
    expect(v.rules.at(-1)).toMatchObject({
      rule: { name: 'role:viewer:*.view', effect: 'allow', roles: ['viewer'], scope: 'global' },
      outcome: 'covers',
    })
  })

  it('grants are cached per action without leaking between actions', () => {
    const member = user(['member'])
    const a = invoicePolicy.decide(
      member,
      'view',
      { status: 'x' },
      provider.roles.grantsFor(member, 'invoice', 'view', invoiceSchema),
    )
    const b = invoicePolicy.decide(
      member,
      'viewAny',
      undefined,
      provider.roles.grantsFor(member, 'invoice', 'viewAny', invoiceSchema),
    )
    expect([a.allowed, b.allowed]).toEqual([true, true])
    expect(invoicePolicy.can(member, 'view', { status: 'x' })).toBe(false) // no grants passed
  })

  it('a malformed grant passed to a policy is rejected', () => {
    expect(() => invoicePolicy.can(user([]), 'view', {}, [null as never])).toThrow(TypeError)
    expect(() =>
      invoicePolicy.can(user([]), 'view', {}, [
        { name: 'bad', when: { op: 'eq', field: 'nope', value: 1 } },
      ]),
    ).toThrow(PolicyDefinitionError)
  })
})

describe('role grants: SQL ≡ in-memory (PGlite)', () => {
  let db: PGlite
  const rows = [
    { id: '0190f2a0-0000-7000-8000-000000000001', owner: ALICE, tenant: TENANT, status: 'draft' },
    { id: '0190f2a0-0000-7000-8000-000000000002', owner: ALICE, tenant: TENANT, status: 'paid' },
    { id: '0190f2a0-0000-7000-8000-000000000003', owner: BOB, tenant: TENANT, status: 'draft' },
    { id: '0190f2a0-0000-7000-8000-000000000004', owner: null, tenant: null, status: null },
    { id: '0190f2a0-0000-7000-8000-000000000005', owner: BOB, tenant: null, status: 'paid' },
  ]
  const countries = [
    { id: '0190f2a0-0000-7000-8000-0000000000c1', name: 'a' },
    { id: '0190f2a0-0000-7000-8000-0000000000c2', name: null },
  ]

  beforeAll(async () => {
    db = new PGlite()
    await db.exec(`
      CREATE TABLE invoices (id uuid PRIMARY KEY, owner_id uuid, tenant_id uuid, status text);
      CREATE TABLE countries (id uuid PRIMARY KEY, name text);
    `)
    for (const r of rows)
      await db.query('INSERT INTO invoices VALUES ($1, $2, $3, $4)', [
        r.id,
        r.owner,
        r.tenant,
        r.status,
      ])
    for (const c of countries)
      await db.query('INSERT INTO countries VALUES ($1, $2)', [c.id, c.name])
  }, 60_000)
  afterAll(async () => {
    await db.close()
  })

  const actors: (Actor | null)[] = [
    null,
    user([]),
    user(['member']),
    user(['member'], { id: BOB }),
    user(['viewer']),
    user(['admin']),
    user(['admin', 'member']),
    user(['admin'], { tenantId: TENANT }),
    user(['owner'], { tenantId: TENANT }),
    user(['member'], { tenantId: TENANT }),
    user(['manager']),
  ]
  const actions = ['viewAny', 'view', 'create', 'update', 'delete', 'approve', 'export']

  it('invoice (ownerId, tenantId, a deny rule): filterFor selects exactly what can() allows', async () => {
    for (const a of actors) {
      for (const action of actions) {
        const filter = await provider.filterFor(a, `invoice.${action}`, 'invoice')
        const { sql, params } = compileToSql(filter, invoiceSchema)
        const viaSql = (
          await db.query<{ id: string }>(
            `SELECT t.id FROM invoices t WHERE ${sql} ORDER BY t.id`,
            params,
          )
        ).rows.map((r) => r.id)
        const viaCan: string[] = []
        for (const r of rows) {
          const record = { id: r.id, ownerId: r.owner, tenantId: r.tenant, status: r.status }
          if (await can(a, `invoice.${action}`, 'invoice', record)) viaCan.push(r.id)
        }
        expect(viaSql, `${JSON.stringify(a?.roles)} ${a?.tenantId ?? '-'} ${action}`).toEqual(
          viaCan,
        )
      }
    }
  })

  it('country (no ownerId, platform-wide): own grants and tenant wildcards select nothing', async () => {
    for (const a of actors) {
      for (const action of actions) {
        const filter = await provider.filterFor(a, `country.${action}`, 'country')
        const { sql, params } = compileToSql(filter, countrySchema)
        const viaSql = (
          await db.query<{ id: string }>(
            `SELECT t.id FROM countries t WHERE ${sql} ORDER BY t.id`,
            params,
          )
        ).rows.map((r) => r.id)
        const viaCan: string[] = []
        for (const c of countries)
          if (await can(a, `country.${action}`, 'country', { id: c.id, name: c.name }))
            viaCan.push(c.id)
        expect(viaSql).toEqual(viaCan)
        if (
          a?.tenantId !== undefined ||
          (a?.roles.includes('member') &&
            !a.roles.includes('admin') &&
            (action === 'update' || action === 'delete'))
        )
          expect(viaSql).toEqual([])
      }
    }
  })
})

describe('filterableFields (contracts PermissionProvider)', () => {
  const salarySchema = defineSchema({
    table: 'staff',
    columns: {
      id: { column: 'id', type: 'uuid' },
      name: { column: 'name', type: 'text' },
      salary: { column: 'salary', type: 'int4' },
    },
  })
  const staffPolicy = definePolicy('staff', { schema: salarySchema }, ({ allow, field }) => {
    allow('viewAny', { role: 'hr' })
    field('salary').readable({ role: 'hr' })
  })
  const p = createPermissionProvider([staffPolicy], {
    roles: ROLES,
    schemas: {
      project: defineSchema({
        table: 'projects',
        columns: { title: { column: 'title', type: 'text' } },
      }),
    },
  })

  it('equals the readable fields of the policy, per actor', async () => {
    expect([...(await p.filterableFields(user(['hr']), 'staff'))].sort()).toEqual([
      'id',
      'name',
      'salary',
    ])
    expect([...(await p.filterableFields(user(['admin']), 'staff'))].sort()).toEqual(['id', 'name'])
    expect([...(await p.filterableFields(null, 'staff'))].sort()).toEqual(['id', 'name'])
  })

  it('uses options.schemas for a role-only resource; unknown resources fail closed', async () => {
    expect([...(await p.filterableFields(user(['admin']), 'project'))]).toEqual(['title'])
    expect((await p.filterableFields(user(['admin']), 'nothing')).size).toBe(0)
    expect((await p.filterableFields(user(['admin']), 42 as unknown as string)).size).toBe(0)
    expect(Object.isFrozen(await p.filterableFields(user(['hr']), 'staff'))).toBe(true)
  })
})

describe('defineAuthConfig', () => {
  it('returns the same object, deep-frozen, ready for the provider', async () => {
    const input = { roles: { admin: { permissions: ['*'] } }, trustedProxies: [] as string[] }
    const config = defineAuthConfig(input)
    expect(config).toBe(input)
    expect(Object.isFrozen(config.roles.admin.permissions)).toBe(true)
    expect(compileRoleMap({ roles: config.roles }).grants).toHaveLength(1)
  })
})
