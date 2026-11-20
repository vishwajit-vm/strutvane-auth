import type { QueryFilter } from '@strutvane/framework/contracts'
import { describe, expect, it } from 'vitest'
import {
  FieldNotLoadedError,
  NotListFilterableError,
  PolicyDefinitionError,
} from '../src/errors.ts'
import { ActorAttributeError } from '../src/policy/bind.ts'
import { evaluateFilter } from '../src/policy/evaluate.ts'
import { definePolicy, type PolicyApi } from '../src/policy/policy.ts'
import { defineSchema } from '../src/policy/schema.ts'
import { ALICE, actor, BOB, invoice, invoicePolicy, invoiceSchema } from './fixtures.ts'

describe('definePolicy: combination', () => {
  it('denies by default', () => {
    const d = invoicePolicy.decide(actor({ roles: ['nobody'] }), 'approve', invoice())
    expect(d).toEqual({ allowed: false, reason: 'default-deny' })
  })

  it('allows by role and names the rule in the reason', () => {
    expect(invoicePolicy.decide(actor({ roles: ['manager'] }), 'viewAny')).toEqual({
      allowed: true,
      reason: 'allow:viewAny|view:role=accountant|manager|admin',
    })
  })

  it('applies when() conditions per record', () => {
    const owner = actor()
    expect(invoicePolicy.can(owner, 'update', invoice({ ownerId: ALICE }))).toBe(true)
    expect(invoicePolicy.can(owner, 'update', invoice({ ownerId: BOB }))).toBe(false)
    // uuid comparison is case-insensitive, like Postgres
    expect(invoicePolicy.can(owner, 'update', invoice({ ownerId: ALICE.toUpperCase() }))).toBe(true)
  })

  it('lets an explicit deny win over an allow', () => {
    const manager = actor({ roles: ['manager'] })
    expect(invoicePolicy.decide(manager, 'delete', invoice({ status: 'draft' })).allowed).toBe(true)
    expect(invoicePolicy.decide(manager, 'delete', invoice({ status: 'paid' }))).toEqual({
      allowed: false,
      reason: 'deny:only-drafts',
    })
    // ne matches null: a record without status is protected too
    expect(invoicePolicy.decide(manager, 'delete', invoice({ status: null })).allowed).toBe(false)
  })

  it('combines multiple allow rules with OR', () => {
    expect(
      invoicePolicy.can(actor({ roles: ['manager'] }), 'approve', invoice({ amount: 20_000 })),
    ).toBe(false)
    expect(
      invoicePolicy.can(
        actor({ roles: ['manager', 'director'] }),
        'approve',
        invoice({ amount: 20_000 }),
      ),
    ).toBe(true)
  })

  it('never applies rules to anonymous actors unless marked anonymous', () => {
    expect(invoicePolicy.can(null, 'view', invoice())).toBe(false)
    expect(invoicePolicy.can(null, 'read', invoice({ status: 'published' }))).toBe(true)
    expect(invoicePolicy.can(null, 'read', invoice({ status: 'draft' }))).toBe(false)
    expect(invoicePolicy.filterFor(null, 'view')).toEqual({ op: 'false' })
  })

  it('treats relation fields through null relations as null', () => {
    const regional = actor({ roles: ['regional'], id: BOB })
    expect(
      invoicePolicy.can(
        regional,
        'view',
        invoice({ customer: { id: ALICE, region: 'eu', tier: 1 } }),
      ),
    ).toBe(true)
    expect(invoicePolicy.can(regional, 'view', invoice({ customer: null }))).toBe(false)
  })

  it('a null actor attribute never matches null rows', () => {
    const regional = actor({ roles: ['regional'], id: BOB, attrs: { region: null } })
    expect(
      invoicePolicy.can(
        regional,
        'view',
        invoice({ customer: { id: ALICE, region: null, tier: 1 } }),
      ),
    ).toBe(false)
    // Only the owner rule remains: the regional rule folded away to FALSE.
    expect(invoicePolicy.filterFor(regional, 'view')).toEqual({
      op: 'eq',
      field: 'ownerId',
      value: BOB,
    })
  })

  it('throws when a referenced actor attribute is missing or mistyped', () => {
    expect(() =>
      invoicePolicy.can(actor({ roles: ['regional'], attrs: {} }), 'view', invoice()),
    ).toThrow(ActorAttributeError)
    expect(() =>
      invoicePolicy.can(actor({ roles: ['regional'], attrs: { region: 7 } }), 'view', invoice()),
    ).toThrow(ActorAttributeError)
    expect(() =>
      invoicePolicy.can(
        actor({ roles: ['regional'], attrs: { region: { x: 1 } } }),
        'view',
        invoice(),
      ),
    ).toThrow(ActorAttributeError)
  })

  it('throws when a needed field was not loaded (fails closed)', () => {
    const { ownerId: _omit, ...partial } = invoice()
    expect(() => invoicePolicy.can(actor(), 'update', partial)).toThrow(FieldNotLoadedError)
    expect(() =>
      invoicePolicy.can(actor({ roles: ['regional'] }), 'view', invoice({ customer: undefined })),
    ).toThrow(FieldNotLoadedError)
  })

  it('pre-resolved actor permissions act as an unconditional allow, still subject to deny', () => {
    const token = actor({ permissions: ['invoice.delete'] })
    expect(invoicePolicy.decide(token, 'delete', invoice()).reason).toBe('allow:actor-permission')
    expect(invoicePolicy.can(token, 'delete', invoice({ status: 'paid' }))).toBe(false)
    expect(invoicePolicy.can(actor({ permissions: ['*'] }), 'approve', invoice())).toBe(true)
    expect(invoicePolicy.can(actor({ permissions: ['invoice.*'] }), 'approve', invoice())).toBe(
      true,
    )
    expect(invoicePolicy.can(actor({ permissions: ['customer.*'] }), 'approve', invoice())).toBe(
      false,
    )
  })

  it('rejects malformed actors and actions', () => {
    expect(() => invoicePolicy.can({ id: ALICE } as never, 'view', invoice())).toThrow(TypeError)
    expect(() => invoicePolicy.can(actor(), '*', invoice())).toThrow(TypeError)
    expect(() => invoicePolicy.can(actor(), 'drop table', invoice())).toThrow(TypeError)
  })
})

describe('definePolicy: decisions without a record fail closed', () => {
  it('denies with record-required when a conditional allow is the only grant', () => {
    expect(invoicePolicy.decide(actor(), 'update')).toEqual({
      allowed: false,
      reason: 'record-required:view|update:signed-in+when',
    })
  })

  it('denies with record-required when a conditional deny could apply', () => {
    expect(invoicePolicy.decide(actor({ roles: ['manager'] }), 'delete')).toEqual({
      allowed: false,
      reason: 'record-required:only-drafts',
    })
  })

  it('decides when every applicable rule is constant after binding', () => {
    // The regional rule binds to FALSE for a null attribute, so it no longer depends on the record.
    expect(
      invoicePolicy.decide(actor({ roles: ['regional'], attrs: { region: null } }), 'view'),
    ).toEqual({
      allowed: false,
      reason: 'record-required:view|update:signed-in+when',
    })
    expect(invoicePolicy.decide(actor({ roles: ['director'] }), 'approve').allowed).toBe(true)
  })
})

describe('definePolicy: filterFor', () => {
  it('returns FALSE when nothing is allowed', () => {
    expect(invoicePolicy.filterFor(actor({ roles: [] }), 'approve')).toEqual({ op: 'false' })
  })

  it('returns TRUE for unconditional grants', () => {
    expect(invoicePolicy.filterFor(actor({ roles: ['director'] }), 'approve')).toEqual({
      op: 'true',
    })
  })

  it('binds actor references and combines allow AND NOT deny', () => {
    expect(invoicePolicy.filterFor(actor({ roles: ['manager'] }), 'delete')).toEqual({
      op: 'not',
      filter: { op: 'ne', field: 'status', value: 'draft' },
    })
    expect(invoicePolicy.filterFor(actor(), 'update')).toEqual({
      op: 'eq',
      field: 'ownerId',
      value: ALICE,
    })
  })

  it('agrees with decide() for every record', () => {
    const records = [
      invoice(),
      invoice({ ownerId: BOB }),
      invoice({ status: 'paid' }),
      invoice({ status: null }),
    ]
    for (const a of [
      actor(),
      actor({ roles: ['manager'] }),
      actor({ roles: ['regional'] }),
      null,
    ]) {
      for (const action of ['view', 'update', 'delete', 'approve', 'read']) {
        const filter = invoicePolicy.filterFor(a, action)
        for (const r of records) {
          expect(evaluateFilter(filter, r, invoiceSchema)).toBe(invoicePolicy.can(a, action, r))
        }
      }
    }
  })

  it('throws NotListFilterableError for check() rules', () => {
    const p = definePolicy('doc', { schema: invoiceSchema }, ({ allow }) => {
      allow('view', { check: ({ record: { title } }) => title === 'ok', name: 'js-check' })
    })
    expect(p.can(actor(), 'view', invoice({ title: 'ok' }))).toBe(true)
    expect(p.can(actor(), 'view', invoice({ title: 'no' }))).toBe(false)
    expect(p.decide(actor(), 'view')).toEqual({
      allowed: false,
      reason: 'record-required:js-check',
    })
    expect(() => p.filterFor(actor(), 'view')).toThrow(NotListFilterableError)
    expect(p.rules[0]?.listFilterable).toBe(false)
  })

  it('treats a check() returning a non-boolean as false', () => {
    const p = definePolicy('doc', { schema: invoiceSchema }, ({ allow }) => {
      allow('view', { check: () => 'yes' as unknown as boolean })
    })
    expect(p.can(actor(), 'view', invoice())).toBe(false)
  })
})

describe('definePolicy: explain', () => {
  it('traces every rule', () => {
    const e = invoicePolicy.explain(
      actor({ roles: ['manager'] }),
      'delete',
      invoice({ status: 'paid' }),
    )
    expect(e.decision.allowed).toBe(false)
    expect(e.rules.map((r) => [r.rule.name, r.outcome])).toEqual([
      ['delete:role=manager|admin', 'covers'],
      ['only-drafts', 'covers'],
    ])
    const anon = invoicePolicy.explain(null, 'view', invoice())
    expect(anon.rules.every((r) => r.outcome === 'not-applicable')).toBe(true)
    const noRecord = invoicePolicy.explain(actor(), 'update')
    expect(noRecord.rules[0]?.outcome).toBe('depends-on-record')
    const miss = invoicePolicy.explain(actor(), 'update', invoice({ ownerId: BOB }))
    expect(miss.rules[0]?.outcome).toBe('does-not-cover')
  })

  it('lists actions and frozen rule metadata', () => {
    expect(invoicePolicy.actions).toEqual([
      'viewAny',
      'view',
      'update',
      'approve',
      'delete',
      'read',
    ])
    expect(Object.isFrozen(invoicePolicy.rules[0])).toBe(true)
  })
})

describe('definePolicy: wildcard actions', () => {
  it('a "*" rule applies to every action', () => {
    const p = definePolicy('doc', { schema: invoiceSchema }, ({ allow, deny }) => {
      allow('*', { role: 'admin' })
      deny('purge', { role: 'admin' })
    })
    expect(p.can(actor({ roles: ['admin'] }), 'anything')).toBe(true)
    expect(p.can(actor({ roles: ['admin'] }), 'purge')).toBe(false)
    expect(p.actions).toEqual(['purge'])
  })
})

describe('definePolicy: field rules', () => {
  it('masks unreadable fields and reports unwritable ones', () => {
    const member = actor()
    const manager = actor({ roles: ['manager'] })
    const director = actor({ roles: ['director'] })
    expect(invoicePolicy.readableFields(member)).not.toContain('internalNotes')
    expect(invoicePolicy.readableFields(manager)).toContain('internalNotes')
    expect(invoicePolicy.maskRecord(member, invoice())).not.toHaveProperty('internalNotes')
    expect(invoicePolicy.maskRecord(manager, invoice())).toHaveProperty('internalNotes', 'secret')
    expect(invoicePolicy.maskRecord(null, invoice())).not.toHaveProperty('internalNotes')
    expect(invoicePolicy.unwritableFields(manager, { title: 'x', internalNotes: 'y' })).toEqual([
      'internalNotes',
    ])
    expect(invoicePolicy.unwritableFields(director, { title: 'x', internalNotes: 'y' })).toEqual([])
    expect(invoicePolicy.writableFields(member)).not.toContain('internalNotes')
    expect(invoicePolicy.writableFields(director)).toContain('internalNotes')
  })

  it('readable() without roles means any signed-in actor', () => {
    const p = definePolicy('doc', { schema: invoiceSchema }, ({ field }) => {
      field('title').readable()
    })
    expect(p.readableFields(actor())).toContain('title')
    expect(p.readableFields(null)).not.toContain('title')
  })
})

describe('definePolicy: definition-time validation', () => {
  const attrs = { region: 'text', n: 'int4' } as const
  type Api = PolicyApi<typeof invoiceSchema, typeof attrs>
  const bad = (build: (api: Api) => void) =>
    definePolicy('doc', { schema: invoiceSchema, attrs }, build)
  /** Reach past the typed proxies, as untyped JavaScript could. */
  const untyped = (
    proxy: object,
    name: string,
  ): { eq(v: unknown): QueryFilter; gt(v: unknown): QueryFilter } => Reflect.get(proxy, name)

  it.each<[string, () => unknown]>([
    [
      'unknown field',
      () => bad(({ allow }) => allow('view', { when: ({ row }) => untyped(row, 'nope').eq('x') })),
    ],
    [
      'unknown relation field',
      () =>
        bad(({ allow }) =>
          allow('view', { when: ({ row }) => untyped(row.customer, 'nope').eq('x') }),
        ),
    ],
    [
      'wrong value type',
      () => bad(({ allow }) => allow('view', { when: ({ row }) => row.amount.eq('x' as never) })),
    ],
    [
      'actor id vs float8 column',
      () =>
        bad(({ allow }) =>
          allow('view', { when: ({ row, actor }) => row.score.eq(actor.id as never) }),
        ),
    ],
    [
      'actor id vs bool column',
      () =>
        bad(({ allow }) =>
          allow('view', { when: ({ row, actor }) => row.archived.eq(actor.id as never) }),
        ),
    ],
    [
      'tenant id vs int4 column',
      () =>
        bad(({ allow }) =>
          allow('view', { when: ({ row, actor }) => row.amount.eq(actor.tenantId as never) }),
        ),
    ],
    [
      'undeclared attr',
      () =>
        bad(({ allow }) =>
          allow('view', {
            when: ({ row, actor }) => row.region.eq(Reflect.get(actor.attrs, 'missing')),
          }),
        ),
    ],
    [
      'attr type mismatch',
      () =>
        bad(({ allow }) =>
          allow('view', { when: ({ row, actor }) => row.region.eq(actor.attrs.n as never) }),
        ),
    ],
    [
      'ordering on text',
      () => bad(({ allow }) => allow('view', { when: ({ row }) => untyped(row, 'title').gt(1) })),
    ],
    [
      'unsupported actor path',
      () =>
        bad(({ allow }) =>
          allow('view', {
            when: () => ({ op: 'eq', field: 'title', value: { $actor: 'email' as never } }),
          }),
        ),
    ],
    ['invalid action', () => bad(({ allow }) => allow('drop table'))],
    ['no actions', () => bad(({ allow }) => allow([]))],
    ['anonymous + role', () => bad(({ allow }) => allow('view', { anonymous: true, role: 'x' }))],
    ['empty role', () => bad(({ allow }) => allow('view', { role: '' }))],
    [
      'when returns nothing',
      () => bad(({ allow }) => allow('view', { when: () => undefined as never })),
    ],
    ['unknown field rule', () => bad(({ field }) => field('nope' as never))],
    ['bad resource name', () => definePolicy('Bad Name', { schema: invoiceSchema }, () => {})],
    [
      'unknown attr type',
      () => definePolicy('doc', { schema: invoiceSchema, attrs: { x: 'date' as never } }, () => {}),
    ],
    [
      'attrs referenced without a declaration',
      () =>
        definePolicy('doc', { schema: invoiceSchema }, ({ allow }) =>
          allow('view', { when: ({ row, actor }) => row.region.eq(Reflect.get(actor.attrs, 'x')) }),
        ),
    ],
  ])('rejects %s', (_name, fn) => {
    expect(fn).toThrow(PolicyDefinitionError)
  })

  it('accepts int4 attributes compared with float8 columns', () => {
    const p = bad(({ allow }) =>
      allow('view', { when: ({ row, actor }) => row.score.gte(actor.attrs.n) }),
    )
    expect(p.can(actor({ attrs: { region: 'eu', n: 1 } }), 'view', invoice({ score: 1.5 }))).toBe(
      true,
    )
  })

  it('supports relations, tenantId references and the logical helpers', () => {
    const p = definePolicy('doc', { schema: invoiceSchema }, ({ allow }) => {
      allow('view', {
        when: ({ row, actor, and, or, not }) =>
          and(
            row.tenantId.eq(actor.tenantId),
            or(row.customer.tier.gte(1), not(row.archived.eq(true))),
          ),
      })
    })
    expect(p.can(actor(), 'view', invoice())).toBe(true)
    const { tenantId: _t, ...global } = actor()
    expect(p.can(global, 'view', invoice())).toBe(false)
  })

  it('rejects actor ids that do not fit a uuid column at request time', () => {
    expect(() => invoicePolicy.can(actor({ id: 'not-a-uuid' }), 'update', invoice())).toThrow(
      ActorAttributeError,
    )
  })

  it('schemas reject unsafe identifiers', () => {
    expect(() => defineSchema({ table: 'x; drop', columns: {} })).toThrow(PolicyDefinitionError)
    expect(() =>
      defineSchema({ table: 't', columns: { a: { column: 'A"b', type: 'text' } } }),
    ).toThrow(PolicyDefinitionError)
    expect(() => defineSchema({ table: 'a.b.c', columns: {} })).toThrow(PolicyDefinitionError)
    expect(() =>
      defineSchema({ table: 't', columns: { 'bad name': { column: 'a', type: 'text' } } }),
    ).toThrow(PolicyDefinitionError)
    expect(() =>
      defineSchema({ table: 't', columns: { a: { column: 'a', type: 'date' as never } } }),
    ).toThrow(PolicyDefinitionError)
    expect(() =>
      defineSchema({
        table: 't',
        columns: { a: { column: 'a', type: 'text' } },
        relations: { a: { table: 'u', foreignKey: 'a', targetKey: 'id', columns: {} } },
      }),
    ).toThrow(PolicyDefinitionError)
    expect(() =>
      defineSchema({
        table: 't',
        columns: {},
        relations: { 'b c': { table: 'u', foreignKey: 'a', targetKey: 'id', columns: {} } },
      }),
    ).toThrow(PolicyDefinitionError)
  })
})
