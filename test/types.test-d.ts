/** Type-level tests: misuse of the typed predicate builder must not compile. */
import type { PermissionProvider, QueryFilter } from '@strutvane/contracts'
import { describe, expectTypeOf, it } from 'vitest'
import {
  createPermissionProvider,
  defineAuthConfig,
  definePolicy,
  defineSchema,
  type Policy,
} from '../src/index.ts'

const schema = defineSchema({
  table: 'invoices',
  columns: {
    ownerId: { column: 'owner_id', type: 'uuid' },
    amount: { column: 'amount', type: 'int4' },
    title: { column: 'title', type: 'text' },
    paid: { column: 'paid', type: 'bool' },
  },
  relations: {
    customer: {
      table: 'customers',
      foreignKey: 'customer_id',
      targetKey: 'id',
      columns: { tier: { column: 'tier', type: 'int4' } },
    },
  },
})

describe('typed predicate builder', () => {
  it('accepts well-typed conditions', () => {
    const p = definePolicy(
      'invoice',
      { schema, attrs: { region: 'text', level: 'int4' } },
      ({ allow, deny, field }) => {
        allow('view', { when: ({ row, actor }) => row.ownerId.eq(actor.id) })
        allow('view', { when: ({ row }) => row.amount.between(1, 10) })
        allow('view', { when: ({ row, actor }) => row.customer.tier.gte(actor.attrs.level) })
        allow('view', { when: ({ row, actor }) => row.title.eq(actor.attrs.region) })
        allow('view', { when: ({ row }) => row.title.contains('x', { caseSensitive: true }) })
        deny('delete', { when: ({ row }) => row.paid.eq(true) })
        allow('view', { when: ({ row }) => row.title.eq(null) })
        field('title').readable({ role: 'manager' })
      },
    )
    expectTypeOf(p).toEqualTypeOf<Policy<typeof schema>>()
    expectTypeOf(p.filterFor(null, 'view')).toEqualTypeOf<QueryFilter>()
    expectTypeOf(createPermissionProvider([p])).toMatchTypeOf<PermissionProvider>()
  })

  it('rejects unknown fields, wrong value types and wrong operators', () => {
    definePolicy('invoice', { schema, attrs: { level: 'int4' } }, ({ allow, field }) => {
      // @ts-expect-error unknown field
      allow('view', { when: ({ row }) => row.amout.eq(1) })
      // @ts-expect-error string value for an int4 column
      allow('view', { when: ({ row }) => row.amount.eq('1') })
      // @ts-expect-error ordering on a text column
      allow('view', { when: ({ row }) => row.title.gt('a') })
      // @ts-expect-error text operators on a numeric column
      allow('view', { when: ({ row }) => row.amount.contains('1') })
      // @ts-expect-error text operators on a uuid column
      allow('view', { when: ({ row }) => row.ownerId.startsWith('0') })
      // @ts-expect-error actor id (string) compared with a number column
      allow('view', { when: ({ row, actor }) => row.amount.eq(actor.id) })
      // @ts-expect-error int attribute compared with a text column
      allow('view', { when: ({ row, actor }) => row.title.eq(actor.attrs.level) })
      // @ts-expect-error undeclared actor attribute
      allow('view', { when: ({ row, actor }) => row.title.eq(actor.attrs.region) })
      // @ts-expect-error unknown relation field
      allow('view', { when: ({ row }) => row.customer.nope.eq(1) })
      // @ts-expect-error field rules only for declared fields
      field('nope')
      // @ts-expect-error a condition must return a filter
      allow('view', { when: () => true })
    })
  })

  it('without declared attrs, actor.attrs has no properties', () => {
    definePolicy('invoice', { schema }, ({ allow }) => {
      // @ts-expect-error no attrs declared
      allow('view', { when: ({ row, actor }) => row.title.eq(actor.attrs.region) })
    })
  })
})

describe('defineAuthConfig', () => {
  it('accepts the documented shape and keeps literal types', () => {
    const config = defineAuthConfig({
      registration: true,
      roles: {
        admin: { permissions: ['*', { action: 'user.update', scope: 'global' }] },
        member: { permissions: ['*.view', { action: '*.update', own: true }] },
        owner: { scope: 'tenant', permissions: ['*'] },
      },
      wildcardExclude: ['user'],
      newModelDefaults: 'inherit-role-patterns',
      trustedOrigins: ['https://app.example.com'],
      trustedProxies: [],
      seedAdmin: { email: undefined, password: undefined, role: 'admin' },
    })
    expectTypeOf(config.newModelDefaults).toEqualTypeOf<'inherit-role-patterns'>()
  })

  it('rejects unknown keys and wrong value shapes', () => {
    // @ts-expect-error a typo is never silently ignored
    defineAuthConfig({ rolse: {} })
    // @ts-expect-error newModelDefaults is a closed set
    defineAuthConfig({ newModelDefaults: 'open' })
    // @ts-expect-error a role is { permissions: [...] }, not a bare list
    defineAuthConfig({ roles: { admin: ['*'] } })
    // @ts-expect-error scope is 'any' | 'global' | 'tenant'
    defineAuthConfig({ roles: { admin: { scope: 'platform', permissions: [] } } })
  })
})
