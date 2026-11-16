import { currentContext } from '@strutvane/framework/core'
import { describe, expect, it } from 'vitest'
import { PolicyDefinitionError } from '../src/errors.ts'
import { createActorRefs, createRow } from '../src/policy/builder.ts'
import { actingAs, runAs } from '../src/testing/index.ts'
import { invoiceSchema, TENANT_A } from './fixtures.ts'

describe('typed predicate builder (runtime)', () => {
  const row = createRow(invoiceSchema)
  const actor = createActorRefs({ region: 'text', n: 'int4' } as const)

  it('produces plain contracts QueryFilter data for every operator', () => {
    expect(row.status.eq('paid')).toEqual({ op: 'eq', field: 'status', value: 'paid' })
    expect(row.status.eq(null)).toEqual({ op: 'isNull', field: 'status' })
    expect(row.status.ne(null)).toEqual({ op: 'isNotNull', field: 'status' })
    expect(row.status.ne('x')).toEqual({ op: 'ne', field: 'status', value: 'x' })
    expect(row.amount.in([1, actor.attrs.n])).toEqual({
      op: 'in',
      field: 'amount',
      values: [1, { $actor: 'attrs.n' }],
    })
    expect(row.amount.nin([])).toEqual({ op: 'nin', field: 'amount', values: [] })
    expect(row.amount.isNull()).toEqual({ op: 'isNull', field: 'amount' })
    expect(row.amount.isNotNull()).toEqual({ op: 'isNotNull', field: 'amount' })
    expect(row.amount.gt(1)).toEqual({ op: 'gt', field: 'amount', value: 1 })
    expect(row.amount.gte(1).op).toBe('gte')
    expect(row.amount.lt(1).op).toBe('lt')
    expect(row.amount.lte(actor.attrs.n)).toEqual({
      op: 'lte',
      field: 'amount',
      value: { $actor: 'attrs.n' },
    })
    expect(row.amount.between(1, actor.attrs.n)).toEqual({
      op: 'between',
      field: 'amount',
      from: 1,
      to: { $actor: 'attrs.n' },
    })
    expect(row.title.contains('a')).toEqual({ op: 'contains', field: 'title', value: 'a' })
    expect(row.title.startsWith('a', { caseSensitive: true })).toEqual({
      op: 'startsWith',
      field: 'title',
      value: 'a',
      caseSensitive: true,
    })
    expect(row.title.endsWith('a', {})).toEqual({ op: 'endsWith', field: 'title', value: 'a' })
    expect(row.customer.region.eq(actor.attrs.region)).toEqual({
      op: 'eq',
      field: 'customer.region',
      value: { $actor: 'attrs.region' },
    })
    expect(row.ownerId.eq(actor.id)).toEqual({
      op: 'eq',
      field: 'ownerId',
      value: { $actor: 'id' },
    })
    expect(row.tenantId.eq(actor.tenantId)).toEqual({
      op: 'eq',
      field: 'tenantId',
      value: { $actor: 'tenantId' },
    })
  })

  it('strips anything but $actor from references (plain, serialisable data)', () => {
    const smuggled = { $actor: 'id', extra: 'x' } as never
    expect(row.ownerId.eq(smuggled)).toEqual({
      op: 'eq',
      field: 'ownerId',
      value: { $actor: 'id' },
    })
  })

  it('throws for unknown names and ignores symbols', () => {
    expect(() => Reflect.get(row, 'nope')).toThrow(PolicyDefinitionError)
    expect(() => Reflect.get(row.customer, 'nope')).toThrow(PolicyDefinitionError)
    expect(() => Reflect.get(actor.attrs, 'nope')).toThrow(PolicyDefinitionError)
    expect(() => Reflect.get(createActorRefs(undefined).attrs, 'any')).toThrow(
      PolicyDefinitionError,
    )
    expect(Reflect.get(row, Symbol.iterator)).toBeUndefined()
    expect(Reflect.get(row.customer, Symbol.iterator)).toBeUndefined()
    expect(Reflect.get(actor.attrs, Symbol.toPrimitive)).toBeUndefined()
  })
})

describe('testing helpers', () => {
  it('actingAs builds frozen actors and runAs sets the request context', () => {
    const a = actingAs({ roles: ['manager'], tenantId: TENANT_A })
    expect(a).toMatchObject({ type: 'user', roles: ['manager'], tenantId: TENANT_A })
    expect(Object.isFrozen(a)).toBe(true)
    expect(runAs(a, () => currentContext()?.actor)).toBe(a)
    expect(
      runAs(null, () => currentContext()?.tenant, { id: TENANT_A, strategy: 'shared' }),
    ).toEqual({ id: TENANT_A, strategy: 'shared' })
  })
})
