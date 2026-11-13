import type { PermissionProvider } from '@strutvane/contracts'
import { describe, expect, expectTypeOf, it } from 'vitest'
import { PolicyDefinitionError } from '../src/errors.ts'
import { definePolicy } from '../src/policy/policy.ts'
import { createPermissionProvider } from '../src/policy/provider.ts'
import { ALICE, actor, BOB, invoice, invoicePolicy, invoiceSchema } from './fixtures.ts'

const provider = createPermissionProvider([invoicePolicy])

describe('createPermissionProvider', () => {
  it('implements the contracts PermissionProvider', () => {
    expectTypeOf(provider).toMatchTypeOf<PermissionProvider>()
    expect(provider.policies).toEqual([invoicePolicy])
    expect(provider.policy('invoice')).toBe(invoicePolicy)
    expect(provider.policy('nope')).toBeUndefined()
  })

  it('routes "<resource>.<action>" to the policy', async () => {
    const manager = actor({ roles: ['manager'] })
    expect(await provider.can(manager, 'invoice.viewAny')).toEqual({
      allowed: true,
      reason: 'allow:viewAny|view:role=accountant|manager|admin',
    })
    expect(
      (
        await provider.can(actor(), 'invoice.update', {
          type: 'invoice',
          id: '1',
          record: invoice({ ownerId: ALICE }),
        })
      ).allowed,
    ).toBe(true)
    expect(
      (
        await provider.can(actor(), 'invoice.update', {
          type: 'invoice',
          record: invoice({ ownerId: BOB }),
        })
      ).allowed,
    ).toBe(false)
  })

  it('denies by default for unknown resources, actions, malformed permissions and mismatches', async () => {
    expect(await provider.can(actor(), 'customer.view')).toEqual({
      allowed: false,
      reason: 'default-deny:no-policy',
    })
    expect(await provider.can(actor({ roles: ['admin'] }), 'invoice.unknownAction')).toEqual({
      allowed: false,
      reason: 'default-deny',
    })
    expect(await provider.can(actor(), '*')).toEqual({
      allowed: false,
      reason: 'default-deny:invalid-permission',
    })
    expect(await provider.can(actor(), 'invoice.*')).toEqual({
      allowed: false,
      reason: 'default-deny:invalid-permission',
    })
    expect(await provider.can(actor(), 'a.b.c' as never)).toEqual({
      allowed: false,
      reason: 'default-deny:invalid-permission',
    })
    expect(await provider.can(actor(), 7 as never)).toEqual({
      allowed: false,
      reason: 'default-deny:invalid-permission',
    })
    expect(
      await provider.can(actor({ roles: ['admin'] }), 'invoice.view', { type: 'customer' }),
    ).toEqual({
      allowed: false,
      reason: 'default-deny:resource-mismatch',
    })
  })

  it('filterFor returns FALSE for anything it cannot resolve, and the policy filter otherwise', async () => {
    expect(await provider.filterFor(actor(), 'customer.view', 'customer')).toEqual({ op: 'false' })
    expect(await provider.filterFor(actor(), 'invoice.view', 'customer')).toEqual({ op: 'false' })
    expect(await provider.filterFor(actor(), 'bogus' as never, 'invoice')).toEqual({ op: 'false' })
    expect(await provider.filterFor(actor(), 'invoice.update', 'invoice')).toEqual({
      op: 'eq',
      field: 'ownerId',
      value: ALICE,
    })
  })

  it('explain works for known and unknown resources', () => {
    expect(provider.explain(actor(), 'nope.view').decision.reason).toBe('default-deny:no-policy')
    expect(
      provider.explain(actor(), 'invoice.update', { type: 'invoice', record: invoice() }).rules
        .length,
    ).toBeGreaterThan(0)
  })

  it('rejects two policies for one resource', () => {
    const twin = definePolicy('invoice', { schema: invoiceSchema }, () => {})
    expect(() => createPermissionProvider([invoicePolicy, twin])).toThrow(PolicyDefinitionError)
  })

  it('is frozen', () => {
    expect(Object.isFrozen(provider)).toBe(true)
  })
})
