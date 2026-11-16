import { runWithContext } from '@strutvane/framework/core'
import { describe, expect, it } from 'vitest'
import { diffChanges, memoryAuditSink, recordAudit } from '../src/audit/audit.ts'
import { actor, TENANT_A, TENANT_B } from './fixtures.ts'

describe('diffChanges', () => {
  it('records only changed fields, sorted, with nulls for added/removed', () => {
    expect(diffChanges({ a: 1, b: 'x', c: true }, { a: 2, b: 'x', d: 'new' })).toEqual([
      { field: 'a', from: 1, to: 2 },
      { field: 'c', from: true, to: null },
      { field: 'd', from: null, to: 'new' },
    ])
  })

  it('compares dates, arrays and objects structurally', () => {
    const d = (s: string) => new Date(s)
    expect(
      diffChanges(
        { at: d('2026-01-01'), tags: ['a'], meta: { x: 1 } },
        { at: d('2026-01-01'), tags: ['a'], meta: { x: 1 } },
      ),
    ).toEqual([])
    expect(diffChanges({ tags: ['a'] }, { tags: ['a', 'b'] })).toHaveLength(1)
    expect(diffChanges({ meta: { x: 1 } }, { meta: { y: 1 } })).toHaveLength(1)
    expect(diffChanges({ v: [1] }, { v: { 0: 1 } })).toHaveLength(1)
    expect(diffChanges({ v: null }, { v: {} })).toHaveLength(1)
  })

  it('redacts sensitive fields (keeping the fact they changed) and nested secrets', () => {
    const changes = diffChanges(
      { passwordHash: 'old', apiToken: 'a', profile: { name: 'x', secret: 's1' } },
      { passwordHash: 'new', apiToken: 'b', profile: { name: 'y', secret: 's2' }, salary: 1 },
      { sensitive: ['salary'] },
    )
    expect(changes).toEqual([
      { field: 'apiToken', from: '[REDACTED]', to: '[REDACTED]', redacted: true },
      { field: 'passwordHash', from: '[REDACTED]', to: '[REDACTED]', redacted: true },
      {
        field: 'profile',
        from: { name: 'x', secret: '[REDACTED]' },
        to: { name: 'y', secret: '[REDACTED]' },
      },
      { field: 'salary', from: '[REDACTED]', to: '[REDACTED]', redacted: true },
    ])
    expect(JSON.stringify(changes)).not.toMatch(/old|new|s1|s2/)
  })

  it('ignores listed fields and handles create / delete', () => {
    expect(diffChanges(null, { a: 1, updatedAt: 'x' }, { ignore: ['updatedAt'] })).toEqual([
      { field: 'a', from: null, to: 1 },
    ])
    expect(diffChanges({ a: 1 }, null)).toEqual([{ field: 'a', from: 1, to: null }])
  })
})

describe('recordAudit', () => {
  const fixed = { now: () => new Date('2026-11-14T00:00:00Z'), id: () => 'id-1' }

  it('takes actor, tenant, request and trace ids from the request context', async () => {
    const sink = memoryAuditSink()
    const a = actor({ roles: ['manager'], attrs: { secretAttr: 'x' } })
    const event = await runWithContext({ actor: a, requestId: 'r1', traceId: 't1' }, () =>
      recordAudit(
        sink,
        {
          action: 'invoice.update',
          resource: { type: 'invoice', id: '42' },
          before: { amount: 1 },
          after: { amount: 2 },
        },
        fixed,
      ),
    )
    expect(event).toEqual({
      id: 'id-1',
      occurredAt: '2026-11-14T00:00:00.000Z',
      actor: { id: a.id, type: 'user' },
      tenantId: TENANT_A,
      action: 'invoice.update',
      resource: { type: 'invoice', id: '42' },
      changes: [{ field: 'amount', from: 1, to: 2 }],
      requestId: 'r1',
      traceId: 't1',
    })
    // Only the minimal actor stamp is stored: no roles, no attributes.
    expect(JSON.stringify(event)).not.toMatch(/manager|secretAttr/)
    expect(sink.events).toEqual([event])
    expect(Object.isFrozen(sink.events[0])).toBe(true)
  })

  it('records anonymous actions, explicit tenants, reasons and client info; ids are UUIDv7 by default', async () => {
    const sink = memoryAuditSink()
    const event = await recordAudit(sink, {
      action: 'auth.login.failed',
      actor: null,
      tenantId: TENANT_B,
      reason: 'INVALID_CREDENTIALS',
      ip: '203.0.113.9',
      userAgent: 'x'.repeat(2000),
      resource: { type: 'session' },
    })
    expect(event.actor).toBeNull()
    expect(event.tenantId).toBe(TENANT_B)
    expect(event.reason).toBe('INVALID_CREDENTIALS')
    expect(event.resource).toEqual({ type: 'session' })
    expect(event.userAgent).toHaveLength(512)
    expect(event.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7/)
    expect(event).not.toHaveProperty('changes')
    sink.clear()
    expect(sink.events).toEqual([])
  })

  it('omits changes when nothing changed, and uses the context tenant as a fallback', async () => {
    const sink = memoryAuditSink()
    const { tenantId: _t, ...global } = actor()
    const event = await runWithContext(
      { actor: global, tenant: { id: TENANT_B, strategy: 'shared' } },
      () => recordAudit(sink, { action: 'invoice.view', before: { a: 1 }, after: { a: 1 } }),
    )
    expect(event).not.toHaveProperty('changes')
    expect(event.tenantId).toBe(TENANT_B)
  })

  it('rejects malformed actions', async () => {
    const sink = memoryAuditSink()
    for (const action of [
      '',
      'noverb',
      'Invoice.update',
      'a.b\nforged log line',
      `a.${'b'.repeat(300)}`,
    ]) {
      await expect(recordAudit(sink, { action })).rejects.toThrow(TypeError)
    }
    expect(sink.events).toEqual([])
  })
})
