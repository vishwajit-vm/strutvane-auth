/** Shared test fixtures: an invoice model with a to-one customer relation, and actors. */
import type { Actor } from '@strutvane/contracts'
import { definePolicy, type Policy } from '../src/policy/policy.ts'
import { defineSchema } from '../src/policy/schema.ts'

export const invoiceSchema = {
  table: 'invoices',
  columns: {
    id: { column: 'id', type: 'uuid' },
    ownerId: { column: 'owner_id', type: 'uuid' },
    tenantId: { column: 'tenant_id', type: 'uuid' },
    status: { column: 'status', type: 'text' },
    title: { column: 'title', type: 'text' },
    amount: { column: 'amount', type: 'int4' },
    score: { column: 'score', type: 'float8' },
    archived: { column: 'archived', type: 'bool' },
    region: { column: 'region', type: 'text' },
    internalNotes: { column: 'internal_notes', type: 'text' },
  },
  relations: {
    customer: {
      table: 'customers',
      foreignKey: 'customer_id',
      targetKey: 'id',
      columns: {
        id: { column: 'id', type: 'uuid' },
        region: { column: 'region', type: 'text' },
        tier: { column: 'tier', type: 'int4' },
      },
    },
  },
} as const
defineSchema(invoiceSchema)

export const ALICE = '0190f2a0-0000-7000-8000-00000000000a'
export const BOB = '0190f2a0-0000-7000-8000-00000000000b'
export const TENANT_A = '0190f2a0-0000-7000-8000-0000000000a1'
export const TENANT_B = '0190f2a0-0000-7000-8000-0000000000b1'

export function actor(overrides: Partial<Actor> = {}): Actor {
  return {
    id: ALICE,
    type: 'user',
    roles: [],
    attrs: { region: 'eu' },
    tenantId: TENANT_A,
    ...overrides,
  }
}

/** The policy from the auth spec (07-package-auth §4.2), adapted to the fixture schema. */
export const invoicePolicy: Policy<typeof invoiceSchema> = definePolicy(
  'invoice',
  { schema: invoiceSchema, attrs: { region: 'text' } },
  ({ allow, deny, field }) => {
    allow(['viewAny', 'view'], { role: ['accountant', 'manager', 'admin'] })
    allow(['view', 'update'], { when: ({ actor, row }) => row.ownerId.eq(actor.id) })
    allow('view', {
      role: 'regional',
      when: ({ actor, row }) => row.customer.region.eq(actor.attrs.region),
    })
    allow('approve', {
      role: 'manager',
      when: ({ row }) => row.amount.lte(10_000),
      name: 'manager-small',
    })
    allow('approve', { role: 'director' })
    allow('delete', { role: ['manager', 'admin'] })
    deny('delete', { when: ({ row }) => row.status.ne('draft'), name: 'only-drafts' })
    allow('read', { anonymous: true, when: ({ row }) => row.status.eq('published') })
    field('internalNotes')
      .readable({ role: ['manager', 'director'] })
      .writable({ role: 'director' })
  },
)

/** A loaded invoice record. */
export interface InvoiceRecord {
  readonly [field: string]: unknown
  readonly id: string
}

/** A full invoice record (every field loaded). */
export function invoice(overrides: Record<string, unknown> = {}): InvoiceRecord {
  return {
    id: '0190f2a0-0000-7000-8000-000000000100',
    ownerId: ALICE,
    tenantId: TENANT_A,
    status: 'draft',
    title: 'Hello',
    amount: 500,
    score: 1.5,
    archived: false,
    region: 'eu',
    internalNotes: 'secret',
    customer: { id: '0190f2a0-0000-7000-8000-000000000200', region: 'eu', tier: 1 },
    ...overrides,
  } as InvoiceRecord
}
