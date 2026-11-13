/** Runs the README quick-start examples against PGlite, so the README always matches the real API. */
import { PGlite } from '@electric-sql/pglite'
import { describe, expect, it } from 'vitest'
import { createPermissionProvider, definePolicy, defineSchema } from '../src/index.ts'
import { tenantRlsSql, withTenant } from '../src/postgres/index.ts'
import { compileToSql } from '../src/sql/index.ts'
import { actingAs } from '../src/testing/index.ts'

const ME = '0190f2a0-0000-7000-8000-00000000000a'
const OTHER = '0190f2a0-0000-7000-8000-00000000000b'

describe('README: policies that compile to SQL', () => {
  it('works as documented', async () => {
    const invoice = defineSchema({
      table: 'invoices',
      columns: {
        ownerId: { column: 'owner_id', type: 'uuid' },
        amount: { column: 'amount', type: 'int4' },
        status: { column: 'status', type: 'text' },
        internalNotes: { column: 'internal_notes', type: 'text' },
      },
    })
    const invoicePolicy = definePolicy('invoice', { schema: invoice }, ({ allow, deny, field }) => {
      allow(['viewAny', 'view'], { role: ['accountant', 'manager'] })
      allow(['view', 'update'], { when: ({ actor, row }) => row.ownerId.eq(actor.id) })
      allow('approve', { role: 'manager', when: ({ row }) => row.amount.lte(10_000) })
      deny('delete', { when: ({ row }) => row.status.eq('paid'), name: 'paid-is-final' })
      field('internalNotes').readable({ role: 'manager' })
    })
    const permissions = createPermissionProvider([invoicePolicy])
    const actor = actingAs({ id: ME })
    const record = { ownerId: ME, amount: 5, status: 'draft', internalNotes: 'x' }

    expect(await permissions.can(actor, 'invoice.update', { type: 'invoice', record })).toEqual({
      allowed: true,
      reason: 'allow:view|update:signed-in+when',
    })

    const pool = new PGlite()
    await pool.exec(
      'CREATE TABLE invoices (owner_id uuid, amount int4, status text, internal_notes text)',
    )
    await pool.query('INSERT INTO invoices VALUES ($1, 1, $3, null), ($2, 2, $3, null)', [
      ME,
      OTHER,
      'draft',
    ])
    const filter = await permissions.filterFor(actor, 'invoice.view', 'invoice')
    const where = compileToSql(filter, invoice, { alias: 'i' })
    const rows = (
      await pool.query(`SELECT * FROM invoices i WHERE ${where.sql} LIMIT 50`, where.params)
    ).rows
    expect(rows).toEqual([{ owner_id: ME, amount: 1, status: 'draft', internal_notes: null }])
    expect(invoicePolicy.maskRecord(actor, record)).not.toHaveProperty('internalNotes')
    await pool.close()
  })
})

describe('README: tenancy with row-level security', () => {
  it('works as documented', async () => {
    const db = new PGlite()
    await db.exec(
      'CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS; CREATE SCHEMA app; CREATE TABLE app.invoices (id int, tenant_id uuid)',
    )
    const { up } = tenantRlsSql({ table: 'app.invoices', runtimeRole: 'app_user' })
    for (const statement of up) await db.exec(statement)
    await db.exec('GRANT USAGE ON SCHEMA app TO app_user; GRANT SELECT ON app.invoices TO app_user')
    await db.query('INSERT INTO app.invoices VALUES (1, $1), (2, $2)', [ME, OTHER])
    await db.exec('SET ROLE app_user')
    const pool = {
      connect: async () => ({
        query: (text: string, values?: unknown[]) =>
          db.query<Record<string, unknown>>(text, values),
        release: () => undefined,
        on: () => undefined,
        off: () => undefined,
      }),
    }
    const tenantId = ME
    const rows = await withTenant(
      pool,
      tenantId,
      async (client) => (await client.query('SELECT * FROM app.invoices')).rows,
    )
    expect(rows).toEqual([{ id: 1, tenant_id: ME }])
    await db.close()
  })
})
