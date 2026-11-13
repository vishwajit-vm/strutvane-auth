/** Per-file databases inside the shared container, plus the tenancy fixture (roles, RLS, seed). */
import { randomBytes } from 'node:crypto'
import pg from 'pg'
import { inject } from 'vitest'
import { tenancyRolesSql, tenantRlsSql } from '../../src/postgres/index.ts'

export const TENANT_A = '0190f2a0-0000-7000-8000-0000000000a1'
export const TENANT_B = '0190f2a0-0000-7000-8000-0000000000b1'
export const PER_TENANT = 5

export interface TestDatabase {
  readonly name: string
  readonly url: (user?: string, password?: string) => string
  readonly admin: pg.Pool
  readonly drop: () => Promise<void>
}

/** Create an isolated database for one test file. */
export async function createDatabase(): Promise<TestDatabase> {
  const adminUrl = inject('pgAdminUrl')
  const name = `t_${randomBytes(6).toString('hex')}`
  const root = new pg.Client({ connectionString: adminUrl })
  await root.connect()
  await root.query(`CREATE DATABASE ${name}`)
  await root.end()
  const url = (user?: string, password?: string): string => {
    const u = new URL(adminUrl)
    u.pathname = `/${name}`
    if (user) {
      u.username = user
      u.password = password ?? ''
    }
    return u.toString()
  }
  const admin = new pg.Pool({ connectionString: url(), max: 4 })
  return {
    name,
    url,
    admin,
    drop: async () => {
      await admin.end().catch(() => undefined)
      const cleanup = new pg.Client({ connectionString: adminUrl })
      await cleanup.connect()
      await cleanup.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`)
      await cleanup.end()
    },
  }
}

/**
 * Roles (cluster-wide, so names are per database), an owned schema, an RLS-protected table and
 * seed rows for two tenants. Returns credentials for each role.
 */
export interface TenancyFixture {
  readonly owner: string
  readonly runtime: string
  readonly bypass: string
  readonly password: string
  readonly pool: (role: string, max?: number) => pg.Pool
}

export async function tenancyFixture(db: TestDatabase): Promise<TenancyFixture> {
  const suffix = db.name.slice(2)
  const owner = `own_${suffix}`
  const runtime = `app_${suffix}`
  const bypass = `byp_${suffix}`
  const password = randomBytes(12).toString('hex')
  const admin = db.admin
  for (const s of tenancyRolesSql({ owner, runtime }).up) await admin.query(s)
  // Passwords are set outside the generated migration, exactly as documented.
  await admin.query(`ALTER ROLE ${owner} PASSWORD '${password}'`)
  await admin.query(`ALTER ROLE ${runtime} PASSWORD '${password}'`)
  await admin.query(`CREATE ROLE ${bypass} LOGIN BYPASSRLS PASSWORD '${password}'`)
  await admin.query(`GRANT CONNECT ON DATABASE ${db.name} TO ${owner}, ${runtime}, ${bypass}`)
  await admin.query(`CREATE SCHEMA app AUTHORIZATION ${owner}`)
  const asOwner = new pg.Client({ connectionString: db.url(owner, password) })
  await asOwner.connect()
  try {
    await asOwner.query(
      'CREATE TABLE app.invoices (id serial PRIMARY KEY, tenant_id uuid NOT NULL, number text NOT NULL)',
    )
    for (const s of tenantRlsSql({ table: 'app.invoices', runtimeRole: runtime }).up)
      await asOwner.query(s)
    await asOwner.query(`GRANT USAGE ON SCHEMA app TO ${runtime}, ${bypass}`)
    await asOwner.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON app.invoices TO ${runtime}`)
    await asOwner.query(`GRANT SELECT ON app.invoices TO ${bypass}`)
    await asOwner.query(`GRANT USAGE ON SEQUENCE app.invoices_id_seq TO ${runtime}`)
  } finally {
    await asOwner.end()
  }
  for (const tenant of [TENANT_A, TENANT_B]) {
    for (let i = 0; i < PER_TENANT; i++) {
      await admin.query('INSERT INTO app.invoices (tenant_id, number) VALUES ($1, $2)', [
        tenant,
        `${tenant.slice(-2)}-${i}`,
      ])
    }
  }
  const pool = (role: string, max = 8) =>
    new pg.Pool({ connectionString: db.url(role, password), max })
  return { owner, runtime, bypass, password, pool }
}

/** Count rows visible to a query runner. */
export async function count(q: {
  query: (sql: string) => Promise<{ rows: { n: string | number }[] }>
}): Promise<number> {
  return Number((await q.query('SELECT count(*) AS n FROM app.invoices')).rows[0]?.n)
}
