/**
 * `@strutvane/auth/sql`: compile a bound contracts `QueryFilter` (from `filterFor()`, or a UI
 * filter that passed the validation gate) to a parameterized Postgres `WHERE` fragment.
 *
 * @example
 * const filter = await provider.filterFor(actor, 'invoice.view', 'invoice')
 * const where = compileToSql(filter, invoiceSchema, { alias: 'i' })
 * await pool.query(`SELECT * FROM invoices i WHERE ${where.sql} ORDER BY i.id LIMIT 50`, where.params)
 *
 * @module
 */
export {
  type CompileOptions,
  compileToSql,
  compileToTokens,
  type RenderedSql,
  renderPostgres,
  type SqlParam,
  type Token,
} from './compile.ts'
