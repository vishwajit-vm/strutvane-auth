const fs = require('node:fs')
const edit = (p, pairs) => {
  let s = fs.readFileSync(p, 'utf8')
  for (const [a, b] of pairs) {
    if (!s.includes(a)) throw new Error(`${p} missing: ${a.slice(0, 90)}`)
    s = s.replace(a, b)
  }
  fs.writeFileSync(p, s)
}

edit('test/app-identity.test.ts', [
  [
    `import { createAuthProvider } from '../src/provider.ts'
import { SQLITE_SCHEMA } from '../src/sqlite.ts'`,
    `import { AUTH_MIGRATIONS } from '../src/migrations.ts'
import { createAuthProvider } from '../src/provider.ts'
import { sqliteWithAuthSchema } from './support/auth-schema.ts'`,
  ],
  [
    `      const { DatabaseSync } = await import('node:sqlite')
      const db = new DatabaseSync(join(dir, 'app.sqlite'))
      db.exec(SQLITE_SCHEMA)
      db.close()`,
    `      // \`node strut migrate\` ran the skeleton's users migration and auth's migrations.
      sqliteWithAuthSchema(join(dir, 'app.sqlite')).close()`,
  ],
  [
    `        expect(await id.compileMigrations?.()).toContain('CREATE TABLE IF NOT EXISTS users')`,
    `        // The native engine never generates DDL: the tables are the app's migrations.
        expect(id.compileMigrations).toBeUndefined()`,
  ],
  [
    `      expect(sqliteFileFrom({ default: 'sqlite' }, dir)).toBe(join(dir, 'storage/database.sqlite'))`,
    `      expect(sqliteFileFrom({ default: 'sqlite' }, dir)).toBe(join(dir, 'database/database.sqlite'))
      // The skeleton's config/database.ts: a flat \`database\` key holds the SQLite file.
      expect(sqliteFileFrom({ default: 'sqlite', database: 'database/app.sqlite' }, dir)).toBe(
        join(dir, 'database/app.sqlite'),
      )`,
  ],
  [
    `    const memory = await project({ 'config/auth.ts': 'export default {}\\n' })
    expect((await run('auth:migration', cli(memory).ctx))?.exitCode).toBe(3)`,
    `    const memory = await project({ 'config/auth.ts': 'export default {}\\n' })`,
  ],
  [
    `    const r = cli(down)
    expect((await run('auth:migration', r.ctx))?.exitCode).toBe(5)
    expect(r.lines.join()).toMatch(/Cannot reach the database/)`,
    `    const r = cli(down)
    expect((await run('tenant:create', cli(down, { name: 'A', slug: 'a', owner: 'a@b.test' }).ctx))?.exitCode).toBe(5)
    process.env['SV_AUTH_PW'] = 'long-enough-password'
    expect(
      (
        await run(
          'auth:user:create',
          cli(down, { email: 'a@b.test', name: 'A', 'password-env': 'SV_AUTH_PW' }).ctx,
        )
      )?.exitCode,
    ).toBe(5)
    delete process.env['SV_AUTH_PW']
    // auth:migration needs no database: it only copies files (decision #2).
    expect((await run('auth:migration', r.ctx))?.exitCode).toBeUndefined()
    // The deprecated Better Auth adapter still compiles SQL, so it needs a database.
    const legacy = await project({
      '.env': \`APP_KEY=\${APP_KEY}\\n\`,
      'config/auth.ts': \`export default { identity: 'better-auth' }\\n\`,
    })
    expect((await run('auth:migration', cli(legacy).ctx))?.exitCode).toBe(3)`,
  ],
  [
    `  test('migration files: timestamp names and framework breakpoints', () => {`,
    `  test('auth:migration copies the shipped migrations once and never overwrites the app\\'s copy', async () => {
    const root = await project({ 'config/auth.ts': 'export default {}\\n' })
    const dir = join(root, 'database', 'migrations')
    const first = cli(root)
    expect((await run('auth:migration', first.ctx))?.data).toEqual({
      copied: AUTH_MIGRATIONS.map((f) => \`database/migrations/\${f}\`),
      present: [],
    })
    expect(first.lines.join('\\n')).toMatch(/node strut migrate/)
    // The app edits its copy; a second run leaves it alone.
    const edited = join(dir, AUTH_MIGRATIONS[0] ?? '')
    await writeFile(edited, '// mine\\n')
    const again = cli(root)
    expect((await run('auth:migration', again.ctx))?.data).toEqual({
      copied: [],
      present: AUTH_MIGRATIONS.map((f) => \`database/migrations/\${f}\`),
    })
    expect(again.lines.join('\\n')).toMatch(/already in database\\/migrations/)
    expect(await readFile(edited, 'utf8')).toBe('// mine\\n')
  })

  test('migration files: timestamp names and framework breakpoints', () => {`,
  ],
  [
    `import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'`,
    `import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'`,
  ],
])

edit('test/packaging.test.ts', [
  [
    `    expect(pkg.devDependencies?.[FRAMEWORK]).toBe('0.2.0-next.0')`,
    `    expect(pkg.devDependencies?.[FRAMEWORK]).toBe('0.2.0-next.1')`,
  ],
])

edit('test/readme.test.ts', [
  [
    `  it('works as documented (PostgreSQL store, the shipped migration, the full engine)', async () => {
    const { createNativeEngine } = await import('../src/index.ts')
    const { POSTGRES_AUTH_STATEMENTS, pgliteClient, postgresAuthStore, postgresCounterStore } =
      await import('../src/postgres/index.ts')
    const pg = await PGlite.create()
    try {
      for (const statement of POSTGRES_AUTH_STATEMENTS) await pg.query(statement)`,
    `  it('works as documented (PostgreSQL store, the migrated tables, the full engine)', async () => {
    const { createNativeEngine } = await import('../src/index.ts')
    const { pgliteClient, postgresAuthStore, postgresCounterStore } = await import(
      '../src/postgres/index.ts'
    )
    const pg = await PGlite.create()
    try {
      // What \`node strut migrate\` leaves: the app's users table plus auth's migrations.
      for (const statement of authSchema('postgres')) await pg.query(statement)`,
  ],
])
let r = fs.readFileSync('test/readme.test.ts', 'utf8')
r = r.replace(/(\nimport [^\n]*\n)(?!import)/, `$1import { authSchema } from './support/auth-schema.ts'\n`)
fs.writeFileSync('test/readme.test.ts', r)
console.log('ok')
