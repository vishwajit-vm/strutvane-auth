const fs = require('node:fs')
const p = 'src/commands.ts'
let s = fs.readFileSync(p, 'utf8')
const rep = (a, b) => { if (!s.includes(a)) throw new Error('missing: ' + a.slice(0, 80)); s = s.replace(a, b) }
rep(` * - \`auth:migration\`: writes \`database/migrations/<timestamp>_auth_identity.sql\` with the identity
 *   tables (native engine: the shipped migration, for apps that keep migrations in the app; the
 *   deprecated Better Auth adapter: only what is missing), applied by \`migrate\`.`,
` * - \`auth:migration\`: copies auth's migrations into \`database/migrations\` (native engine: the
 *   columns auth adds to the app's \`users\` table and auth's own tables, decision #2; files that are
 *   already there are left alone), applied by \`node strut migrate\`. The deprecated Better Auth
 *   adapter still gets \`<timestamp>_auth_identity.sql\` with only what is missing.`)
rep(`import { createAppIdentity, RATE_LIMIT_TABLE } from './identity/app-identity.ts'
import { engineConfigFrom } from './identity/engine-config.ts'
`, `import { createAppIdentity, RATE_LIMIT_TABLE } from './identity/app-identity.ts'
import { engineConfigFrom } from './identity/engine-config.ts'
import { copyAuthMigrations } from './migrations.ts'
`)
rep(`const migrationCommand: AuthCommand = {
  name: 'auth:migration',
  description: 'Write the migration that creates the auth tables (then run sv migrate)',
  details:
    'Compares the database with the tables persistent sign-in needs (accounts, sessions, tenants, memberships, rate limits) and writes only what is missing to database/migrations. Needs session.driver "database" on PostgreSQL.',
  async run(ctx) {
    return guarded(ctx, async () => {
      const project = await loadAuthProject(ctx.requireProject().root)
      if (project.auth.session?.driver === 'memory' || !project.database)`,
`/**
 * The native engine: copy the shipped migrations (idempotent, no database needed). The app owns
 * them from then on; \`node strut migrate\` applies them on any engine.
 */
function copyNativeMigrations(
  ctx: AuthCommandContext,
  root: string,
  dir: string,
): { readonly data: unknown } {
  const { copied, present } = copyAuthMigrations(dir)
  const rel = (file: string) => relative(root, join(dir, file)).replaceAll('\\', '/')
  for (const file of copied) ctx.out.success(\`Created \${rel(file)}\`)
  if (copied.length === 0) ctx.out.success('The auth migrations are already in database/migrations.')
  else ctx.out.info('Run: node strut migrate')
  return { data: { copied: copied.map(rel), present: present.map(rel) } }
}

const migrationCommand: AuthCommand = {
  name: 'auth:migration',
  description: 'Copy the auth migrations into database/migrations (then run node strut migrate)',
  details:
    'Copies the migrations persistent sign-in needs: the columns auth adds to your users table, and the tables for roles, sessions, tokens, passkeys, teams and rate limits. Files already in database/migrations are left as they are. Works on MySQL, MariaDB, PostgreSQL and SQLite.',
  async run(ctx) {
    return guarded(ctx, async () => {
      const project = await loadAuthProject(ctx.requireProject().root)
      if (project.auth.identity !== 'better-auth')
        return copyNativeMigrations(ctx, project.root, project.migrationsDirectory)
      if (project.auth.session?.driver === 'memory' || !project.database)`)
rep(`        // The native engine compiles its whole schema (idempotent), the adapter only what is
        // missing: either way, nothing to write once the tables exist.
        if (!missing && (sql === '' || identity.native !== undefined)) {`,
`        // The adapter compiles only what is missing: nothing to write once the tables exist.
        if (!missing && sql === '') {`)
rep(`        // The rate-limit table is ours, not Better Auth's; IF NOT EXISTS keeps it idempotent.
        const rateLimits =
          identity.native === undefined ? \`\${rateLimitTableSql({ table: RATE_LIMIT_TABLE })};\` : ''`,
`        // The rate-limit table is ours, not Better Auth's; IF NOT EXISTS keeps it idempotent.
        const rateLimits = \`\${rateLimitTableSql({ table: RATE_LIMIT_TABLE })};\``)
fs.writeFileSync(p, s)
console.log('ok')
