const fs = require('node:fs')
const p = 'test/engine/store-contract.test.ts'
let s = fs.readFileSync(p, 'utf8')
const rep = (a, b, all) => {
  if (!s.includes(a)) throw new Error('missing: ' + a.slice(0, 90))
  s = all ? s.split(a).join(b) : s.replace(a, b)
}
rep(`import { mkdtempSync, rmSync } from 'node:fs'`, `import { existsSync, mkdtempSync, rmSync } from 'node:fs'`)
rep(
  `import { Browser, harness, rejectsWith, START } from './helpers/harness.ts'`,
  `import { isUserId } from '../../src/engine/tokens/formats.ts'
import { sqliteWithAuthSchema } from '../support/auth-schema.ts'
import { Browser, harness, rejectsWith, START } from './helpers/harness.ts'`,
)
rep(
  `const openFile = (file: string): DatabaseSync => {
  const db = new DatabaseSync(file)`,
  `/** A connection to \`file\`; the first one migrates it (as \`node strut migrate\` would). */
const openFile = (file: string): DatabaseSync => {
  const db = existsSync(file) ? new DatabaseSync(file) : sqliteWithAuthSchema(file)`,
)
rep(
  `  ['sqlite', () => sqliteAuthStore(new DatabaseSync(':memory:'))],`,
  `  ['sqlite', () => sqliteAuthStore(sqliteWithAuthSchema())],`,
)
rep(
  `  it('advanceTotpStep only moves forward', async () => {
    const s = make()
    await s.createUser(user('u1', 'a@b.io'))
    expect(await s.advanceTotpStep('u1', 10)).toBe(true)
    expect(await s.advanceTotpStep('u1', 10)).toBe(false)
    expect(await s.advanceTotpStep('u1', 9)).toBe(false)
    expect(await s.advanceTotpStep('u1', 11)).toBe(true)
    expect(await s.advanceTotpStep('missing', 1)).toBe(false)
  })`,
  `  it('advanceTotpStep only moves forward', async () => {
    const s = make()
    const id = (await s.createUser(user(UUID_1, 'a@b.io')))?.id ?? ''
    expect(await s.advanceTotpStep(id, 10)).toBe(true)
    expect(await s.advanceTotpStep(id, 10)).toBe(false)
    expect(await s.advanceTotpStep(id, 9)).toBe(false)
    expect(await s.advanceTotpStep(id, 11)).toBe(true)
    expect(await s.advanceTotpStep('missing', 1)).toBe(false)
  })

  it('user ids are the store\\'s (the users table key); malformed ids are "not found", never an error', async () => {
    const s = make()
    const created = await s.createUser(user(UUID_1, 'a@b.io'))
    expect(created !== undefined && isUserId(created.id)).toBe(true)
    expect((await s.findUserById(created?.id ?? ''))?.email).toBe('a@b.io')
    for (const bad of ['abc', '1; DROP TABLE users', '01', '-1', '1.5', '9223372036854775808', ''])
      expect(await s.findUserById(bad), bad).toBeUndefined()
    expect(await s.listUserRoles('abc')).toEqual([])
    await s.updateUser('abc', { name: 'x' })
    expect(await s.advanceTotpStep('abc', 1)).toBe(false)
  })

  it('user times round-trip to the millisecond (stored as the framework\\'s timestamps)', async () => {
    const s = make()
    const created = await s.createUser({ ...user(UUID_1, 'a@b.io'), emailVerifiedAt: START + 7 })
    const id = created?.id ?? ''
    expect(created?.createdAt).toBe(START)
    expect(created?.emailVerifiedAt).toBe(START + 7)
    await s.updateUser(id, { twoFactorConfirmedAt: START + 9, emailVerifiedAt: null, name: 'Ada' })
    const after = await s.findUserById(id)
    expect(after?.twoFactorConfirmedAt).toBe(START + 9)
    expect(after?.emailVerifiedAt).toBeNull()
    expect(after?.name).toBe('Ada')
  })

  it('roles belong to the user row', async () => {
    const s = make()
    const id = (await s.createUser(user(UUID_1, 'a@b.io')))?.id ?? ''
    await s.setUserRoles(id, ['admin', 'admin', 'member'])
    expect(await s.listUserRoles(id)).toEqual(['admin', 'member'])
    await s.setUserRoles(id, [])
    expect(await s.listUserRoles(id)).toEqual([])
  })

  it('a passkey with a 1024-character credential id (the WebAuthn maximum) is stored and found', async () => {
    const s = make()
    const credentialId = 'A'.repeat(1024)
    await s.addPasskey({
      id: 'p-long',
      userId: 'u1',
      name: 'x',
      credentialId,
      publicKey: 'k',
      counter: 0,
      transports: ['usb'],
      backedUp: true,
      createdAt: 1,
      lastUsedAt: null,
    })
    expect((await s.findPasskeyByCredentialId(credentialId))?.id).toBe('p-long')
    expect(await s.findPasskeyByCredentialId(\`\${credentialId.slice(1)}B\`)).toBeUndefined()
  })`,
)
rep(
  `const user = (id: string, email: string): UserRecord => ({`,
  `const UUID_1 = '00000000-0000-4000-8000-000000000001'

const user = (id: string, email: string): UserRecord => ({`,
)
rep(`    await client.query('ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_state_check')
`, ``)
rep(`INSERT INTO sessions (id, user_id, state`, `INSERT INTO auth_sessions (id, user_id, state`, true)
rep(
  `  it('a corrupt number column fails closed instead of reading as NaN', async () => {
    const client = pgliteSchemaClient()
    const store = postgresAuthStore(client)
    await store.createUser(user('u', 'a@b.io'))
    await client.query("ALTER TABLE users ALTER COLUMN created_at TYPE text USING 'soon'")
    await expect(store.findUserById('u')).rejects.toThrow(TypeError)
  })`,
  `  it('a corrupt number column fails closed instead of reading as NaN', async () => {
    const client = pgliteSchemaClient()
    const store = postgresAuthStore(client)
    const id = (await store.createUser(user(UUID_1, 'a@b.io')))?.id ?? ''
    await client.query("ALTER TABLE users ALTER COLUMN two_factor_last_step TYPE text USING 'soon'")
    await expect(store.findUserById(id)).rejects.toThrow(TypeError)
  })

  it('a corrupt timestamp in the users table fails closed instead of reading as NaN', async () => {
    const client = pgliteSchemaClient()
    const store = postgresAuthStore(client)
    const id = (await store.createUser(user(UUID_1, 'a@b.io')))?.id ?? ''
    await client.query(
      "ALTER TABLE users ALTER COLUMN email_verified_at TYPE text USING 'yesterday-ish'",
    )
    await expect(store.findUserById(id)).rejects.toThrow(TypeError)
  })`,
)
rep(
  `    await a.createUser(user('u', 'a@b.io'))
    expect(await b.consumeOneTime('d', 'email-link')).toBeDefined()
    expect(await a.consumeOneTime('d', 'email-link')).toBeUndefined()
    expect(await b.advanceTotpStep('u', 5)).toBe(true)
    expect(await a.advanceTotpStep('u', 5)).toBe(false)`,
  `    const id = (await a.createUser(user(UUID_1, 'a@b.io')))?.id ?? ''
    expect(await b.consumeOneTime('d', 'email-link')).toBeDefined()
    expect(await a.consumeOneTime('d', 'email-link')).toBeUndefined()
    expect(await b.advanceTotpStep(id, 5)).toBe(true)
    expect(await a.advanceTotpStep(id, 5)).toBe(false)`,
)
rep(
  `    const db = new DatabaseSync(':memory:')
    const store = sqliteAuthStore(db)
    db.exec('PRAGMA ignore_check_constraints = ON')`,
  `    const db = sqliteWithAuthSchema()
    const store = sqliteAuthStore(db)`,
)
rep(
  `(c: ReturnType<typeof manualClock>) => sqliteCounterStore(new DatabaseSync(':memory:'), c),`,
  `(c: ReturnType<typeof manualClock>) => sqliteCounterStore(sqliteWithAuthSchema(), c),`,
)
fs.writeFileSync(p, s)

const q = 'test/engine/passwords.test.ts'
let t = fs.readFileSync(q, 'utf8')
const before = `        store === 'sqlite' ? new (await import('node:sqlite')).DatabaseSync(':memory:') : undefined`
if (!t.includes(before)) throw new Error('passwords: missing')
t = t.replace(before, `        store === 'sqlite' ? sqliteWithAuthSchema() : undefined`)
t = t.replace(/(\nimport [^\n]*\n)(?!import)/, `$1import { sqliteWithAuthSchema } from '../support/auth-schema.ts'\n`)
fs.writeFileSync(q, t)
console.log('ok')
