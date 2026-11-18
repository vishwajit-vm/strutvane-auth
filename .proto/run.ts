import { join } from 'node:path'
import { PGlite } from '@electric-sql/pglite'
import { Connection, pgliteDriver, replayInSandbox, runMigrations, sqliteDriver } from '@strutvane/framework/database'
const dir = join(import.meta.dirname, 'm')
const t0 = Date.now()
const replay = await replayInSandbox(dir, { timeoutMs: 60000 })
console.log('replay ms', Date.now() - t0)
for (const [name, mk] of [['sqlite', () => new Connection(sqliteDriver(':memory:'))], ['postgres', async () => new Connection(pgliteDriver(await PGlite.create()))]] as const) {
  const c = await mk()
  const r = await runMigrations(c, replay, { pretend: true })
  console.log('=====', name)
  console.log(JSON.stringify(r, null, 1).slice(0, 6000))
  const r2 = await runMigrations(c, replay)
  console.log('applied', JSON.stringify(r2).slice(0, 300))
  await c.close()
}
