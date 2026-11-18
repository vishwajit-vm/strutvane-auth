import { mkdirSync, mkdtempSync, cpSync, readFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import commands from '@strutvane/framework/commands'
const root = mkdtempSync(join(tmpdir(), 'sv-sync-'))
mkdirSync(join(root, 'database', 'migrations'), { recursive: true })
for (const f of readdirSync('.proto/m')) cpSync(join('.proto/m', f), join(root, 'database', 'migrations', f))
const list = (Array.isArray(commands) ? commands : []) as { name: string; run: (ctx: unknown) => Promise<unknown> }[]
const sync = list.find((c) => c.name === 'sync')
console.log('commands', list.map((c) => c.name).join(' '))
const out = { line: console.log, success: console.log, info: console.log, warn: console.log, error: console.log }
await sync!.run({ flags: {}, requireProject: () => ({ root }), out, services: { env: {} } })
console.log(readdirSync(join(root, '.strutvane', 'sql')))
console.log(readFileSync(join(root, '.strutvane', 'sql', 'migrations.mysql.sql'), 'utf8').slice(0, 5000))
const res = JSON.parse(readFileSync(join(root, '.strutvane', 'resources.json'), 'utf8'))
console.log('RES', JSON.stringify(res).slice(0, 600))
const sch = JSON.parse(readFileSync(join(root, '.strutvane', 'schema.json'), 'utf8'))
console.log('SCH', JSON.stringify(sch).slice(0, 300))
console.log(JSON.stringify((sch.tables ?? sch.state?.tables ?? []).map((t: { name: string; internal?: boolean; options?: unknown }) => [t.name, t.internal, t.options])))
