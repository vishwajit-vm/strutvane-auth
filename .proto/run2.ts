import { replayInSandbox } from '@strutvane/framework/database'
const r = await replayInSandbox(process.argv[2]!, { timeoutMs: 60000 })
console.log(r.migrations.length, r.state.tables.map((t) => t.name).join(','))
