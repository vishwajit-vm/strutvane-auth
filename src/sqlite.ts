/**
 * `@strutvane/auth/sqlite`: the native engine's SQLite store on Node's built-in `node:sqlite`.
 * A separate entry so apps on PostgreSQL never load `node:sqlite`.
 *
 * @example
 * ```ts
 * import { DatabaseSync } from 'node:sqlite'
 * import { sqliteAuthStore, sqliteCounterStore } from '@strutvane/auth/sqlite'
 * const db = new DatabaseSync('storage/database.sqlite')
 * const engine = createNativeEngine({ baseURL, appKey, store: sqliteAuthStore(db), counters: sqliteCounterStore(db) })
 * ```
 *
 * @module
 */
export { sqliteAuthStore, sqliteCounterStore } from './engine/store/sqlite.ts'
export { SQLITE_SCHEMA } from './engine/store/sqlite-schema.ts'
