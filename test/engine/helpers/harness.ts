/**
 * Test harness: an auth instance on a chosen store, a manual clock, a fake browser with a real
 * cookie jar, and recorders for mail, events and logs (the redaction tests scan them).
 */
import { randomBytes } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'
import { type Auth, createAuth } from '../../../src/engine/auth.ts'
import { type AuthConfigInput, defineAuthConfig } from '../../../src/engine/config.ts'
import { createScryptHasher, type PasswordHasher } from '../../../src/engine/password/hasher.ts'
import type { PasswordCheck } from '../../../src/engine/password/rules.ts'
import { type ManualClock, manualClock } from '../../../src/engine/ports/clock.ts'
import type { AuthRequest, CookieJar, CookieOptions } from '../../../src/engine/ports/cookies.ts'
import type { CounterStore } from '../../../src/engine/ports/counter-store.ts'
import type { AuthEvent } from '../../../src/engine/ports/events.ts'
import type { AuthMail } from '../../../src/engine/ports/mailer.ts'
import type { AuthStore, UserRecord } from '../../../src/engine/ports/store.ts'
import { memoryAuthStore, memoryCounterStore } from '../../../src/engine/store/memory.ts'
import { sqliteAuthStore, sqliteCounterStore } from '../../../src/engine/store/sqlite.ts'

/** Both stores every behaviour suite runs against. */
export const STORES = ['memory', 'sqlite'] as const
export type StoreKind = (typeof STORES)[number]

export const START: number = Date.UTC(2026, 10, 15, 9, 0, 0)
export const APP_KEY: string = `base64:${randomBytes(32).toString('base64')}`
export const PASSWORD = 'correct-horse-battery-staple-42'
/** One shared fast hasher: the dummy hash is computed once for the whole run. */
export const FAST_HASHER: PasswordHasher = createScryptHasher({ params: { logN: 14, r: 8, p: 1 } })

/** A browser: a cookie jar that persists across requests, with an IP. */
export class Browser implements CookieJar {
  readonly jar: Map<string, string> = new Map<string, string>()
  ip: string | undefined
  userAgent: string
  constructor(ip: string | undefined = '203.0.113.10', userAgent = 'TestBrowser/1.0') {
    this.ip = ip
    this.userAgent = userAgent
  }
  get(name: string): string | undefined {
    return this.jar.get(name)
  }
  set(name: string, value: string, _options?: CookieOptions): void {
    this.jar.set(name, value)
  }
  clear(name: string): void {
    this.jar.delete(name)
  }
  /** The request context for the next call. */
  get req(): AuthRequest {
    return { cookies: this, ip: this.ip, userAgent: this.userAgent }
  }
  /** A copy of this browser's cookies in another browser (a stolen or planted cookie). */
  clone(ip?: string): Browser {
    const b = new Browser(ip ?? this.ip)
    for (const [k, v] of this.jar) b.jar.set(k, v)
    return b
  }
}

export interface HarnessOptions {
  readonly store?: StoreKind
  readonly config?: Partial<AuthConfigInput>
  readonly hasher?: PasswordHasher
  readonly passwordCheck?: PasswordCheck
  readonly db?: DatabaseSync
  readonly clock?: ManualClock
}

export interface Harness {
  readonly auth: Auth
  readonly clock: ManualClock
  readonly store: AuthStore
  readonly counters: CounterStore
  readonly mails: AuthMail[]
  readonly events: AuthEvent[]
  readonly logs: string[]
  /** Every secret handed to a user during the test (for redaction checks). */
  readonly secrets: Set<string>
  /** Wait for background mail, then return the last mail of `kind` (to `to`, if given). */
  mail(kind: AuthMail['kind'], to?: string): Promise<AuthMail>
  /** The secret token at the end of the last mailed URL of `kind`. */
  mailedToken(kind: AuthMail['kind'], to?: string): Promise<string>
  eventsOf<T extends AuthEvent['type']>(type: T): Extract<AuthEvent, { type: T }>[]
  user(
    email?: string,
    opts?: {
      readonly roles?: readonly string[]
      readonly password?: string | null
      readonly verified?: boolean
    },
  ): Promise<UserRecord>
  /** A browser signed in as `email` (password sign-in; fails if 2FA is pending). */
  signedIn(email: string, ip?: string): Promise<Browser>
}

/** Build a harness. */
export function harness(options: HarnessOptions = {}): Harness {
  const clock = options.clock ?? manualClock(START)
  const kind = options.store ?? 'memory'
  const db = options.db ?? (kind === 'sqlite' ? new DatabaseSync(':memory:') : undefined)
  const store = db ? sqliteAuthStore(db) : memoryAuthStore()
  const counters = db ? sqliteCounterStore(db, clock) : memoryCounterStore(clock)
  const mails: AuthMail[] = []
  const events: AuthEvent[] = []
  const logs: string[] = []
  const secrets = new Set<string>()
  const auth = createAuth({
    config: defineAuthConfig({ appUrl: 'http://localhost:3000', ...options.config }),
    store,
    counters,
    clock,
    appKey: APP_KEY,
    hasher: options.hasher ?? FAST_HASHER,
    mailer: {
      async send(mail) {
        mails.push(mail)
        if ('url' in mail) secrets.add(mail.url)
      },
    },
    events: { emit: (e) => void events.push(e) },
    logger: {
      warn: (message, context) => void logs.push(`${message} ${JSON.stringify(context ?? {})}`),
    },
    ...(options.passwordCheck ? { passwordCheck: options.passwordCheck } : {}),
  })
  const h: Harness = {
    auth,
    clock,
    store,
    counters,
    mails,
    events,
    logs,
    secrets,
    async mail(kind, to) {
      await auth.idle()
      const found = mails.filter((m) => m.kind === kind && (to === undefined || m.to === to)).at(-1)
      if (!found) throw new Error(`no ${kind} mail${to ? ` to ${to}` : ''}`)
      return found
    },
    async mailedToken(kind, to) {
      const mail = await h.mail(kind, to)
      if (!('url' in mail)) throw new Error('mail has no url')
      const token = new URL(mail.url).pathname.split('/').at(-1) ?? ''
      secrets.add(token)
      return token
    },
    eventsOf(type) {
      return events.filter((e): e is Extract<AuthEvent, { type: typeof type }> => e.type === type)
    },
    async user(email = 'ada@acme.test', opts = {}) {
      return auth.system.createUser({
        name: email.split('@')[0] ?? 'user',
        email,
        ...(opts.password === null ? {} : { password: opts.password ?? PASSWORD }),
        ...(opts.roles ? { roles: opts.roles } : {}),
        verified: opts.verified ?? true,
      })
    },
    async signedIn(email, ip) {
      const b = new Browser(ip)
      const r = await auth.passwords.login(b.req, { email, password: PASSWORD })
      if (r.status !== 'signed-in') throw new Error(`expected signed-in, got ${r.status}`)
      for (const v of b.jar.values()) secrets.add(v)
      return b
    },
  }
  return h
}

/** Assert that `fn` rejects with an AuthError of `code`; resolve the error. */
export async function rejectsWith(
  fn: () => Promise<unknown>,
  code: string,
): Promise<{ code: string; retryAfterSeconds?: number | undefined; options: unknown }> {
  try {
    await fn()
  } catch (error) {
    const e = error as { code?: unknown; name?: unknown }
    if (e.name === 'AuthError' && e.code === code)
      return error as { code: string; options: unknown }
    throw new Error(
      `expected AuthError ${code}, got ${String(e.name)} ${String(e.code)}: ${String(error)}`,
    )
  }
  throw new Error(`expected AuthError ${code}, but it resolved`)
}
