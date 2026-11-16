/**
 * Audit logging: permanent records of who did what, when, to which record (contracts `AuditEvent`).
 *
 * - {@link recordAudit} builds the event (UUIDv7 id, UTC timestamp, actor stamp, tenant, request
 *   and trace ids taken from the request context) and writes it to an {@link AuditSink}.
 * - {@link diffChanges} produces field-level changes between two versions of a record. Fields
 *   that look sensitive (passwords, tokens, secrets… plus any you name) keep the fact that they
 *   changed but lose both values (`redacted: true`). Nested values are redacted too. Pass a
 *   policy as `maskFor` and every field with a read rule is redacted the same way, so the audit
 *   log never shows values (salaries, internal notes…) that the policy hides from most readers.
 *
 * **Write audit in the same transaction as the change** (contracts: "audit and data can never
 * disagree"): give `recordAudit` a sink bound to your transaction. The framework's Postgres sink
 * does exactly that; {@link memoryAuditSink} is for tests.
 *
 * @module
 */
import type { Actor, AuditEvent, FieldChange } from '@strutvane/framework/contracts'
import {
  currentContext,
  DEFAULT_SENSITIVE_KEYS,
  REDACTED,
  sensitiveKeyMatcher,
  toLoggable,
  uuidv7,
} from '@strutvane/framework/core'

/** Where audit events go. Implementations should write durably and atomically with the change. */
export interface AuditSink {
  write(event: AuditEvent): Promise<void>
}

/** An in-memory sink for tests. */
export interface MemoryAuditSink extends AuditSink {
  readonly events: readonly AuditEvent[]
  clear(): void
}

/** Create an in-memory sink (events are frozen as written). */
export function memoryAuditSink(): MemoryAuditSink {
  const events: AuditEvent[] = []
  return {
    events,
    async write(event) {
      events.push(Object.freeze(event))
    },
    clear() {
      events.length = 0
    },
  }
}

/** Options for {@link diffChanges}. */
export interface DiffOptions {
  /** Extra sensitive key fragments, added to core's defaults (`password`, `token`, `secret`…). */
  readonly sensitive?: readonly string[]
  /** Fields never recorded at all (e.g. `updatedAt`). */
  readonly ignore?: readonly string[]
  /**
   * The resource's policy (anything with `restrictedFields`): every field that has a read rule is
   * redacted, whoever may read the audit log later.
   */
  readonly maskFor?: { readonly restrictedFields: readonly string[] }
}

/** Structural equality for JSON-like values (dates by time, objects key by key). */
function same(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) return true
  if (a instanceof Date && b instanceof Date) return a.getTime() === b.getTime()
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false
  if (Array.isArray(a) !== Array.isArray(b)) return false
  const ka = Object.keys(a)
  const kb = Object.keys(b)
  if (ka.length !== kb.length) return false
  return ka.every(
    (k) =>
      Object.hasOwn(b, k) &&
      same((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
  )
}

/**
 * Field-level changes from `before` to `after` (`null` for create / delete). Sensitive fields are
 * reported as changed with both values replaced by `[REDACTED]`; other values are made JSON-safe,
 * with sensitive nested keys redacted.
 */
export function diffChanges(
  before: Readonly<Record<string, unknown>> | null,
  after: Readonly<Record<string, unknown>> | null,
  options: DiffOptions = {},
): FieldChange[] {
  const isSensitive = sensitiveKeyMatcher([...DEFAULT_SENSITIVE_KEYS, ...(options.sensitive ?? [])])
  const ignore = new Set(options.ignore ?? [])
  const masked = new Set(options.maskFor?.restrictedFields ?? [])
  const keys = [...new Set([...Object.keys(before ?? {}), ...Object.keys(after ?? {})])].sort()
  const changes: FieldChange[] = []
  for (const field of keys) {
    if (ignore.has(field)) continue
    const from = before && Object.hasOwn(before, field) ? before[field] : undefined
    const to = after && Object.hasOwn(after, field) ? after[field] : undefined
    if (same(from, to)) continue
    if (masked.has(field) || isSensitive(field)) {
      changes.push({ field, from: REDACTED, to: REDACTED, redacted: true })
    } else {
      changes.push({
        field,
        from: from === undefined ? null : toLoggable(from, isSensitive),
        to: to === undefined ? null : toLoggable(to, isSensitive),
      })
    }
  }
  return changes
}

/** What to record. Anything omitted is taken from the request context where possible. */
export interface AuditInput {
  /** What happened, e.g. `"invoice.update"`, `"auth.login.failed"`. */
  readonly action: string
  readonly resource?: { readonly type: string; readonly id?: string }
  /** Record before the change (`null` for create). With `after`, produces field changes. */
  readonly before?: Readonly<Record<string, unknown>> | null
  /** Record after the change (`null` for delete). */
  readonly after?: Readonly<Record<string, unknown>> | null
  /** Why (e.g. a policy `Decision.reason` for a denial). Never put personal data here. */
  readonly reason?: string
  /** Defaults to the context actor. `null` records an anonymous action. */
  readonly actor?: Actor | null
  /** Defaults to the actor's tenant, then the context tenant. */
  readonly tenantId?: string
  /** Store only where your privacy policy allows. */
  readonly ip?: string
  readonly userAgent?: string
}

/** Options for {@link recordAudit}. */
export interface RecordAuditOptions extends DiffOptions {
  /** Clock, for tests. */
  readonly now?: () => Date
  /** Id generator, for tests. Default UUIDv7. */
  readonly id?: () => string
}

const ACTION = /^[a-z][a-zA-Z0-9_-]*(\.[a-zA-Z][a-zA-Z0-9_-]*)+$/

/** Build an audit event and write it to `sink`. Returns the event written. */
export async function recordAudit(
  sink: AuditSink,
  input: AuditInput,
  options: RecordAuditOptions = {},
): Promise<AuditEvent> {
  if (typeof input.action !== 'string' || !ACTION.test(input.action) || input.action.length > 200) {
    throw new TypeError('audit action must look like "resource.verb" (e.g. "invoice.update")')
  }
  const ctx = currentContext()
  const actor = input.actor !== undefined ? input.actor : (ctx?.actor ?? null)
  const tenantId = input.tenantId ?? actor?.tenantId ?? ctx?.tenant?.id
  const changes =
    input.before !== undefined || input.after !== undefined
      ? diffChanges(input.before ?? null, input.after ?? null, options)
      : undefined
  const event: AuditEvent = {
    id: (options.id ?? uuidv7)(),
    occurredAt: (options.now?.() ?? new Date()).toISOString(),
    actor: actor ? { id: actor.id, type: actor.type } : null,
    action: input.action,
    ...(tenantId !== undefined ? { tenantId } : {}),
    ...(input.resource
      ? {
          resource:
            input.resource.id !== undefined
              ? { type: input.resource.type, id: input.resource.id }
              : { type: input.resource.type },
        }
      : {}),
    ...(changes && changes.length > 0 ? { changes } : {}),
    ...(input.reason !== undefined ? { reason: input.reason } : {}),
    ...(ctx?.requestId !== undefined ? { requestId: ctx.requestId } : {}),
    ...(ctx?.traceId !== undefined ? { traceId: ctx.traceId } : {}),
    ...(input.ip !== undefined ? { ip: input.ip } : {}),
    ...(input.userAgent !== undefined ? { userAgent: input.userAgent.slice(0, 512) } : {}),
  }
  await sink.write(event)
  return event
}
