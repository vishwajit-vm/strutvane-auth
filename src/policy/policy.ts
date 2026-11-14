/**
 * `definePolicy`: one rule set, two execution paths.
 *
 * ```ts
 * export const invoicePolicy = definePolicy('invoice', { schema: invoiceSchema }, ({ allow, deny, field }) => {
 *   allow(['viewAny', 'view'], { role: ['accountant', 'manager'] })
 *   allow(['view', 'update'], { when: ({ actor, row }) => row.ownerId.eq(actor.id) })
 *   allow('approve', { role: 'manager', when: ({ row }) => row.amount.lte(10_000) })
 *   deny('delete', { when: ({ row }) => row.status.eq('paid') })
 *   field('internalNotes').readable({ role: 'manager' }).writable({ role: 'director' })
 * })
 * ```
 *
 * - `decide(actor, action, record)` evaluates in memory, for single-record checks.
 * - `filterFor(actor, action)` returns a bound, validated contracts `QueryFilter` for list queries
 *   (compile it with `@strutvane/auth/sql`, or let the framework do it).
 *
 * ## Combination (both paths, normative)
 *
 *     allowed = (OR of covering allow rules) AND NOT (OR of covering deny rules)
 *
 * - **Deny by default:** nothing covers → denied (`reason: "default-deny"`).
 * - **Deny wins:** a covering deny overrides every allow.
 * - A rule *applies* to an actor when it has no `role` (any signed-in actor) or the actor holds one
 *   of its roles. Anonymous actors (`null`) only match rules marked `anonymous: true`. An explicit
 *   empty role list (`role: []`) is a definition error, never "everyone".
 * - `scope` separates platform roles from tenant roles that share a name: `'global'` rules apply
 *   only to actors outside any tenant (`actor.tenantId` unset), `'tenant'` rules only inside one.
 *   Default `'any'`. Write platform-admin rules with `scope: 'global'`, so a tenant's own `admin`
 *   can never match them.
 * - In allow rules, a condition part that depends on a null actor value never widens access, even
 *   under `ne`, `nin` or `not` (see `bindActor`'s `failClosed`).
 * - A rule *covers* a record when its `when` condition (if any) and its `check` (if any) are true.
 *
 * ## Without a record (fail closed)
 * When no record is passed, a rule whose outcome depends on the record cannot be decided. The
 * result is then denied with `reason: "record-required:<rule>"` instead of guessing. Type-level
 * actions (`viewAny`, `create`) should use unconditional rules; record actions should be checked
 * with the record, or listed with `filterFor`.
 *
 * @module
 */
import type { Actor, Decision, QueryFilter } from '@strutvane/contracts'
import { InvalidFilterError, NotListFilterableError, PolicyDefinitionError } from '../errors.ts'
import { ActorAttributeError, bindActor, resolveActorRef } from './bind.ts'
import {
  type ActorProxy,
  type AttrDecl,
  createActorRefs,
  createRow,
  type RowProxy,
} from './builder.ts'
import { evaluateFilter, type RecordValue } from './evaluate.ts'
import { and, FALSE, fold, not, or, TRUE } from './filter.ts'
import { type ColumnType, fitsType, type ModelSchema } from './schema.ts'
import { type FilterLimits, validateFilter } from './validate.ts'

/** What a rule condition is written against. */
export interface RuleContext<S extends ModelSchema, A extends AttrDecl> {
  /** The record being checked (typed from the schema). */
  readonly row: RowProxy<S>
  /** References to the acting user, bound per request. */
  readonly actor: ActorProxy<A>
  readonly and: typeof and
  readonly or: typeof or
  readonly not: typeof not
}

/** What a `check()` escape hatch receives. */
export interface CheckContext {
  readonly actor: Actor | null
  readonly record: RecordValue
}

/**
 * Where a role must have been granted:
 * - `'any'` (default): globally or in the actor's active tenant;
 * - `'global'`: only outside tenants (`actor.tenantId` unset), e.g. platform administrators;
 * - `'tenant'`: only inside the actor's active tenant.
 */
export type RoleScope = 'any' | 'global' | 'tenant'

/** Options for one allow or deny rule. */
export interface RuleOptions<S extends ModelSchema, A extends AttrDecl> {
  /**
   * The actor must hold at least one of these roles. Omit for "any signed-in actor". An empty list
   * is rejected at definition time (it would otherwise read as "no restriction").
   */
  readonly role?: string | readonly string[]
  /** Which grants of `role` count (see {@link RoleScope}). Default `'any'`. */
  readonly scope?: RoleScope
  /** Also apply to anonymous requests (actor `null`). Cannot be combined with `role` or `scope`. */
  readonly anonymous?: boolean
  /** A structured condition on the record. Compiles to SQL, so the rule stays list-filterable. */
  readonly when?: (ctx: RuleContext<S, A>) => QueryFilter
  /**
   * Escape hatch: arbitrary JavaScript. Works for single-record checks, but the rule CANNOT be
   * compiled to SQL, so `filterFor()` throws {@link NotListFilterableError} when it applies.
   */
  readonly check?: (ctx: CheckContext) => boolean
  /** A stable name for `Decision.reason`, audit logs and `explain()`. Defaults to a generated one. */
  readonly name?: string
}

/** Who may read or write a field. */
export interface FieldAccessOptions {
  /** The actor must hold one of these roles. Omit for "any signed-in actor"; `[]` is rejected. */
  readonly role?: string | readonly string[]
  /** Which grants of `role` count (see {@link RoleScope}). Default `'any'`. */
  readonly scope?: RoleScope
}

/** Chainable field rule builder: `field('salary').readable({ role: 'hr' }).writable({ role: 'hr' })`. */
export interface FieldRuleBuilder {
  /** Restrict who can read the field. Fields without a read rule are readable by everyone allowed to view the record. */
  readable(options?: FieldAccessOptions): FieldRuleBuilder
  /** Restrict who can write the field. Fields without a write rule are writable by everyone allowed to update the record. */
  writable(options?: FieldAccessOptions): FieldRuleBuilder
}

/** The API a policy definition receives. */
export interface PolicyApi<S extends ModelSchema, A extends AttrDecl> {
  allow(action: string | readonly string[], options?: RuleOptions<S, A>): void
  deny(action: string | readonly string[], options?: RuleOptions<S, A>): void
  field(name: keyof S['columns'] & string): FieldRuleBuilder
}

/** Options for {@link definePolicy}. */
export interface PolicyOptions<S extends ModelSchema, A extends AttrDecl> {
  /** The model the policy protects (fields, column types, relations). */
  readonly schema: S
  /**
   * Declared actor attributes (`{ region: 'text' }`). When given, `actor.attrs.*` is typed, only
   * declared attributes may be referenced, and the actor's values are type-checked per request.
   */
  readonly attrs?: A
  /** Limits for the validation gate (defaults suit policies). */
  readonly limits?: FilterLimits
}

/** Public, serialisable description of one rule (for `explain()` and the role × permission matrix). */
export interface RuleInfo {
  readonly name: string
  readonly effect: 'allow' | 'deny'
  readonly actions: readonly string[]
  readonly roles: readonly string[]
  /** Which grants of `roles` count. */
  readonly scope: RoleScope
  readonly anonymous: boolean
  /** Has a `when` condition. */
  readonly conditional: boolean
  /** `false` when the rule has a `check()` escape hatch. */
  readonly listFilterable: boolean
}

/** How one rule took part in a decision. */
export interface RuleTrace {
  readonly rule: RuleInfo
  readonly outcome: 'not-applicable' | 'covers' | 'does-not-cover' | 'depends-on-record'
}

/** A decision plus the reasoning behind it. */
export interface Explanation {
  readonly resource: string
  readonly action: string
  readonly decision: Decision
  readonly rules: readonly RuleTrace[]
}

/** A defined policy. */
export interface Policy<S extends ModelSchema = ModelSchema> {
  /** The resource type, e.g. `"invoice"`. Permissions are `"<resource>.<action>"`. */
  readonly resource: string
  readonly schema: S
  /** Every action named by a rule (without the resource prefix). */
  readonly actions: readonly string[]
  readonly rules: readonly RuleInfo[]
  /** Decide one action, in memory. Pass `record` for record-level actions. */
  decide(actor: Actor | null, action: string, record?: RecordValue): Decision
  /** Shorthand for `decide(...).allowed`. */
  can(actor: Actor | null, action: string, record?: RecordValue): boolean
  /** The bound, validated row filter for list queries. `{ op: 'false' }` when nothing is allowed. */
  filterFor(actor: Actor | null, action: string): QueryFilter
  /** The decision plus a per-rule trace (`sv auth:explain`). */
  explain(actor: Actor | null, action: string, record?: RecordValue): Explanation
  /** Fields the actor may read. */
  readableFields(actor: Actor | null): readonly string[]
  /** Fields the actor may write. */
  writableFields(actor: Actor | null): readonly string[]
  /**
   * Fields the actor may use in an UNTRUSTED filter or sort (today: exactly its readable fields).
   * Pass it as `validateFilter(…, { allowedFields })` and check sort fields against it, so a hidden
   * field cannot be learned one comparison at a time.
   */
  filterableFields(actor: Actor | null): readonly string[]
  /** Fields with a read rule (for masking them in audit diffs: `diffChanges(…, { maskFor })`). */
  readonly restrictedFields: readonly string[]
  /**
   * A copy of `record` with ONLY the schema fields the actor may read. Keys that are not schema
   * columns (relations, computed or internal values such as a password hash) are dropped, never
   * copied through.
   */
  maskRecord<T extends Readonly<Record<string, unknown>>>(
    actor: Actor | null,
    record: T,
  ): Partial<T>
  /**
   * The keys of `input` the actor may not write (empty when the input is acceptable). Keys that are
   * not schema columns count as unwritable.
   */
  unwritableFields(actor: Actor | null, input: Readonly<Record<string, unknown>>): readonly string[]
}

interface Rule {
  readonly info: RuleInfo
  readonly roles: ReadonlySet<string>
  readonly scope: RoleScope
  readonly when: QueryFilter | undefined
  readonly check: ((ctx: CheckContext) => boolean) | undefined
  /** Every actor reference in `when`, with the column type it is compared to. */
  readonly refs: readonly (readonly [string, ColumnType])[]
}

interface Grant {
  readonly roles: ReadonlySet<string>
  readonly scope: RoleScope
}

interface FieldAccess {
  read?: Grant
  write?: Grant
}

type Cover = boolean | 'depends'

const RESOURCE_NAME = /^[a-z][a-zA-Z0-9_-]{0,63}$/
const ACTION_NAME = /^(\*|[a-zA-Z][a-zA-Z0-9_-]{0,63})$/
const COLUMN_TYPES: ReadonlySet<string> = new Set(['text', 'uuid', 'int4', 'float8', 'bool'])

const toList = (value: string | readonly string[] | undefined): readonly string[] =>
  value === undefined ? [] : typeof value === 'string' ? [value] : [...value]

const SCOPES: ReadonlySet<string> = new Set(['any', 'global', 'tenant'])

const inScope = (actor: Actor, scope: RoleScope): boolean =>
  scope === 'any' || (scope === 'global') === (actor.tenantId === undefined)

const holdsRole = (actor: Actor | null, roles: ReadonlySet<string>, scope: RoleScope): boolean =>
  actor !== null &&
  inScope(actor, scope) &&
  (roles.size === 0 || actor.roles.some((r) => roles.has(r)))

/** Validate a `role` option: omitted → no restriction; otherwise a NON-EMPTY list of names. */
function roleList(where: string, value: unknown): readonly string[] {
  if (value === undefined) return []
  const list: unknown[] =
    typeof value === 'string' ? [value] : Array.isArray(value) ? [...value] : [value]
  if (list.length === 0) {
    throw new PolicyDefinitionError(
      `${where}: role: [] would match everyone; omit role for "any signed-in actor" or name a role`,
    )
  }
  if (list.some((r) => typeof r !== 'string' || r.trim().length === 0 || r.length > 64)) {
    throw new PolicyDefinitionError(`${where}: role names must be non-empty strings`)
  }
  return list as string[]
}

function scopeOf(where: string, value: unknown): RoleScope {
  if (value === undefined) return 'any'
  if (typeof value !== 'string' || !SCOPES.has(value))
    throw new PolicyDefinitionError(`${where}: scope must be 'any', 'global' or 'tenant'`)
  return value as RoleScope
}

/**
 * Define a policy for one resource. All validation happens here, at boot: unknown fields, unsafe
 * names, conditions whose value types don't match the schema and misused options throw a
 * {@link PolicyDefinitionError} immediately instead of at the first request.
 */
export function definePolicy<
  const S extends ModelSchema,
  const A extends AttrDecl = Record<never, ColumnType>,
>(
  resource: string,
  options: PolicyOptions<S, A>,
  build: (api: PolicyApi<S, A>) => void,
): Policy<S> {
  if (!RESOURCE_NAME.test(resource)) {
    throw new PolicyDefinitionError(
      `Invalid resource name ${JSON.stringify(resource)} (use e.g. "invoice")`,
    )
  }
  const { schema, attrs, limits } = options
  for (const [name, type] of Object.entries(attrs ?? {})) {
    if (!COLUMN_TYPES.has(type)) {
      throw new PolicyDefinitionError(
        `Actor attribute "${name}" has unknown type ${JSON.stringify(type)}`,
      )
    }
  }
  const rules: Rule[] = []
  const fields = new Map<string, FieldAccess>()
  const ctx: RuleContext<S, A> = {
    row: createRow(schema),
    actor: createActorRefs(attrs),
    and,
    or,
    not,
  }

  const checkCondition = (
    where: string,
    condition: unknown,
  ): { when: QueryFilter; refs: [string, ColumnType][] } => {
    if (typeof condition !== 'object' || condition === null) {
      throw new PolicyDefinitionError(
        `${where}: when() must return a filter (use the row/actor builder)`,
      )
    }
    const refs: [string, ColumnType][] = []
    try {
      validateFilter(condition as QueryFilter, schema, {
        ...limits,
        checkActorRef: (ref, column, at) => {
          const path = ref.$actor
          if (path === 'id' || path === 'tenantId') {
            if (column !== 'text' && column !== 'uuid') {
              throw new PolicyDefinitionError(
                `${where}: ${at} compares actor.${path} with a ${column} column`,
              )
            }
          } else if (path.startsWith('attrs.') && path.length > 'attrs.'.length) {
            const declared = attrs?.[path.slice('attrs.'.length)]
            if (
              declared !== undefined &&
              declared !== column &&
              !(declared === 'int4' && column === 'float8')
            ) {
              throw new PolicyDefinitionError(
                `${where}: ${at} compares actor.${path} (${declared}) with a ${column} column`,
              )
            }
          } else {
            throw new PolicyDefinitionError(`${where}: unsupported actor reference "${path}"`)
          }
          refs.push([path, column])
        },
      })
    } catch (error) {
      if (error instanceof InvalidFilterError)
        throw new PolicyDefinitionError(`${where}: ${error.reason}`)
      throw error
    }
    return { when: condition as QueryFilter, refs }
  }

  const add =
    (effect: 'allow' | 'deny') =>
    (action: string | readonly string[], opts: RuleOptions<S, A> = {}): void => {
      const actions = toList(action)
      if (actions.length === 0)
        throw new PolicyDefinitionError(`${resource}: ${effect}() needs at least one action`)
      for (const a of actions) {
        if (!ACTION_NAME.test(a))
          throw new PolicyDefinitionError(`${resource}: invalid action ${JSON.stringify(a)}`)
      }
      const roles = roleList(resource, opts.role)
      const scope = scopeOf(resource, opts.scope)
      const anonymous = opts.anonymous === true
      if (anonymous && (roles.length > 0 || scope !== 'any')) {
        throw new PolicyDefinitionError(
          `${resource}: a rule cannot be both anonymous and role- or scope-restricted`,
        )
      }
      const who = roles.length > 0 ? `role=${roles.join('|')}` : anonymous ? 'anyone' : 'signed-in'
      const name =
        opts.name ??
        `${actions.join('|')}:${who}${opts.when ? '+when' : ''}${opts.check ? '+check' : ''}`
      const condition = opts.when
        ? checkCondition(`${resource} rule "${name}"`, opts.when(ctx))
        : undefined
      rules.push({
        info: Object.freeze({
          name,
          effect,
          actions: Object.freeze(actions),
          roles: Object.freeze([...roles]),
          scope,
          anonymous,
          conditional: condition !== undefined,
          listFilterable: opts.check === undefined,
        }),
        roles: new Set(roles),
        scope,
        when: condition?.when,
        check: opts.check,
        refs: condition?.refs ?? [],
      })
    }

  const field = (name: string): FieldRuleBuilder => {
    if (!Object.hasOwn(schema.columns, name)) {
      throw new PolicyDefinitionError(`${resource}: field rule for unknown field "${name}"`)
    }
    const access = fields.get(name) ?? {}
    fields.set(name, access)
    const where = `${resource}: field("${name}")`
    const grant = (o: FieldAccessOptions): Grant => ({
      roles: new Set(roleList(where, o.role)),
      scope: scopeOf(where, o.scope),
    })
    const builder: FieldRuleBuilder = {
      readable(o: FieldAccessOptions = {}) {
        access.read = grant(o)
        return builder
      },
      writable(o: FieldAccessOptions = {}) {
        access.write = grant(o)
        return builder
      },
    }
    return builder
  }

  build({ allow: add('allow'), deny: add('deny'), field })

  const actionsList = [...new Set(rules.flatMap((r) => r.info.actions))].filter((a) => a !== '*')

  // The combined list filter of an action (OR of allows AND NOT OR of denies) is checked against
  // the limits at request time. Check its worst case here, so a policy whose single-record checks
  // work can never fail only in `filterFor` (binding never makes a condition larger).
  for (const action of [...actionsList, '*']) {
    const covering = rules.filter(
      (r) => r.info.actions.includes(action) || r.info.actions.includes('*'),
    )
    const part = (effect: 'allow' | 'deny'): QueryFilter => ({
      op: 'or',
      filters: [
        TRUE, // a pre-resolved actor permission adds one unconditional allow
        ...covering.filter((r) => r.info.effect === effect).map((r) => r.when ?? TRUE),
      ],
    })
    try {
      validateFilter({ op: 'and', filters: [part('allow'), not(part('deny'))] }, schema, {
        ...limits,
        checkActorRef: () => undefined,
      })
    } catch (error) {
      if (error instanceof InvalidFilterError)
        throw new PolicyDefinitionError(
          `${resource}: the combined rules for action "${action}" exceed the filter limits (${error.reason})`,
        )
      throw error
    }
  }

  /** Pre-resolved permissions on the actor (e.g. from an API token) act as an unconditional allow. */
  const permissionRule = (action: string): Rule =>
    ({
      info: {
        name: 'actor-permission',
        effect: 'allow',
        actions: [action],
        roles: [],
        scope: 'any',
        anonymous: false,
        conditional: false,
        listFilterable: true,
      },
      roles: new Set<string>(),
      scope: 'any',
      when: undefined,
      check: undefined,
      refs: [],
    }) satisfies Rule

  const hasPermission = (actor: Actor | null, action: string): boolean =>
    actor?.permissions?.some(
      (p) => p === '*' || p === `${resource}.*` || p === `${resource}.${action}`,
    ) ?? false

  const assertActor = (actor: Actor | null): void => {
    if (actor !== null && (typeof actor !== 'object' || !Array.isArray(actor.roles))) {
      throw new TypeError('actor must be null or an Actor with a roles array')
    }
  }

  const assertAction = (action: string): void => {
    if (typeof action !== 'string' || action === '*' || !ACTION_NAME.test(action)) {
      throw new TypeError(`Invalid action ${JSON.stringify(action)}`)
    }
  }

  /** Every rule for this action, flagged with whether it applies to this actor. */
  const candidates = (actor: Actor | null, action: string): { rule: Rule; applies: boolean }[] => {
    assertActor(actor)
    assertAction(action)
    const list = rules
      .filter((r) => r.info.actions.includes(action) || r.info.actions.includes('*'))
      .map((rule) => ({
        rule,
        applies: actor === null ? rule.info.anonymous : holdsRole(actor, rule.roles, rule.scope),
      }))
    if (hasPermission(actor, action)) list.push({ rule: permissionRule(action), applies: true })
    return list
  }

  /** Bind a rule's condition for this actor, after checking every referenced actor value's type. */
  const bound = (rule: Rule, actor: Actor | null): QueryFilter => {
    if (!rule.when) return TRUE
    for (const [path, column] of rule.refs) {
      const value = resolveActorRef({ $actor: path as 'id' }, actor)
      if (value !== null && !fitsType(value, column)) {
        throw new ActorAttributeError(
          `actor.${path} does not fit column type ${column} (policy ${resource})`,
        )
      }
    }
    // Allow rules bind fail-closed: an unknown (null) actor value never widens access.
    return fold(bindActor(rule.when, actor, { failClosed: rule.info.effect === 'allow' }))
  }

  const cover = (rule: Rule, actor: Actor | null, record: RecordValue | undefined): Cover => {
    const condition = bound(rule, actor)
    if (record === undefined) {
      if (rule.check || (condition.op !== 'true' && condition.op !== 'false')) {
        validateFilter(condition, schema, limits)
        return 'depends'
      }
      return condition.op === 'true'
    }
    if (!evaluateFilter(condition, record, schema, limits)) return false
    return rule.check ? rule.check({ actor, record }) === true : true
  }

  const explain = (actor: Actor | null, action: string, record?: RecordValue): Explanation => {
    const traces: RuleTrace[] = []
    let deny: Rule | undefined
    let allow: Rule | undefined
    let dependsDeny: Rule | undefined
    let dependsAllow: Rule | undefined
    // Evaluate EVERY applicable rule (no short-circuit), so errors such as an unloaded field always
    // surface, independent of rule order.
    for (const { rule, applies } of candidates(actor, action)) {
      if (!applies) {
        traces.push({ rule: rule.info, outcome: 'not-applicable' })
        continue
      }
      const c = cover(rule, actor, record)
      traces.push({
        rule: rule.info,
        outcome: c === 'depends' ? 'depends-on-record' : c ? 'covers' : 'does-not-cover',
      })
      if (rule.info.effect === 'deny') {
        if (c === true) deny ??= rule
        else if (c === 'depends') dependsDeny ??= rule
      } else if (c === true) allow ??= rule
      else if (c === 'depends') dependsAllow ??= rule
    }
    let decision: Decision
    if (deny) decision = { allowed: false, reason: `deny:${deny.info.name}` }
    else if (!allow) {
      decision = dependsAllow
        ? { allowed: false, reason: `record-required:${dependsAllow.info.name}` }
        : { allowed: false, reason: 'default-deny' }
    } else if (dependsDeny)
      decision = { allowed: false, reason: `record-required:${dependsDeny.info.name}` }
    else decision = { allowed: true, reason: `allow:${allow.info.name}` }
    return { resource, action, decision: Object.freeze(decision), rules: traces }
  }

  const filterFor = (actor: Actor | null, action: string): QueryFilter => {
    const applicable = candidates(actor, action)
      .filter((c) => c.applies)
      .map((c) => c.rule)
    const scripted = applicable.find((r) => r.check)
    if (scripted) {
      throw new NotListFilterableError(
        `Policy "${resource}" action "${action}": rule "${scripted.info.name}" uses check(), which cannot be compiled to SQL`,
      )
    }
    const allows = or(
      ...applicable.filter((r) => r.info.effect === 'allow').map((r) => bound(r, actor)),
    )
    if (allows.op === 'false') return FALSE
    const denies = or(
      ...applicable.filter((r) => r.info.effect === 'deny').map((r) => bound(r, actor)),
    )
    const result = fold(and(allows, not(denies)))
    validateFilter(result, schema, limits)
    return result
  }

  const fieldsWhere = (actor: Actor | null, kind: 'read' | 'write'): string[] => {
    assertActor(actor)
    return Object.keys(schema.columns).filter((name) => {
      const g = fields.get(name)?.[kind]
      return g === undefined || holdsRole(actor, g.roles, g.scope)
    })
  }
  const restricted = Object.freeze(
    [...fields].filter(([, a]) => a.read !== undefined).map(([n]) => n),
  )

  const policy: Policy<S> = {
    resource,
    schema,
    actions: Object.freeze(actionsList),
    rules: Object.freeze(rules.map((r) => r.info)),
    decide: (actor, action, record) => explain(actor, action, record).decision,
    can: (actor, action, record) => explain(actor, action, record).decision.allowed,
    filterFor,
    explain,
    readableFields: (actor) => fieldsWhere(actor, 'read'),
    writableFields: (actor) => fieldsWhere(actor, 'write'),
    filterableFields: (actor) => fieldsWhere(actor, 'read'),
    restrictedFields: restricted,
    maskRecord: <T extends Readonly<Record<string, unknown>>>(
      actor: Actor | null,
      record: T,
    ): Partial<T> => {
      // Built from the readable schema fields only (an allow-list): unknown keys never pass, and
      // defineProperty keeps a field literally named `__proto__` an own data property.
      const out: Partial<T> = {}
      for (const key of fieldsWhere(actor, 'read')) {
        if (!Object.hasOwn(record, key)) continue
        Object.defineProperty(out, key, {
          value: record[key],
          enumerable: true,
          writable: true,
          configurable: true,
        })
      }
      return out
    },
    unwritableFields: (actor, input) => {
      const writable = new Set(fieldsWhere(actor, 'write'))
      return Object.keys(input).filter((key) => !writable.has(key))
    },
  }
  return Object.freeze(policy)
}
