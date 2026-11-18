/** Binding, the validation gate and in-memory evaluation: the normative semantics of ADR-0008. */
import type { QueryFilter } from '@strutvane/framework/contracts'
import { describe, expect, it } from 'vitest'
import { FieldNotLoadedError, InvalidFilterError } from '../src/errors.ts'
import { ActorAttributeError, bindActor, isActorRef, resolveActorRef } from '../src/policy/bind.ts'
import { evaluateFilter } from '../src/policy/evaluate.ts'
import { and, FALSE, fold, not, or, TRUE } from '../src/policy/filter.ts'
import { foldAscii, validateFilter } from '../src/policy/validate.ts'
import { ALICE, actor, invoice, invoiceSchema } from './fixtures.ts'

const ev = (f: QueryFilter, overrides: Record<string, unknown> = {}) =>
  evaluateFilter(f, invoice(overrides), invoiceSchema)

describe('filter constructors', () => {
  it('fold constants and flatten', () => {
    const a: QueryFilter = { op: 'isNull', field: 'title' }
    const b: QueryFilter = { op: 'isNull', field: 'status' }
    expect(and()).toBe(TRUE)
    expect(or()).toBe(FALSE)
    expect(and(TRUE, a)).toBe(a)
    expect(and(a, FALSE)).toBe(FALSE)
    expect(or(a, TRUE)).toBe(TRUE)
    expect(or(FALSE, a)).toBe(a)
    expect(and(a, and(b, a))).toEqual({ op: 'and', filters: [a, b, a] })
    expect(or(a, or(b))).toEqual({ op: 'or', filters: [a, b] })
    expect(not(TRUE)).toBe(FALSE)
    expect(not(FALSE)).toBe(TRUE)
    expect(not(not(a))).toBe(a)
    expect(fold({ op: 'and', filters: [{ op: 'not', filter: FALSE }, a] })).toBe(a)
    expect(fold({ op: 'or', filters: [{ op: 'and', filters: [] }] })).toBe(TRUE)
    expect(Object.isFrozen(TRUE)).toBe(true)
  })
})

describe('bindActor', () => {
  it('replaces references with values', () => {
    expect(bindActor({ op: 'eq', field: 'ownerId', value: { $actor: 'id' } }, actor())).toEqual({
      op: 'eq',
      field: 'ownerId',
      value: ALICE,
    })
    expect(
      bindActor({ op: 'in', field: 'region', values: ['x', { $actor: 'attrs.region' }] }, actor()),
    ).toEqual({
      op: 'in',
      field: 'region',
      values: ['x', 'eu'],
    })
    expect(
      bindActor(
        { op: 'between', field: 'amount', from: { $actor: 'attrs.n' }, to: 5 },
        actor({ attrs: { n: 1 } }),
      ),
    ).toEqual({
      op: 'between',
      field: 'amount',
      from: 1,
      to: 5,
    })
  })

  it('a null actor value never matches: eq → FALSE, ne → TRUE, dropped from lists, ordering FALSE', () => {
    const nullRegion = actor({ attrs: { region: null } })
    expect(
      bindActor({ op: 'eq', field: 'region', value: { $actor: 'attrs.region' } }, nullRegion),
    ).toEqual(FALSE)
    expect(
      bindActor({ op: 'ne', field: 'region', value: { $actor: 'attrs.region' } }, nullRegion),
    ).toEqual(TRUE)
    expect(
      bindActor(
        { op: 'nin', field: 'region', values: [{ $actor: 'attrs.region' }, 'x'] },
        nullRegion,
      ),
    ).toEqual({ op: 'nin', field: 'region', values: ['x'] })
    expect(
      bindActor({ op: 'gt', field: 'amount', value: { $actor: 'attrs.region' } }, nullRegion),
    ).toEqual(FALSE)
    expect(
      bindActor(
        { op: 'between', field: 'amount', from: 1, to: { $actor: 'attrs.region' } },
        nullRegion,
      ),
    ).toEqual(FALSE)
  })

  it('anonymous actors resolve every reference to null', () => {
    expect(resolveActorRef({ $actor: 'id' }, null)).toBeNull()
    expect(resolveActorRef({ $actor: 'tenantId' }, null)).toBeNull()
    expect(resolveActorRef({ $actor: 'attrs.x' }, null)).toBeNull()
    const { tenantId: _t, ...global } = actor()
    expect(resolveActorRef({ $actor: 'tenantId' }, global)).toBeNull()
  })

  it('throws for missing, empty, non-scalar or unsupported references', () => {
    expect(() => resolveActorRef({ $actor: 'attrs.nope' }, actor())).toThrow(ActorAttributeError)
    expect(() => resolveActorRef({ $actor: 'attrs.' }, actor())).toThrow(ActorAttributeError)
    expect(() =>
      resolveActorRef({ $actor: 'attrs.list' }, actor({ attrs: { list: [1] } })),
    ).toThrow(ActorAttributeError)
    expect(() => resolveActorRef({ $actor: 'email' as never }, actor())).toThrow(
      ActorAttributeError,
    )
    // Prototype keys are not attributes.
    expect(() => resolveActorRef({ $actor: 'attrs.constructor' }, actor())).toThrow(
      ActorAttributeError,
    )
  })

  it('leaves non-reference nodes alone and recurses through logic', () => {
    const f: QueryFilter = {
      op: 'not',
      filter: {
        op: 'or',
        filters: [
          { op: 'contains', field: 'title', value: 'a' },
          { op: 'isNull', field: 'title' },
          TRUE,
        ],
      },
    }
    expect(bindActor(f, actor())).toEqual(f)
    expect(isActorRef({ $actor: 'id' })).toBe(true)
    expect(isActorRef({ $actor: 1 })).toBe(false)
    expect(isActorRef(null)).toBe(false)
  })
})

describe('validateFilter (the shared gate)', () => {
  const reject =
    (f: unknown, limits = {}) =>
    () =>
      validateFilter(f as QueryFilter, invoiceSchema, limits)

  it.each<[string, unknown]>([
    ['unknown field', { op: 'eq', field: 'nope', value: 1 }],
    ['unknown relation', { op: 'eq', field: 'nope.x', value: 1 }],
    ['unknown relation field', { op: 'eq', field: 'customer.nope', value: 1 }],
    ['too deep a path', { op: 'eq', field: 'customer.region.x', value: 1 }],
    ['prototype field', { op: 'isNull', field: '__proto__' }],
    ['prototype relation', { op: 'isNull', field: 'constructor.name' }],
    ['non-string field', { op: 'isNull', field: 7 }],
    ['empty field', { op: 'isNull', field: '' }],
    ['null value', { op: 'eq', field: 'title', value: null }],
    ['undefined value', { op: 'eq', field: 'title' }],
    ['wrong type (string for int)', { op: 'eq', field: 'amount', value: '1' }],
    ['non-integer int4', { op: 'eq', field: 'amount', value: 1.5 }],
    ['out-of-range int4', { op: 'eq', field: 'amount', value: 2 ** 31 }],
    ['NaN float8', { op: 'eq', field: 'score', value: Number.NaN }],
    ['Infinity float8', { op: 'gt', field: 'score', value: Number.POSITIVE_INFINITY }],
    ['malformed uuid', { op: 'eq', field: 'ownerId', value: 'not-a-uuid' }],
    ['number for bool', { op: 'eq', field: 'archived', value: 1 }],
    ['ordering on text', { op: 'gt', field: 'title', value: 'a' }],
    ['ordering on uuid', { op: 'lt', field: 'ownerId', value: ALICE }],
    ['between on text', { op: 'between', field: 'title', from: 'a', to: 'b' }],
    ['text op on int', { op: 'contains', field: 'amount', value: '1' }],
    ['text op with non-string value', { op: 'contains', field: 'title', value: 1 }],
    ['text op with actor ref', { op: 'contains', field: 'title', value: { $actor: 'id' } }],
    [
      'non-boolean caseSensitive',
      { op: 'contains', field: 'title', value: 'a', caseSensitive: 'yes' },
    ],
    ['U+0000 in a value', { op: 'eq', field: 'title', value: 'a\u0000b' }],
    ['lone high surrogate', { op: 'eq', field: 'title', value: 'a\uD800' }],
    ['lone low surrogate', { op: 'contains', field: 'title', value: '\uDC00b' }],
    ['unbound actor reference', { op: 'eq', field: 'ownerId', value: { $actor: 'id' } }],
    ['non-array values', { op: 'in', field: 'title', values: 'abc' }],
    ['bad list element', { op: 'in', field: 'amount', values: [1, 'x'] }],
    ['non-array filters', { op: 'and', filters: {} }],
    ['non-object node', { op: 'and', filters: [42] }],
    ['null node', null],
    ['unknown operator', { op: 'regex', field: 'title', value: '.*' }],
    ['missing operator', { field: 'title' }],
    ['not without filter', { op: 'not' }],
  ])('rejects %s', (_name, f) => {
    expect(reject(f)).toThrow(InvalidFilterError)
  })

  it('accepts surrogate pairs (emoji) and every well-formed operator', () => {
    const ok: QueryFilter = {
      op: 'and',
      filters: [
        { op: 'eq', field: 'title', value: 'hi 👋' },
        { op: 'ne', field: 'ownerId', value: ALICE.toUpperCase() },
        { op: 'in', field: 'amount', values: [] },
        { op: 'nin', field: 'archived', values: [true] },
        { op: 'between', field: 'score', from: -1.5, to: 2 },
        { op: 'startsWith', field: 'customer.region', value: 'e', caseSensitive: true },
        { op: 'endsWith', field: 'title', value: '' },
        { op: 'isNotNull', field: 'customer.tier' },
        { op: 'not', filter: FALSE },
      ],
    }
    expect(() => validateFilter(ok, invoiceSchema)).not.toThrow()
  })

  it('bounds the cost of untrusted filters', () => {
    let deep: QueryFilter = TRUE
    for (let i = 0; i < 40; i++) deep = { op: 'not', filter: deep }
    expect(reject(deep)).toThrow(/nested deeper/)
    const wide: QueryFilter = { op: 'or', filters: Array.from({ length: 3000 }, () => TRUE) }
    expect(reject(wide)).toThrow(/more than 2000 nodes/)
    expect(
      reject({ op: 'in', field: 'amount', values: Array.from({ length: 1001 }, (_, i) => i) }),
    ).toThrow(/more than 1000 values/)
    expect(reject({ op: 'eq', field: 'title', value: 'x'.repeat(10_001) })).toThrow(/longer than/)
    expect(
      reject({ op: 'eq', field: 'title', value: 'x'.repeat(11) }, { maxStringLength: 10 }),
    ).toThrow(/longer than 10/)
  })

  it('the error is a 422 problem with a stable code and never echoes values', () => {
    try {
      validateFilter({ op: 'eq', field: 'amount', value: 'SECRET-VALUE' as never }, invoiceSchema)
      expect.unreachable()
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidFilterError)
      expect((error as InvalidFilterError).code).toBe('invalid_filter')
      expect((error as InvalidFilterError).status).toBe(422)
      expect((error as Error).message).not.toContain('SECRET-VALUE')
    }
  })
})

describe('evaluateFilter: two-valued, NULL-safe semantics', () => {
  it('eq never matches null; ne is its exact negation and matches null', () => {
    expect(ev({ op: 'eq', field: 'status', value: 'draft' })).toBe(true)
    expect(ev({ op: 'eq', field: 'status', value: 'draft' }, { status: null })).toBe(false)
    expect(ev({ op: 'ne', field: 'status', value: 'draft' }, { status: null })).toBe(true)
    expect(
      ev({ op: 'not', filter: { op: 'eq', field: 'status', value: 'draft' } }, { status: null }),
    ).toBe(true)
  })

  it('in / nin with nulls and empty lists', () => {
    expect(ev({ op: 'in', field: 'status', values: ['draft', 'paid'] })).toBe(true)
    expect(ev({ op: 'in', field: 'status', values: ['draft'] }, { status: null })).toBe(false)
    expect(ev({ op: 'nin', field: 'status', values: ['draft'] }, { status: null })).toBe(true)
    expect(ev({ op: 'in', field: 'status', values: [] })).toBe(false)
    expect(ev({ op: 'nin', field: 'status', values: [] })).toBe(true)
  })

  it('ordering and between are false on null', () => {
    expect(ev({ op: 'gt', field: 'amount', value: 100 })).toBe(true)
    expect(ev({ op: 'gte', field: 'amount', value: 500 })).toBe(true)
    expect(ev({ op: 'lt', field: 'amount', value: 500 })).toBe(false)
    expect(ev({ op: 'lte', field: 'amount', value: 500 })).toBe(true)
    expect(ev({ op: 'gt', field: 'amount', value: 1 }, { amount: null })).toBe(false)
    expect(ev({ op: 'lte', field: 'amount', value: 1 }, { amount: null })).toBe(false)
    expect(ev({ op: 'between', field: 'amount', from: 100, to: 500 })).toBe(true)
    expect(ev({ op: 'between', field: 'amount', from: 600, to: 100 })).toBe(false)
    expect(ev({ op: 'between', field: 'amount', from: 1, to: 2 }, { amount: null })).toBe(false)
  })

  it('text operators: literal (no wildcards), ASCII-case-insensitive by default, false on null', () => {
    expect(ev({ op: 'contains', field: 'title', value: 'ELL' })).toBe(true)
    expect(ev({ op: 'contains', field: 'title', value: 'ELL', caseSensitive: true })).toBe(false)
    expect(ev({ op: 'startsWith', field: 'title', value: 'he' })).toBe(true)
    expect(ev({ op: 'endsWith', field: 'title', value: 'LO' })).toBe(true)
    expect(ev({ op: 'endsWith', field: 'title', value: '' })).toBe(true)
    expect(ev({ op: 'contains', field: 'title', value: '%' }, { title: 'abc' })).toBe(false)
    expect(ev({ op: 'contains', field: 'title', value: '_' }, { title: 'a_c' })).toBe(true)
    expect(ev({ op: 'contains', field: 'title', value: 'x' }, { title: null })).toBe(false)
    // Only A–Z fold: "É" and "é" are different, identically in SQL.
    expect(ev({ op: 'contains', field: 'title', value: 'é' }, { title: 'CAFÉ' })).toBe(false)
    expect(foldAscii('ÀBC-xyZ')).toBe('Àbc-xyz')
  })

  it('isNull / isNotNull and bool / float8 columns', () => {
    expect(ev({ op: 'isNull', field: 'status' }, { status: null })).toBe(true)
    expect(ev({ op: 'isNotNull', field: 'status' })).toBe(true)
    expect(ev({ op: 'eq', field: 'archived', value: false })).toBe(true)
    expect(ev({ op: 'gte', field: 'score', value: 1.5 })).toBe(true)
  })

  it('uuid comparisons are case-insensitive, like Postgres', () => {
    expect(ev({ op: 'eq', field: 'ownerId', value: ALICE.toUpperCase() })).toBe(true)
    expect(ev({ op: 'in', field: 'ownerId', values: [ALICE.toUpperCase()] })).toBe(true)
  })

  it('relation fields: a null relation reads as null fields', () => {
    expect(ev({ op: 'eq', field: 'customer.region', value: 'eu' })).toBe(true)
    expect(ev({ op: 'isNull', field: 'customer.region' }, { customer: null })).toBe(true)
    expect(ev({ op: 'ne', field: 'customer.region', value: 'eu' }, { customer: null })).toBe(true)
  })

  it('fails closed on unloaded fields and malformed relations', () => {
    const { title: _t, ...partial } = invoice()
    expect(() => evaluateFilter({ op: 'isNull', field: 'title' }, partial, invoiceSchema)).toThrow(
      FieldNotLoadedError,
    )
    expect(() => ev({ op: 'isNull', field: 'customer.region' }, { customer: undefined })).toThrow(
      FieldNotLoadedError,
    )
    expect(() => ev({ op: 'isNull', field: 'customer.region' }, { customer: 'x' })).toThrow(
      FieldNotLoadedError,
    )
    expect(() =>
      ev({ op: 'isNull', field: 'customer.region' }, { customer: { id: ALICE } }),
    ).toThrow(FieldNotLoadedError)
    // A prototype-polluted record does not count as "loaded".
    expect(() =>
      evaluateFilter(
        { op: 'isNull', field: 'title' },
        Object.create({ title: 'x' }),
        invoiceSchema,
      ),
    ).toThrow(FieldNotLoadedError)
  })

  it('values of the wrong runtime type in the record fail closed (throw), never guess', () => {
    expect(() => ev({ op: 'gt', field: 'amount', value: 1 }, { amount: '500' })).toThrow(
      FieldNotLoadedError,
    )
    expect(() =>
      ev({ op: 'between', field: 'amount', from: 1, to: 1000 }, { amount: '500' }),
    ).toThrow(FieldNotLoadedError)
    expect(() => ev({ op: 'contains', field: 'title', value: '1' }, { title: 1 })).toThrow(
      FieldNotLoadedError,
    )
  })
})
