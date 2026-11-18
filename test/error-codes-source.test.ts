/**
 * Every code `@strutvane/auth` throws, compares, registers or reports is lowercase `snake_case`
 * (CONSISTENCY #68, #123), and every one a client can receive renders with a registered title.
 *
 * Why a source scan: through the framework's 0.2 line an uppercase code still works at run time
 * (`StrutvaneError` maps `NOT_FOUND` to `not_found` and prints a DeprecationWarning), so a
 * behaviour test cannot tell that the source still used an old name, and the old names stop
 * working in 0.3. This test covers the whole class, like the framework's own
 * `test/core/error-codes-source.test.ts`: the first argument of every `new …Error(…)`, every
 * `code: '…'` member (including each member of a `code:` union type), every comparison with a
 * `code`, and every `[code, status, title]` registry row.
 */
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { ValidationIssue } from '@strutvane/framework/contracts'
import {
  BUILTIN_ERRORS,
  createErrorRegistry,
  StrutvaneError,
  toProblem,
} from '@strutvane/framework/core'
import { describe, expect, test } from 'vitest'
import { toIssue } from '../src/engine/errors.ts'
import { AUTH_ERRORS } from '../src/errors.ts'
import { IDENTITY_STATUS } from '../src/identity/engine.ts'

const ROOT = join(import.meta.dirname, '..')
const SRC = join(ROOT, 'src')

/** Code-shaped literals: `not_found`, `NOT_FOUND`, `Not_Found` (anything a scan must judge). */
const LITERAL = String.raw`['"\`]([A-Za-z][A-Za-z0-9_]*)['"\`]`

const CODE_SITES: readonly RegExp[] = [
  // new StrutvaneError('not_found'), new AuthError('validation_failed', …)
  new RegExp(String.raw`\bnew\s+[A-Z]\w*Error\(\s*${LITERAL}`, 'g'),
  // { code: 'not_found' } and the first member of `readonly code: 'a' | 'b'`
  new RegExp(String.raw`\bcode\??:\s*\|?\s*${LITERAL}`, 'g'),
  // error.code === 'internal_error', code !== 'x'
  new RegExp(String.raw`\bcode\s*[!=]==?\s*${LITERAL}`, 'g'),
  // ['invalid_filter', 422, 'Invalid filter'] (registry rows)
  new RegExp(String.raw`\[\s*${LITERAL}\s*,\s*[45]\d\d\s*,`, 'g'),
]

/** The later members of a multi-line `code:` union type (`| 'session_set'`). */
const UNION_TYPE = /\bcode\??:((?:\s*\|?\s*'[A-Za-z][A-Za-z0-9_]*')+)/g
const UNION_MEMBER = /'([A-Za-z][A-Za-z0-9_]*)'/g

/**
 * Uppercase on purpose, by exact `[file, code]`, each for a reason that is not ours to change. A new
 * entry needs the same kind of reason; a Strutvane problem or finding code never qualifies.
 */
const NOT_OURS: ReadonlySet<string> = new Set([
  // Node's own module-resolution error codes, compared when probing an optional peer.
  'identity/app-identity.ts:ERR_MODULE_NOT_FOUND',
  'identity/app-identity.ts:MODULE_NOT_FOUND',
  // A Node process-warning code (`process.emitWarning`), uppercase by Node convention like the
  // framework's `STRUTVANE_UPPERCASE_ERROR_CODE`; it never reaches a client.
  'identity/better-auth.ts:STRUTVANE_AUTH_BETTER_AUTH',
])

const SNAKE = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/
/** PostgreSQL SQLSTATE values (`42P01`) are compared as codes too; they are not ours either. */
const SQLSTATE = /^[0-9A-Z]{5}$/

function scan(text: string): string[] {
  const found: string[] = []
  for (const pattern of CODE_SITES)
    for (const match of text.matchAll(pattern)) if (match[1] !== undefined) found.push(match[1])
  for (const union of text.matchAll(UNION_TYPE))
    for (const member of (union[1] ?? '').matchAll(UNION_MEMBER))
      if (member[1] !== undefined) found.push(member[1])
  return found
}

/** `file:code` for every code literal in `src` (paths relative to `src`, `/`-separated). */
function codeLiterals(): string[] {
  const found: string[] = []
  for (const file of readdirSync(SRC, { recursive: true, encoding: 'utf8' })) {
    if (!file.endsWith('.ts')) continue
    const name = file.replaceAll('\\', '/')
    for (const code of scan(readFileSync(join(SRC, file), 'utf8'))) found.push(`${name}:${code}`)
  }
  return found
}

describe('error codes in the source (CONSISTENCY #68, #123)', () => {
  test('every code in src is lowercase snake_case', () => {
    const literals = codeLiterals()
    // Guard against a scan that silently matches nothing (a moved src folder, a broken pattern).
    expect(literals.length).toBeGreaterThan(150)
    const offenders = literals.filter((entry) => {
      const code = entry.slice(entry.lastIndexOf(':') + 1)
      return !SNAKE.test(code) && !SQLSTATE.test(code) && !NOT_OURS.has(entry)
    })
    expect(offenders).toEqual([])
  })

  test('every allow-listed exception still exists (the list never goes stale)', () => {
    const literals = new Set(codeLiterals())
    for (const entry of NOT_OURS) expect(literals.has(entry), entry).toBe(true)
  })

  test('the README shows only lowercase codes', () => {
    const offenders = scan(readFileSync(join(ROOT, 'README.md'), 'utf8')).filter(
      (code) => !SNAKE.test(code),
    )
    expect(offenders).toEqual([])
  })

  test('the scan sees every shape it guards against', () => {
    const sample = [
      "throw new StrutvaneError('NOT_FOUND', { status: 404 })",
      "new AuthError('Weak_Password')",
      "{ severity: 'error', code: 'RLS_DISABLED' }",
      "readonly code?: 'SESSION_SET'",
      "readonly code:\n    | 'SET_LOCAL'\n    | 'SESSION_RESET'",
      "if (error.code === 'INTERNAL_ERROR') {}",
      "['INVALID_FILTER', 422, 'Invalid filter'],",
    ].join('\n')
    expect([...new Set(scan(sample))].sort()).toEqual([
      'INTERNAL_ERROR',
      'INVALID_FILTER',
      'NOT_FOUND',
      'RLS_DISABLED',
      'SESSION_RESET',
      'SESSION_SET',
      'SET_LOCAL',
      'Weak_Password',
    ])
  })
})

describe('every code a client can receive has a registered title', () => {
  const registry = createErrorRegistry()
  for (const definition of AUTH_ERRORS)
    if (!registry.get(definition.code)) registry.register(definition)

  test('auth registers no code the framework already defines (registering never collides)', () => {
    const builtin = new Set(BUILTIN_ERRORS.map((d) => d.code))
    expect(AUTH_ERRORS.filter((d) => builtin.has(d.code)).map((d) => d.code)).toEqual([])
    expect(() => {
      const fresh = createErrorRegistry()
      for (const definition of AUTH_ERRORS) fresh.register(definition)
    }).not.toThrow()
  })

  test('identity failures and the codes auth throws as StrutvaneError', () => {
    const thrown = codeLiterals()
      .filter((entry) => /^(?:provider|middleware\/core|errors)\.ts:/.test(entry))
      .map((entry) => entry.slice(entry.lastIndexOf(':') + 1))
      .filter((code) => SNAKE.test(code))
    const codes = new Set([...Object.keys(IDENTITY_STATUS), ...thrown])
    expect(codes.size).toBeGreaterThan(10)
    for (const code of codes) {
      const definition = registry.get(code)
      expect(definition, code).toBeDefined()
      const problem = toProblem(new StrutvaneError(code), { registry })
      expect(problem.code).toBe(code)
      expect(problem.status).toBe(definition?.status)
      expect(problem.title.length).toBeGreaterThan(0)
    }
  })
})

describe('field issues match the framework shape (CONSISTENCY #69)', () => {
  test('an auth issue is a framework ValidationIssue, with `field` as the dotted path', () => {
    const issue: ValidationIssue = toIssue({
      field: 'members.2.email',
      code: 'invalid',
    })
    expect(issue.field).toBe(issue.path.join('.'))
    expect(issue.path).toEqual(['members', 2, 'email'])
  })
})
