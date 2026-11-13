/**
 * `findSessionSet`: a lint for ADR-0007 rule 3. The tenant setting may only be set
 * transaction-locally, with `set_config('app.tenant_id', $1, true)`. This finds the forms that
 * leak the tenant across pooled connections or invite SQL injection:
 *
 * - `SET app.tenant_id = …` / `SET SESSION app.tenant_id …`: session-level, leaks (error);
 * - `set_config('app.tenant_id', …, false)` (or anything but a literal `true`): leaks (error);
 * - `SET LOCAL app.tenant_id = …`: transaction-local, but `SET` cannot take parameters, so a
 *   dynamic value means string interpolation (warning).
 *
 * Use it in a unit test over your migrations and raw SQL, or in a CI script.
 *
 * @module
 */
import { TENANT_SETTING } from './with-tenant.ts'

/** One finding. */
export interface SessionSetFinding {
  readonly severity: 'error' | 'warning'
  readonly code: 'SESSION_SET' | 'SESSION_SET_CONFIG' | 'SET_LOCAL'
  /** 1-based line number in the input. */
  readonly line: number
  readonly message: string
}

/** Replace comments with spaces (keeping line numbers), so commented-out code is not reported. */
function stripComments(sql: string): string {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/--[^\n]*/g, (m) => ' '.repeat(m.length))
}

const lineOf = (text: string, index: number): number => text.slice(0, index).split('\n').length

/** Split the top-level comma-separated arguments of a call whose `(` is at `open`. */
function callArguments(text: string, open: number): string[] | undefined {
  const args: string[] = []
  let depth = 0
  let quote: string | undefined
  let start = open + 1
  for (let i = open; i < text.length; i++) {
    const ch = text[i]
    if (quote) {
      if (ch === quote) quote = undefined
      continue
    }
    if (ch === "'" || ch === '"') quote = ch
    else if (ch === '(') depth++
    else if (ch === ')') {
      depth--
      if (depth === 0) {
        args.push(text.slice(start, i).trim())
        return args
      }
    } else if (ch === ',' && depth === 1) {
      args.push(text.slice(start, i).trim())
      start = i + 1
    }
  }
  return undefined
}

/** Find session-level (or interpolation-prone) writes of the tenant setting in SQL text. */
export function findSessionSet(sql: string, setting: string = TENANT_SETTING): SessionSetFinding[] {
  const text = stripComments(sql)
  const name = setting.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const findings: SessionSetFinding[] = []

  const set = new RegExp(
    `\\bSET\\s+(SESSION\\s+|LOCAL\\s+)?["']?${name}["']?\\s*(=|\\bTO\\b)`,
    'gi',
  )
  for (const m of text.matchAll(set)) {
    const local = /^LOCAL/i.test(m[1] ?? '')
    findings.push(
      local
        ? {
            severity: 'warning',
            code: 'SET_LOCAL',
            line: lineOf(text, m.index),
            message: `SET LOCAL ${setting} cannot take a bind parameter; use set_config('${setting}', $1, true) instead.`,
          }
        : {
            severity: 'error',
            code: 'SESSION_SET',
            line: lineOf(text, m.index),
            message: `Session-level SET ${setting} leaks the tenant to the next user of a pooled connection; use set_config('${setting}', $1, true) inside a transaction.`,
          },
    )
  }

  for (const m of text.matchAll(/\bset_config\s*\(/gi)) {
    const args = callArguments(text, m.index + m[0].length - 1)
    if (args?.length !== 3) continue
    const [target = '', , local = ''] = args
    if (target.replace(/^'|'$/g, '').toLowerCase() !== setting.toLowerCase()) continue
    if (local.toLowerCase() !== 'true') {
      findings.push({
        severity: 'error',
        code: 'SESSION_SET_CONFIG',
        line: lineOf(text, m.index),
        message: `set_config('${setting}', …, ${local}) is session-level unless the third argument is the literal true.`,
      })
    }
  }
  return findings.sort((a, b) => a.line - b.line)
}
