/**
 * Loading `app/policies/*.policy.ts` (AUTH-3, demo acceptance run).
 *
 * One folder holds two kinds of policy, and auth must boot with either:
 * - **Framework policies** (the v2 app style, decision #73): a class or object with Laravel's
 *   methods (`viewAny`, `view`, `create`, `update`, `delete`, `before`, …), found by model name by
 *   the framework's `PolicyRegistry` and checked by `ResourceController` and `authorize()`. The
 *   skeleton's `UserPolicy` and every policy `node strut make:migration` writes are this kind.
 *   Auth leaves them to the framework: they are code, not data, so they cannot become SQL.
 * - **`definePolicy(...)`** (auth's own): rules as data, compiled to SQL for list filtering and
 *   checked in memory for one record (ADR-0008). Auth loads these into the permission provider.
 *
 * Anything else in the folder is an error at boot (fail closed): a file that exports nothing usable
 * would otherwise silently authorise nothing, or worse, look like it did.
 *
 * @module
 */
import { existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { BootError } from '@strutvane/framework'
import type { Policy } from './policy.ts'
import type { ModelSchema } from './schema.ts'

/** What a policy file exports, as auth sees it. */
export type PolicyFileKind = 'define-policy' | 'framework' | 'invalid'

/** Laravel's policy method names: an object with any of these is a framework policy. */
const FRAMEWORK_METHODS: readonly string[] = [
  'before',
  'viewAny',
  'view',
  'create',
  'update',
  'delete',
  'restore',
  'forceDelete',
]

const isDefinePolicy = (value: unknown): value is Policy<ModelSchema> =>
  typeof value === 'object' &&
  value !== null &&
  typeof (value as Partial<Policy<ModelSchema>>).resource === 'string' &&
  typeof (value as Partial<Policy<ModelSchema>>).filterFor === 'function'

const isFrameworkPolicy = (value: unknown): boolean => {
  // A class (the framework instantiates it through the container).
  if (typeof value === 'function') return value.prototype !== undefined
  if (typeof value !== 'object' || value === null) return false
  return FRAMEWORK_METHODS.some(
    (name) => typeof (value as Readonly<Record<string, unknown>>)[name] === 'function',
  )
}

/**
 * Classify a policy module the way the framework's discovery reads it: the default export, or
 * else the `<Model>Policy` named export.
 *
 * @example
 * classifyPolicyModule({ default: class UserPolicy { view() { return true } } }) // 'framework'
 * classifyPolicyModule({ default: definePolicy('user', { schema }, () => {}) }) // 'define-policy'
 */
export function classifyPolicyModule(module: Readonly<Record<string, unknown>>): {
  readonly kind: PolicyFileKind
  readonly policy?: Policy<ModelSchema>
} {
  const exported = module['default']
  if (isDefinePolicy(exported)) return { kind: 'define-policy', policy: exported }
  if (isFrameworkPolicy(exported)) return { kind: 'framework' }
  if (exported === undefined) {
    const named = Object.entries(module).find(([name]) => /^[A-Z][A-Za-z0-9]*Policy$/.test(name))
    if (named !== undefined && isFrameworkPolicy(named[1])) return { kind: 'framework' }
  }
  return { kind: 'invalid' }
}

/** Options for {@link loadPolicies}. */
export interface LoadPoliciesOptions {
  /** Told about each framework policy auth leaves to the framework (debug output). */
  readonly onFrameworkPolicy?: (file: string) => void
}

/**
 * Load the `definePolicy(...)` exports of `app/policies/*.policy.ts`. Framework (class) policies
 * are skipped: the framework's `PolicyRegistry` owns them. A file that is neither fails the boot
 * with `invalid_policy_file` and says how to fix it.
 *
 * @example
 * const policies = await loadPolicies(app.basePath)
 */
export async function loadPolicies(
  root: string,
  options: LoadPoliciesOptions = {},
): Promise<Policy<ModelSchema>[]> {
  const dir = join(root, 'app', 'policies')
  if (!existsSync(dir)) return []
  const files = readdirSync(dir)
    .filter((f) => f.endsWith('.policy.ts'))
    .sort()
  const out: Policy<ModelSchema>[] = []
  for (const file of files) {
    const module = (await import(pathToFileURL(join(dir, file)).href)) as Readonly<
      Record<string, unknown>
    >
    const found = classifyPolicyModule(module)
    if (found.policy !== undefined) out.push(found.policy)
    else if (found.kind === 'framework') options.onFrameworkPolicy?.(`app/policies/${file}`)
    else
      throw new BootError(
        'invalid_policy_file',
        `app/policies/${file} exports no policy.`,
        'Export a policy class as the default export (export default class UserPolicy { view(user, model) { … } }), or export default definePolicy(…) from @strutvane/auth.',
      )
  }
  return out
}
