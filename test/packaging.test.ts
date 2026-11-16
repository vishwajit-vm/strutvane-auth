/**
 * Packaging guard: this package must share the app's single kernel, `@strutvane/framework`.
 *
 * Why: contracts, core, devkit and cli were folded into `@strutvane/framework` (framework
 * CONSOLIDATION.md). A package that still depends on `@strutvane/core` or `@strutvane/contracts`
 * installs a second kernel next to the framework's own. Container tokens are `Symbol()`s and
 * error checks use `instanceof`, so across two kernels the logger token is not found and a
 * `NotFoundError` renders as a 500. The framework must be a **peer** (the app owns the one copy),
 * on a range that excludes `0.1.0-next.0`, which was published before the merge and has no
 * `./core` or `./contracts` subpath.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

type Deps = Readonly<Record<string, string>>
interface Manifest {
  readonly dependencies?: Deps
  readonly devDependencies?: Deps
  readonly peerDependencies?: Deps
  readonly engines?: { readonly node?: string }
}

const root = fileURLToPath(new URL('..', import.meta.url))
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as Manifest
const FRAMEWORK = '@strutvane/framework'
const ABSORBED = /^@strutvane\/(core|contracts|devkit|cli)$/
const PRODUCT = /^@strutvane\/(auth|ui|logs|log-viewer|files)$/
const ABSORBED_IMPORT =
  /(?:from|import)\s*\(?\s*['"]@strutvane\/(?:core|contracts|devkit|cli)(?:\/[^'"]*)?['"]/

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return sourceFiles(path)
    return /\.(m?ts|tsx)$/.test(name) ? [path] : []
  })
}

const fields = ['dependencies', 'devDependencies', 'peerDependencies'] as const

describe('packaging: one kernel', () => {
  it('declares no absorbed package (@strutvane/core, contracts, devkit, cli)', () => {
    const found = fields.flatMap((f) => Object.keys(pkg[f] ?? {}).filter((n) => ABSORBED.test(n)))
    expect(found).toEqual([])
  })

  it('peer-depends on the merged framework and never bundles or pins its own copy', () => {
    expect(pkg.dependencies?.[FRAMEWORK]).toBeUndefined()
    const range = pkg.peerDependencies?.[FRAMEWORK]
    expect(range).toMatch(/^\^0\.\d+\.\d+(-next\.\d+)?$/)
    expect(range).not.toBe('^0.1.0-next.0')
  })

  it('depends on no other product package', () => {
    const found = fields.flatMap((f) => Object.keys(pkg[f] ?? {}).filter((n) => PRODUCT.test(n)))
    expect(found).toEqual([])
  })

  it('requires Node >=24.3 (earlier 24.x break arguments in PowerShell)', () => {
    expect(pkg.engines?.node).toBe('>=24.3')
  })

  it('imports the kernel only through @strutvane/framework subpaths', () => {
    const offenders = sourceFiles(join(root, 'src')).filter((file) =>
      ABSORBED_IMPORT.test(readFileSync(file, 'utf8')),
    )
    expect(offenders).toEqual([])
  })
})
