/**
 * AUTH-2 (demo acceptance run): `node strut install:auth` registers the provider in a v2 app's
 * `bootstrap/providers.ts`, copies the migrations and writes `config/auth.ts` when missing, all
 * idempotent; and never edits a provider file it cannot handle (it prints the lines instead).
 *
 * The framework's `createAppPatcher` lands in 0.2.0-next.2 (framework branch `v2/gaps`); until
 * then the installed framework has none, so the "added" path runs against a stand-in that follows
 * its documented contract, and the real default path is checked to fall back to printed lines.
 */
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import commands, { type AuthCommandContext } from '../src/commands.ts'
import {
  type CreateAppPatcher,
  DEFAULT_AUTH_CONFIG,
  ensureAuthConfig,
  frameworkAppPatcher,
  PROVIDER_MANUAL_LINES,
  registerAuthProvider,
} from '../src/install.ts'
import { AUTH_MIGRATIONS } from '../src/migrations.ts'

/** The skeleton's bootstrap/providers.ts, as it ships for an app without sign-in. */
const SKELETON_PROVIDERS = `// The service providers that run at boot, in order.
import type { AnyProvider } from '@strutvane/framework'
import { AppServiceProvider } from '../app/providers/app.provider.ts'

const providers: readonly AnyProvider[] = [AppServiceProvider]

export default providers
`

const roots: string[] = []
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

function app(files: Record<string, string> = { 'bootstrap/providers.ts': SKELETON_PROVIDERS }) {
  const root = mkdtempSync(join(tmpdir(), 'sv-auth-install-'))
  roots.push(root)
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), content)
  }
  return root
}

/** A stand-in for the framework's createAppPatcher: the skeleton's shape, nothing else. */
const standIn: CreateAppPatcher = (fs) => ({
  async addProvider(entry) {
    const path = 'bootstrap/providers.ts'
    const source = await fs.read(path)
    const list = /\[AppServiceProvider\]/
    if (!list.test(source)) return { status: 'manual', manual: ['by hand'] }
    const line =
      entry.importKind === 'default'
        ? `import ${entry.name} from '${entry.specifier}'`
        : `import { ${entry.name} } from '${entry.specifier}'`
    await fs.write(
      path,
      source
        .replace('import { AppServiceProvider }', `${line}\nimport { AppServiceProvider }`)
        .replace(list, `[AppServiceProvider, ${entry.name}]`),
      { overwrite: true },
    )
    return { status: 'added', manual: [] }
  },
})

describe('registerAuthProvider', () => {
  it('adds `import auth from @strutvane/auth/provider` and lists it, once', async () => {
    const root = app()
    const warn: string[] = []
    const first = await registerAuthProvider(root, { warn: (m) => warn.push(m), patcher: standIn })
    expect(first).toEqual({ status: 'added', manual: [] })
    const source = readFileSync(join(root, 'bootstrap/providers.ts'), 'utf8')
    expect(source).toContain("import auth from '@strutvane/auth/provider'")
    expect(source).toContain('[AppServiceProvider, auth]')
    // Idempotent: the second run sees the import and changes nothing.
    const second = await registerAuthProvider(root, { warn: (m) => warn.push(m), patcher: standIn })
    expect(second).toEqual({ status: 'unchanged', manual: [] })
    expect(readFileSync(join(root, 'bootstrap/providers.ts'), 'utf8')).toBe(source)
    expect(warn).toEqual([])
  })

  it('a file the patcher cannot edit is left alone; the lines are returned to print', async () => {
    const odd = 'export default [...base, AppServiceProvider]\n'
    const root = app({ 'bootstrap/providers.ts': odd })
    const result = await registerAuthProvider(root, { warn: () => undefined, patcher: standIn })
    expect(result).toEqual({ status: 'manual', manual: ['by hand'] })
    expect(readFileSync(join(root, 'bootstrap/providers.ts'), 'utf8')).toBe(odd)
  })

  it('without a framework app patcher it prints the exact lines and edits nothing', async () => {
    const root = app()
    const warn: string[] = []
    const result = await registerAuthProvider(root, {
      warn: (m) => warn.push(m),
      patcher: undefined,
    })
    expect(result).toEqual({ status: 'manual', manual: PROVIDER_MANUAL_LINES })
    expect(warn.join('\n')).toMatch(/0\.2\.0-next\.2/)
    expect(readFileSync(join(root, 'bootstrap/providers.ts'), 'utf8')).toBe(SKELETON_PROVIDERS)
  })

  it('a v1 app (no bootstrap/providers.ts) gets the lines, never a new file', async () => {
    const root = app({})
    const result = await registerAuthProvider(root, { warn: () => undefined, patcher: standIn })
    expect(result.status).toBe('manual')
    expect(existsSync(join(root, 'bootstrap/providers.ts'))).toBe(false)
  })

  it('the default patcher is the installed framework one, when it has one', async () => {
    const found = await frameworkAppPatcher()
    expect(found === undefined || typeof found === 'function').toBe(true)
  })
})

describe('ensureAuthConfig', () => {
  it('writes the Recommended config/auth.ts once and never overwrites', async () => {
    const root = app()
    expect(ensureAuthConfig(root)).toBe(true)
    expect(readFileSync(join(root, 'config/auth.ts'), 'utf8')).toBe(DEFAULT_AUTH_CONFIG)
    writeFileSync(join(root, 'config/auth.ts'), 'export default { features: {} }\n')
    expect(ensureAuthConfig(root)).toBe(false)
    expect(readFileSync(join(root, 'config/auth.ts'), 'utf8')).toBe(
      'export default { features: {} }\n',
    )
    // It is plain data the provider can read.
    const loaded = (await import(pathToFileURL(join(root, 'config/auth.ts')).href)) as {
      default: { features: Record<string, boolean> }
    }
    expect(loaded.default.features).toEqual({})
  })
})

describe('node strut install:auth', () => {
  const install = commands.find((c) => c.name === 'install:auth')
  const run = async (root: string) => {
    const lines: string[] = []
    const ctx: AuthCommandContext = {
      flags: {},
      requireProject: () => ({ root }),
      out: {
        line: (t = '') => lines.push(t),
        success: (t) => lines.push(`ok ${t}`),
        info: (t) => lines.push(`i ${t}`),
        warn: (t) => lines.push(`! ${t}`),
      },
    }
    const result = await install?.run(ctx)
    return { result, lines }
  }

  it('is contributed next to auth:migration', () => {
    expect(install?.description).toMatch(/register the provider/)
  })

  it('on a skeleton app that already lists auth: copies the migrations, idempotently', async () => {
    const root = app({
      'bootstrap/providers.ts': SKELETON_PROVIDERS.replace(
        'import { AppServiceProvider }',
        "import auth from '@strutvane/auth/provider'\nimport { AppServiceProvider }",
      ).replace('[AppServiceProvider]', '[AppServiceProvider, auth]'),
      'config/auth.ts': 'export default { features: { password: true } }\n',
    })
    const first = await run(root)
    expect(first.result).toMatchObject({
      data: { config: 'present', provider: 'unchanged', manual: [] },
    })
    expect(first.result).not.toHaveProperty('exitCode')
    expect(readdirSync(join(root, 'database/migrations')).sort()).toEqual([...AUTH_MIGRATIONS])
    const second = await run(root)
    expect(second.result).toMatchObject({ data: { provider: 'unchanged' } })
    expect(second.lines.join('\n')).toContain('already in database/migrations')
  })

  it('on an app without sign-in: writes config/auth.ts and asks for the two lines (exit 3) when the framework cannot patch', async () => {
    const root = app()
    const { result, lines } = await run(root)
    expect(existsSync(join(root, 'config/auth.ts'))).toBe(true)
    expect(readdirSync(join(root, 'database/migrations')).sort()).toEqual([...AUTH_MIGRATIONS])
    if ((await frameworkAppPatcher()) === undefined) {
      expect(result).toMatchObject({ exitCode: 3, data: { provider: 'manual' } })
      expect(lines).toContain(`    ${PROVIDER_MANUAL_LINES[0]}`)
    } else {
      expect(result).toMatchObject({ data: { provider: 'added' } })
    }
  })
})
