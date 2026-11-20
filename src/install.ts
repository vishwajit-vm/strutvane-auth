/**
 * `node strut install:auth` (AUTH-2, demo acceptance run): auth installs itself into a v2 app
 * (blueprint §3.3: every package installs itself completely, install order never matters).
 *
 * What it does, each step idempotent (running it twice changes nothing):
 * 1. **Registers the provider** in `bootstrap/providers.ts`
 *    (`import auth from '@strutvane/auth/provider'` plus `auth` in the list). Without this the app
 *    has no sign-in routes and its auth migrations are "ignored". The edit is made by the
 *    framework's app patcher (`createAppPatcher`, `@strutvane/framework/devkit`), which parses the
 *    file and edits only what changes. A framework without it (0.2.0-next.1 and older) gets the
 *    exact lines printed instead: auth never rewrites a file it cannot parse (fail safe).
 * 2. **Copies the migrations** into `database/migrations` (decision #2; same as `auth:migration`).
 * 3. **Writes `config/auth.ts`** with the Recommended features when the app has none (never
 *    overwrites one; the installer writes it from your answers).
 *
 * @module
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

/** The provider list file of a v2 app. */
export const PROVIDERS_FILE = 'bootstrap/providers.ts'

/** The module an app imports auth's provider from. */
export const PROVIDER_MODULE = '@strutvane/auth/provider'

/** The two lines that register auth by hand (printed when the file can't be edited safely). */
export const PROVIDER_MANUAL_LINES: readonly string[] = Object.freeze([
  `import auth from '${PROVIDER_MODULE}'`,
  'const providers: readonly AnyProvider[] = [AppServiceProvider, auth]   // add auth to the list',
])

/** One entry of a provider list, in the framework app patcher's shape. */
interface AppListEntry {
  readonly specifier: string
  readonly name: string
  readonly importKind?: 'named' | 'default'
}

/** What an edit did, in the framework app patcher's shape. */
export interface ProviderRegistration {
  readonly status: 'added' | 'unchanged' | 'manual'
  /** The lines to write by hand when `status` is `manual`. */
  readonly manual: readonly string[]
}

/** The part of the framework's `createAppPatcher` (framework `v2/gaps`, 0.2.0-next.2+) auth uses. */
export type CreateAppPatcher = (
  fs: {
    exists(path: string): Promise<boolean>
    read(path: string): Promise<string>
    write(path: string, content: string, options?: { readonly overwrite?: boolean }): Promise<void>
  },
  options?: { readonly log?: { warn(message: string): void } },
) => {
  addProvider(entry: AppListEntry): Promise<{
    readonly status: 'added' | 'removed' | 'unchanged' | 'manual'
    readonly manual: readonly string[]
  }>
}

/**
 * The framework's app patcher, when the installed framework has one. Looked up at run time
 * because auth's peer range still allows 0.2.0-next.1, which does not export it.
 */
export async function frameworkAppPatcher(): Promise<CreateAppPatcher | undefined> {
  try {
    const devkit = (await import('@strutvane/framework/devkit')) as Readonly<
      Record<string, unknown>
    >
    const create = devkit['createAppPatcher']
    return typeof create === 'function' ? (create as CreateAppPatcher) : undefined
  } catch {
    return undefined
  }
}

/** The auth provider, as the patcher lists it: `import auth from '@strutvane/auth/provider'`. */
const AUTH_ENTRY: AppListEntry = Object.freeze({
  specifier: PROVIDER_MODULE,
  name: 'auth',
  importKind: 'default',
})

/** Options for {@link registerAuthProvider}. */
export interface RegisterOptions {
  /** Where "do this by hand" instructions go. */
  readonly warn: (message: string) => void
  /** The patcher to use; default: the installed framework's (see {@link frameworkAppPatcher}). */
  readonly patcher?: CreateAppPatcher | undefined
}

/**
 * Add auth's provider to `bootstrap/providers.ts`. Returns `unchanged` when it is already there,
 * `manual` (with the lines to write) when the file is missing, unusual, or the framework has no
 * app patcher; the file is then left exactly as it was.
 *
 * @example
 * await registerAuthProvider(root, { warn: (m) => ctx.out.warn(m) })
 */
export async function registerAuthProvider(
  root: string,
  options: RegisterOptions,
): Promise<ProviderRegistration> {
  const file = join(root, PROVIDERS_FILE)
  if (!existsSync(file)) {
    options.warn(
      `${PROVIDERS_FILE} was not found (is this a Strutvane 0.2 app?). Register the provider by hand:`,
    )
    return { status: 'manual', manual: PROVIDER_MANUAL_LINES }
  }
  const source = readFileSync(file, 'utf8')
  // Already registered (by the skeleton or a previous run): nothing to do.
  if (source.includes(`'${PROVIDER_MODULE}'`) || source.includes(`"${PROVIDER_MODULE}"`))
    return { status: 'unchanged', manual: [] }
  const create = 'patcher' in options ? options.patcher : await frameworkAppPatcher()
  if (create === undefined) {
    options.warn(
      `This framework version cannot edit ${PROVIDERS_FILE} yet (it needs @strutvane/framework 0.2.0-next.2 or later). Add these lines by hand:`,
    )
    return { status: 'manual', manual: PROVIDER_MANUAL_LINES }
  }
  const patcher = create(
    {
      exists: async (path) => existsSync(join(root, path)),
      read: async (path) => readFileSync(join(root, path), 'utf8'),
      write: async (path, content) => {
        const target = join(root, path)
        mkdirSync(dirname(target), { recursive: true })
        writeFileSync(target, content)
      },
    },
    { log: { warn: options.warn } },
  )
  const result = await patcher.addProvider(AUTH_ENTRY)
  if (result.status === 'manual') return { status: 'manual', manual: result.manual }
  return { status: result.status === 'added' ? 'added' : 'unchanged', manual: [] }
}

/**
 * The Recommended `config/auth.ts` (the same features the skeleton's template holds), written
 * only when the app has none.
 */
export const DEFAULT_AUTH_CONFIG = `// Sign-in features, read by @strutvane/auth. Written by \`node strut install:auth\`; edit freely.
// APP_KEY is the one root secret: every signing and encryption key is derived from it.
export default {
  features: {
    password: true,
    emailLink: false,
    // Public sign-up stays off: B2B apps are invite-only unless you decide otherwise.
    registration: false,
    emailVerification: true,
    passwordReset: true,
    passwordConfirmation: true,
    twoFactor: true,
    passkeys: false,
    apiTokens: true,
    teams: false,
    impersonation: false,
  },
}
`

/**
 * Write `config/auth.ts` when it is missing. Returns whether it was written (never overwrites).
 *
 * @example
 * ensureAuthConfig(root) // true on an app created without sign-in
 */
export function ensureAuthConfig(root: string): boolean {
  const file = join(root, 'config', 'auth.ts')
  if (existsSync(file)) return false
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(file, DEFAULT_AUTH_CONFIG, { flag: 'wx' })
  return true
}
