/**
 * `config/auth.ts`: the typed shape of an app's auth settings, and `defineAuthConfig`.
 *
 * ```ts
 * // config/auth.ts
 * import { defineAuthConfig } from '@strutvane/auth'
 * import { env } from '../env.ts'
 *
 * export default defineAuthConfig({
 *   registration: env.AUTH_ALLOW_REGISTRATION,
 *   roles: {
 *     admin: { permissions: ['*'] },
 *     member: { permissions: ['*.viewAny', '*.view', '*.create', { action: '*.update', own: true }] },
 *     viewer: { permissions: ['*.viewAny', '*.view'] },
 *   },
 *   newModelDefaults: 'inherit-role-patterns',
 * })
 * ```
 *
 * **Why a dedicated helper instead of core's `defineConfig`?** `defineConfig` accepts any object,
 * so a misspelt key (`rolse`, `trustedOrigin`) or a wrong value shape would be silently ignored,
 * and in an authorization config "ignored" means "different access than you wrote". This helper
 * returns exactly what `defineConfig` returns (the same deep-frozen object, literal types kept for
 * typed `app.config('auth.…')` paths) but checks the object against {@link AuthConfig} and rejects
 * unknown top-level keys at compile time. The role map is validated again at boot by the provider
 * (`compileRoleMap`), for configs written without TypeScript.
 *
 * @module
 */
import { type DeepReadonly, defineConfig } from '@strutvane/framework/core'
import type { NewModelDefaults, RoleDefinition } from './policy/roles.ts'

/** Client credentials of one social sign-in provider (values usually come from the env). */
export type SocialProviderConfig = Readonly<Record<string, string | undefined>>

/**
 * Everything `config/auth.ts` may contain. The app provider (`@strutvane/auth/provider`) reads
 * `registration`, `seedAdmin`, `defaultRoles`, `session.idleMinutes`, `trustedOrigins`,
 * `trustedProxies` and the role map (`roles`, `wildcardExclude`, `newModelDefaults`); the other keys
 * are declared for the identity engines and installers that read them.
 */
export interface AuthConfig {
  /** Sign-in methods offered (e.g. `['email', 'google']`). */
  readonly methods?: readonly string[]
  /** The signing secret (from `AUTH_SECRET`; never hard-code it). */
  readonly secret?: string | undefined
  /**
   * Whether anyone may self-register (`POST /auth/sign-up`). Default `false`: sign-up is open only
   * when this is exactly `true`. Deny-by-default, so an app that omits the key (or loads an unset or
   * mistyped env value) never exposes public registration by accident.
   */
  readonly registration?: boolean | undefined
  readonly session?: {
    readonly driver?: string | undefined
    /** Idle timeout in minutes. */
    readonly idleMinutes?: number | undefined
  }
  readonly tokens?: { readonly accessTokenSeconds?: number | undefined }
  /** MFA policy (`off | optional | admins | required`). */
  readonly mfa?: string | undefined
  /** Social sign-in providers by name. */
  readonly social?: Readonly<Record<string, SocialProviderConfig>>
  /**
   * The account created on boot so there is always a way in. Its role is bound to the created
   * account's id (never to the email). Default role `admin`, held globally (outside tenants).
   */
  readonly seedAdmin?: {
    readonly email?: string | undefined
    readonly password?: string | undefined
    readonly role?: string | undefined
  }
  /** Roles every self-registered user gets outside tenants. Default: none. */
  readonly defaultRoles?: readonly string[]
  /**
   * The role map (docs/07 §4.4): role → permissions, compiled into allow grants that combine with
   * the policies (`(policy allows OR role grants) AND NOT policy denies`). See `compileRoleMap`.
   */
  readonly roles?: Readonly<Record<string, RoleDefinition>>
  /** Resources no resource wildcard (`*`, `*.view`) ever matches; grant them by exact name. */
  readonly wildcardExclude?: readonly string[]
  /** What models not named in the role map get. Default `'inherit-role-patterns'`. */
  readonly newModelDefaults?: NewModelDefaults
  /**
   * Extra origins allowed to call the state-changing auth endpoints (e.g. a SPA served from
   * another origin: `['https://app.example.com']`). The app URL and the request's own origin are
   * always allowed.
   */
  readonly trustedOrigins?: readonly string[]
  /**
   * Reverse proxies whose `X-Forwarded-For` may be trusted for rate limiting (addresses or CIDRs).
   * Default: none, so the socket peer address is used. Only list proxies you operate: a trusted
   * entry lets that peer choose the client address the per-IP limits are keyed by.
   */
  readonly trustedProxies?: readonly string[]
  readonly audit?: { readonly enabled?: boolean | undefined }
}

/** Rejects keys that {@link AuthConfig} does not declare (a typo would otherwise be ignored). */
type NoUnknownKeys<T> = { readonly [K in Exclude<keyof T, keyof AuthConfig>]: never }

/**
 * Declare `config/auth.ts`. Type-checks the object against {@link AuthConfig} (unknown top-level
 * keys are compile errors) and returns it deep-frozen, exactly like core's `defineConfig`.
 */
export function defineAuthConfig<const T extends AuthConfig>(
  config: T & NoUnknownKeys<T>,
): DeepReadonly<T> {
  return defineConfig<T>(config)
}
