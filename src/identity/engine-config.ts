/**
 * `config/auth.ts` → the native engine's settings.
 *
 * One file says how the app's config maps onto the engine, so the provider, the admin API and the
 * CLI commands build the same engine:
 * - **every feature switch is explicit** in the result, and off unless `config/auth.ts` turns it
 *   on (password sign-in and password confirmation are the two that default on). Nothing below
 *   this function supplies a default, so a key the app leaves out can never be switched on by a
 *   lower layer. `registration` is on only when `registration: true` (top level, v1) or
 *   `features.registration: true`; `teams` only with tenancy on (`config/tenancy.ts` `enabled`)
 *   or `features.teams: true`;
 * - role names: the platform roles and the tenant roles of the role map (split by each role's
 *   `scope`; see `partitionRoles`), else `rolePreset` (team roles: `owner` plus the preset's roles
 *   other than `admin`);
 * - `session.idleMinutes` (v1) becomes `sessions.idleMinutes` unless `sessions` sets it;
 * - personal teams are off unless `teams.personal` turns them on (a team is a customer company).
 *
 * @module
 */
import type { AuthConfig } from '../config.ts'
import type { AuthConfigInput, AuthFeatures } from '../engine/config.ts'
import { partitionRoles } from '../policy/roles.ts'

/** The switches `engineConfigFrom` always sets (`passwordReset` follows `password`). */
export type ExplicitFeatures = Readonly<Omit<AuthFeatures, 'passwordReset'>>

/** Every feature key `engineConfigFrom` sets, in a stable order (for tests and tooling). */
export const FEATURE_KEYS: readonly (keyof ExplicitFeatures)[] = Object.freeze([
  'password',
  'registration',
  'emailVerification',
  'passwordConfirmation',
  'twoFactor',
  'passkeys',
  'emailLink',
  'apiTokens',
  'teams',
  'impersonation',
])

/** On only when the config says exactly `true` (a JavaScript config may hold anything). */
const on = (value: unknown): boolean => value === true
/** On unless the config says exactly `false`. */
const onUnlessOff = (value: unknown): boolean => value !== false

/**
 * The complete feature set for an app: every key explicit, everything optional off unless set.
 *
 * @example
 * resolveFeatures({}, { tenancy: false }).registration // false
 */
export function resolveFeatures(
  cfg: AuthConfig,
  app: { readonly tenancy: boolean },
): ExplicitFeatures {
  const f: Readonly<Record<string, unknown>> = cfg.features ?? {}
  return Object.freeze({
    password: onUnlessOff(f['password']),
    registration: on(cfg.registration) || on(f['registration']),
    emailVerification: on(f['emailVerification']),
    passwordConfirmation: onUnlessOff(f['passwordConfirmation']),
    twoFactor: on(f['twoFactor']),
    passkeys: on(f['passkeys']),
    emailLink: on(f['emailLink']),
    apiTokens: on(f['apiTokens']),
    teams: app.tenancy || on(f['teams']),
    impersonation: on(f['impersonation']),
  })
}

/**
 * Build the engine settings for an app.
 *
 * @example
 * engineConfigFrom({ features: { twoFactor: true } }, { tenancy: true, sessionCookie: 'strutvane_session' })
 */
export function engineConfigFrom(
  cfg: AuthConfig,
  app: { readonly tenancy: boolean; readonly sessionCookie?: string },
): Omit<AuthConfigInput, 'appUrl'> {
  const roles = cfg.roles ? partitionRoles(cfg.roles) : undefined
  const idle = cfg.sessions?.idleMinutes ?? cfg.session?.idleMinutes
  return {
    ...(app.sessionCookie !== undefined ? { sessionCookie: app.sessionCookie } : {}),
    features: resolveFeatures(cfg, app),
    teams: { personal: false, ...cfg.teams },
    ...(roles
      ? { roles: roles.global, tenantRoles: roles.tenant }
      : cfg.rolePreset
        ? { roles: cfg.rolePreset }
        : {}),
    ...(cfg.passwords ? { passwords: cfg.passwords } : {}),
    ...(cfg.sessions || idle !== undefined
      ? { sessions: { ...cfg.sessions, ...(idle !== undefined ? { idleMinutes: idle } : {}) } }
      : {}),
    ...(cfg.links ? { links: cfg.links } : {}),
    ...(cfg.twoFactor ? { twoFactor: cfg.twoFactor } : {}),
    ...(cfg.tokens ? { tokens: cfg.tokens } : {}),
    ...(cfg.passkeys ? { passkeys: cfg.passkeys } : {}),
    ...(cfg.limits ? { limits: cfg.limits } : {}),
    ...(cfg.lockout ? { lockout: cfg.lockout } : {}),
  }
}
