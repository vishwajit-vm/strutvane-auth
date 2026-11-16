/**
 * `config/auth.ts` → the native engine's settings.
 *
 * One file says how the app's config maps onto the engine, so the provider, the admin API and the
 * CLI commands build the same engine:
 * - `features` are taken as written; `registration: true` at the top level (v1) also opens
 *   sign-up, and teams are on whenever tenancy is (`config/tenancy.ts` `enabled`);
 * - role names come from the role map's keys (with `admin`, the team-managing role), else from
 *   `rolePreset`;
 * - `session.idleMinutes` (v1) becomes `sessions.idleMinutes` unless `sessions` sets it;
 * - personal teams are off unless `teams.personal` turns them on (a team is a customer company).
 *
 * @module
 */
import type { AuthConfig } from '../config.ts'
import type { AuthConfigInput } from '../engine/config.ts'

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
  const roleNames = cfg.roles ? [...new Set(['admin', ...Object.keys(cfg.roles)])] : undefined
  const idle = cfg.sessions?.idleMinutes ?? cfg.session?.idleMinutes
  return {
    ...(app.sessionCookie !== undefined ? { sessionCookie: app.sessionCookie } : {}),
    features: {
      ...cfg.features,
      ...(cfg.registration === true ? { registration: true } : {}),
      ...(app.tenancy ? { teams: true } : {}),
    },
    teams: { personal: false, ...cfg.teams },
    ...(roleNames ? { roles: roleNames } : cfg.rolePreset ? { roles: cfg.rolePreset } : {}),
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
