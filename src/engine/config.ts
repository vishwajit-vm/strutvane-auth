/**
 * `config/auth.ts`: feature switches and tunables, with secure defaults.
 *
 * The `features` block mirrors the installer's sign-in questions (blueprint §2.1, questions 5–12)
 * and Fortify's features array. A feature that is off has NO routes and its service methods throw
 * `not_found`, so it is indistinguishable from a feature that never existed (404, never 403).
 *
 * Defaults follow the security review: public registration is OFF (F-02), sign-in by email and
 * password is on, everything optional is off until the installer (or the developer) turns it on.
 *
 * @module
 */

/**
 * The switches, with the names used everywhere: installer, `config/auth.ts`, docs and routes
 * (CONSISTENCY #25 and #107). Each maps to installer answers; unknown keys are compile errors.
 */
export interface AuthFeatures {
  /** Email + password sign-in (question 5). `false` with `emailLink: true` = "email link only" (#107). */
  readonly password: boolean
  /** Public sign-up (question 6). Off by default: B2B apps are invite-only (review F-02). */
  readonly registration: boolean
  /** Signed email-verification links (question 6). */
  readonly emailVerification: boolean
  /**
   * Password reset. Always on wherever passwords are (it can't be switched off on its own, #25):
   * it resolves to the value of `password`.
   */
  readonly passwordReset: boolean
  /**
   * "Confirm your password" before sensitive actions (2FA settings, tokens, passkeys, sessions,
   * impersonation), within a 3-hour window (Laravel's `password.confirm`). On by default.
   */
  readonly passwordConfirmation: boolean
  /** TOTP two-factor with recovery codes (question 6). */
  readonly twoFactor: boolean
  /** Passkeys (WebAuthn), as a first factor and as a second factor (question 6). */
  readonly passkeys: boolean
  /** Passwordless email links (question 5, "email link only"). */
  readonly emailLink: boolean
  /** Personal access tokens (question 9). */
  readonly apiTokens: boolean
  /** Teams (question 11). */
  readonly teams: boolean
  /** Admin impersonation. */
  readonly impersonation: boolean
}

/**
 * The `features` block `config/auth.ts` may write. `passwordReset` can only be `true` (it follows
 * `password`); every other switch is a boolean.
 */
export type AuthFeaturesInput = Partial<Omit<AuthFeatures, 'passwordReset'>> & {
  readonly passwordReset?: true
}

/**
 * The role that runs a team (a tenant): its creator holds it, and only it manages members and
 * invitations. Reserved: it is never a global (platform) role, so a self-made team owner can
 * never match a grant written for platform roles such as `admin`.
 */
export const TEAM_OWNER_ROLE = 'owner'

/** The platform administrator role (global only; never a team role). */
export const PLATFORM_ADMIN_ROLE = 'admin'

/**
 * The starting global role presets (question 10). Role NAMES live in code; only assignments are
 * rows. Team roles default to `owner` plus the preset's roles other than `admin`.
 */
export const ROLE_PRESETS = {
  'admin-member': ['admin', 'member'],
  'admin-manager-member-viewer': ['admin', 'manager', 'member', 'viewer'],
} as const

/** A preset name for {@link ROLE_PRESETS}. */
export type RolePreset = keyof typeof ROLE_PRESETS

/** One rate limit: at most `max` hits per sliding `windowSeconds`. */
export interface RateRule {
  readonly max: number
  readonly windowSeconds: number
}

/** WebAuthn relying-party settings. */
export interface PasskeyConfig {
  /** The registrable domain, e.g. `example.com` (or `localhost` in development). */
  readonly rpId: string
  /** Shown by the browser's passkey prompt. */
  readonly rpName: string
  /** Exact origins allowed to answer a ceremony, e.g. `['https://app.example.com']`. */
  readonly origins: readonly string[]
}

/** Everything {@link defineAuthConfig} accepts. Every key except `appUrl` is optional. */
export interface AuthConfigInput {
  /** The public base URL; links are built on it and `https` turns on `__Host-` cookies. */
  readonly appUrl: string
  /**
   * The session cookie's base name (`config/session.ts` `cookie`; default `strutvane_session`).
   * `__Host-` is added on https. The framework's CSRF check reads the resolved name from the same
   * place (`SessionCookieToken`), so the two can never disagree (#105).
   */
  readonly sessionCookie?: string
  readonly features?: AuthFeaturesInput
  readonly passwords?: {
    /** Minimum length (default 12; Laravel's is 8, v1's non-regression list keeps 12). */
    readonly min?: number
    readonly max?: number
  }
  readonly sessions?: {
    /** Idle timeout (default 120 minutes, Laravel's session lifetime). */
    readonly idleMinutes?: number
    /** Absolute lifetime of a normal session (default 12 hours). */
    readonly absoluteHours?: number
    /** Absolute and idle lifetime of a "remember me" session (default 30 days). */
    readonly rememberDays?: number
    /** The password-confirmation window (default 3 hours, Laravel's `password_timeout`). */
    readonly confirmPasswordMinutes?: number
    /** How long a half-done 2FA sign-in waits for the second factor (default 10 minutes). */
    readonly twoFactorPendingMinutes?: number
  }
  readonly links?: {
    readonly passwordResetMinutes?: number
    readonly emailLinkMinutes?: number
    readonly verificationMinutes?: number
    readonly invitationDays?: number
  }
  readonly twoFactor?: {
    /** Recovery codes issued (8–10; default 10). */
    readonly recoveryCodes?: number
    /** "Remember this device" lifetime in days (0 turns the option off; default 30). */
    readonly rememberDeviceDays?: number
    /** Issuer shown in authenticator apps. */
    readonly issuer?: string
  }
  readonly tokens?: {
    /** Ability patterns a token may be given (`post.view`, `post.*`, `*`). Default `['*']`. */
    readonly abilities?: readonly string[]
    /** Default expiry (default 365 days; Sanctum's default is never). */
    readonly defaultExpiryDays?: number
    /** Longest expiry a user may pick (default 365 days). */
    readonly maxExpiryDays?: number
    /** The prefix secret scanners look for (default `svp_`). */
    readonly prefix?: string
  }
  /**
   * The global (platform) role names: a preset (installer question 10), or the app's own list.
   * A list must contain `admin` and must not contain `owner` (the reserved team role).
   */
  readonly roles?: RolePreset | readonly string[]
  /**
   * The team (tenant) role names: what an invitation or a membership may carry. Must contain
   * `owner` (the role that runs a team) and must not contain `admin` (the platform role). Default:
   * `owner` plus the global roles other than `admin`.
   */
  readonly tenantRoles?: readonly string[]
  readonly teams?: {
    /**
     * Give every new user a personal team (Laravel's teams kit). Default `true`. B2B apps where a
     * team is a customer company turn it off, so users join teams only by invitation.
     */
    readonly personal?: boolean
  }
  readonly passkeys?: PasskeyConfig
  readonly limits?: Partial<RateLimits>
  readonly lockout?: {
    /** Consecutive failures before a lockout (default 5). */
    readonly threshold?: number
    /** First lockout length (default 60 s); it doubles per further failure. */
    readonly baseSeconds?: number
    /** Longest lockout (default 1 hour). */
    readonly maxSeconds?: number
  }
}

/** The rate limits, all sliding windows (review F-22). */
export interface RateLimits {
  readonly loginPerIp: RateRule
  readonly loginPerAccount: RateRule
  readonly registerPerIp: RateRule
  readonly resetPerIp: RateRule
  readonly resetPerAccount: RateRule
  readonly emailLinkPerIp: RateRule
  readonly emailLinkPerAccount: RateRule
  readonly verificationResendPerAccount: RateRule
  readonly verificationResendCooldown: RateRule
  readonly twoFactorPerAccount: RateRule
  readonly passkeyPerIp: RateRule
  readonly confirmPasswordPerAccount: RateRule
  /** Team invitations sent by one account (every user admins a personal team: mail-bomb guard). */
  readonly invitePerAccount: RateRule
}

/** The resolved configuration every service reads. */
export interface AuthConfig {
  readonly appUrl: string
  readonly secureCookies: boolean
  /** The session cookie's base name (without `__Host-`). */
  readonly sessionCookie: string
  readonly features: AuthFeatures
  readonly passwords: { readonly min: number; readonly max: number }
  readonly sessions: {
    readonly idleMs: number
    readonly absoluteMs: number
    readonly rememberMs: number
    readonly confirmPasswordMs: number
    readonly twoFactorPendingMs: number
  }
  readonly links: {
    readonly passwordResetMs: number
    readonly emailLinkMs: number
    readonly verificationMs: number
    readonly invitationMs: number
  }
  readonly twoFactor: {
    readonly recoveryCodes: number
    readonly rememberDeviceMs: number
    readonly issuer: string
  }
  readonly tokens: {
    readonly abilities: readonly string[]
    readonly defaultExpiryMs: number
    readonly maxExpiryMs: number
    readonly prefix: string
  }
  /** Global (platform) role names; always with `admin`, never with `owner`. */
  readonly roles: readonly string[]
  /** Team role names; always with `owner`, never with `admin`. */
  readonly tenantRoles: readonly string[]
  readonly teams: { readonly personal: boolean }
  readonly passkeys: PasskeyConfig | undefined
  readonly limits: RateLimits
  readonly lockout: { readonly threshold: number; readonly baseMs: number; readonly maxMs: number }
}

/** Defaults for {@link AuthFeatures}. */
export const DEFAULT_FEATURES: AuthFeatures = Object.freeze({
  password: true,
  registration: false,
  emailVerification: false,
  passwordReset: true,
  passwordConfirmation: true,
  twoFactor: false,
  passkeys: false,
  emailLink: false,
  apiTokens: false,
  teams: false,
  impersonation: false,
})

/** Defaults for {@link RateLimits} (v1's values, plus the new flows). */
export const DEFAULT_LIMITS: RateLimits = Object.freeze({
  loginPerIp: { max: 10, windowSeconds: 60 },
  loginPerAccount: { max: 20, windowSeconds: 900 },
  registerPerIp: { max: 10, windowSeconds: 3600 },
  resetPerIp: { max: 5, windowSeconds: 900 },
  resetPerAccount: { max: 3, windowSeconds: 900 },
  emailLinkPerIp: { max: 5, windowSeconds: 900 },
  emailLinkPerAccount: { max: 3, windowSeconds: 900 },
  verificationResendPerAccount: { max: 6, windowSeconds: 3600 },
  verificationResendCooldown: { max: 1, windowSeconds: 60 },
  // Looser than the lockout (5 failures) on purpose: the lockout is the real bound; this caps the rate.
  twoFactorPerAccount: { max: 10, windowSeconds: 300 },
  passkeyPerIp: { max: 20, windowSeconds: 60 },
  confirmPasswordPerAccount: { max: 5, windowSeconds: 300 },
  invitePerAccount: { max: 20, windowSeconds: 3600 },
})

const MINUTE = 60_000
const ABILITY = /^(\*|[a-z][a-zA-Z0-9-]*(\.([a-z][a-zA-Z0-9-]*|\*))*)$/

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]'])

/** Local development: loopback or a `*.localhost` name (which browsers resolve to loopback). */
function isLocalHost(hostname: string): boolean {
  return LOCAL_HOSTS.has(hostname) || hostname.endsWith('.localhost')
}

/**
 * Check the WebAuthn relying party at boot. The library compares origins exactly, but a wrong
 * list fails OPEN in ways it cannot see: a foreign origin (`https://evil.test`) or a plain-http
 * origin would let that site answer ceremonies for this rpId. Each origin must be an exact http(s)
 * origin (no path, no wildcard), https unless it is localhost, and its host must be the rpId or a
 * subdomain of it (the browser rule).
 */
function checkPasskeys(config: PasskeyConfig): PasskeyConfig {
  const fail = (why: string): never => {
    throw new TypeError(`auth config: passkeys ${why}`)
  }
  const rpId = config.rpId
  if (
    typeof rpId !== 'string' ||
    !/^[a-z0-9.-]+$/.test(rpId) ||
    rpId.startsWith('.') ||
    rpId.endsWith('.')
  )
    fail('rpId must be a bare lowercase host name, e.g. `example.com`')
  if (!Array.isArray(config.origins) || config.origins.length === 0)
    fail('origins must list at least one origin')
  for (const origin of config.origins) {
    let url: URL | undefined
    try {
      url = new URL(origin)
    } catch {
      url = undefined
    }
    if (!url || url.origin !== origin)
      fail(`origin ${JSON.stringify(origin)} must be an exact origin like https://app.example.com`)
    else {
      if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOCAL_HOSTS.has(url.hostname)))
        fail(`origin ${JSON.stringify(origin)} must use https (http only on localhost)`)
      if (url.hostname !== rpId && !url.hostname.endsWith(`.${rpId}`))
        fail(`origin ${JSON.stringify(origin)} is not ${rpId} or a subdomain of it`)
    }
  }
  return Object.freeze({ ...config, origins: Object.freeze([...config.origins]) })
}

const ROLE_NAME = /^[a-z][a-z0-9_-]{0,63}$/

/** A checked list of role names (lowercase, no duplicates). */
function roleList(name: string, roles: unknown): readonly string[] {
  if (!Array.isArray(roles) || roles.some((r) => typeof r !== 'string' || !ROLE_NAME.test(r)))
    throw new TypeError(
      `auth config: ${name} must be lowercase names like \`admin\` or \`team-lead\``,
    )
  if (new Set(roles).size !== roles.length)
    throw new TypeError(`auth config: ${name} has duplicates`)
  return Object.freeze([...(roles as string[])])
}

/** A preset's roles, or a checked custom list (with `admin`, without `owner`). */
function resolveRoles(roles: RolePreset | readonly string[] | undefined): readonly string[] {
  if (roles === undefined || typeof roles === 'string') {
    const preset = ROLE_PRESETS[roles ?? 'admin-member']
    if (preset === undefined)
      throw new TypeError(`auth config: unknown role preset ${JSON.stringify(roles)}`)
    return Object.freeze([...preset])
  }
  const list = roleList('roles', roles)
  if (!list.includes(PLATFORM_ADMIN_ROLE))
    throw new TypeError('auth config: roles must include `admin` (the platform administrator)')
  if (list.includes(TEAM_OWNER_ROLE))
    throw new TypeError(
      'auth config: `owner` is the reserved team role and cannot be a global role (list it in tenantRoles)',
    )
  return list
}

/**
 * The team roles (with `owner`, without `admin`). Kept apart from the global roles so a team role
 * anyone can give themselves (create a team) never carries a platform role's grants.
 */
function resolveTenantRoles(
  tenantRoles: readonly string[] | undefined,
  global: readonly string[],
): readonly string[] {
  if (tenantRoles === undefined)
    return Object.freeze([TEAM_OWNER_ROLE, ...global.filter((r) => r !== PLATFORM_ADMIN_ROLE)])
  const list = roleList('tenantRoles', tenantRoles)
  if (!list.includes(TEAM_OWNER_ROLE))
    throw new TypeError('auth config: tenantRoles must include `owner` (it runs a team)')
  if (list.includes(PLATFORM_ADMIN_ROLE))
    throw new TypeError(
      'auth config: `admin` is the platform role and cannot be a team role (teams are run by `owner`)',
    )
  return list
}

/** RFC 6265 token characters, and never a prefix (the prefix is decided by the scheme). */
const COOKIE_BASE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$/

function checkCookieBase(base: string | undefined): string {
  if (base === undefined) return 'strutvane_session'
  if (typeof base !== 'string' || !COOKIE_BASE.test(base) || /^__(?:host|secure)-/i.test(base))
    throw new TypeError(
      `auth config: sessionCookie ${JSON.stringify(base)} is not a plain cookie name (the __Host- prefix is added on https)`,
    )
  return base
}

function positive(name: string, value: number): number {
  if (!Number.isFinite(value) || value <= 0)
    throw new RangeError(`auth config: ${name} must be a positive number`)
  return value
}

/**
 * Resolve `config/auth.ts` with defaults, failing at boot on nonsense (fail closed).
 *
 * @example
 * ```ts
 * // config/auth.ts
 * export default defineAuthConfig({
 *   appUrl: env.APP_URL,
 *   features: { twoFactor: true, emailVerification: true, passkeys: true },
 *   passkeys: { rpId: 'example.com', rpName: 'Acme', origins: ['https://example.com'] },
 * })
 * ```
 */
export function defineAuthConfig(input: AuthConfigInput): AuthConfig {
  const url = new URL(input.appUrl)
  // Every mailed link is built on appUrl; `javascript:`/`file:` URLs have origin "null".
  if (url.protocol !== 'https:' && url.protocol !== 'http:')
    throw new TypeError('auth config: appUrl must be an http(s) URL')
  const requested: Partial<AuthFeatures> = input.features ?? {}
  // A JavaScript config (no compile-time check) could still pass `passwordReset: false`; resetting
  // a forgotten password is never optional where passwords exist (#25), so refuse it at boot.
  if ((requested as { readonly passwordReset?: unknown }).passwordReset === false)
    throw new TypeError(
      'auth config: features.passwordReset is always on with passwords; turn off `password` instead',
    )
  const merged = { ...DEFAULT_FEATURES, ...requested }
  const features: AuthFeatures = { ...merged, passwordReset: merged.password }
  // An email link only signs in the browser holding its nonce cookie. Over plain http that cookie
  // is neither `__Host-` nor Secure, so anyone on the path (or a sibling host) can plant their own
  // nonce and log the victim into the attacker's account (CONSISTENCY #117). HTTPS outside local.
  if (features.emailLink && url.protocol !== 'https:' && !isLocalHost(url.hostname))
    throw new TypeError(
      'auth config: features.emailLink needs an https appUrl outside local development',
    )
  if (features.passkeys && input.passkeys === undefined)
    throw new TypeError(
      'auth config: features.passkeys needs a `passkeys: { rpId, rpName, origins }` block',
    )
  if (features.impersonation && !features.passwordConfirmation)
    throw new TypeError(
      'auth config: impersonation needs passwordConfirmation (admins confirm before impersonating)',
    )
  if (features.impersonation && !features.password && !features.passkeys)
    throw new TypeError(
      'auth config: impersonation needs password or passkeys (admins must confirm first)',
    )
  const min = input.passwords?.min ?? 12
  const max = input.passwords?.max ?? 256
  if (min < 8 || max < min)
    throw new RangeError('auth config: passwords.min must be at least 8 and at most max')
  const recoveryCodes = input.twoFactor?.recoveryCodes ?? 10
  if (!Number.isInteger(recoveryCodes) || recoveryCodes < 8 || recoveryCodes > 10)
    throw new RangeError('auth config: twoFactor.recoveryCodes must be 8, 9 or 10')
  const abilities = input.tokens?.abilities ?? ['*']
  for (const a of abilities)
    if (!ABILITY.test(a))
      throw new TypeError(`auth config: invalid token ability ${JSON.stringify(a)}`)
  const limits: RateLimits = { ...DEFAULT_LIMITS, ...input.limits }
  for (const [name, rule] of Object.entries(limits)) {
    if (!Number.isInteger(rule.max) || rule.max < 1)
      throw new RangeError(`auth config: limits.${name}.max must be a positive integer`)
    positive(`limits.${name}.windowSeconds`, rule.windowSeconds)
  }
  // A threshold of NaN or Infinity silently switched the lockout off; 0 or a fraction is nonsense.
  const threshold = input.lockout?.threshold ?? 5
  if (!Number.isInteger(threshold) || threshold < 1)
    throw new RangeError('auth config: lockout.threshold must be a positive integer')
  const lockoutBaseMs = positive('lockout.baseSeconds', input.lockout?.baseSeconds ?? 60) * 1000
  const lockoutMaxMs = positive('lockout.maxSeconds', input.lockout?.maxSeconds ?? 3600) * 1000
  if (lockoutMaxMs < lockoutBaseMs)
    throw new RangeError('auth config: lockout.maxSeconds must be at least lockout.baseSeconds')
  const roles = resolveRoles(input.roles)
  const prefix = input.tokens?.prefix ?? 'svp_'
  if (!/^[a-z]{2,8}_$/.test(prefix))
    throw new TypeError('auth config: tokens.prefix must look like `abc_`')
  return Object.freeze({
    appUrl: url.origin,
    secureCookies: url.protocol === 'https:',
    sessionCookie: checkCookieBase(input.sessionCookie),
    features: Object.freeze(features),
    passwords: { min, max },
    sessions: {
      idleMs: positive('sessions.idleMinutes', input.sessions?.idleMinutes ?? 120) * MINUTE,
      absoluteMs:
        positive('sessions.absoluteHours', input.sessions?.absoluteHours ?? 12) * 60 * MINUTE,
      rememberMs:
        positive('sessions.rememberDays', input.sessions?.rememberDays ?? 30) * 24 * 60 * MINUTE,
      confirmPasswordMs:
        positive('sessions.confirmPasswordMinutes', input.sessions?.confirmPasswordMinutes ?? 180) *
        MINUTE,
      twoFactorPendingMs:
        positive(
          'sessions.twoFactorPendingMinutes',
          input.sessions?.twoFactorPendingMinutes ?? 10,
        ) * MINUTE,
    },
    links: {
      passwordResetMs:
        positive('links.passwordResetMinutes', input.links?.passwordResetMinutes ?? 60) * MINUTE,
      emailLinkMs: positive('links.emailLinkMinutes', input.links?.emailLinkMinutes ?? 15) * MINUTE,
      verificationMs:
        positive('links.verificationMinutes', input.links?.verificationMinutes ?? 60) * MINUTE,
      invitationMs:
        positive('links.invitationDays', input.links?.invitationDays ?? 7) * 24 * 60 * MINUTE,
    },
    twoFactor: {
      recoveryCodes,
      rememberDeviceMs: (input.twoFactor?.rememberDeviceDays ?? 30) * 24 * 60 * MINUTE,
      issuer: input.twoFactor?.issuer ?? url.hostname,
    },
    tokens: {
      abilities: Object.freeze([...abilities]),
      defaultExpiryMs:
        positive('tokens.defaultExpiryDays', input.tokens?.defaultExpiryDays ?? 365) *
        24 *
        60 *
        MINUTE,
      maxExpiryMs:
        positive('tokens.maxExpiryDays', input.tokens?.maxExpiryDays ?? 365) * 24 * 60 * MINUTE,
      prefix,
    },
    roles,
    tenantRoles: resolveTenantRoles(input.tenantRoles, roles),
    teams: Object.freeze({ personal: input.teams?.personal ?? true }),
    passkeys: input.passkeys === undefined ? undefined : checkPasskeys(input.passkeys),
    limits: Object.freeze(limits),
    lockout: { threshold, baseMs: lockoutBaseMs, maxMs: lockoutMaxMs },
  })
}

/** True when `ability` is a well-formed ability pattern. */
export function isAbility(ability: string): boolean {
  return ABILITY.test(ability)
}
