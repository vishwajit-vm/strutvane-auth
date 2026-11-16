/**
 * The seam between Strutvane and any identity engine (Better Auth, the native engine, OIDC…),
 * proven by spike 07 and fixed by ADR-0013.
 *
 * Design rules:
 * 1. **Only Strutvane types cross this boundary.** Requests and responses are Web-standard
 *    `Request` / `Headers`, so every HTTP host can use it, and no engine type leaks out.
 * 2. **Errors are values, not exceptions.** Every operation returns an {@link IdentityResult} with
 *    a stable code (RFC-0003). Raw engine errors never escape: they could leak internals.
 * 3. **Cookies travel as headers.** Operations that change the session return the `Set-Cookie`
 *    headers the host must copy onto its response. The engine owns cookie names and attributes.
 * 4. **Fail closed.** Anything unexpected becomes `INTERNAL_ERROR`, and `authenticate` resolves to
 *    an anonymous actor.
 * 5. **Tenant and roles come from membership, on every request** (never trusted from the session).
 *
 * Every engine must pass the contract suite in `@strutvane/auth/testing`.
 *
 * @module
 */
import type { Actor } from '@strutvane/framework/contracts'

/** Stable error codes. Messages are rendered from catalogs by the host, never taken from the engine. */
export type IdentityErrorCode =
  /** Input failed validation (password too short, malformed email…). */
  | 'VALIDATION_FAILED'
  /** Wrong email or password. Identical for unknown emails (no user enumeration). */
  | 'INVALID_CREDENTIALS'
  /** Sign-up with an email that cannot be used. Reveals that an account exists (documented trade-off). */
  | 'EMAIL_UNAVAILABLE'
  /** Too many attempts; retry after `retryAfterSeconds`. */
  | 'RATE_LIMITED'
  /** A reset token that is invalid, expired or already used. */
  | 'INVALID_TOKEN'
  /** No valid session. */
  | 'UNAUTHENTICATED'
  /** Authenticated, but not allowed (e.g. switching to a tenant you are not a member of). */
  | 'FORBIDDEN'
  /** The engine failed unexpectedly. Details go to the reporter, never to the client. */
  | 'INTERNAL_ERROR'

/** The HTTP status for each code, so every engine answers identically. */
export const IDENTITY_STATUS: Readonly<Record<IdentityErrorCode, number>> = Object.freeze({
  VALIDATION_FAILED: 422,
  INVALID_CREDENTIALS: 401,
  EMAIL_UNAVAILABLE: 422,
  RATE_LIMITED: 429,
  INVALID_TOKEN: 400,
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  INTERNAL_ERROR: 500,
})

/** A failed identity operation. */
export interface IdentityError {
  readonly code: IdentityErrorCode
  /** The HTTP status the host should answer with. */
  readonly status: number
  /** Present for `RATE_LIMITED`. */
  readonly retryAfterSeconds?: number
}

/**
 * The outcome of an identity operation. `headers` always exists and must be applied to the host's
 * response (`Set-Cookie` on sign-in/out, `Retry-After` on rate limits).
 */
export type IdentityResult<T> =
  | { readonly ok: true; readonly value: T; readonly headers: Headers }
  | { readonly ok: false; readonly error: IdentityError; readonly headers: Headers }

/** The outcome of authenticating a request. Never an error: no valid session means `actor: null`. */
export interface Authentication {
  readonly actor: Actor | null
  /** Headers for the response, e.g. a refreshed rolling-session cookie. */
  readonly headers: Headers
}

/** A tenant the current user belongs to. */
export interface TenantMembership {
  readonly tenantId: string
  readonly name: string
  readonly slug: string
  /** Roles the user holds in this tenant. */
  readonly roles: readonly string[]
}

export interface SignUpInput {
  readonly email: string
  readonly password: string
  readonly name: string
}

export interface SignInInput {
  readonly email: string
  readonly password: string
}

/** A user as system operations see it (never a password or hash). */
export interface IdentityUser {
  readonly id: string
  /** Normalised (lowercased) email. */
  readonly email: string
  readonly name: string
}

/** A member of a tenant, with the roles held there. */
export interface TenantMember {
  readonly userId: string
  readonly email: string
  readonly name: string
  readonly roles: readonly string[]
}

/** A tenant, as system operations see it. */
export interface TenantInfo {
  readonly tenantId: string
  readonly name: string
  readonly slug: string
}

export interface CreateTenantInput {
  readonly name: string
  /** URL-safe unique identifier, e.g. `"acme"`. */
  readonly slug: string
}

/** Delivers a password-reset token (wire it to your mailer or queue). */
export type PasswordResetDelivery = (message: {
  readonly email: string
  readonly token: string
}) => Promise<void>

/** Receives unexpected engine failures (wire it to the logger). Never receives secrets. */
export type ErrorReporter = (context: string, error: unknown) => void

/**
 * An identity engine. Every operation that acts "as the current user" reads the session from the
 * incoming `request` (cookies, origin, client address for rate limiting).
 */
export interface IdentityEngine {
  /** Engine name for diagnostics (`sv doctor`). */
  readonly name: string

  /**
   * Resolve the actor for a request. Never throws and never fails: no session, a forged or
   * revoked session and engine failures all resolve to `actor: null` (fail closed).
   */
  authenticate(request: Request): Promise<Authentication>

  /** Shorthand for `(await authenticate(request)).actor`. */
  getActor(request: Request): Promise<Actor | null>

  /** Create an account with email and password, and sign it in. */
  signUp(input: SignUpInput, request: Request): Promise<IdentityResult<{ readonly actor: Actor }>>

  /** Sign in. Always issues a NEW session (no session fixation). */
  signIn(input: SignInInput, request: Request): Promise<IdentityResult<{ readonly actor: Actor }>>

  /** End the current session server-side (an old copy of the cookie stops working). */
  signOut(request: Request): Promise<IdentityResult<null>>

  /** Start a password reset. Identical outcome for known and unknown emails (no enumeration). */
  startPasswordReset(
    input: { readonly email: string },
    request: Request,
  ): Promise<IdentityResult<null>>

  /** Finish a reset with the delivered token. Single-use; revokes every existing session. */
  completePasswordReset(
    input: { readonly token: string; readonly newPassword: string },
    request: Request,
  ): Promise<IdentityResult<null>>

  /** Create a tenant owned by the current user. */
  createTenant(
    input: CreateTenantInput,
    request: Request,
  ): Promise<IdentityResult<TenantMembership>>

  /** Tenants the current user belongs to. */
  listTenants(request: Request): Promise<IdentityResult<readonly TenantMembership[]>>

  /**
   * Make `tenantId` the session's active tenant. Not a member and does not exist both return
   * `FORBIDDEN` (indistinguishable on purpose).
   */
  switchTenant(
    input: { readonly tenantId: string },
    request: Request,
  ): Promise<IdentityResult<{ readonly actor: Actor }>>

  /**
   * SYSTEM operation (no session): add a user to a tenant, or replace the role of an existing
   * member (idempotent). For seeders, invitation acceptance and tests. Callers authorise it
   * themselves; never expose it over HTTP as is.
   */
  addMemberAsSystem(input: {
    readonly tenantId: string
    readonly userId: string
    readonly role: string
  }): Promise<IdentityResult<null>>

  /** SYSTEM operation: remove a membership. Sessions lose that tenant and its roles immediately. */
  removeMemberAsSystem(input: {
    readonly tenantId: string
    readonly userId: string
  }): Promise<IdentityResult<null>>

  /**
   * SYSTEM operation: look a user up by email (case-insensitive). `null` when unknown. For
   * seeders, CLI commands and membership management; never expose it to anonymous callers.
   */
  findUserAsSystem(input: { readonly email: string }): Promise<IdentityResult<IdentityUser | null>>

  /**
   * SYSTEM operation: create an account without signing it in (seeders, `sv auth:user:create`).
   * Same validation as sign-up; `EMAIL_UNAVAILABLE` when the email is taken. Rate limits do not
   * apply (no client is involved).
   */
  createUserAsSystem(input: SignUpInput): Promise<IdentityResult<IdentityUser>>

  /** SYSTEM operation: create a tenant owned by `ownerUserId` (who becomes `owner`). */
  createTenantAsSystem(
    input: CreateTenantInput & { readonly ownerUserId: string },
  ): Promise<IdentityResult<TenantMembership>>

  /** SYSTEM operation: a tenant by slug, or `null`. */
  findTenantAsSystem(input: { readonly slug: string }): Promise<IdentityResult<TenantInfo | null>>

  /** SYSTEM operation: every member of a tenant with their roles. */
  listMembersAsSystem(input: {
    readonly tenantId: string
  }): Promise<IdentityResult<readonly TenantMember[]>>
}

/** A successful result. */
export function ok<T>(value: T, headers: Headers = new Headers()): IdentityResult<T> {
  return { ok: true, value, headers }
}

/** A failed result, with the standard status for the code. */
export function fail<T>(
  code: IdentityErrorCode,
  headers: Headers = new Headers(),
  retryAfterSeconds?: number,
): IdentityResult<T> {
  const error: IdentityError =
    retryAfterSeconds === undefined
      ? { code, status: IDENTITY_STATUS[code] }
      : { code, status: IDENTITY_STATUS[code], retryAfterSeconds }
  if (retryAfterSeconds !== undefined) headers.set('retry-after', String(retryAfterSeconds))
  return { ok: false, error, headers }
}
