/**
 * The one error type every auth service throws, with a stable `code`.
 *
 * Why one type: the HTTP layer maps `code` to an RFC 9457 problem (status + catalog message), so
 * services never build responses and never hard-code user-facing text (RFC-0003). Messages are
 * deliberately vague where precision would help an attacker (`invalid_credentials` never says
 * whether the email or the password was wrong).
 *
 * Codes are lowercase `snake_case` (CONSISTENCY #68), and field issues have the shape
 * `{ path, field, code, message }` (#69), the same in every Strutvane package.
 *
 * @module
 */

/** Every code an auth service can throw, with its HTTP status. */
export const AUTH_ERROR_STATUS: {
  readonly validation_failed: 422
  readonly invalid_credentials: 422
  readonly weak_password: 422
  readonly email_taken: 422
  readonly invalid_token: 422
  readonly invalid_code: 422
  readonly email_link_other_browser: 422
  readonly invalid_signature: 403
  readonly signature_expired: 403
  readonly rate_limited: 429
  readonly unauthenticated: 401
  readonly forbidden: 403
  readonly email_not_verified: 403
  readonly not_found: 404
  readonly password_confirmation_required: 423
  readonly conflict: 409
  readonly last_admin: 409
  readonly internal_error: 500
} = Object.freeze({
  validation_failed: 422,
  invalid_credentials: 422,
  weak_password: 422,
  email_taken: 422,
  invalid_token: 422,
  invalid_code: 422,
  email_link_other_browser: 422,
  // A signed link that was edited or has expired (CONSISTENCY #67): the same 403 answer every
  // signed link in the framework gives, so clients handle "bad link" one way.
  invalid_signature: 403,
  signature_expired: 403,
  rate_limited: 429,
  unauthenticated: 401,
  forbidden: 403,
  email_not_verified: 403,
  not_found: 404,
  password_confirmation_required: 423,
  conflict: 409,
  last_admin: 409,
  internal_error: 500,
} as const)

/** A stable error code (part of the public contract: clients branch on it). */
export type AuthErrorCode = keyof typeof AUTH_ERROR_STATUS

/**
 * The default English catalog. The framework replaces it with its message catalogs (RFC-0003);
 * the codes stay the same.
 */
export const AUTH_MESSAGES: Readonly<Record<AuthErrorCode, string>> = Object.freeze({
  validation_failed: 'Some fields are missing or invalid.',
  invalid_credentials: 'These credentials do not match our records.',
  weak_password: 'Choose a stronger password.',
  email_taken: 'This email address cannot be used.',
  invalid_token: 'This link or token is invalid or has expired.',
  invalid_code: 'The code is invalid.',
  email_link_other_browser: 'Open the sign-in link in the same browser you requested it from.',
  invalid_signature: 'This link is invalid.',
  signature_expired: 'This link has expired.',
  rate_limited: 'Too many attempts. Please try again later.',
  unauthenticated: 'You need to sign in.',
  forbidden: 'You are not allowed to do this.',
  email_not_verified: 'Verify your email address first.',
  not_found: 'Not found.',
  password_confirmation_required: 'Confirm your password to continue.',
  conflict: 'This conflicts with the current state.',
  last_admin: 'A team needs at least one owner.',
  internal_error: 'Something went wrong.',
})

/**
 * Default English messages for field-issue codes. An unknown code falls back to `invalid`'s
 * message, so a new issue code never renders as an empty string.
 */
export const AUTH_ISSUE_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  invalid: 'This value is invalid.',
  required: 'This field is required.',
  taken: 'This value cannot be used.',
  too_short: 'This value is too short.',
  too_long: 'This value is too long.',
  too_large: 'The request body is too large.',
  json_required: 'Send the body as application/json.',
  invalid_json: 'The request body is not valid JSON.',
  object_required: 'The request body must be a JSON object.',
  compromised: 'This password has appeared in a data breach. Choose another one.',
  check_unavailable: 'The password could not be checked right now. Try again later.',
  not_allowed: 'This value is not allowed.',
  mismatch: 'This value does not match.',
})

/** What a service passes when it reports a field problem: the dotted field name and a code. */
export interface AuthIssueInput {
  /** Dotted field name, e.g. `password` or `abilities.0`. */
  readonly field: string
  /** Stable, lowercase snake_case issue code, e.g. `too_short`. */
  readonly code: string
}

/**
 * One field-level problem, as clients receive it (CONSISTENCY #69: RFC-0003's `path` plus the
 * dotted `field` convenience).
 *
 * @example
 * const issue: AuthIssue = { path: ['password'], field: 'password', code: 'too_short', message: 'This value is too short.' }
 */
export interface AuthIssue {
  readonly path: readonly (string | number)[]
  readonly field: string
  readonly code: string
  readonly message: string
}

const FALLBACK_ISSUE_MESSAGE = 'This value is invalid.'

/**
 * Turn a service's `{ field, code }` into the full issue shape.
 *
 * @example
 * toIssue({ field: 'abilities.0', code: 'not_allowed' })
 * // { path: ['abilities', 0], field: 'abilities.0', code: 'not_allowed', message: 'This value is not allowed.' }
 */
export function toIssue(input: AuthIssueInput): AuthIssue {
  const path =
    input.field === '' ? [] : input.field.split('.').map((s) => (/^\d+$/.test(s) ? Number(s) : s))
  return Object.freeze({
    path: Object.freeze(path),
    field: input.field,
    code: input.code,
    message: AUTH_ISSUE_MESSAGES[input.code] ?? FALLBACK_ISSUE_MESSAGE,
  })
}

/** Options an {@link AuthError} carries. */
export interface AuthErrorOptions {
  readonly issues?: readonly AuthIssueInput[]
  readonly retryAfterSeconds?: number
}

/**
 * Thrown by every auth service for an expected failure.
 *
 * @example
 * ```ts
 * try { await auth.passwords.login(req, input) }
 * catch (e) { if (e instanceof AuthError && e.code === 'rate_limited') retryAfter = e.retryAfterSeconds }
 * ```
 */
export class AuthError extends Error {
  /** The HTTP status the adapter should answer with. */
  readonly status: number
  /** The stable code clients branch on. */
  readonly code: AuthErrorCode
  /** Field issues in the RFC-0003 shape (empty when there are none). */
  readonly issues: readonly AuthIssue[]
  /** Field issues and the retry delay, as the service passed them. */
  readonly options: AuthErrorOptions
  constructor(code: AuthErrorCode, options: AuthErrorOptions = {}) {
    super(AUTH_MESSAGES[code])
    this.name = 'AuthError'
    this.code = code
    this.options = options
    this.status = AUTH_ERROR_STATUS[code]
    this.issues = Object.freeze((options.issues ?? []).map(toIssue))
  }

  /** Seconds the client should wait, for `rate_limited`. */
  get retryAfterSeconds(): number | undefined {
    return this.options.retryAfterSeconds
  }
}

/**
 * The error a disabled feature throws. It is deliberately the SAME as an unknown route
 * (`not_found`), never 403: a 403 would confirm the feature exists (feature switches, item 11).
 */
export function featureDisabled(): AuthError {
  return new AuthError('not_found')
}
