/**
 * The one error type every auth service throws, with a stable `code`.
 *
 * Why one type: the HTTP layer maps `code` to an RFC 9457 problem (status + catalog message), so
 * services never build responses and never hard-code user-facing text (RFC-0003). Messages are
 * deliberately vague where precision would help an attacker (`INVALID_CREDENTIALS` never says
 * whether the email or the password was wrong).
 *
 * @module
 */

/** Every code an auth service can throw, with its HTTP status. */
export const AUTH_ERROR_STATUS = {
  VALIDATION_FAILED: 422,
  INVALID_CREDENTIALS: 422,
  WEAK_PASSWORD: 422,
  EMAIL_TAKEN: 422,
  INVALID_TOKEN: 422,
  INVALID_CODE: 422,
  EMAIL_LINK_OTHER_BROWSER: 422,
  RATE_LIMITED: 429,
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  EMAIL_NOT_VERIFIED: 403,
  NOT_FOUND: 404,
  PASSWORD_CONFIRMATION_REQUIRED: 423,
  CONFLICT: 409,
  LAST_ADMIN: 409,
  INTERNAL_ERROR: 500,
} as const

/** A stable error code (part of the public contract: clients branch on it). */
export type AuthErrorCode = keyof typeof AUTH_ERROR_STATUS

/**
 * The default English catalog. The framework replaces it with its message catalogs (RFC-0003);
 * the codes stay the same.
 */
export const AUTH_MESSAGES: Readonly<Record<AuthErrorCode, string>> = {
  VALIDATION_FAILED: 'Some fields are missing or invalid.',
  INVALID_CREDENTIALS: 'These credentials do not match our records.',
  WEAK_PASSWORD: 'Choose a stronger password.',
  EMAIL_TAKEN: 'This email address cannot be used.',
  INVALID_TOKEN: 'This link or token is invalid or has expired.',
  INVALID_CODE: 'The code is invalid.',
  EMAIL_LINK_OTHER_BROWSER: 'Open the sign-in link in the same browser you requested it from.',
  RATE_LIMITED: 'Too many attempts. Please try again later.',
  UNAUTHENTICATED: 'You need to sign in.',
  FORBIDDEN: 'You are not allowed to do this.',
  EMAIL_NOT_VERIFIED: 'Verify your email address first.',
  NOT_FOUND: 'Not found.',
  PASSWORD_CONFIRMATION_REQUIRED: 'Confirm your password to continue.',
  CONFLICT: 'This conflicts with the current state.',
  LAST_ADMIN: 'A team needs at least one admin.',
  INTERNAL_ERROR: 'Something went wrong.',
}

/** One field-level problem, for `VALIDATION_FAILED` and `WEAK_PASSWORD`. */
export interface AuthIssue {
  readonly field: string
  readonly code: string
}

/**
 * Thrown by every auth service for an expected failure.
 *
 * @example
 * ```ts
 * try { await auth.login(req, input) }
 * catch (e) { if (e instanceof AuthError && e.code === 'RATE_LIMITED') retryAfter = e.retryAfterSeconds }
 * ```
 */
export class AuthError extends Error {
  /** The HTTP status the adapter should answer with. */
  readonly status: number
  /** The stable code clients branch on. */
  readonly code: AuthErrorCode
  /** Field issues and the retry delay, when they apply. */
  readonly options: { readonly issues?: readonly AuthIssue[]; readonly retryAfterSeconds?: number }
  constructor(
    code: AuthErrorCode,
    options: { readonly issues?: readonly AuthIssue[]; readonly retryAfterSeconds?: number } = {},
  ) {
    super(AUTH_MESSAGES[code])
    this.name = 'AuthError'
    this.code = code
    this.options = options
    this.status = AUTH_ERROR_STATUS[code]
  }

  /** Seconds the client should wait, for `RATE_LIMITED`. */
  get retryAfterSeconds(): number | undefined {
    return this.options.retryAfterSeconds
  }
}

/**
 * The error a disabled feature throws. It is deliberately the SAME as an unknown route
 * (`NOT_FOUND`), never 403: a 403 would confirm the feature exists (feature switches, item 11).
 */
export function featureDisabled(): AuthError {
  return new AuthError('NOT_FOUND')
}
