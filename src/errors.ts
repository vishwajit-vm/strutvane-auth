/**
 * Errors raised by `@strutvane/auth`.
 *
 * Two kinds, deliberately separated:
 * - **Client-facing** ({@link InvalidFilterError}): an untrusted filter (e.g. from a UI) failed the
 *   validation gate. It extends core's `StrutvaneError`, so the framework's error handler turns it
 *   into a 422 problem with a stable code.
 * - **Programming errors** ({@link PolicyDefinitionError}, {@link FieldNotLoadedError},
 *   {@link NotListFilterableError}): mistakes in app code. They are plain `Error`s, so they surface
 *   as a 500 (with details only in logs), never as something a client could probe.
 *
 * @module
 */
import { type ErrorDefinition, StrutvaneError } from '@strutvane/framework/core'

/**
 * Error codes `@strutvane/auth` can answer with that the framework's built-in list does not have.
 * The app provider registers each one at boot unless something registered it first, so every
 * problem auth returns renders with a proper title instead of a humanized code.
 *
 * Codes are lowercase `snake_case` (CONSISTENCY #68, #123): `test/error-codes-source.test.ts`
 * fails on an uppercase code anywhere in `src`. `tenant_required`, `malformed_request` and
 * `unsupported_media_type` are also registered by the framework's HTTP kernel; whichever registers
 * first wins, and the error instance sets the status either way.
 *
 * @example
 * for (const definition of AUTH_ERRORS)
 *   if (!registry.get(definition.code)) registry.register(definition)
 */
export const AUTH_ERRORS: readonly ErrorDefinition[] = Object.freeze(
  (
    [
      ['invalid_filter', 422, 'Invalid filter'],
      ['invalid_credentials', 401, 'Invalid email or password'],
      ['email_unavailable', 422, 'This email cannot be used'],
      ['invalid_token', 400, 'Invalid or expired link'],
      ['two_factor_required', 401, 'Two-factor authentication required'],
      ['email_not_verified', 403, 'Email address not verified'],
      ['tenant_required', 400, 'No tenant could be determined for this request'],
      ['malformed_request', 400, 'Malformed request'],
      ['unsupported_media_type', 415, 'Unsupported media type'],
    ] as const
  ).map(([code, status, title]) =>
    Object.freeze({ code, status, title, owner: '@strutvane/auth' }),
  ),
)

/**
 * A filter failed the shared validation gate (unknown field, wrong value type, ordering on a
 * non-numeric field, a forbidden character…). Both the in-memory evaluator and the SQL compiler
 * raise it for exactly the same inputs, so they can never disagree (ADR-0008).
 */
export class InvalidFilterError extends StrutvaneError {
  /** Developer-facing explanation. Safe to log; it never contains filter VALUES. */
  readonly reason: string
  constructor(reason: string) {
    super('invalid_filter', { status: 422 })
    this.reason = reason
    this.message = `invalid_filter: ${reason}`
  }
}

/** A policy or schema was defined incorrectly (unsafe identifier, unknown relation, …). */
export class PolicyDefinitionError extends Error {
  override readonly name = 'PolicyDefinitionError'
}

/**
 * A single-record check needed a field that was not loaded on the record (e.g. a partial SELECT).
 * Guessing `null` could grant or deny wrongly, so evaluation fails closed, loudly.
 */
export class FieldNotLoadedError extends Error {
  override readonly name = 'FieldNotLoadedError'
}

/** A policy action uses a `check()` escape-hatch rule, which cannot be compiled to SQL. */
export class NotListFilterableError extends Error {
  override readonly name = 'NotListFilterableError'
}
