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

/** Error codes owned by `@strutvane/auth`. Register them with core's error registry at boot. */
export const AUTH_ERRORS: readonly ErrorDefinition[] = Object.freeze(
  (
    [
      ['INVALID_FILTER', 422, 'Invalid filter'],
      ['INVALID_CREDENTIALS', 401, 'Invalid email or password'],
      ['EMAIL_UNAVAILABLE', 422, 'This email cannot be used'],
      ['INVALID_TOKEN', 400, 'Invalid or expired link'],
      ['TENANT_REQUIRED', 400, 'No tenant could be determined for this request'],
      ['UNSUPPORTED_MEDIA_TYPE', 415, 'Unsupported media type'],
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
    super('INVALID_FILTER', { status: 422 })
    this.reason = reason
    this.message = `INVALID_FILTER: ${reason}`
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
