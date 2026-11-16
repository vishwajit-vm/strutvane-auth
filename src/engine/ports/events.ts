/**
 * Audit events and the logger port.
 *
 * Why the event shapes are closed: an event can only carry ids, enum values and counts. There is
 * no free-form `data` bag, so a password, token, code, cookie or URL cannot end up in the audit
 * log by accident (item 12). The redaction test in `test/redaction.test.ts` proves it end to end by
 * scanning every emitted event and log line for every secret a run produced.
 *
 * @module
 */

/** How a user proved who they are. */
export type LoginMethod = 'password' | 'email-link' | 'passkey'

/** The second factor used, when there was one. */
export type SecondFactor = 'totp' | 'recovery-code' | 'passkey' | 'trusted-device'

/** Why a sign-in step failed (never which part of the credentials was wrong). */
export type FailureReason =
  | 'invalid-credentials'
  | 'invalid-code'
  | 'locked'
  | 'rate-limited'
  | 'email-not-verified'

/** Fields every event has. `ip` is the rate-limit subject (IPv6 is reduced to its /64). */
interface Base {
  readonly at: number
  readonly ip: string | null
  /**
   * Who did it: the impersonating admin while impersonating (CONSISTENCY #115), else the signed-in
   * user making the request, else `null` (anonymous: a sign-in attempt, a reset request).
   */
  readonly actorId: string | null
  /** Whose account it concerns: the event's `userId`, or `null` when there is none. */
  readonly subjectId: string | null
}

/** Every audit event the auth core emits. */
export type AuthEvent =
  | (Base & { readonly type: 'registered'; readonly userId: string })
  | (Base & {
      readonly type: 'login'
      readonly userId: string
      readonly method: LoginMethod
      readonly secondFactor: SecondFactor | null
    })
  | (Base & {
      readonly type: 'login.failed'
      readonly stage: 'first-factor' | 'second-factor'
      readonly reason: FailureReason
      /** Present only when the account exists; a keyed digest of the email otherwise links attempts. */
      readonly userId: string | null
      readonly emailDigest: string | null
    })
  | (Base & {
      readonly type: 'lockout'
      readonly scope: 'login' | 'two-factor'
      readonly emailDigest: string | null
      readonly userId: string | null
      readonly seconds: number
    })
  | (Base & { readonly type: 'logout'; readonly userId: string })
  | (Base & {
      readonly type: 'password.changed'
      readonly userId: string
      readonly via: 'settings' | 'reset'
    })
  | (Base & { readonly type: 'password.rehashed'; readonly userId: string })
  | (Base & { readonly type: 'email.verified'; readonly userId: string })
  | (Base & { readonly type: 'two-factor.enabled'; readonly userId: string })
  | (Base & { readonly type: 'two-factor.disabled'; readonly userId: string })
  | (Base & { readonly type: 'recovery-codes.regenerated'; readonly userId: string })
  | (Base & {
      readonly type: 'recovery-code.used'
      readonly userId: string
      readonly remaining: number
    })
  | (Base & { readonly type: 'passkey.added'; readonly userId: string; readonly passkeyId: string })
  | (Base & {
      readonly type: 'passkey.removed'
      readonly userId: string
      readonly passkeyId: string
    })
  | (Base & { readonly type: 'session.revoked'; readonly userId: string; readonly count: number })
  | (Base & { readonly type: 'token.created'; readonly userId: string; readonly tokenId: string })
  | (Base & { readonly type: 'token.revoked'; readonly userId: string; readonly tokenId: string })
  | (Base & { readonly type: 'team.created'; readonly userId: string; readonly teamId: string })
  | (Base & { readonly type: 'team.switched'; readonly userId: string; readonly teamId: string })
  | (Base & {
      readonly type: 'team.invitation.created'
      readonly userId: string
      readonly teamId: string
      readonly invitationId: string
    })
  | (Base & {
      readonly type: 'team.invitation.accepted'
      readonly userId: string
      readonly teamId: string
      readonly invitationId: string
    })
  | (Base & {
      readonly type: 'team.member.changed'
      readonly userId: string
      readonly teamId: string
      readonly memberId: string
      readonly role: string | null
    })
  | (Base & {
      readonly type: 'role.assigned'
      readonly userId: string
      /** The global role the user now holds (names come from the configured preset). */
      readonly role: string
    })
  | (Base & {
      readonly type: 'impersonation.started'
      readonly adminId: string
      readonly userId: string
    })
  | (Base & {
      readonly type: 'impersonation.stopped'
      readonly adminId: string
      readonly userId: string
    })

/** The `type` of an {@link AuthEvent}. */
export type AuthEventType = AuthEvent['type']

/**
 * Receives audit events (the framework's event bus / audit log). Must not throw; if it does, the
 * error is logged and the auth operation still completes.
 *
 * @example
 * ```ts
 * const events: AuthEventSink = { emit: (e) => audit.record(e) }
 * ```
 */
export interface AuthEventSink {
  emit(event: AuthEvent): void | Promise<void>
}

/**
 * The logger port (a subset of the framework `Logger` contract). The auth core only logs
 * operational problems (a mailer that failed, a breached-password service that is down) and only
 * with ids, never secrets.
 */
export interface AuthLogger {
  warn(message: string, context?: Readonly<Record<string, string | number | boolean | null>>): void
}
