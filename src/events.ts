/**
 * Auth's domain events on the framework event bus (integration map §5, connection 4).
 *
 * The engine emits a closed union of audit events (ids, enums and counts only: no secret can ride
 * along). This module publishes each one under a stable, public name: the integration map's
 * `auth.user.registered`, `auth.login.failed`, `auth.role.assigned` and `tenant.created`, plus one
 * name for every other event the engine defines (`auth.*` for accounts, `tenant.*` for teams).
 *
 * - The payload is the event without `type`, `at` (the bus stamps `occurredAt`) and `ip`: domain
 *   events travel to other packages and outboxes, and a client address is personal data that
 *   belongs in the audit log, not in a welcome-mail listener.
 * - `actor` is the user (or impersonating admin, #115) who did it; `tenantId` is set for `tenant.*`.
 * - A failing listener or bus never breaks sign-in: the failure is logged by event name only.
 *
 * @module
 */
import type { Logger } from '@strutvane/framework/contracts'
import type { EventBus } from '@strutvane/framework/core'
import type { AuthEvent, AuthEventSink, AuthEventType } from './engine/ports/events.ts'

/** The public name of every engine event (connection 4 of the integration map). */
export const AUTH_DOMAIN_EVENTS: Readonly<Record<AuthEventType, string>> = Object.freeze({
  registered: 'auth.user.registered',
  login: 'auth.login.succeeded',
  'login.failed': 'auth.login.failed',
  lockout: 'auth.lockout',
  logout: 'auth.logout',
  'password.changed': 'auth.password.changed',
  'password.rehashed': 'auth.password.rehashed',
  'email.verified': 'auth.email.verified',
  'two-factor.enabled': 'auth.two_factor.enabled',
  'two-factor.disabled': 'auth.two_factor.disabled',
  'recovery-codes.regenerated': 'auth.recovery_codes.regenerated',
  'recovery-code.used': 'auth.recovery_code.used',
  'passkey.added': 'auth.passkey.added',
  'passkey.removed': 'auth.passkey.removed',
  'session.revoked': 'auth.session.revoked',
  'token.created': 'auth.token.created',
  'token.revoked': 'auth.token.revoked',
  'team.created': 'tenant.created',
  'team.switched': 'tenant.switched',
  'team.invitation.created': 'tenant.invitation.created',
  'team.invitation.accepted': 'tenant.invitation.accepted',
  'team.member.changed': 'tenant.member.changed',
  'role.assigned': 'auth.role.assigned',
  'impersonation.started': 'auth.impersonation.started',
  'impersonation.stopped': 'auth.impersonation.stopped',
})

/** The payload of an auth domain event: the engine event without `type`, `at` and `ip`. */
export type AuthDomainPayload = Readonly<Record<string, string | number | boolean | null>>

/**
 * An {@link AuthEventSink} that publishes every engine event on the framework event bus.
 *
 * @example
 * const events = domainEventSink(app.make(EventBusToken), app.make(LoggerToken))
 * bus.on('auth.user.registered', (e) => welcome.send(e.payload.userId))
 */
export function domainEventSink(
  bus: Pick<EventBus<Record<string, unknown>>, 'emit'>,
  logger: Pick<Logger, 'warn'>,
): AuthEventSink {
  return {
    async emit(event: AuthEvent) {
      const name = AUTH_DOMAIN_EVENTS[event.type]
      const { type: _type, at: _at, ip: _ip, ...rest } = event
      const payload = rest as AuthDomainPayload
      const tenantId = 'teamId' in event ? event.teamId : undefined
      try {
        await bus.emit(name, payload, {
          ...(event.actorId !== null
            ? { actor: { id: event.actorId, type: 'user' as const } }
            : {}),
          ...(name.startsWith('tenant.') && tenantId !== undefined ? { tenantId } : {}),
        })
      } catch {
        try {
          logger.warn('auth: publishing a domain event failed', { event: name })
        } catch {
          // Nothing left to tell.
        }
      }
    },
  }
}
