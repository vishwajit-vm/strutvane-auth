/**
 * The per-IP + per-account limiter shared by every identity engine (native, Better Auth).
 *
 * The client IP comes from the socket peer through trusted proxies (`resolveClientIp`), so a forged
 * `X-Forwarded-For` cannot rotate it, and IPv6 clients count per /64 (`rateLimitSubject`).
 *
 * **No peer address = fail closed.** When no HTTP adapter attached the peer address, the per-IP
 * limit is NOT skipped: every such request counts against ONE shared fallback bucket per scope
 * (`<scope>:ip:unknown`), and a warning is logged once so the misconfiguration is visible. Hosts
 * that knowingly run without a peer address (a trusted internal caller, a test harness) can set
 * `allowMissingPeer` to skip the per-IP limit instead; the per-account limit applies either way.
 *
 * @module
 */
import type { Logger } from '@strutvane/contracts'
import { rateLimitSubject, resolveClientIp, type TrustedProxies } from '../http/client-ip.ts'
import {
  accountKey,
  checkRateLimits,
  type RateLimitRule,
  type RateLimitStore,
} from './rate-limit.ts'

/** Options for {@link createIdentityLimiter}. */
export interface IdentityLimiterOptions {
  readonly store: RateLimitStore
  readonly proxies: TrustedProxies
  /** Skip the per-IP limit (instead of using the shared fallback bucket) when the peer is unknown. */
  readonly allowMissingPeer?: boolean
  /** Receives the one-time "no peer address" warning. */
  readonly logger?: Pick<Logger, 'warn'> | undefined
  /** The engine name, for the warning. */
  readonly engine: string
}

/** Checks one operation; resolves to `retryAfterSeconds` when limited, `undefined` otherwise. */
export type IdentityLimiter = (
  request: Request,
  scope: string,
  ipRule: RateLimitRule,
  email?: string,
  accountRule?: RateLimitRule,
) => Promise<number | undefined>

/** The bucket used for requests whose client address is unknown. */
export const UNKNOWN_PEER = 'unknown'

/** Build the limiter an engine uses in front of sign-up, sign-in and password reset. */
export function createIdentityLimiter(options: IdentityLimiterOptions): IdentityLimiter {
  let warned = false
  const warnOnce = (): void => {
    if (warned) return
    warned = true
    try {
      options.logger?.warn(
        'auth: a request reached the identity engine without a client address; per-IP rate limits now share one fallback bucket. Attach the socket peer address (attachRequestMeta, or the http.onRequest clientAddress).',
        { engine: options.engine },
      )
    } catch {
      // Logging must never break authentication.
    }
  }

  return async (request, scope, ipRule, email, accountRule) => {
    const ip = resolveClientIp(request, options.proxies)
    const checks: [string, RateLimitRule][] = []
    if (ip !== undefined) checks.push([`${scope}:ip:${rateLimitSubject(ip)}`, ipRule])
    else if (options.allowMissingPeer !== true) {
      warnOnce()
      checks.push([`${scope}:ip:${UNKNOWN_PEER}`, ipRule])
    }
    if (email !== undefined && accountRule) checks.push([accountKey(scope, email), accountRule])
    const result = await checkRateLimits(options.store, checks)
    return result.limited ? result.retryAfterSeconds : undefined
  }
}
