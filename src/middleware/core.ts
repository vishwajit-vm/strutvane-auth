/**
 * Framework-agnostic authentication middleware logic. HTTP adapters (`@strutvane/auth/hono`,
 * `@strutvane/auth/node`) are thin wrappers around {@link authenticateRequest}.
 *
 * Per request:
 * 1. **Authenticate** with the identity engine (never throws; no session → anonymous).
 * 2. **Resolve the tenant** with the resolver chain, if tenancy is configured.
 * 3. **Check tenant membership**: a request for a tenant other than the actor's
 *    (membership-verified) tenant is refused with 403, so a session for tenant A can never act in
 *    tenant B by changing a subdomain, path or header. The one exception is a tenant-less service
 *    actor using the trusted `header` resolver (internal services acting for a tenant).
 * 4. **Enforce** `requireAuth` / `tenancy.required`.
 * 5. Run the handler inside core's request context (`currentContext()` sees actor and tenant),
 *    and copy the engine's headers (refreshed cookies) onto the response.
 *
 * Failures are RFC 9457 problem+json responses built with core's `toProblem`, never stack traces.
 *
 * @module
 */
import type { Actor, TenantContext, TenantStrategy } from '@strutvane/contracts'
import {
  ForbiddenError,
  runWithContext,
  StrutvaneError,
  toProblem,
  UnauthenticatedError,
} from '@strutvane/core'
import type { IdentityEngine } from '../identity/engine.ts'
import { resolveTenant, type TenantResolver } from '../tenancy/resolver.ts'

/** Options shared by every adapter. */
export interface AuthMiddlewareOptions {
  /** Anything that can authenticate a request (an `IdentityEngine`). */
  readonly engine: Pick<IdentityEngine, 'authenticate'>
  /** Refuse anonymous requests with 401. Default `false` (handlers see `actor: null`). */
  readonly requireAuth?: boolean
  readonly tenancy?: {
    /** Tried in order; the first valid UUID wins. */
    readonly resolvers: readonly TenantResolver[]
    /** Refuse requests without a tenant with 400 `TENANT_REQUIRED`. Default `false`. */
    readonly required?: boolean
    /** Reported in the `TenantContext`. Default `shared`. */
    readonly strategy?: TenantStrategy
  }
}

/** What a handler gets to know. */
export interface AuthState {
  readonly actor: Actor | null
  readonly tenant: TenantContext | undefined
  /** Headers to add to the response (e.g. a refreshed session cookie). */
  readonly headers: Headers
}

/** The outcome of {@link authenticateRequest}. */
export type AuthOutcome =
  | { readonly ok: true; readonly state: AuthState }
  | { readonly ok: false; readonly response: Response }

/** Build a problem+json response for an error, carrying `headers` (cookies, Retry-After). */
export function problemResponse(error: StrutvaneError, headers: Headers = new Headers()): Response {
  const problem = toProblem(error)
  const out = new Headers(headers)
  out.set('content-type', 'application/problem+json')
  out.set('cache-control', 'no-store')
  return new Response(JSON.stringify(problem), { status: problem.status, headers: out })
}

/** Authenticate a request and resolve its tenant. Never throws for client-caused problems. */
export async function authenticateRequest(
  request: Request,
  options: AuthMiddlewareOptions,
): Promise<AuthOutcome> {
  let actor: Actor | null = null
  let headers = new Headers()
  try {
    const result = await options.engine.authenticate(request)
    actor = result.actor
    headers = result.headers
  } catch {
    // The engine contract says authenticate never throws; if one does anyway, fail closed.
    actor = null
  }

  let tenant: TenantContext | undefined
  if (options.tenancy) {
    const resolved = await resolveTenant(
      options.tenancy.resolvers,
      { request, actor },
      options.tenancy.strategy ? { strategy: options.tenancy.strategy } : {},
    )
    tenant = resolved.tenant
    if (tenant && actor) {
      const member = actor.tenantId?.toLowerCase() === tenant.id
      const trustedService =
        actor.type === 'service' && actor.tenantId === undefined && resolved.resolvedBy === 'header'
      if (!member && !trustedService)
        return { ok: false, response: problemResponse(new ForbiddenError(), headers) }
    }
    if (!tenant && options.tenancy.required) {
      return {
        ok: false,
        response: problemResponse(new StrutvaneError('TENANT_REQUIRED', { status: 400 }), headers),
      }
    }
  }

  if (options.requireAuth && !actor)
    return { ok: false, response: problemResponse(new UnauthenticatedError(), headers) }
  return { ok: true, state: Object.freeze({ actor, tenant, headers }) }
}

/** Run `fn` inside core's request context with the authenticated actor and tenant. */
export function runWithAuth<R>(state: AuthState, fn: () => R): R {
  return runWithContext(
    state.tenant ? { actor: state.actor, tenant: state.tenant } : { actor: state.actor },
    fn,
  )
}
