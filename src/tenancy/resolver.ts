/**
 * Tenant resolution: which tenant (customer organisation) is this request for?
 *
 * A chain of resolvers is tried in order and the first answer wins, e.g.
 * `subdomain → path → header (trusted callers only) → session`.
 *
 * **Resolution is not authorization.** A resolver only says which tenant the request *asks for*.
 * Whether the actor may act in it is decided by membership: `authMiddleware` refuses a request
 * whose resolved tenant differs from the actor's (membership-verified) tenant, and Postgres RLS
 * (`withTenant`) enforces the final boundary in the database.
 *
 * Every resolved id must be a UUID, because it flows into `NULLIF(current_setting(...),'')::uuid`
 * in the RLS policy (ADR-0007). Slugs (subdomains, path segments) are mapped to ids by a `lookup`
 * function you provide; a slug that does not resolve yields no tenant (fail closed).
 *
 * @module
 */
import type { Actor, TenantContext, TenantStrategy } from '@strutvane/contracts'
import { isUuid } from '../policy/schema.ts'

/** What a resolver receives. */
export interface TenantResolveInput {
  readonly request: Request
  /** The authenticated actor (already membership-checked by the identity engine), or `null`. */
  readonly actor: Actor | null
}

/** One resolver: returns a tenant id, or `undefined` to let the next resolver try. */
export interface TenantResolver {
  /** For diagnostics (`sv doctor`) and logs. */
  readonly name: string
  resolve(input: TenantResolveInput): Promise<string | undefined> | string | undefined
}

/** Maps a slug (`acme`) to a tenant id, or `undefined` when there is no such tenant. */
export type TenantLookup = (slug: string) => Promise<string | undefined> | string | undefined

const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

async function viaLookup(
  slug: string | undefined,
  lookup: TenantLookup | undefined,
): Promise<string | undefined> {
  if (slug === undefined) return undefined
  if (isUuid(slug)) return slug
  if (!lookup || !SLUG.test(slug)) return undefined
  return (await lookup(slug)) ?? undefined
}

/**
 * `acme.example.com` → lookup(`"acme"`). The host is taken from the request URL, which the HTTP
 * adapter builds from the `Host` header; only hosts directly under `baseDomain` are considered.
 */
export function subdomainResolver(options: {
  readonly baseDomain: string
  readonly lookup: TenantLookup
  /** Subdomains that are never tenants. Default `["www", "app", "api", "admin"]`. */
  readonly reserved?: readonly string[]
}): TenantResolver {
  const base = options.baseDomain.toLowerCase().replace(/^\./, '')
  const reserved = new Set(options.reserved ?? ['www', 'app', 'api', 'admin'])
  return {
    name: 'subdomain',
    resolve: ({ request }) => {
      let host: string
      try {
        host = new URL(request.url).hostname.toLowerCase()
      } catch {
        return undefined
      }
      if (!host.endsWith(`.${base}`)) return undefined
      const sub = host.slice(0, -(base.length + 1))
      if (sub.includes('.') || reserved.has(sub)) return undefined
      return viaLookup(sub, options.lookup)
    },
  }
}

/** `/t/acme/invoices` → lookup(`"acme"`). */
export function pathResolver(options: {
  readonly prefix?: string
  readonly lookup: TenantLookup
}): TenantResolver {
  const prefix = `/${(options.prefix ?? 't').replace(/^\/+|\/+$/g, '')}/`
  return {
    name: 'path',
    resolve: ({ request }) => {
      let path: string
      try {
        path = new URL(request.url).pathname
      } catch {
        return undefined
      }
      if (!path.startsWith(prefix)) return undefined
      const segment = path.slice(prefix.length).split('/')[0] ?? ''
      let slug: string
      try {
        slug = decodeURIComponent(segment).toLowerCase()
      } catch {
        return undefined
      }
      return viaLookup(slug, options.lookup)
    },
  }
}

/**
 * `X-Tenant-Id: <uuid>`, **only from trusted callers** (internal services behind your network).
 *
 * The header is trivially forged by browsers and scripts, so `trust` is required and is checked
 * before the header is even read. A typical `trust` checks for a tenant-less service actor. An
 * untrusted request's header is ignored, never an error, so probing it reveals nothing.
 *
 * Even when `trust` says yes, `authenticateRequest` drops a header-resolved tenant for an
 * ANONYMOUS request unless `tenancy.allowAnonymousTenant` lists `'header'` explicitly (for internal
 * callers trusted by peer address, see `requestMeta`).
 */
export function headerResolver(options: {
  readonly trust: (input: TenantResolveInput) => boolean
  /** Header name. Default `x-tenant-id`. */
  readonly header?: string
}): TenantResolver {
  const header = (options.header ?? 'x-tenant-id').toLowerCase()
  return {
    name: 'header',
    resolve: (input) => {
      if (options.trust(input) !== true) return undefined
      const value = input.request.headers.get(header)?.trim()
      return value !== undefined && isUuid(value) ? value : undefined
    },
  }
}

/** The actor's active tenant, as verified against membership by the identity engine. */
export function sessionResolver(): TenantResolver {
  return { name: 'session', resolve: ({ actor }) => actor?.tenantId }
}

/** Options for {@link resolveTenant}. */
export interface ResolveTenantOptions {
  /** Isolation strategy to report in the `TenantContext`. Default `shared`. */
  readonly strategy?: TenantStrategy
}

/** The outcome of a resolver chain. */
export interface TenantResolution {
  /** The resolved tenant, if any resolver answered with a valid UUID. */
  readonly tenant: TenantContext | undefined
  /** Which resolver answered. */
  readonly resolvedBy: string | undefined
}

/**
 * Run resolvers in order; the first one that returns a valid UUID wins. A non-UUID answer from a
 * custom resolver is ignored (fail closed) rather than passed on to the database.
 */
export async function resolveTenant(
  resolvers: readonly TenantResolver[],
  input: TenantResolveInput,
  options: ResolveTenantOptions = {},
): Promise<TenantResolution> {
  for (const resolver of resolvers) {
    const id = await resolver.resolve(input)
    if (id !== undefined && isUuid(id)) {
      return {
        tenant: Object.freeze({ id: id.toLowerCase(), strategy: options.strategy ?? 'shared' }),
        resolvedBy: resolver.name,
      }
    }
  }
  return { tenant: undefined, resolvedBy: undefined }
}
