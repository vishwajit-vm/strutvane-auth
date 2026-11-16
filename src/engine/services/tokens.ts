/**
 * Personal access tokens (Sanctum's `personal_access_tokens`, with stricter defaults).
 *
 * - Format `svp_<40 random base62><6 base62 CRC-32>`: a scanner-friendly prefix and a checksum,
 *   parsed strictly before any lookup.
 * - Shown ONCE at creation; only a keyed SHA-256 digest is stored.
 * - Abilities (`post.view`, `post.*`, `*`) must stay within the app's configured patterns; the
 *   effective permission is `policy(user) AND token.can(ability)` (the framework's guard does the
 *   AND).
 * - Expires after 1 year by default (Sanctum's default is never); `lastUsedAt` is written at most
 *   once a minute.
 * - Revocable one by one; all are revoked by a password reset.
 * - Never created while an admin impersonates (a token would outlive the impersonation).
 *
 * @module
 */
import { isAbility } from '../config.ts'
import { type AuthDeps, emit, requireFeature } from '../core/deps.ts'
import { assertNotImpersonating, requireActive } from '../core/sessions.ts'
import { newId } from '../crypto/random.ts'
import { AuthError } from '../errors.ts'
import type { AuthRequest } from '../ports/cookies.ts'
import type { TokenRecord, UserRecord } from '../ports/store.ts'
import {
  createPersonalAccessToken,
  parseBearer,
  parsePersonalAccessToken,
} from '../tokens/formats.ts'

/** A token as listed in settings (never the secret). */
export interface TokenView {
  readonly id: string
  readonly name: string
  readonly abilities: readonly string[]
  readonly createdAt: number
  readonly lastUsedAt: number | null
  readonly expiresAt: number | null
}

/** A request authenticated by a bearer token. */
export interface TokenAuthentication {
  readonly user: UserRecord
  readonly token: TokenView
  /** Does the token carry `ability`? (The policy must ALSO allow it.) */
  can(ability: string): boolean
}

/** Personal access token operations (feature `tokens`). */
export interface TokenService {
  /**
   * Create a token; the plain text is returned once and never again.
   *
   * @example
   * ```ts
   * const { plainText } = await auth.tokens.create(req, { name: 'CI', abilities: ['post.view'] })
   * ```
   */
  create(
    req: AuthRequest,
    input: {
      readonly name: unknown
      readonly abilities?: unknown
      readonly expiresInDays?: unknown
    },
  ): Promise<{ readonly plainText: string; readonly token: TokenView }>
  list(req: AuthRequest): Promise<readonly TokenView[]>
  revoke(req: AuthRequest, input: { readonly id: unknown }): Promise<void>
  /**
   * Authenticate an `Authorization` header value; `undefined` for anything invalid, expired or
   * revoked (the guard answers 401 without saying which).
   *
   * @example
   * ```ts
   * const auth = await tokens.authenticate(request.headers.get('authorization'))
   * if (!auth?.can('post.create')) return problem(403)
   * ```
   */
  authenticate(authorization: unknown): Promise<TokenAuthentication | undefined>
}

/**
 * Does the ability list grant `ability`? `*` grants everything; `post.*` grants `post.view` and
 * `post.comment.create`; otherwise the match is exact.
 */
export function abilityGranted(abilities: readonly string[], ability: string): boolean {
  return abilities.some(
    (a) => a === '*' || a === ability || (a.endsWith('.*') && ability.startsWith(a.slice(0, -1))),
  )
}

const view = (t: TokenRecord): TokenView => ({
  id: t.id,
  name: t.name,
  abilities: t.abilities,
  createdAt: t.createdAt,
  lastUsedAt: t.lastUsedAt,
  expiresAt: t.expiresAt,
})

const DAY = 24 * 60 * 60 * 1000
const TOUCH_EVERY_MS = 60_000

/** Build the {@link TokenService}. */
export function tokenService(deps: AuthDeps): TokenService {
  const { tokens } = deps.config
  const digest = (plain: string): string => deps.keys.digest('personal-access-token', plain)

  const parseAbilities = (value: unknown): readonly string[] => {
    // No abilities asked for: the token gets every pattern the app allows (Sanctum's `['*']`).
    if (value === undefined) return tokens.abilities
    if (!Array.isArray(value) || value.length === 0 || value.length > 50)
      throw new AuthError('VALIDATION_FAILED', {
        issues: [{ field: 'abilities', code: 'invalid' }],
      })
    const out: string[] = []
    for (const a of value) {
      // A requested pattern must be covered by an allowed one: `post.*` needs `*` or `post.*`.
      if (typeof a !== 'string' || !isAbility(a) || !abilityGranted(tokens.abilities, a))
        throw new AuthError('VALIDATION_FAILED', {
          issues: [{ field: 'abilities', code: 'not_allowed' }],
        })
      if (!out.includes(a)) out.push(a)
    }
    return out
  }

  return {
    async create(req, input) {
      requireFeature(deps, 'tokens')
      const active = await requireActive(deps, req)
      assertNotImpersonating(active)
      if (
        typeof input.name !== 'string' ||
        input.name.trim().length < 1 ||
        input.name.trim().length > 100
      )
        throw new AuthError('VALIDATION_FAILED', { issues: [{ field: 'name', code: 'invalid' }] })
      const abilities = parseAbilities(input.abilities)
      if (abilities.length === 0)
        throw new AuthError('VALIDATION_FAILED', {
          issues: [{ field: 'abilities', code: 'required' }],
        })
      let lifetime = tokens.defaultExpiryMs
      if (input.expiresInDays !== undefined) {
        const days = input.expiresInDays
        if (
          typeof days !== 'number' ||
          !Number.isInteger(days) ||
          days < 1 ||
          days * DAY > tokens.maxExpiryMs
        )
          throw new AuthError('VALIDATION_FAILED', {
            issues: [{ field: 'expiresInDays', code: 'invalid' }],
          })
        lifetime = days * DAY
      }
      const plainText = createPersonalAccessToken(tokens.prefix)
      const now = deps.clock.now()
      const record: TokenRecord = {
        id: newId(),
        userId: active.user.id,
        name: input.name.trim(),
        digest: digest(plainText),
        abilities,
        createdAt: now,
        lastUsedAt: null,
        expiresAt: now + lifetime,
      }
      await deps.store.addToken(record)
      await emit(deps, req, { type: 'token.created', userId: active.user.id, tokenId: record.id })
      return { plainText, token: view(record) }
    },

    async list(req) {
      requireFeature(deps, 'tokens')
      const active = await requireActive(deps, req)
      return (await deps.store.listTokens(active.user.id)).map(view)
    },

    async revoke(req, input) {
      requireFeature(deps, 'tokens')
      const active = await requireActive(deps, req)
      assertNotImpersonating(active)
      // Someone else's token id answers exactly like an unknown one.
      if (typeof input.id !== 'string' || !(await deps.store.deleteToken(active.user.id, input.id)))
        throw new AuthError('NOT_FOUND')
      await emit(deps, req, { type: 'token.revoked', userId: active.user.id, tokenId: input.id })
    },

    async authenticate(authorization) {
      if (!deps.config.features.tokens) return undefined
      const plain = parsePersonalAccessToken(parseBearer(authorization), tokens.prefix)
      if (plain === undefined) return undefined
      const record = await deps.store.findTokenByDigest(digest(plain))
      const now = deps.clock.now()
      if (!record || (record.expiresAt !== null && record.expiresAt <= now)) return undefined
      const user = await deps.store.findUserById(record.userId)
      if (!user) return undefined
      if (record.lastUsedAt === null || now - record.lastUsedAt >= TOUCH_EVERY_MS)
        await deps.store.touchToken(record.id, now)
      const token = view(record)
      // The token's own abilities AND the app's CURRENT allowed patterns: narrowing the config
      // narrows tokens issued before it, instead of grandfathering them.
      const can = (ability: string): boolean =>
        abilityGranted(record.abilities, ability) && abilityGranted(tokens.abilities, ability)
      return Object.freeze({ user, token, can })
    },
  }
}
