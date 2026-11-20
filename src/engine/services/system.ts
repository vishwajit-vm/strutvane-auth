/**
 * Trusted, server-side operations: seeders, CLI commands (`auth:user:create`, `tenant:create`) and
 * the identity-engine adapter's "as system" operations. Never exposed as routes: there is no
 * session and no rate limit here, so callers authorise the caller themselves.
 *
 * They keep every rule the request-facing services keep (email and password rules, roles from the
 * configured lists, unique slugs, the atomic last-owner guard) and emit the same audit events,
 * with no actor (`actorId: null`: the system did it).
 *
 * @module
 */
import { TEAM_OWNER_ROLE } from '../config.ts'
import { type AuthDeps, emit } from '../core/deps.ts'
import { newId } from '../crypto/random.ts'
import { AuthError } from '../errors.ts'
import { parseEmail } from '../password/email.ts'
import { assertPasswordAllowed } from '../password/rules.ts'
import type { MemberRecord, TeamRecord, UserRecord } from '../ports/store.ts'
import { createPersonalTeam, parseTeamName, parseTeamSlug } from './teams.ts'

/** The outcome of a membership change: `last-admin` when it would leave a team without an owner. */
export type MembershipOutcome = 'ok' | 'last-admin' | 'not-found'

/** A team member with their account, for rosters. */
export interface TeamMemberView {
  readonly member: MemberRecord
  readonly user: UserRecord
}

/** Trusted, server-side operations for seeders and commands, never routes. */
export interface SystemService {
  /**
   * Create a user directly (seeders, `auth:user:create --password-env`). `email_taken` when the
   * address has an account; `validation_failed` / `weak_password` like sign-up.
   *
   * @example
   * ```ts
   * await auth.system.createUser({ name: 'Ada', email: 'ada@acme.test', password: process.env.ADMIN_PASSWORD, roles: ['admin'] })
   * ```
   */
  createUser(input: {
    readonly name: string
    readonly email: string
    readonly password?: string
    readonly roles?: readonly string[]
    readonly verified?: boolean
  }): Promise<UserRecord>
  /**
   * The account with this email (normalised first), or `undefined`.
   *
   * @example
   * const ada = await auth.system.findUserByEmail('Ada@Acme.test')
   */
  findUserByEmail(email: unknown): Promise<UserRecord | undefined>
  /**
   * Replace a user's global roles (outside teams). Each role must be a global role of the app
   * (`owner`, the reserved team role, never is).
   * Emits `role.assigned` for every role the user did not hold before.
   *
   * @example
   * await auth.system.setRoles(ada.id, ['admin'])
   */
  setRoles(userId: string, roles: readonly string[]): Promise<void>
  /**
   * A user's global roles (sorted).
   *
   * @example
   * const roles = await auth.system.rolesOf(ada.id) // ['admin']
   */
  rolesOf(userId: string): Promise<readonly string[]>
  /**
   * Create a team owned by `ownerId` (who becomes its `owner`). `validation_failed` for a bad name
   * or slug, a taken slug, or an unknown owner.
   *
   * @example
   * const acme = await auth.system.createTeam({ name: 'Acme', slug: 'acme', ownerId: ada.id })
   */
  createTeam(input: {
    readonly name: unknown
    readonly slug?: unknown
    readonly ownerId: string
  }): Promise<TeamRecord>
  /**
   * The team with this slug, or `undefined` (an invalid slug is simply not found).
   *
   * @example
   * const acme = await auth.system.findTeamBySlug('acme')
   */
  findTeamBySlug(slug: unknown): Promise<TeamRecord | undefined>
  /**
   * Add a member or replace their role (idempotent). The role must be a team role of the app.
   * The last-owner guard is atomic: demoting the only owner answers `last-admin` and changes
   * nothing. `not-found` for an unknown team or user.
   *
   * @example
   * await auth.system.setMember({ teamId: acme.id, userId: bob.id, role: 'member' })
   */
  setMember(input: {
    readonly teamId: string
    readonly userId: string
    readonly role: unknown
  }): Promise<MembershipOutcome>
  /**
   * Remove a membership (`ok` when it is gone, also when there was none). The only owner cannot
   * be removed (`last-admin`).
   *
   * @example
   * await auth.system.removeMember({ teamId: acme.id, userId: bob.id })
   */
  removeMember(input: {
    readonly teamId: string
    readonly userId: string
  }): Promise<MembershipOutcome>
  /**
   * Every member of a team with their account (an unknown team has no members).
   *
   * @example
   * const roster = await auth.system.listMembers(acme.id)
   */
  listMembers(teamId: string): Promise<readonly TeamMemberView[]>
}

const invalid = (field: string): AuthError =>
  new AuthError('validation_failed', { issues: [{ field, code: 'invalid' }] })

/** Build the {@link SystemService}. */
export function systemService(deps: AuthDeps): SystemService {
  /** A global role (platform) or a team role, from the configured lists only. */
  const parseRole = (role: unknown, field: string, scope: 'global' | 'team'): string => {
    const allowed = scope === 'global' ? deps.config.roles : deps.config.tenantRoles
    if (typeof role !== 'string' || !allowed.includes(role)) throw invalid(field)
    return role
  }

  const setRoles = async (userId: string, roles: readonly string[]): Promise<void> => {
    const wanted = [...new Set(roles.map((r) => parseRole(r, 'roles', 'global')))]
    const before = new Set(await deps.store.listUserRoles(userId))
    await deps.store.setUserRoles(userId, wanted)
    for (const role of wanted)
      if (!before.has(role)) await emit(deps, undefined, { type: 'role.assigned', userId, role })
  }

  return {
    async createUser(input) {
      const email = parseEmail(input.email)
      if (email === undefined) throw invalid('email')
      const name = typeof input.name === 'string' ? input.name.trim() : ''
      if (name.length < 1 || name.length > 200) throw invalid('name')
      const password =
        input.password === undefined
          ? undefined
          : await assertPasswordAllowed(input.password, {
              min: deps.config.passwords.min,
              max: deps.config.passwords.max,
              check: deps.passwordCheck,
              onUnknown: deps.passwordCheckOnUnknown,
              logger: deps.logger,
            })
      for (const role of input.roles ?? []) parseRole(role, 'roles', 'global')
      const now = deps.clock.now()
      const created = await deps.store.createUser({
        id: newId(),
        email,
        name,
        passwordHash: password === undefined ? null : await deps.hasher.hash(password),
        emailVerifiedAt: input.verified === true ? now : null,
        twoFactorSecret: null,
        twoFactorConfirmedAt: null,
        twoFactorLastStep: null,
        currentTeamId: null,
        createdAt: now,
      })
      if (!created) throw new AuthError('email_taken')
      if (input.roles) await setRoles(created.id, input.roles)
      if (deps.config.features.teams && deps.config.teams.personal) {
        await createPersonalTeam(deps, undefined, created)
        return (await deps.store.findUserById(created.id)) ?? created
      }
      return created
    },

    async findUserByEmail(value) {
      const email = parseEmail(value)
      return email === undefined ? undefined : deps.store.findUserByEmail(email)
    },

    setRoles,

    rolesOf: (userId) => deps.store.listUserRoles(userId),

    async createTeam(input) {
      const team: TeamRecord = {
        id: newId(),
        name: parseTeamName(input.name),
        slug: parseTeamSlug(input.slug),
        personal: false,
        createdAt: deps.clock.now(),
      }
      if (!(await deps.store.findUserById(input.ownerId))) throw invalid('ownerId')
      if (
        !(await deps.store.createTeam(team, {
          teamId: team.id,
          userId: input.ownerId,
          role: TEAM_OWNER_ROLE,
        }))
      )
        throw new AuthError('validation_failed', { issues: [{ field: 'slug', code: 'taken' }] })
      await emit(deps, undefined, { type: 'team.created', userId: input.ownerId, teamId: team.id })
      return team
    },

    async findTeamBySlug(value) {
      try {
        const slug = parseTeamSlug(value)
        return slug === null ? undefined : await deps.store.findTeamBySlug(slug)
      } catch (error) {
        if (error instanceof AuthError) return undefined
        throw error
      }
    },

    async setMember(input) {
      const role = parseRole(input.role, 'role', 'team')
      const [team, user] = await Promise.all([
        deps.store.findTeam(input.teamId),
        deps.store.findUserById(input.userId),
      ])
      if (!team || !user) return 'not-found'
      const existing = await deps.store.findMember(team.id, user.id)
      let outcome: MembershipOutcome = 'ok'
      if (existing) outcome = await deps.store.changeMemberRole(team.id, user.id, role)
      else await deps.store.putMember({ teamId: team.id, userId: user.id, role })
      if (outcome === 'ok')
        await emit(deps, undefined, {
          type: 'team.member.changed',
          userId: user.id,
          teamId: team.id,
          memberId: user.id,
          role,
        })
      return outcome
    },

    async removeMember(input) {
      const outcome = await deps.store.changeMemberRole(input.teamId, input.userId, null)
      if (outcome === 'ok')
        await emit(deps, undefined, {
          type: 'team.member.changed',
          userId: input.userId,
          teamId: input.teamId,
          memberId: input.userId,
          role: null,
        })
      // Gone already is the goal reached (idempotent for seeders and retries).
      return outcome === 'not-found' ? 'ok' : outcome
    },

    async listMembers(teamId) {
      const members = await deps.store.listMembers(teamId)
      const out: TeamMemberView[] = []
      for (const member of members) {
        const user = await deps.store.findUserById(member.userId)
        if (user) out.push({ member, user })
      }
      return out
    },
  }
}
