/**
 * Teams: creation, invitations, roles, switching and the current team.
 *
 * Tenancy ENFORCEMENT (scoping queries, RLS) belongs to the framework (spike 11's tenant scope);
 * this service only decides membership and exposes the current team, re-reading the membership on
 * every request so a removed member loses access immediately.
 *
 * - **Roles** come from the configured preset (`admin`+`member`, or
 *   `admin`+`manager`+`member`+`viewer`). Only `admin` manages members and invitations here; the
 *   other roles mean what the app's policies say. A team always keeps at least one admin.
 * - **Invitations** are 256-bit tokens stored as keyed digests, expire (7 days), are single-use, and
 *   are bound to the invited EMAIL: only a signed-in user with exactly that (normalised, and, when
 *   verification is on, verified) address can accept. A forwarded invitation is useless.
 * - **Switching** teams is a privilege change, so the session id rotates.
 * - **No grants while impersonating:** invite, role changes and accepting are refused, so an
 *   impersonating admin cannot leave with access to the user's teams.
 * - Teams a user is not in answer `not_found`, never `forbidden`: ids do not confirm existence.
 *
 * @module
 */

import { type AuthDeps, emit, requireFeature, sendMail } from '../core/deps.ts'
import {
  type ActiveSession,
  assertNotImpersonating,
  requireActive,
  rotateSession,
} from '../core/sessions.ts'
import { newId, randomSecret } from '../crypto/random.ts'
import { AuthError } from '../errors.ts'
import { parseEmail } from '../password/email.ts'
import type { AuthRequest } from '../ports/cookies.ts'
import type { MemberRecord, TeamRecord, UserRecord } from '../ports/store.ts'
import { parseSecret } from '../tokens/formats.ts'

/** The current team as the framework sees it (the tenant for this request). */
export interface CurrentTeam {
  readonly id: string
  readonly name: string
  readonly role: string
}

/** An invitation as listed for team admins (no token). */
export interface InvitationView {
  readonly id: string
  readonly email: string
  readonly role: string
  readonly expiresAt: number
}

/** Team operations (feature `teams`). */
export interface TeamService {
  /**
   * Create a team; the creator becomes its admin and it becomes their current team.
   *
   * @example
   * ```ts
   * const team = await auth.teams.create(req, { name: 'Acme' })
   * ```
   */
  create(req: AuthRequest, input: { readonly name: unknown }): Promise<CurrentTeam>
  /** The signed-in user's current team, or `null` (the framework's tenant for this request). */
  current(req: AuthRequest): Promise<CurrentTeam | null>
  /** Every team the user belongs to. */
  list(req: AuthRequest): Promise<readonly CurrentTeam[]>
  /** Make another team current (rotates the session id). */
  switch(req: AuthRequest, input: { readonly teamId: unknown }): Promise<CurrentTeam>
  /**
   * Invite an email address (team admins only).
   *
   * @example
   * ```ts
   * await auth.teams.invite(req, { teamId, email: 'vic@acme.test', role: 'member' })
   * ```
   */
  invite(
    req: AuthRequest,
    input: { readonly teamId: unknown; readonly email: unknown; readonly role: unknown },
  ): Promise<InvitationView>
  invitations(
    req: AuthRequest,
    input: { readonly teamId: unknown },
  ): Promise<readonly InvitationView[]>
  revokeInvitation(
    req: AuthRequest,
    input: { readonly teamId: unknown; readonly invitationId: unknown },
  ): Promise<void>
  /** Accept an invitation as the signed-in user (the email must match). */
  accept(req: AuthRequest, input: { readonly token: unknown }): Promise<CurrentTeam>
  members(req: AuthRequest, input: { readonly teamId: unknown }): Promise<readonly MemberRecord[]>
  changeRole(
    req: AuthRequest,
    input: { readonly teamId: unknown; readonly userId: unknown; readonly role: unknown },
  ): Promise<void>
  /** Remove a member (admins), or leave (anyone, for themselves). The last admin cannot go. */
  removeMember(
    req: AuthRequest,
    input: { readonly teamId: unknown; readonly userId: unknown },
  ): Promise<void>
}

function parseTeamName(value: unknown): string {
  if (typeof value !== 'string' || value.trim().length < 1 || value.trim().length > 100)
    throw new AuthError('validation_failed', { issues: [{ field: 'name', code: 'invalid' }] })
  return value.trim()
}

/** Create the personal team a new user gets when teams are on (Laravel's teams kit). */
export async function createPersonalTeam(
  deps: AuthDeps,
  req: AuthRequest | undefined,
  user: UserRecord,
): Promise<TeamRecord> {
  const team: TeamRecord = {
    id: newId(),
    name: `${user.name}'s team`.slice(0, 100),
    personal: true,
    createdAt: deps.clock.now(),
  }
  await deps.store.createTeam(team, { teamId: team.id, userId: user.id, role: 'admin' })
  await deps.store.updateUser(user.id, { currentTeamId: team.id })
  await emit(deps, req, { type: 'team.created', userId: user.id, teamId: team.id })
  return team
}

/** Build the {@link TeamService}. */
export function teamService(deps: AuthDeps): TeamService {
  const roles = deps.config.roles

  const signedIn = async (req: AuthRequest): Promise<ActiveSession> => {
    requireFeature(deps, 'teams')
    return requireActive(deps, req)
  }

  /**
   * For operations that GRANT access (invite, change a role, accept): refused while an admin
   * impersonates, because the grant would outlive the impersonation (inviting yourself into the
   * user's team, promoting a colleague). Same reasoning as tokens being refused.
   */
  const grantingAs = async (req: AuthRequest): Promise<ActiveSession> => {
    const active = await signedIn(req)
    assertNotImpersonating(active)
    return active
  }

  /** The caller's membership of `teamId`; not_found when they are not a member (or it is not an id). */
  const membership = async (
    active: ActiveSession,
    teamId: unknown,
  ): Promise<{ team: TeamRecord; member: MemberRecord }> => {
    if (typeof teamId !== 'string') throw new AuthError('not_found')
    const member = await deps.store.findMember(teamId, active.user.id)
    const team = member ? await deps.store.findTeam(teamId) : undefined
    if (!member || !team) throw new AuthError('not_found')
    return { team, member }
  }

  const adminOf = async (active: ActiveSession, teamId: unknown) => {
    const m = await membership(active, teamId)
    if (m.member.role !== 'admin') throw new AuthError('forbidden')
    return m
  }

  const parseRole = (value: unknown): string => {
    if (typeof value !== 'string' || !roles.includes(value))
      throw new AuthError('validation_failed', { issues: [{ field: 'role', code: 'invalid' }] })
    return value
  }

  const current = async (active: ActiveSession): Promise<CurrentTeam | null> => {
    const teamId = active.user.currentTeamId
    if (teamId === null) return null
    const member = await deps.store.findMember(teamId, active.user.id)
    const team = member ? await deps.store.findTeam(teamId) : undefined
    return member && team ? { id: team.id, name: team.name, role: member.role } : null
  }

  return {
    async create(req, input) {
      const active = await signedIn(req)
      const team: TeamRecord = {
        id: newId(),
        name: parseTeamName(input.name),
        personal: false,
        createdAt: deps.clock.now(),
      }
      await deps.store.createTeam(team, { teamId: team.id, userId: active.user.id, role: 'admin' })
      await deps.store.updateUser(active.user.id, { currentTeamId: team.id })
      await rotateSession(deps, req, active.session)
      await emit(deps, req, { type: 'team.created', userId: active.user.id, teamId: team.id })
      return { id: team.id, name: team.name, role: 'admin' }
    },

    async current(req) {
      if (!deps.config.features.teams) return null
      return current(await requireActive(deps, req))
    },

    async list(req) {
      const active = await signedIn(req)
      const out: CurrentTeam[] = []
      for (const m of await deps.store.listUserTeams(active.user.id)) {
        const team = await deps.store.findTeam(m.teamId)
        if (team) out.push({ id: team.id, name: team.name, role: m.role })
      }
      return out
    },

    async switch(req, input) {
      const active = await signedIn(req)
      const { team, member } = await membership(active, input.teamId)
      await deps.store.updateUser(active.user.id, { currentTeamId: team.id })
      await rotateSession(deps, req, active.session)
      await emit(deps, req, { type: 'team.switched', userId: active.user.id, teamId: team.id })
      return { id: team.id, name: team.name, role: member.role }
    },

    async invite(req, input) {
      const active = await grantingAs(req)
      const { team } = await adminOf(active, input.teamId)
      const email = parseEmail(input.email)
      if (email === undefined)
        throw new AuthError('validation_failed', { issues: [{ field: 'email', code: 'invalid' }] })
      const role = parseRole(input.role)
      // Every invitation mails an address the inviter chose, and every user admins a personal team,
      // so without a budget any account is a free mail cannon. Keyed on the inviting ACCOUNT, so
      // spreading the mails over several teams does not reset it.
      const retry = await deps.limiter.hit([
        [`invite:acct:${active.user.id}`, deps.config.limits.invitePerAccount],
      ])
      if (retry !== undefined) throw new AuthError('rate_limited', { retryAfterSeconds: retry })
      const invitee = await deps.store.findUserByEmail(email)
      if (invitee && (await deps.store.findMember(team.id, invitee.id)))
        throw new AuthError('conflict')
      const token = randomSecret()
      const now = deps.clock.now()
      const invitation = {
        id: newId(),
        teamId: team.id,
        email,
        role,
        digest: deps.keys.digest('team-invitation', token),
        invitedBy: active.user.id,
        createdAt: now,
        expiresAt: now + deps.config.links.invitationMs,
      }
      await deps.store.addInvitation(invitation)
      sendMail(deps, {
        kind: 'team-invitation',
        to: email,
        teamName: team.name,
        role,
        url: `${deps.config.appUrl}/team-invitations/${token}`,
      })
      await emit(deps, req, {
        type: 'team.invitation.created',
        userId: active.user.id,
        teamId: team.id,
        invitationId: invitation.id,
      })
      return { id: invitation.id, email, role, expiresAt: invitation.expiresAt }
    },

    async invitations(req, input) {
      const active = await signedIn(req)
      const { team } = await adminOf(active, input.teamId)
      return (await deps.store.listInvitations(team.id)).map((i) => ({
        id: i.id,
        email: i.email,
        role: i.role,
        expiresAt: i.expiresAt,
      }))
    },

    async revokeInvitation(req, input) {
      const active = await signedIn(req)
      const { team } = await adminOf(active, input.teamId)
      const invitation = (await deps.store.listInvitations(team.id)).find(
        (i) => i.id === input.invitationId,
      )
      if (!invitation) throw new AuthError('not_found')
      await deps.store.consumeInvitation(invitation.id)
    },

    async accept(req, input) {
      const active = await grantingAs(req)
      const token = parseSecret(input.token)
      if (token === undefined) throw new AuthError('invalid_token')
      const invitation = await deps.store.findInvitationByDigest(
        deps.keys.digest('team-invitation', token),
      )
      // Unknown, expired and "for someone else" all look the same.
      if (
        !invitation ||
        invitation.expiresAt <= deps.clock.now() ||
        invitation.email !== active.user.email
      )
        throw new AuthError('invalid_token')
      if (deps.config.features.emailVerification && active.user.emailVerifiedAt === null)
        throw new AuthError('email_not_verified')
      const consumed = await deps.store.consumeInvitation(invitation.id)
      // Expiry is judged at the consume, not only at the earlier lookup.
      if (!consumed || consumed.expiresAt <= deps.clock.now()) throw new AuthError('invalid_token')
      const team = await deps.store.findTeam(consumed.teamId)
      if (!team) throw new AuthError('invalid_token')
      if (!(await deps.store.findMember(team.id, active.user.id)))
        await deps.store.putMember({ teamId: team.id, userId: active.user.id, role: consumed.role })
      await deps.store.updateUser(active.user.id, { currentTeamId: team.id })
      await rotateSession(deps, req, active.session)
      await emit(deps, req, {
        type: 'team.invitation.accepted',
        userId: active.user.id,
        teamId: team.id,
        invitationId: consumed.id,
      })
      const member = await deps.store.findMember(team.id, active.user.id)
      return { id: team.id, name: team.name, role: member?.role ?? consumed.role }
    },

    async members(req, input) {
      const active = await signedIn(req)
      const { team } = await membership(active, input.teamId)
      return deps.store.listMembers(team.id)
    },

    async changeRole(req, input) {
      const active = await grantingAs(req)
      const { team } = await adminOf(active, input.teamId)
      const role = parseRole(input.role)
      if (typeof input.userId !== 'string') throw new AuthError('not_found')
      // One atomic store operation: a read-then-write check let two admins demote each other.
      const outcome = await deps.store.changeMemberRole(team.id, input.userId, role)
      if (outcome === 'not-found') throw new AuthError('not_found')
      if (outcome === 'last-admin') throw new AuthError('last_admin')
      await emit(deps, req, {
        type: 'team.member.changed',
        userId: active.user.id,
        teamId: team.id,
        memberId: input.userId,
        role,
      })
    },

    async removeMember(req, input) {
      const active = await signedIn(req)
      const { team, member } = await membership(active, input.teamId)
      if (typeof input.userId !== 'string') throw new AuthError('not_found')
      const leaving = input.userId === active.user.id
      if (!leaving && member.role !== 'admin') throw new AuthError('forbidden')
      const outcome = await deps.store.changeMemberRole(team.id, input.userId, null)
      if (outcome === 'not-found') throw new AuthError('not_found')
      if (outcome === 'last-admin') throw new AuthError('last_admin')
      // The removed user's current team is re-checked per request (current() returns null), so
      // their sessions lose the team immediately without touching them here.
      await emit(deps, req, {
        type: 'team.member.changed',
        userId: active.user.id,
        teamId: team.id,
        memberId: input.userId,
        role: null,
      })
    },
  }
}
