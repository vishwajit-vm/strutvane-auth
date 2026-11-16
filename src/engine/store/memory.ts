/**
 * In-memory implementations of {@link AuthStore} and {@link CounterStore}, for tests and demos.
 *
 * Single process only. Every method completes synchronously inside its promise, so the atomic
 * operations (consume, advance) are atomic within the process by construction.
 *
 * @module
 */

import type { Clock } from '../ports/clock.ts'
import { systemClock } from '../ports/clock.ts'
import type { CounterStore } from '../ports/counter-store.ts'
import type {
  AuthStore,
  InvitationRecord,
  MemberRecord,
  OneTimePurpose,
  OneTimeRecord,
  PasskeyRecord,
  SessionRecord,
  TeamRecord,
  TokenRecord,
  UserRecord,
} from '../ports/store.ts'

/**
 * A fresh, empty in-memory auth store.
 *
 * @example
 * ```ts
 * const store = memoryAuthStore()
 * ```
 */
export function memoryAuthStore(): AuthStore {
  const users = new Map<string, UserRecord>()
  const roles = new Map<string, readonly string[]>()
  const sessions = new Map<string, SessionRecord>()
  const oneTime = new Map<string, OneTimeRecord>()
  const recovery = new Map<string, Set<string>>()
  const passkeys = new Map<string, PasskeyRecord>()
  const tokens = new Map<string, TokenRecord>()
  const teams = new Map<string, TeamRecord>()
  const members = new Map<string, MemberRecord>()
  const invitations = new Map<string, InvitationRecord>()
  const otKey = (digest: string, purpose: OneTimePurpose): string => `${purpose}:${digest}`
  const mKey = (teamId: string, userId: string): string => `${teamId}:${userId}`

  return {
    async createUser(user) {
      for (const u of users.values()) if (u.email === user.email) return undefined
      users.set(user.id, user)
      return user
    },
    async findUserById(id) {
      return users.get(id)
    },
    async findUserByEmail(email) {
      for (const u of users.values()) if (u.email === email) return u
      return undefined
    },
    async updateUser(id, patch) {
      const u = users.get(id)
      if (u) users.set(id, { ...u, ...patch })
    },
    async advanceTotpStep(userId, step) {
      const u = users.get(userId)
      if (!u || (u.twoFactorLastStep !== null && u.twoFactorLastStep >= step)) return false
      users.set(userId, { ...u, twoFactorLastStep: step })
      return true
    },
    async listUserRoles(userId) {
      return roles.get(userId) ?? []
    },
    async setUserRoles(userId, list) {
      roles.set(userId, [...new Set(list)])
    },

    async createSession(session) {
      sessions.set(session.digest, session)
    },
    async findSession(digest) {
      return sessions.get(digest)
    },
    async updateSession(digest, patch) {
      const s = sessions.get(digest)
      if (s) sessions.set(digest, { ...s, ...patch })
    },
    async deleteSession(digest) {
      sessions.delete(digest)
    },
    async deleteUserSessions(userId, exceptDigest) {
      let n = 0
      for (const [d, s] of sessions)
        if (s.userId === userId && d !== exceptDigest) {
          sessions.delete(d)
          n++
        }
      return n
    },
    async listUserSessions(userId) {
      return [...sessions.values()].filter((s) => s.userId === userId)
    },

    async putOneTime(record) {
      oneTime.set(otKey(record.digest, record.purpose), record)
    },
    async findOneTime(digest, purpose) {
      return oneTime.get(otKey(digest, purpose))
    },
    async consumeOneTime(digest, purpose) {
      const key = otKey(digest, purpose)
      const r = oneTime.get(key)
      oneTime.delete(key)
      return r
    },
    async deleteUserOneTime(userId, purpose) {
      for (const [k, r] of oneTime)
        if (r.userId === userId && r.purpose === purpose) oneTime.delete(k)
    },

    async replaceRecoveryCodes(userId, digests) {
      recovery.set(userId, new Set(digests))
    },
    async consumeRecoveryCode(userId, digest) {
      return recovery.get(userId)?.delete(digest) ?? false
    },
    async countRecoveryCodes(userId) {
      return recovery.get(userId)?.size ?? 0
    },

    async addPasskey(passkey) {
      passkeys.set(passkey.id, passkey)
    },
    async findPasskeyByCredentialId(credentialId) {
      for (const p of passkeys.values()) if (p.credentialId === credentialId) return p
      return undefined
    },
    async listPasskeys(userId) {
      return [...passkeys.values()]
        .filter((p) => p.userId === userId)
        .sort((a, b) => a.createdAt - b.createdAt)
    },
    async updatePasskey(id, patch) {
      const p = passkeys.get(id)
      if (p) passkeys.set(id, { ...p, ...patch })
    },
    async advancePasskeyCounter(id, expected, patch) {
      const p = passkeys.get(id)
      if (!p || p.counter !== expected) return false
      passkeys.set(id, { ...p, ...patch })
      return true
    },
    async deletePasskey(userId, id) {
      const p = passkeys.get(id)
      if (!p || p.userId !== userId) return false
      return passkeys.delete(id)
    },

    async addToken(token) {
      tokens.set(token.id, token)
    },
    async findTokenByDigest(digest) {
      for (const t of tokens.values()) if (t.digest === digest) return t
      return undefined
    },
    async listTokens(userId) {
      return [...tokens.values()].filter((t) => t.userId === userId)
    },
    async touchToken(id, at) {
      const t = tokens.get(id)
      if (t) tokens.set(id, { ...t, lastUsedAt: at })
    },
    async deleteToken(userId, id) {
      const t = tokens.get(id)
      if (!t || t.userId !== userId) return false
      return tokens.delete(id)
    },
    async deleteUserTokens(userId) {
      let n = 0
      for (const [id, t] of tokens)
        if (t.userId === userId) {
          tokens.delete(id)
          n++
        }
      return n
    },

    async createTeam(team, owner) {
      teams.set(team.id, team)
      members.set(mKey(owner.teamId, owner.userId), owner)
    },
    async findTeam(id) {
      return teams.get(id)
    },
    async findMember(teamId, userId) {
      return members.get(mKey(teamId, userId))
    },
    async listMembers(teamId) {
      return [...members.values()].filter((m) => m.teamId === teamId)
    },
    async listUserTeams(userId) {
      return [...members.values()].filter((m) => m.userId === userId)
    },
    async putMember(member) {
      members.set(mKey(member.teamId, member.userId), member)
    },
    async removeMember(teamId, userId) {
      members.delete(mKey(teamId, userId))
    },
    async changeMemberRole(teamId, userId, role) {
      // Synchronous between the check and the write: atomic within the process.
      const m = members.get(mKey(teamId, userId))
      if (!m) return 'not-found'
      const otherAdmin = [...members.values()].some(
        (o) => o.teamId === teamId && o.userId !== userId && o.role === 'admin',
      )
      if (m.role === 'admin' && role !== 'admin' && !otherAdmin) return 'last-admin'
      if (role === null) members.delete(mKey(teamId, userId))
      else members.set(mKey(teamId, userId), { ...m, role })
      return 'ok'
    },
    async addInvitation(invitation) {
      invitations.set(invitation.id, invitation)
    },
    async findInvitationByDigest(digest) {
      for (const i of invitations.values()) if (i.digest === digest) return i
      return undefined
    },
    async listInvitations(teamId) {
      return [...invitations.values()].filter((i) => i.teamId === teamId)
    },
    async consumeInvitation(id) {
      const i = invitations.get(id)
      invitations.delete(id)
      return i
    },
  }
}

/**
 * An in-memory {@link CounterStore}. Not shared between processes: production needs the
 * framework's shared cache (review F-22).
 */
export function memoryCounterStore(clock: Clock = systemClock): CounterStore {
  const entries = new Map<string, { value: number; expiresAt: number }>()
  const live = (key: string) => {
    const e = entries.get(key)
    if (e && e.expiresAt <= clock.now()) {
      entries.delete(key)
      return undefined
    }
    return e
  }
  return {
    async increment(key, ttlMs) {
      const e = live(key)
      if (e) {
        e.value++
        return e.value
      }
      entries.set(key, { value: 1, expiresAt: clock.now() + ttlMs })
      return 1
    },
    async get(key) {
      return live(key)?.value
    },
    async set(key, value, ttlMs) {
      entries.set(key, { value, expiresAt: clock.now() + ttlMs })
    },
    async delete(key) {
      entries.delete(key)
    },
  }
}
