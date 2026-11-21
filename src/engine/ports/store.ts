/**
 * The storage port: the only way the auth core reads or writes persistent state.
 *
 * The framework implements it on its ORM (spike 11) over the app's own migrations; this spike ships
 * an in-memory store and a real SQLite store (`node:sqlite`) that pass the same tests.
 *
 * Rules every implementation must keep (the store contract test checks them):
 * - **Secrets are never stored raw.** Every token-like column holds a keyed digest (`digest`), the
 *   TOTP secret holds AES-GCM ciphertext. The core does the hashing; the store only compares.
 * - **Single-use is atomic.** `consumeOneTime`, `consumeRecoveryCode`, `consumeInvitation`,
 *   `advanceTotpStep` and `advancePasskeyCounter` must succeed for exactly one of two concurrent
 *   callers (SQL: `DELETE … RETURNING` / a conditional `UPDATE`).
 * - **Guards are atomic.** `changeMemberRole` decides "would this leave the team without an
 *   admin?" in the same statement that writes (a conditional `UPDATE`/`DELETE`, or a row lock),
 *   never as a read followed by a write (CONSISTENCY #117).
 * - **Emails arrive normalized** (`normalizeEmail`); compare them byte for byte (MySQL: a binary
 *   collation, review F-08).
 * - Times are epoch milliseconds.
 * - **Unknown enum values fail closed.** A row whose `state` or `method` is not one of the known
 *   values must throw, never map to a default (an unknown state read as `active` signs in a pending
 *   two-factor session).
 *
 * @module
 */

/** A user row. */
export interface UserRecord {
  readonly id: string
  readonly email: string
  readonly name: string
  /** A PHC-style hash, or `null` for passwordless accounts (email link / passkey only). */
  readonly passwordHash: string | null
  readonly emailVerifiedAt: number | null
  /** AES-256-GCM ciphertext of the TOTP secret (bound to the user id), or `null`. */
  readonly twoFactorSecret: string | null
  /** Set once the user proved the authenticator works; 2FA is enforced only after that. */
  readonly twoFactorConfirmedAt: number | null
  /** The last TOTP time step accepted (replay protection), or `null`. */
  readonly twoFactorLastStep: number | null
  readonly currentTeamId: string | null
  readonly createdAt: number
}

/** The fields {@link AuthStore.updateUser} may change. */
export type UserPatch = Partial<
  Pick<
    UserRecord,
    | 'name'
    | 'passwordHash'
    | 'emailVerifiedAt'
    | 'twoFactorSecret'
    | 'twoFactorConfirmedAt'
    | 'twoFactorLastStep'
    | 'currentTeamId'
  >
>

/** The state of a session row. A `two-factor` session is a guest to every guard (review F-09). */
export type SessionState = 'active' | 'two-factor'

/** A session row. The cookie holds the raw id; the row holds only its keyed digest (F-09). */
export interface SessionRecord {
  readonly digest: string
  readonly userId: string
  readonly state: SessionState
  readonly createdAt: number
  readonly lastSeenAt: number
  /** The absolute expiry; rotation never moves it later (only a new login does). */
  readonly expiresAt: number
  /** Idle timeout in ms for this session ("remember me" sessions get a longer one). */
  readonly idleMs: number
  readonly remember: boolean
  /** How the user proved who they are at sign-in (shown in the sessions list). */
  readonly method: 'password' | 'email-link' | 'passkey'
  readonly passwordConfirmedAt: number | null
  /** The admin who is impersonating `userId`, or `null`. */
  readonly impersonatorId: string | null
  readonly ip: string | null
  readonly userAgent: string | null
}

/** The fields {@link AuthStore.updateSession} may change. */
export type SessionPatch = Partial<Pick<SessionRecord, 'lastSeenAt' | 'passwordConfirmedAt'>>

/** What a one-time secret is for. One table serves them all; `purpose` keeps them apart. */
export type OneTimePurpose =
  | 'password-reset'
  | 'email-link'
  | 'trusted-device'
  | 'webauthn-registration'
  | 'webauthn-authentication'
  /** Binds a registration to the browser that made it (CONSISTENCY #122). */
  | 'registration'

/** A single-use (or, for trusted devices, until-expiry) secret, stored as a keyed digest. */
export interface OneTimeRecord {
  readonly digest: string
  readonly purpose: OneTimePurpose
  readonly userId: string | null
  /** Small JSON-safe data (a challenge, a nonce digest). Never a raw secret. */
  readonly payload: Readonly<Record<string, string>>
  readonly createdAt: number
  readonly expiresAt: number
}

/** A WebAuthn credential row. */
export interface PasskeyRecord {
  readonly id: string
  readonly userId: string
  readonly name: string
  /** base64url credential id (unique across all users). */
  readonly credentialId: string
  /** COSE public key bytes, base64url. */
  readonly publicKey: string
  readonly counter: number
  readonly transports: readonly string[]
  readonly backedUp: boolean
  readonly createdAt: number
  readonly lastUsedAt: number | null
}

/** A personal access token row (Sanctum's `personal_access_tokens`). */
export interface TokenRecord {
  readonly id: string
  readonly userId: string
  readonly name: string
  readonly digest: string
  readonly abilities: readonly string[]
  readonly createdAt: number
  readonly lastUsedAt: number | null
  readonly expiresAt: number | null
}

/** A team row. */
export interface TeamRecord {
  readonly id: string
  readonly name: string
  /**
   * URL-safe unique handle (`acme`), used to pick the team from a subdomain (installer question
   * 12) and by seeders. `null` for personal teams and teams created without one.
   */
  readonly slug: string | null
  readonly personal: boolean
  readonly createdAt: number
}

/** A team membership row. */
export interface MemberRecord {
  readonly teamId: string
  readonly userId: string
  readonly role: string
}

/** A team invitation row; the token is stored as a digest and bound to `email`. */
export interface InvitationRecord {
  readonly id: string
  readonly teamId: string
  readonly email: string
  readonly role: string
  readonly digest: string
  readonly invitedBy: string
  readonly createdAt: number
  readonly expiresAt: number
}

/**
 * The storage port. See the module comment for the rules.
 *
 * @example
 * ```ts
 * const store: AuthStore = sqliteAuthStore(new DatabaseSync('auth.sqlite'))
 * const auth = createAuth({ store, ...ports })
 * ```
 */
export interface AuthStore {
  // Users
  /** Insert a user; resolves `undefined` when the email is already taken (unique index). */
  createUser(user: UserRecord): Promise<UserRecord | undefined>
  findUserById(id: string): Promise<UserRecord | undefined>
  findUserByEmail(email: string): Promise<UserRecord | undefined>
  updateUser(id: string, patch: UserPatch): Promise<void>
  /** Atomically set `twoFactorLastStep = step` only if it is null or lower. True if it moved. */
  advanceTotpStep(userId: string, step: number): Promise<boolean>
  /** Global roles (Laravel-style `user_roles`; names are defined in code). */
  listUserRoles(userId: string): Promise<readonly string[]>
  setUserRoles(userId: string, roles: readonly string[]): Promise<void>

  // Sessions
  createSession(session: SessionRecord): Promise<void>
  findSession(digest: string): Promise<SessionRecord | undefined>
  updateSession(digest: string, patch: SessionPatch): Promise<void>
  deleteSession(digest: string): Promise<void>
  /** Delete every session of a user except `exceptDigest`; resolves how many were deleted. */
  deleteUserSessions(userId: string, exceptDigest?: string): Promise<number>
  listUserSessions(userId: string): Promise<readonly SessionRecord[]>

  // One-time secrets
  putOneTime(record: OneTimeRecord): Promise<void>
  findOneTime(digest: string, purpose: OneTimePurpose): Promise<OneTimeRecord | undefined>
  /** Atomically delete and return the record (single use). */
  consumeOneTime(digest: string, purpose: OneTimePurpose): Promise<OneTimeRecord | undefined>
  deleteUserOneTime(userId: string, purpose: OneTimePurpose): Promise<void>

  // Recovery codes
  replaceRecoveryCodes(userId: string, digests: readonly string[]): Promise<void>
  /** Atomically delete one matching code. True if it existed. */
  consumeRecoveryCode(userId: string, digest: string): Promise<boolean>
  countRecoveryCodes(userId: string): Promise<number>

  // Passkeys
  addPasskey(passkey: PasskeyRecord): Promise<void>
  findPasskeyByCredentialId(credentialId: string): Promise<PasskeyRecord | undefined>
  listPasskeys(userId: string): Promise<readonly PasskeyRecord[]>
  updatePasskey(
    id: string,
    patch: Partial<Pick<PasskeyRecord, 'name' | 'counter' | 'lastUsedAt' | 'backedUp'>>,
  ): Promise<void>
  /**
   * Store a sign-in's new counter only if the stored one is still `expected` (compare-and-set).
   * False when another sign-in moved it first: a cloned authenticator racing the original.
   */
  advancePasskeyCounter(
    id: string,
    expected: number,
    patch: { readonly counter: number; readonly lastUsedAt: number; readonly backedUp: boolean },
  ): Promise<boolean>
  /** Delete one of `userId`'s passkeys; false when it does not belong to them. */
  deletePasskey(userId: string, id: string): Promise<boolean>

  // Personal access tokens
  addToken(token: TokenRecord): Promise<void>
  findTokenByDigest(digest: string): Promise<TokenRecord | undefined>
  listTokens(userId: string): Promise<readonly TokenRecord[]>
  touchToken(id: string, at: number): Promise<void>
  /** Delete one of `userId`'s tokens; false when it does not belong to them. */
  deleteToken(userId: string, id: string): Promise<boolean>
  deleteUserTokens(userId: string): Promise<number>

  // Teams
  /**
   * Create a team and its first member in one transaction. Resolves `false` (and writes nothing)
   * when the slug is already taken (unique index).
   */
  createTeam(team: TeamRecord, owner: MemberRecord): Promise<boolean>
  findTeam(id: string): Promise<TeamRecord | undefined>
  /** The team with this slug (compared byte for byte; slugs are stored lowercase). */
  findTeamBySlug(slug: string): Promise<TeamRecord | undefined>
  findMember(teamId: string, userId: string): Promise<MemberRecord | undefined>
  listMembers(teamId: string): Promise<readonly MemberRecord[]>
  listUserTeams(userId: string): Promise<readonly MemberRecord[]>
  /** Insert or update a membership. */
  putMember(member: MemberRecord): Promise<void>
  removeMember(teamId: string, userId: string): Promise<void>
  /**
   * Change a member's role (`null` removes them), atomically refusing when it would leave the team
   * with no admin.
   */
  changeMemberRole(
    teamId: string,
    userId: string,
    role: string | null,
  ): Promise<'ok' | 'not-found' | 'last-admin'>
  /**
   * Rename a team role on every membership and pending invitation, in one transaction. Idempotent
   * (a second call changes nothing); resolves to the number of rows changed. Used to move teams
   * created before the team role was `owner` (they held `admin`).
   */
  renameTeamRole(from: string, to: string): Promise<number>
  addInvitation(invitation: InvitationRecord): Promise<void>
  findInvitationByDigest(digest: string): Promise<InvitationRecord | undefined>
  listInvitations(teamId: string): Promise<readonly InvitationRecord[]>
  /** Atomically delete and return the invitation (single use). */
  consumeInvitation(id: string): Promise<InvitationRecord | undefined>
}
