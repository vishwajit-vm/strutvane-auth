/**
 * The system service: seeders, CLI commands and the identity-engine adapter's "as system"
 * operations. Same rules as the request-facing services (roles, slugs, the atomic last-admin
 * guard), no session, audited with no actor.
 */
import { describe, expect, it } from 'vitest'
import { harness, rejectsWith, STORES } from './helpers/harness.ts'

describe.each(STORES)('system service (%s store)', (store) => {
  const config = {
    features: { teams: true },
    teams: { personal: false },
    roles: 'admin-manager-member-viewer',
  } as const

  it('creates users with the sign-up rules, and finds them by any spelling of the email', async () => {
    const h = harness({ store, config })
    const ada = await h.auth.system.createUser({
      name: ' Ada ',
      email: 'Ada@Acme.test',
      password: 'a long enough password',
    })
    expect(ada).toMatchObject({ name: 'Ada', email: 'ada@acme.test', currentTeamId: null })
    expect((await h.auth.system.findUserByEmail(' ADA@acme.test '))?.id).toBe(ada.id)
    expect(await h.auth.system.findUserByEmail({ $ne: '' })).toBeUndefined()
    for (const name of ['', '   ', 'n'.repeat(201)])
      await rejectsWith(
        () => h.auth.system.createUser({ name, email: 'b@acme.test' }),
        'validation_failed',
      )
    await rejectsWith(
      () => h.auth.system.createUser({ name: 'A', email: 'ada@acme.test' }),
      'email_taken',
    )
    await rejectsWith(
      () => h.auth.system.createUser({ name: 'W', email: 'w@acme.test', password: 'short' }),
      'weak_password',
    )
    await rejectsWith(
      () => h.auth.system.createUser({ name: 'R', email: 'r@acme.test', roles: ['root'] }),
      'validation_failed',
    )
  })

  it('global roles: replaced, validated, and every newly assigned role is audited', async () => {
    const h = harness({ store, config })
    const ada = await h.user('ada@acme.test')
    await h.auth.system.setRoles(ada.id, ['admin', 'member', 'admin'])
    expect(await h.store.listUserRoles(ada.id)).toEqual(['admin', 'member'])
    await h.auth.system.setRoles(ada.id, ['member', 'viewer'])
    expect(await h.store.listUserRoles(ada.id)).toEqual(['member', 'viewer'])
    expect(h.eventsOf('role.assigned').map((e) => e.role)).toEqual(['admin', 'member', 'viewer'])
    expect(
      h.eventsOf('role.assigned').every((e) => e.actorId === null && e.subjectId === ada.id),
    ).toBe(true)
    await rejectsWith(() => h.auth.system.setRoles(ada.id, ['owner']), 'validation_failed')
    expect(await h.store.listUserRoles(ada.id)).toEqual(['member', 'viewer'])
  })

  it('teams: created for an existing owner with a unique slug, found by slug', async () => {
    const h = harness({ store, config })
    const ada = await h.user('ada@acme.test')
    const acme = await h.auth.system.createTeam({ name: 'Acme', slug: 'acme', ownerId: ada.id })
    expect(acme).toMatchObject({ name: 'Acme', slug: 'acme', personal: false })
    expect(await h.store.findMember(acme.id, ada.id)).toMatchObject({ role: 'owner' })
    expect(h.eventsOf('team.created')).toMatchObject([
      { teamId: acme.id, userId: ada.id, actorId: null },
    ])
    expect((await h.auth.system.findTeamBySlug('acme'))?.id).toBe(acme.id)
    for (const slug of ['ACME', "x' OR 1=1", 42, undefined])
      expect(await h.auth.system.findTeamBySlug(slug)).toBeUndefined()
    await rejectsWith(
      () => h.auth.system.createTeam({ name: 'Dup', slug: 'acme', ownerId: ada.id }),
      'validation_failed',
    )
    await rejectsWith(
      () => h.auth.system.createTeam({ name: 'X', slug: 'x', ownerId: 'nobody' }),
      'validation_failed',
    )
    await rejectsWith(
      () => h.auth.system.createTeam({ name: '', slug: 'y', ownerId: ada.id }),
      'validation_failed',
    )
    expect(await h.auth.system.findTeamBySlug('x')).toBeUndefined()
  })

  it('members: add, replace (idempotent), the atomic last-admin guard, remove', async () => {
    const h = harness({ store, config })
    const ada = await h.user('ada@acme.test')
    const bob = await h.user('bob@acme.test')
    const team = await h.auth.system.createTeam({ name: 'Acme', ownerId: ada.id })
    expect(await h.auth.system.setMember({ teamId: team.id, userId: bob.id, role: 'viewer' })).toBe(
      'ok',
    )
    expect(await h.auth.system.setMember({ teamId: team.id, userId: bob.id, role: 'member' })).toBe(
      'ok',
    )
    const roster = await h.auth.system.listMembers(team.id)
    expect(roster.map((m) => [m.user.email, m.member.role]).sort()).toEqual([
      ['ada@acme.test', 'owner'],
      ['bob@acme.test', 'member'],
    ])
    // The only owner can be neither demoted nor removed…
    expect(await h.auth.system.setMember({ teamId: team.id, userId: ada.id, role: 'member' })).toBe(
      'last-admin',
    )
    expect(await h.auth.system.removeMember({ teamId: team.id, userId: ada.id })).toBe('last-admin')
    // …until there is another one.
    expect(await h.auth.system.setMember({ teamId: team.id, userId: bob.id, role: 'owner' })).toBe(
      'ok',
    )
    expect(await h.auth.system.removeMember({ teamId: team.id, userId: ada.id })).toBe('ok')
    expect(await h.auth.system.removeMember({ teamId: team.id, userId: ada.id })).toBe('ok')
    expect(await h.auth.system.setMember({ teamId: 'nope', userId: bob.id, role: 'member' })).toBe(
      'not-found',
    )
    expect(
      await h.auth.system.setMember({ teamId: team.id, userId: 'nobody', role: 'member' }),
    ).toBe('not-found')
    await rejectsWith(
      () => h.auth.system.setMember({ teamId: team.id, userId: bob.id, role: 'admin' }),
      'validation_failed',
    )
    expect(await h.auth.system.listMembers('nope')).toEqual([])
    expect(
      h.eventsOf('team.member.changed').map((e) => [e.memberId === bob.id ? 'bob' : 'ada', e.role]),
    ).toEqual([
      ['bob', 'viewer'],
      ['bob', 'member'],
      ['bob', 'owner'],
      ['ada', null],
    ])
  })
})
