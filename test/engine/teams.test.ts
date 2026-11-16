import { describe, expect, it } from 'vitest'
import { Browser, type Harness, harness, rejectsWith, STORES } from './helpers/harness.ts'

const config = {
  features: { teams: true, emailVerification: true },
  roles: 'admin-manager-member-viewer' as const,
}

async function invite(
  h: Harness,
  admin: Browser,
  teamId: string,
  email: string,
  role = 'member',
): Promise<string> {
  await h.auth.teams.invite(admin.req, { teamId, email, role })
  return h.mailedToken('team-invitation', email.toLowerCase())
}

describe.each(STORES)('teams (%s store)', (store) => {
  it('new users get a personal team as admin; current team is exposed', async () => {
    const h = harness({ store, config })
    await h.user()
    const b = await h.signedIn('ada@acme.test')
    const current = await h.auth.teams.current(b.req)
    expect(current).toMatchObject({ name: "ada's team", role: 'admin' })
    expect((await h.auth.state(b.req))?.team).toEqual(current)
  })

  it('race: two admins demoting (or removing) each other at once never leave a team without an admin', async () => {
    for (const action of ['demote', 'remove'] as const) {
      const h = harness({ store, config })
      const ada = await h.user('ada@acme.test')
      await h.user('vic@acme.test')
      const adaB = await h.signedIn(ada.email)
      const team = await h.auth.teams.create(adaB.req, { name: 'Acme' })
      const vicB = await h.signedIn('vic@acme.test')
      await h.auth.teams.accept(vicB.req, {
        token: await invite(h, adaB, team.id, 'vic@acme.test', 'admin'),
      })
      const vic = await h.store.findUserByEmail('vic@acme.test')
      const run = (who: Browser, target: string) =>
        action === 'demote'
          ? h.auth.teams.changeRole(who.req, { teamId: team.id, userId: target, role: 'member' })
          : h.auth.teams.removeMember(who.req, { teamId: team.id, userId: target })
      const results = await Promise.allSettled([run(adaB, vic?.id ?? ''), run(vicB, ada.id)])
      expect(
        results.filter((r) => r.status === 'fulfilled'),
        action,
      ).toHaveLength(1)
      const admins = (await h.store.listMembers(team.id)).filter((m) => m.role === 'admin')
      expect(admins, action).toHaveLength(1)
    }
  })

  it('attack: invitations cannot be used to mail-bomb arbitrary addresses (per-account limit, across teams)', async () => {
    const h = harness({ store, config })
    await h.user('ada@acme.test')
    const ada = await h.signedIn('ada@acme.test')
    const personal = await h.auth.teams.current(ada.req)
    const other = await h.auth.teams.create(ada.req, { name: 'Second' })
    // Any registered user is admin of a personal team, so the budget is per inviting account,
    // not per team: switching teams must not reset it.
    for (let i = 0; i < 20; i++)
      await h.auth.teams.invite(ada.req, {
        teamId: i % 2 === 0 ? personal?.id : other.id,
        email: `victim+${i}@mail.test`,
        role: 'member',
      })
    const err = await rejectsWith(
      () =>
        h.auth.teams.invite(ada.req, {
          teamId: other.id,
          email: 'victim+x@mail.test',
          role: 'member',
        }),
      'rate_limited',
    )
    expect(err.retryAfterSeconds).toBeGreaterThan(0)
    await h.auth.idle()
    expect(h.mails.filter((m) => m.kind === 'team-invitation')).toHaveLength(20)
    expect(
      (await h.store.listInvitations(other.id)).some((i) => i.email === 'victim+x@mail.test'),
    ).toBe(false)
  })

  it('invitation: email-bound, single-use, expires; a forwarded invitation is useless', async () => {
    const h = harness({ store, config })
    await h.user('ada@acme.test')
    await h.user('vic@acme.test')
    await h.user('eve@acme.test')
    const ada = await h.signedIn('ada@acme.test')
    const team = await h.auth.teams.create(ada.req, { name: 'Acme' })
    const token = await invite(h, ada, team.id, 'VIC@acme.test', 'viewer')
    // Eve got the forwarded mail: refused, with the same answer as a bogus token
    const eve = await h.signedIn('eve@acme.test')
    await rejectsWith(() => h.auth.teams.accept(eve.req, { token }), 'invalid_token')
    await rejectsWith(
      () => h.auth.teams.accept(eve.req, { token: 'A'.repeat(43) }),
      'invalid_token',
    )
    const vic = await h.signedIn('vic@acme.test')
    const before = vic.get('strutvane_session')
    expect(await h.auth.teams.accept(vic.req, { token })).toEqual({
      id: team.id,
      name: 'Acme',
      role: 'viewer',
    })
    expect(vic.get('strutvane_session')).not.toBe(before) // privilege change → rotation
    expect((await h.auth.teams.current(vic.req))?.id).toBe(team.id)
    await rejectsWith(() => h.auth.teams.accept(vic.req, { token }), 'invalid_token')
    const late = await invite(h, ada, team.id, 'eve@acme.test')
    h.clock.advance(7 * 24 * 60 * 60_000)
    const eveAgain = await h.signedIn('eve@acme.test')
    await rejectsWith(() => h.auth.teams.accept(eveAgain.req, { token: late }), 'invalid_token')
  })

  it('an unverified invitee must verify first', async () => {
    const h = harness({ store, config })
    await h.user('ada@acme.test')
    await h.user('new@acme.test', { verified: false })
    const ada = await h.signedIn('ada@acme.test')
    const team = await h.auth.teams.create(ada.req, { name: 'Acme' })
    const token = await invite(h, ada, team.id, 'new@acme.test')
    await rejectsWith(
      async () => h.auth.teams.accept((await h.signedIn('new@acme.test')).req, { token }),
      'email_not_verified',
    )
  })

  it('only admins manage; non-members get not_found; roles come from the preset', async () => {
    const h = harness({ store, config })
    for (const e of ['ada', 'vic', 'out']) await h.user(`${e}@acme.test`)
    const ada = await h.signedIn('ada@acme.test')
    const team = await h.auth.teams.create(ada.req, { name: 'Acme' })
    const vic = await h.signedIn('vic@acme.test')
    await h.auth.teams.accept(vic.req, {
      token: await invite(h, ada, team.id, 'vic@acme.test', 'manager'),
    })
    await rejectsWith(
      () => h.auth.teams.invite(vic.req, { teamId: team.id, email: 'x@acme.test', role: 'member' }),
      'forbidden',
    )
    const outsider = await h.signedIn('out@acme.test')
    await rejectsWith(
      () =>
        h.auth.teams.invite(outsider.req, {
          teamId: team.id,
          email: 'x@acme.test',
          role: 'member',
        }),
      'not_found',
    )
    await rejectsWith(() => h.auth.teams.members(outsider.req, { teamId: team.id }), 'not_found')
    await rejectsWith(() => h.auth.teams.switch(outsider.req, { teamId: team.id }), 'not_found')
    await rejectsWith(
      () => h.auth.teams.invite(ada.req, { teamId: team.id, email: 'x@acme.test', role: 'owner' }),
      'validation_failed',
    )
    await rejectsWith(
      () =>
        h.auth.teams.invite(ada.req, { teamId: team.id, email: 'vic@acme.test', role: 'member' }),
      'conflict',
    )
    expect(
      (await h.auth.teams.members(vic.req, { teamId: team.id })).map((m) => m.role).sort(),
    ).toEqual(['admin', 'manager'])
  })

  it('a team always keeps an admin; removal drops the current team immediately', async () => {
    const h = harness({ store, config })
    await h.user('ada@acme.test')
    await h.user('vic@acme.test')
    const ada = await h.signedIn('ada@acme.test')
    const adaUser = await h.store.findUserByEmail('ada@acme.test')
    const team = await h.auth.teams.create(ada.req, { name: 'Acme' })
    await rejectsWith(
      () => h.auth.teams.removeMember(ada.req, { teamId: team.id, userId: adaUser?.id }),
      'last_admin',
    )
    await rejectsWith(
      () =>
        h.auth.teams.changeRole(ada.req, { teamId: team.id, userId: adaUser?.id, role: 'member' }),
      'last_admin',
    )
    const vic = await h.signedIn('vic@acme.test')
    await h.auth.teams.accept(vic.req, { token: await invite(h, ada, team.id, 'vic@acme.test') })
    const vicId = (await h.store.findUserByEmail('vic@acme.test'))?.id
    expect((await h.auth.teams.current(vic.req))?.id).toBe(team.id)
    await h.auth.teams.removeMember(ada.req, { teamId: team.id, userId: vicId })
    expect(await h.auth.teams.current(vic.req)).toBeNull()
    expect(h.eventsOf('team.member.changed').at(-1)).toMatchObject({ memberId: vicId, role: null })
  })

  it('switching rotates the session and is audited; invitations can be listed and revoked', async () => {
    const h = harness({ store, config })
    await h.user('ada@acme.test')
    const ada = await h.signedIn('ada@acme.test')
    const personal = await h.auth.teams.current(ada.req)
    const acme = await h.auth.teams.create(ada.req, { name: 'Acme' })
    expect((await h.auth.teams.list(ada.req)).map((t) => t.name).sort()).toEqual([
      'Acme',
      "ada's team",
    ])
    const before = ada.get('strutvane_session')
    await h.auth.teams.switch(ada.req, { teamId: personal?.id })
    expect(ada.get('strutvane_session')).not.toBe(before)
    expect((await h.auth.teams.current(ada.req))?.id).toBe(personal?.id)
    expect(h.eventsOf('team.switched')).toHaveLength(1)
    const inv = await h.auth.teams.invite(ada.req, {
      teamId: acme.id,
      email: 'z@acme.test',
      role: 'member',
    })
    const token = await h.mailedToken('team-invitation')
    expect(await h.auth.teams.invitations(ada.req, { teamId: acme.id })).toEqual([
      expect.objectContaining({ id: inv.id, email: 'z@acme.test' }),
    ])
    await h.auth.teams.revokeInvitation(ada.req, { teamId: acme.id, invitationId: inv.id })
    await h.user('z@acme.test')
    await rejectsWith(
      async () => h.auth.teams.accept((await h.signedIn('z@acme.test')).req, { token }),
      'invalid_token',
    )
  })

  it('teams off: current() is null and every team route is not_found', async () => {
    const h = harness({ store })
    await h.user()
    const b = await h.signedIn('ada@acme.test')
    expect(await h.auth.teams.current(b.req)).toBeNull()
    await rejectsWith(() => h.auth.teams.create(b.req, { name: 'x' }), 'not_found')
    await rejectsWith(() => h.auth.teams.accept(new Browser().req, { token: 'x' }), 'not_found')
  })
})
