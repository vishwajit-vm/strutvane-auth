import { describe, expect, it } from 'vitest'
import { abilityGranted } from '../../src/engine/services/tokens.ts'
import { Browser, harness, rejectsWith, STORES } from './helpers/harness.ts'

const config = { features: { tokens: true }, tokens: { abilities: ['post.*', 'comment.view'] } }

describe('abilityGranted', () => {
  it('matches *, exact names and prefix wildcards only', () => {
    expect(abilityGranted(['*'], 'anything.at.all')).toBe(true)
    expect(abilityGranted(['post.*'], 'post.view')).toBe(true)
    expect(abilityGranted(['post.*'], 'post.comment.create')).toBe(true)
    expect(abilityGranted(['post.*'], 'postx.view')).toBe(false)
    expect(abilityGranted(['post.*'], 'post')).toBe(false)
    expect(abilityGranted(['post.view'], 'post.update')).toBe(false)
    expect(abilityGranted(['post.view'], 'post.*')).toBe(false)
    expect(abilityGranted([], 'post.view')).toBe(false)
  })
})

describe.each(STORES)('personal access tokens (%s store)', (store) => {
  it('is shown once, stored as a digest only, authenticates with abilities, expiry and last-used', async () => {
    const h = harness({ store, config })
    const user = await h.user()
    const b = await h.signedIn(user.email)
    const { plainText, token } = await h.auth.tokens.create(b.req, {
      name: 'CI',
      abilities: ['post.view'],
    })
    h.secrets.add(plainText)
    expect(plainText).toMatch(/^svp_[0-9A-Za-z]{46}$/)
    expect(token.expiresAt).toBe(h.clock.now() + 365 * 24 * 60 * 60_000)
    expect(JSON.stringify(await h.store.listTokens(user.id))).not.toContain(plainText)
    expect(JSON.stringify(await h.auth.tokens.list(b.req))).not.toContain(plainText)
    const authed = await h.auth.tokens.authenticate(`Bearer ${plainText}`)
    expect(authed?.user.id).toBe(user.id)
    expect(authed?.can('post.view')).toBe(true)
    expect(authed?.can('post.delete')).toBe(false)
    expect((await h.auth.tokens.list(b.req))[0]?.lastUsedAt).toBe(h.clock.now())
    h.clock.advance(30_000)
    await h.auth.tokens.authenticate(`Bearer ${plainText}`)
    expect((await h.auth.tokens.list(b.req))[0]?.lastUsedAt).toBe(h.clock.now() - 30_000) // at most once a minute
    h.clock.advance(365 * 24 * 60 * 60_000)
    expect(await h.auth.tokens.authenticate(`Bearer ${plainText}`)).toBeUndefined()
    expect(h.eventsOf('token.created')).toEqual([
      expect.objectContaining({ userId: user.id, tokenId: token.id }),
    ])
  })

  it("abilities must stay within the app's allowed patterns; expiry within the maximum", async () => {
    const h = harness({ store, config })
    const b = await h.signedIn((await h.user()).email)
    await rejectsWith(
      () => h.auth.tokens.create(b.req, { name: 'x', abilities: ['*'] }),
      'VALIDATION_FAILED',
    )
    await rejectsWith(
      () => h.auth.tokens.create(b.req, { name: 'x', abilities: ['comment.*'] }),
      'VALIDATION_FAILED',
    )
    await rejectsWith(
      () => h.auth.tokens.create(b.req, { name: 'x', abilities: ['user.delete'] }),
      'VALIDATION_FAILED',
    )
    await rejectsWith(
      () => h.auth.tokens.create(b.req, { name: 'x', abilities: 'post.view' }),
      'VALIDATION_FAILED',
    )
    await rejectsWith(
      () => h.auth.tokens.create(b.req, { name: 'x', expiresInDays: 400 }),
      'VALIDATION_FAILED',
    )
    await rejectsWith(() => h.auth.tokens.create(b.req, { name: '' }), 'VALIDATION_FAILED')
    const ok = await h.auth.tokens.create(b.req, {
      name: 'x',
      abilities: ['post.view', 'post.update', 'comment.view'],
      expiresInDays: 7,
    })
    expect(ok.token.abilities).toEqual(['post.view', 'post.update', 'comment.view'])
    const all = await h.auth.tokens.create(b.req, { name: 'default' })
    expect(all.token.abilities).toEqual(['post.*', 'comment.view'])
  })

  it("revoke stops a token at once; another user's token id is NOT_FOUND", async () => {
    const h = harness({ store, config })
    await h.user('ada@acme.test')
    await h.user('eve@acme.test')
    const ada = await h.signedIn('ada@acme.test')
    const eve = await h.signedIn('eve@acme.test')
    const { plainText, token } = await h.auth.tokens.create(ada.req, { name: 'CLI' })
    await rejectsWith(() => h.auth.tokens.revoke(eve.req, { id: token.id }), 'NOT_FOUND')
    expect(await h.auth.tokens.authenticate(`Bearer ${plainText}`)).toBeDefined()
    await h.auth.tokens.revoke(ada.req, { id: token.id })
    expect(await h.auth.tokens.authenticate(`Bearer ${plainText}`)).toBeUndefined()
    expect(h.eventsOf('token.revoked')).toHaveLength(1)
  })

  it('refuses forged, mutated and checksum-broken tokens without a lookup error', async () => {
    const h = harness({ store, config })
    const b = await h.signedIn((await h.user()).email)
    const { plainText } = await h.auth.tokens.create(b.req, { name: 'x' })
    const flip = (s: string, i: number) =>
      s.slice(0, i) + (s[i] === 'a' ? 'b' : 'a') + s.slice(i + 1)
    for (const header of [
      undefined,
      '',
      plainText,
      `Basic ${plainText}`,
      `Bearer ${flip(plainText, 10)}`,
      `Bearer ${flip(plainText, plainText.length - 1)}`,
      `Bearer ${plainText}x`,
      `Bearer ${plainText.replace('svp_', 'sv_x')}`,
      `Bearer ' OR 1=1 --`,
      42,
      { toString: () => `Bearer ${plainText}` },
    ])
      expect(await h.auth.tokens.authenticate(header)).toBeUndefined()
    expect(await h.auth.tokens.authenticate(`bearer   ${plainText}`)).toBeDefined()
  })

  it('narrowing the allowed abilities in config also narrows tokens issued before (no grandfathering)', async () => {
    const before = harness({ store, config })
    const user = await before.user()
    const b = await before.signedIn(user.email)
    const { plainText } = await before.auth.tokens.create(b.req, {
      name: 'ci',
      abilities: ['post.*', 'comment.view'],
    })
    // The app drops `post.*` (say, after a leak scare) and redeploys: same data, same APP_KEY.
    const after = harness({ store, config: { ...config, tokens: { abilities: ['comment.view'] } } })
    await after.store.createUser(user)
    for (const t of await before.store.listTokens(user.id)) await after.store.addToken(t)
    const auth = await after.auth.tokens.authenticate(`Bearer ${plainText}`)
    expect(auth?.can('comment.view')).toBe(true)
    expect(auth?.can('post.delete')).toBe(false)
    expect(auth?.can('post.view')).toBe(false)
  })

  it('a disabled tokens feature authenticates nothing (no leak through the guard)', async () => {
    const on = harness({ store, config })
    const b = await on.signedIn((await on.user()).email)
    const { plainText } = await on.auth.tokens.create(b.req, { name: 'x' })
    const off = harness({ store })
    await off.store.addToken(
      (await on.store.listTokens((await on.store.findUserByEmail('ada@acme.test'))?.id ?? ''))[0] ??
        (() => {
          throw new Error('no token')
        })(),
    )
    expect(await off.auth.tokens.authenticate(`Bearer ${plainText}`)).toBeUndefined()
    await rejectsWith(() => off.auth.tokens.create(new Browser().req, { name: 'x' }), 'NOT_FOUND')
  })
})
