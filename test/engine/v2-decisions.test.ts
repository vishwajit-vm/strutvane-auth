/**
 * The v2 decisions applied on top of spike 20 (hub spikes/CONSISTENCY-2026-11-15.md):
 * - #25/#107: the feature names, `passwordReset` always following `password`, and the
 *   `passwordConfirmation` switch;
 * - #67: signed-link failures are 403 `invalid_signature` / `signature_expired`;
 * - #68/#69: lowercase snake_case codes and `{ path, field, code, message }` issues, on the
 *   service error and in the problem+json body.
 */
import { describe, expect, it } from 'vitest'
import { defineAuthConfig } from '../../src/engine/config.ts'
import { AUTH_ERROR_STATUS, AuthError, toIssue } from '../../src/engine/errors.ts'
import { createAuthHandler } from '../../src/engine/http/routes.ts'
import { Browser, type Harness, harness, PASSWORD, rejectsWith, STORES } from './helpers/harness.ts'

const APP = 'http://localhost:3000'

/** Stay active (2 h idle limit) while moving past the 3 h confirmation window. */
async function pastConfirmationWindow(h: Harness, b: Browser): Promise<void> {
  for (let i = 0; i < 4; i++) {
    h.clock.advance(60 * 60_000)
    await h.auth.state(b.req)
  }
}

describe('#68: error codes are lowercase snake_case', () => {
  it('every code', () => {
    for (const code of Object.keys(AUTH_ERROR_STATUS)) expect(code).toMatch(/^[a-z]+(?:_[a-z]+)*$/)
  })
})

describe('#69: field issues are { path, field, code, message }', () => {
  it('builds the path from the dotted field, numbers for indexes, with a catalog message', () => {
    expect(toIssue({ field: 'abilities.0', code: 'not_allowed' })).toEqual({
      path: ['abilities', 0],
      field: 'abilities.0',
      code: 'not_allowed',
      message: 'This value is not allowed.',
    })
    expect(toIssue({ field: '', code: 'something_new' })).toEqual({
      path: [],
      field: '',
      code: 'something_new',
      message: 'This value is invalid.',
    })
  })

  it('a service error carries full issues, and the HTTP problem shows them', async () => {
    const h = harness({ config: { features: { registration: true } } })
    const error = await rejectsWith(
      () =>
        h.auth.passwords.register(new Browser().req, {
          name: 'A',
          email: 'a@b.io',
          password: 'short',
        }),
      'weak_password',
    )
    expect((error as unknown as AuthError).issues).toEqual([
      {
        path: ['password'],
        field: 'password',
        code: 'too_short',
        message: 'This value is too short.',
      },
    ])
    const handle = createAuthHandler(h.auth)
    const res = await handle(
      new Request(`${APP}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'sec-fetch-site': 'same-origin' },
        body: JSON.stringify({ name: 'A', email: 'not-an-email', password: PASSWORD }),
      }),
      { ip: '192.0.2.1' },
    )
    expect(res.status).toBe(422)
    const body = (await res.json()) as { code: string; issues: unknown[] }
    expect(body.code).toBe('validation_failed')
    expect(body.issues).toEqual([
      { path: ['email'], field: 'email', code: 'invalid', message: 'This value is invalid.' },
    ])
  })
})

describe('#67: signed links answer 403', () => {
  it('invalid_signature and signature_expired are 403 problems over HTTP', async () => {
    const h = harness({ config: { features: { emailVerification: true } } })
    const handle = createAuthHandler(h.auth)
    const res = await handle(new Request(`${APP}/email/verify/x/y?expires=1&signature=z`), {
      ip: '192.0.2.1',
    })
    expect(res.status).toBe(403)
    expect(((await res.json()) as { code: string }).code).toBe('invalid_signature')
    expect(new AuthError('signature_expired').status).toBe(403)
  })
})

describe('#25/#107: feature switches', () => {
  it('uses the agreed names, with password and passwordConfirmation on by default', () => {
    expect(defineAuthConfig({ appUrl: APP }).features).toEqual({
      password: true,
      registration: false,
      emailVerification: false,
      passwordReset: true,
      passwordConfirmation: true,
      twoFactor: false,
      passkeys: false,
      emailLink: false,
      apiTokens: false,
      teams: false,
      impersonation: false,
    })
  })

  it('passwordReset follows password ("email link only" has no reset) and cannot be turned off alone', () => {
    const linkOnly = defineAuthConfig({
      appUrl: APP,
      features: { password: false, emailLink: true },
    })
    expect(linkOnly.features.passwordReset).toBe(false)
    expect(() =>
      defineAuthConfig({ appUrl: APP, features: { passwordReset: false } as never }),
    ).toThrow(/passwordReset is always on/)
  })

  it('impersonation needs passwordConfirmation (admins confirm before impersonating)', () => {
    expect(() =>
      defineAuthConfig({
        appUrl: APP,
        features: { impersonation: true, passwordConfirmation: false },
      }),
    ).toThrow(/impersonation needs passwordConfirmation/)
  })

  it('with passwordConfirmation on, sensitive actions need a fresh confirmation; off, they do not and confirm is gone', async () => {
    const on = harness({ config: { features: { twoFactor: true } } })
    await on.user()
    const a = await on.signedIn('ada@acme.test')
    await pastConfirmationWindow(on, a)
    await rejectsWith(() => on.auth.twoFactor.enable(a.req), 'password_confirmation_required')

    const off = harness({ config: { features: { twoFactor: true, passwordConfirmation: false } } })
    await off.user()
    const b = await off.signedIn('ada@acme.test')
    await pastConfirmationWindow(off, b)
    await expect(off.auth.twoFactor.enable(b.req)).resolves.toBeDefined()
    await rejectsWith(() => off.auth.passwords.confirm(b.req, { password: PASSWORD }), 'not_found')
  })
})

describe('teams as tenants: slugs and the personal-team switch', () => {
  it.each(STORES)(
    '%s: slugs are validated and unique; personal teams can be off',
    async (store) => {
      const h = harness({
        store,
        config: { features: { teams: true }, teams: { personal: false } },
      })
      const ada = await h.user('ada@acme.test')
      expect(ada.currentTeamId).toBeNull()
      const a = await h.signedIn('ada@acme.test')
      expect(await h.auth.teams.list(a.req)).toEqual([])
      const team = await h.auth.teams.create(a.req, { name: 'Acme', slug: 'acme' })
      expect(team).toMatchObject({ name: 'Acme', slug: 'acme', role: 'owner' })
      const again = await rejectsWith(
        () => h.auth.teams.create(a.req, { name: 'Other', slug: 'acme' }),
        'validation_failed',
      )
      expect((again as unknown as AuthError).issues[0]).toMatchObject({
        field: 'slug',
        code: 'taken',
      })
      for (const slug of ['Acme', '-x', 'a b', 7, 'x'.repeat(64)])
        await rejectsWith(
          () => h.auth.teams.create(a.req, { name: 'Bad', slug }),
          'validation_failed',
        )
      expect((await h.auth.teams.create(a.req, { name: 'No slug' })).slug).toBeNull()
      expect((await h.store.findTeamBySlug('acme'))?.id).toBe(team.id)
      const withPersonal = harness({ store, config: { features: { teams: true } } })
      expect((await withPersonal.user('bob@acme.test')).currentTeamId).not.toBeNull()
    },
  )
})
