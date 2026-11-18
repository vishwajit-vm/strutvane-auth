// Field-level read/write rules enforced on the framework's resource hooks (attack-style):
// a viewer must never receive a read-restricted field in any record payload, and nobody without
// the role may write a write-restricted field (e.g. hand a record to another owner).
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import type { Actor } from '@strutvane/framework/contracts'
import { createApp, HooksToken } from '@strutvane/framework/core'
import { afterEach, describe, expect, test } from 'vitest'
import { forbiddenWrites, unreadableFields } from '../src/field-rules.ts'
import { createAuthProvider } from '../src/provider.ts'

const AUTH_SRC = pathToFileURL(resolve(import.meta.dirname, '../src/index.ts')).href
const DEAL_POLICY = `import { definePolicy, defineSchema } from '${AUTH_SRC}'
const schema = defineSchema({ table: 'deals', columns: {
  id: { column: 'id', type: 'uuid' }, title: { column: 'title', type: 'text' },
  amount: { column: 'amount', type: 'float8' }, ownerId: { column: 'owner_id', type: 'uuid' },
} })
export default definePolicy('deal', { schema }, ({ allow, field }) => {
  allow(['viewAny', 'view', 'create', 'update'], { role: ['viewer', 'member', 'admin'] })
  field('amount').readable({ role: ['member', 'admin'] })
  field('ownerId').writable({ role: 'admin' })
})
`

const dirs: string[] = []
afterEach(async () => {
  for (const d of dirs.splice(0)) await rm(d, { recursive: true, force: true })
})

async function boot() {
  const root = await mkdtemp(join(tmpdir(), 'sv-auth-fields-'))
  dirs.push(root)
  await mkdir(join(root, 'app/policies'), { recursive: true })
  await writeFile(join(root, 'app/policies/deal.policy.ts'), DEAL_POLICY)
  const app = createApp({
    config: { app: { root, url: 'http://localhost:3000' }, auth: {} },
    providers: [createAuthProvider()],
  })
  await app.boot()
  return app.make(HooksToken)
}

const actor = (roles: string[]): Actor => ({ id: 'u1', type: 'user', roles, attrs: {} })
const record = { id: 'd1', title: 'Big deal', amount: 50_000, ownerId: 'u1', createdAt: 'x' }

describe('resource.serialize: field read rules', () => {
  test('strips read-restricted fields for actors without the role, in every record', async () => {
    const hooks = await boot()
    const out = async (roles: string[] | null, extra: Record<string, unknown> = {}) =>
      (
        (await hooks.run('resource.serialize', {
          resource: 'Deal',
          type: 'deal',
          actor: roles === null ? null : actor(roles),
          record,
          ...extra,
        })) as { record: Record<string, unknown> }
      ).record
    expect(await out(['viewer'])).toEqual({
      id: 'd1',
      title: 'Big deal',
      ownerId: 'u1',
      createdAt: 'x',
    })
    expect(await out([])).not.toHaveProperty('amount')
    expect(await out(null)).not.toHaveProperty('amount')
    expect(await out(['member'])).toHaveProperty('amount', 50_000)
    // A framework that sends no `type`: the model name still finds the policy (fail closed).
    expect(await out(['viewer'], { type: undefined })).not.toHaveProperty('amount')
    // Resources without a policy, and payloads without a record, pass through untouched.
    expect(await out(['viewer'], { type: 'invoice', resource: 'Invoice' })).toEqual(record)
    const noRecord = await hooks.run('resource.serialize', { type: 'deal', actor: actor([]) })
    expect(noRecord).toEqual({ type: 'deal', actor: actor([]) })
  })
})

describe('resource.beforeWrite: field write rules', () => {
  test('refuses write-restricted fields (403), allows everything else', async () => {
    const hooks = await boot()
    const write = (roles: string[], input: Record<string, unknown>) =>
      hooks.run('resource.beforeWrite', {
        resource: 'Deal',
        type: 'deal',
        action: 'update',
        actor: actor(roles),
        input,
      })
    await expect(write(['member'], { title: 'ok' })).resolves.toBeDefined()
    // Handing a record to another owner is privilege escalation for a non-admin.
    await expect(write(['member'], { title: 'x', ownerId: 'u2' })).rejects.toMatchObject({
      cause: { code: 'forbidden', status: 403 },
    })
    await expect(write(['viewer'], { ownerId: 'u1' })).rejects.toMatchObject({
      cause: { status: 403 },
    })
    await expect(write(['admin'], { ownerId: 'u2' })).resolves.toBeDefined()
    // Keys that are not schema fields are the framework's job (unknown_field), not a 403 here.
    await expect(write(['member'], { included: 1 })).resolves.toBeDefined()
    // A payload without input is ignored.
    await expect(
      hooks.run('resource.beforeWrite', { type: 'deal', actor: actor([]) }),
    ).resolves.toBeDefined()
  })
})

describe('manifest.build: what a UI may offer', () => {
  test('unreadable fields are left out, unwritable ones become read-only, per actor', async () => {
    const hooks = await boot()
    const field = (name: string, readOnly = false) => ({
      name,
      type: 'string',
      label: name,
      required: false,
      nullable: true,
      unique: false,
      readOnly,
      writeOnce: false,
      filterOperators: [],
      sortable: false,
      searchable: false,
    })
    const manifest = {
      manifestVersion: 1,
      app: { name: 'x', apiVersion: 'v1' },
      generatedAt: 'now',
      resources: [
        {
          name: 'Deal',
          path: 'deals',
          label: 'Deal',
          pluralLabel: 'Deals',
          fields: [field('id', true), field('title'), field('amount'), field('ownerId')],
          actions: [],
          capabilities: {},
        },
        { name: 'Other', path: 'others', label: 'O', pluralLabel: 'Os', fields: [field('amount')] },
      ],
    }
    const view = async (roles: string[] | null) =>
      (
        (await hooks.run('manifest.build', {
          actor: roles === null ? null : actor(roles),
          manifest,
        })) as { manifest: typeof manifest }
      ).manifest.resources
    const viewer = await view(['viewer'])
    expect(viewer[0]?.fields.map((f) => `${f.name}${f.readOnly ? '(ro)' : ''}`)).toEqual([
      'id(ro)',
      'title',
      'ownerId(ro)',
    ])
    // Resources without a policy pass through untouched.
    expect(viewer[1]?.fields.map((f) => f.name)).toEqual(['amount'])
    const admin = await view(['admin'])
    expect(admin[0]?.fields.map((f) => `${f.name}${f.readOnly ? '(ro)' : ''}`)).toEqual([
      'id(ro)',
      'title',
      'amount',
      'ownerId',
    ])
    expect((await view(null))[0]?.fields.map((f) => f.name)).not.toContain('amount')
    expect(await hooks.run('manifest.build', { actor: null })).toEqual({ actor: null })
  })
})

describe('helpers', () => {
  test('unreadableFields / forbiddenWrites only report fields that carry a rule', async () => {
    const { createPermissionProvider } = await import('../src/policy/provider.ts')
    const { definePolicy, defineSchema } = await import('../src/index.ts')
    const schema = defineSchema({
      table: 't',
      columns: { id: { column: 'id', type: 'uuid' }, a: { column: 'a', type: 'text' } },
    })
    const plain = definePolicy('t', { schema }, ({ allow }) => {
      allow('view', { role: 'x' })
    })
    expect(unreadableFields(plain, actor([]))).toEqual([])
    expect(forbiddenWrites(plain, actor([]), { a: 1 })).toEqual([])
    expect(createPermissionProvider([plain]).policy('t')).toBe(plain)
  })
})
