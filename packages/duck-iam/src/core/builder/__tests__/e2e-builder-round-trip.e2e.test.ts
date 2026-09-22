// E2E: a builder-authored catalog, saved to Postgres via drizzle, must survive `jsonb` and be enforced
// identically in production and development mode.
import { and, eq, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { iamNormalizePolicy } from '../../../shared/rows'
import { applyPgSchema, assertE2eReachable, databaseUrl, isolatedDatabaseUrl } from '../../../test/e2e-env'
import { IamEngine } from '../../engine'
import type { AccessControl, IamPrimitives, IamRequest } from '../../types'
import { definePolicy } from '../policy'
import { defineRole } from '../role'
import { defineRule } from '../rule'
import { when } from '../when'

const BASE_URL = databaseUrl()
const URL = await isolatedDatabaseUrl('builder_round_trip')
if (BASE_URL !== undefined && URL === undefined) {
  throw new Error(
    '[e2e-builder] DUCKIAM_E2E_DATABASE_URL is set but an isolated database could not be created. ' +
      'Refusing to skip: a skipped suite is not a passing suite.',
  )
}
assertE2eReachable('builder-round-trip', URL)
const suite = URL ? describe : describe.skip

type Action = 'read' | 'update' | 'delete'
type Resource = 'doc'
type Role = 'viewer' | 'editor' | 'admin' | 'auditor'
type Scope = 'org-a' | 'org-a.team-1' | 'org-b'

const TABLES = { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles }
const OPS = { and, eq, or }

/** A reusable condition group, handed to a rule by returning it from the callback. */
const sharedOwnerOrAdmin = when<Action, Resource, Role, Scope>().or((o) =>
  o.isOwner('resource.attributes.ownerId').role('admin'),
)

function catalog(): {
  roles: AccessControl.IRole<Action, Resource, Role, Scope>[]
  policies: AccessControl.IPolicy<Action, Resource, Role>[]
} {
  const viewer = defineRole<Role, Action, Resource, Scope>('viewer').name('Viewer').grant('read', 'doc').build()

  const editor = defineRole<Role, Action, Resource, Scope>('editor')
    .name('Editor')
    .inherits('viewer')
    // The grant carries the condition, so the generated RBAC policy enforces it.
    .grantWhen('update', 'doc', (w) => w.attr('department', 'eq', 'engineering'))
    .build()

  const admin = defineRole<Role, Action, Resource, Scope>('admin')
    .name('Admin')
    .inherits('editor')
    .grant('delete', 'doc')
    .build()

  const auditor = defineRole<Role, Action, Resource, Scope>('auditor').name('Auditor').grant('read', 'doc').build()

  // NOTE: each guard needs its priority-1 allow: under `policyCombine: 'and'` a deny-only policy defaults to deny
  // and vetoes the requests it meant to let through.
  const drafts = definePolicy<Action, Resource, Role, Scope>('drafts')
    .name('Draft visibility')
    .algorithm('deny-overrides')
    .rule('deny-foreign-drafts', (r) =>
      r
        .deny()
        .on('read')
        .of('doc')
        .priority(100)
        .when((w) => w.resourceAttr('status', 'eq', 'draft').not((n) => n.isOwner('resource.attributes.ownerId'))),
    )
    .rule('otherwise-defer', (r) => r.allow().on('read').of('doc').priority(1))
    .build()

  const window = definePolicy<Action, Resource, Role, Scope>('hours')
    .name('Change window')
    .algorithm('deny-overrides')
    .rule('deny-out-of-hours', (r) =>
      r
        .deny()
        .on('update', 'delete')
        .of('doc')
        .priority(100)
        // Outside the window is before nine OR from six, hence `whenAny`.
        .whenAny((w) => w.env('hour', 'lt', 9).env('hour', 'gte', 18)),
    )
    // Update only: a catch-all delete allow would mask the owner-or-admin rule under `allow-overrides`.
    .rule('otherwise-defer', (r) => r.allow().on('update').of('doc').priority(1))
    // The reusable group, handed over by returning it from the callback.
    .rule('allow-owner-or-admin-delete', (r) =>
      r
        .allow()
        .on('delete')
        .of('doc')
        .when(() => sharedOwnerOrAdmin),
    )
    .build()

  return { policies: [drafts, window], roles: [viewer, editor, admin, auditor] }
}

const HOURS = { hour: 12 }
const OUT_OF_HOURS = { hour: 3 }

suite('a builder-authored catalog, stored in Postgres and enforced from there', () => {
  let pool: Pool
  let adapter: IamDrizzleAdapter<Action, Resource, Role, Scope>
  const built = catalog()

  beforeAll(async () => {
    pool = new Pool({ connectionString: URL, max: 6 })
    await applyPgSchema(pool)
    adapter = new IamDrizzleAdapter<Action, Resource, Role, Scope>({ db: drizzle(pool), ops: OPS, tables: TABLES })
    for (const role of built.roles) await adapter.saveRole(role)
    for (const policy of built.policies) await adapter.savePolicy(policy)

    await adapter.assignRole('alice', 'editor')
    await adapter.setSubjectAttributes('alice', { department: 'engineering' })
    await adapter.assignRole('bob', 'editor')
    await adapter.setSubjectAttributes('bob', { department: 'sales' })
    await adapter.assignRole('root', 'admin')
    await adapter.setSubjectAttributes('root', { department: 'engineering' })
    await adapter.assignRole('carol', 'auditor')
  })

  afterAll(async () => {
    await pool.end()
  })

  function engine<M extends 'development' | 'production'>(mode: M): IamEngine<Action, Resource, Role, Scope, M> {
    // A fresh engine per question: engines cache, so a shared one would answer one mode from the other's cache.
    return new IamEngine<Action, Resource, Role, Scope, M>({ adapter, defaultEffect: 'deny', mode })
  }

  /** Both modes must answer the same thing, and that thing is the answer. */
  async function bothModes(
    subject: string,
    action: Action,
    resource: IamRequest.IResource<Resource>,
    environment: IamPrimitives.Attributes = HOURS,
  ): Promise<boolean> {
    const production = await engine('production').can(subject, action, resource, environment)
    const development = await engine('development').can(subject, action, resource, environment)
    expect(development, `production said ${production}, development said ${development}`).toBe(production)
    return production
  }

  const doc = (attributes: IamPrimitives.Attributes = {}): IamRequest.IResource<Resource> => ({
    attributes,
    type: 'doc',
  })

  describe('what the roles say, after a round trip through jsonb', () => {
    it('the inherited read reaches the editor', async () => {
      expect(await bothModes('alice', 'read', doc({ ownerId: 'alice', status: 'published' }))).toBe(true)
    })

    it('the conditional grant on the inherited role holds for engineering', async () => {
      expect(await bothModes('alice', 'update', doc({ ownerId: 'alice' }))).toBe(true)
    })

    it('and denies the same editor in another department', async () => {
      // Same role, action and document; only the grant's stored condition differs.
      expect(await bothModes('bob', 'update', doc({ ownerId: 'bob' }))).toBe(false)
    })

    it('two levels of inheritance reach the admin', async () => {
      expect(await bothModes('root', 'update', doc({ ownerId: 'someone' }))).toBe(true)
    })

    it('a role that inherits nothing gets nothing extra', async () => {
      expect(await bothModes('carol', 'update', doc({ ownerId: 'carol' }))).toBe(false)
      expect(await bothModes('carol', 'read', doc({ ownerId: 'carol', status: 'published' }))).toBe(true)
    })
  })

  describe('what the policies say', () => {
    it('a draft belonging to someone else is denied even to a reader', async () => {
      expect(await bothModes('carol', 'read', doc({ ownerId: 'alice', status: 'draft' }))).toBe(false)
    })

    it('the owner still reads their own draft', async () => {
      expect(await bothModes('alice', 'read', doc({ ownerId: 'alice', status: 'draft' }))).toBe(true)
    })

    it('the change window closes for everyone, admin included', async () => {
      expect(await bothModes('root', 'update', doc({ ownerId: 'root' }), OUT_OF_HOURS)).toBe(false)
      expect(await bothModes('alice', 'update', doc({ ownerId: 'alice' }), OUT_OF_HOURS)).toBe(false)
    })

    it('the reusable condition group is enforced, not dropped', async () => {
      // `allow-overrides` lets this policy grant on its own; under `'and'` the RBAC policy denies an editor's
      // delete, which would hide the group entirely.
      const ask = async (mode: 'development' | 'production', ownerId: string): Promise<boolean> =>
        await new IamEngine<Action, Resource, Role, Scope, typeof mode>({
          adapter,
          defaultEffect: 'deny',
          mode,
          policyCombine: 'allow-overrides',
        }).can('alice', 'delete', doc({ ownerId }), HOURS)

      // Alice owns only the first document and is not an admin; a dropped group (`{ all: [] }`) would allow both.
      expect(await ask('production', 'alice')).toBe(true)
      expect(await ask('development', 'alice')).toBe(true)
      expect(await ask('production', 'someone-else')).toBe(false)
      expect(await ask('development', 'someone-else')).toBe(false)
    })
  })

  describe('the row is what the builder built', () => {
    it('every policy comes back out of jsonb carrying what was authored', async () => {
      for (const policy of built.policies) {
        const stored = await adapter.getPolicy(policy.id)
        expect(stored, `policy ${policy.id} is not in the store`).not.toBeNull()
        // `toMatchObject`: the store may add fields, but every authored rule must survive in order, nested as built.
        expect(JSON.parse(JSON.stringify(stored))).toMatchObject(JSON.parse(JSON.stringify(policy)))
      }
    })

    it('has exactly the keys the author wrote, on the way out as on the way in', async () => {
      const stored = await adapter.getPolicy('drafts')
      const authored = built.policies.find((p) => p.id === 'drafts')
      if (stored === null || authored === undefined) throw new Error('the drafts policy is missing')
      // The store promises `iamNormalizePolicy` of what was written (e.g. `version: 1` added), key for key.
      const expected = iamNormalizePolicy(authored)
      expect(Object.keys(stored).sort()).toEqual(Object.keys(expected).sort())
      // No version was authored: the builder must not add the key, the store must.
      expect('version' in authored).toBe(false)
      expect(stored.version).toBe(1)
      // INFO: `jsonb` reorders object keys (by length, then bytewise), so key presence is asserted, not order.
      expect(stored.rules.map((rule) => Object.keys(rule).sort())).toEqual(
        expected.rules.map((rule) => Object.keys(rule).sort()),
      )
      expect(stored.rules).toEqual(expected.rules)
      expect(stored).toEqual(expected)
    })

    it('every role does too, conditions and inheritance included', async () => {
      for (const role of built.roles) {
        const stored = await adapter.getRole(role.id)
        expect(JSON.parse(JSON.stringify(stored))).toMatchObject(JSON.parse(JSON.stringify(role)))
      }
    })

    it('the shared condition group did not leak between the two policies that used it', async () => {
      // Chaining onto the shared `when()` instance after save must not change the stored policy.
      const before = JSON.parse(JSON.stringify(await adapter.getPolicy('hours')))
      sharedOwnerOrAdmin.role('auditor')
      const after = JSON.parse(JSON.stringify(await adapter.getPolicy('hours')))
      expect(after).toEqual(before)
    })

    it('a policy the builder refuses never reaches the database', async () => {
      expect(() =>
        defineRule<Action, Resource, Scope, Role>('never')
          .deny()
          .on('update')
          .of('doc')
          .when((w) => w.roles())
          .build(),
      ).toThrow(/roles/)
      expect(await adapter.getPolicy('never')).toBeNull()
    })
  })
})
