/**
 * E2E: a catalog authored with the builder, stored in real Postgres, enforced
 * by both engines.
 *
 * Every other builder test in this package stops at the object the builder
 * returns. That object is not what a deployment enforces: it is serialised into
 * `jsonb`, read back by a driver, revalidated, compiled, and evaluated. Each of
 * those steps can drop a key or reorder an array, and the builder is the only
 * place an author's intent exists in full.
 *
 * So the catalog below is authored once, written through the drizzle adapter,
 * and then asked real questions - the same questions in `production` and in
 * `development`, which additionally cross-checks the interpreter against the
 * compiled table and fails closed when they disagree.
 */
import { and, eq, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { iamNormalizePolicy } from '../../../shared/rows'
import { applyPgSchema, databaseUrl, isolatedDatabaseUrl } from '../../../test/e2e-env'
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
const suite = URL ? describe : describe.skip

type Action = 'read' | 'update' | 'delete'
type Resource = 'doc'
type Role = 'viewer' | 'editor' | 'admin' | 'auditor'
type Scope = 'org-a' | 'org-a.team-1' | 'org-b'

const TABLES = { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles }
const OPS = { and, eq, or }

/**
 * A document catalog of the shape a real deployment has: inheritance three
 * deep, a conditional grant on the inherited role, a deny that overrides it,
 * an environment window, and one condition group written once and reused by two
 * rules - the pattern `when()`'s own documentation recommends.
 */
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
    // Editing is departmental: the grant itself carries the condition, so it is
    // enforced by the RBAC policy the engine generates rather than by a rule
    // someone has to remember to write.
    .grantWhen('update', 'doc', (w) => w.attr('department', 'eq', 'engineering'))
    .build()

  const admin = defineRole<Role, Action, Resource, Scope>('admin')
    .name('Admin')
    .inherits('editor')
    .grant('delete', 'doc')
    .build()

  const auditor = defineRole<Role, Action, Resource, Scope>('auditor').name('Auditor').grant('read', 'doc').build()

  // Each guard policy carries its own allow arm. Under the default
  // `policyCombine: 'and'` every *applicable* policy has to allow, and a policy
  // with only deny rules is applicable to the action it names and then defaults
  // to deny - so a deny-only policy vetoes the very requests it meant to let
  // through. The catch-all allow at priority 1 is what makes "deny-overrides"
  // mean what it reads like.
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
        // Outside the window is a disjunction - before nine OR from six -
        // not "neither of the two bounds holds", which is true only in the
        // hours that satisfy exactly one of them.
        .whenAny((w) => w.env('hour', 'lt', 9).env('hour', 'gte', 18)),
    )
    // Update only. Extending the catch-all to `delete` would allow every
    // deletion under `allow-overrides`, and the owner-or-admin rule below -
    // the one these tests are about - would never be reached.
    .rule('otherwise-defer', (r) => r.allow().on('update').of('doc').priority(1))
    // The reusable group, handed to a rule by returning it - the shape that
    // used to leave `{ all: [] }` behind and grant unconditionally.
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
    // A fresh engine per question: these all cache, and a shared instance would
    // answer the second mode from the first mode's caches.
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
      // Same role, same action, same document - the condition stored on the
      // grant is the only difference.
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
      // `policyCombine: 'allow-overrides'` is the mode in which an authored
      // policy can grant on its own; under the default `'and'` the RBAC policy
      // is applicable to delete/doc and votes deny for an editor, so no ABAC
      // rule could show through and this case would prove nothing about the
      // group.
      const ask = async (mode: 'development' | 'production', ownerId: string): Promise<boolean> =>
        await new IamEngine<Action, Resource, Role, Scope, typeof mode>({
          adapter,
          defaultEffect: 'deny',
          mode,
          policyCombine: 'allow-overrides',
        }).can('alice', 'delete', doc({ ownerId }), HOURS)

      // The group is `isOwner OR role admin`. Alice is neither an admin nor the
      // owner of the second document, so if the group had been dropped - the
      // `{ all: [] }` shape - both of these would allow.
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
        // `toMatchObject` rather than `toEqual`: the store normalises a policy
        // on the way in and may add fields the author did not write. What must
        // survive byte for byte is everything the author *did* write - every
        // rule, in order, with its conditions nested exactly as built.
        expect(JSON.parse(JSON.stringify(stored))).toMatchObject(JSON.parse(JSON.stringify(policy)))
      }
    })

    it('has exactly the keys the author wrote, on the way out as on the way in', async () => {
      const stored = await adapter.getPolicy('drafts')
      const authored = built.policies.find((p) => p.id === 'drafts')
      if (stored === null || authored === undefined) throw new Error('the drafts policy is missing')
      // The builder used to emit `description: undefined`, `targets: undefined`
      // and `version: undefined`; the memory adapter kept those keys and every
      // JSON-backed store dropped them, so the same authored policy read back
      // unequal depending on where it had been. The contract the store does
      // promise is `iamNormalizePolicy` of what was written - unversioned goes
      // in, `version: 1` comes out, on every adapter - so that is what the
      // read is compared against, key for key.
      const expected = iamNormalizePolicy(authored)
      expect(Object.keys(stored).sort()).toEqual(Object.keys(expected).sort())
      // The author never set a version, so the builder must not invent the
      // key; the store must.
      expect('version' in authored).toBe(false)
      expect(stored.version).toBe(1)
      // Key *order* is deliberately not asserted: postgres `jsonb` is a parsed
      // value type and re-serialises object keys by length then bytewise, so
      // `{effect, priority, actions}` comes back as `{effect, actions,
      // priority}`. Key *presence* is the contract that matters - an omitted
      // `description` must stay omitted and a written one must survive - so it
      // is asserted per rule and per condition leaf instead.
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
      // Both rules were built from one `when()` instance. If they shared its
      // array, chaining onto it now - or the engine freezing one policy - would
      // reach the other.
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
