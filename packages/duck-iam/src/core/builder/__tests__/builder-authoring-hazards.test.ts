import { describe, expect, it } from 'vitest'
import { evaluate } from '../../evaluate/evaluate'
import { rolesToPolicy } from '../../rbac'
import type { AccessControl, IamPrimitives, IamRequest } from '../../types'
import { definePolicy } from '../policy'
import { defineRole } from '../role'
import { defineRule } from '../rule'
import { when } from '../when'

/**
 * The builder is the authoring surface: whatever it emits is what the engine
 * enforces, and an author who mis-writes a chain has no second reader to catch
 * it. So the failure mode that matters here is not "the build throws" - it is
 * "the build succeeds and the rule means something else", and in particular the
 * shapes that quietly turn into *no condition at all*.
 *
 * Every case below asserts a verdict rather than a JSON shape. A condition
 * group that vanished is only interesting because of what the engine then
 * answers.
 */

const REQUEST = (attributes: IamPrimitives.Attributes, roles: string[] = []): IamRequest.IAccessRequest => ({
  action: 'update',
  resource: { attributes: { ownerId: 'someone-else' }, type: 'post' },
  subject: { attributes, id: 'u1', roles },
})

function verdict(rules: AccessControl.IRule[], request: IamRequest.IAccessRequest): boolean {
  return evaluate([{ algorithm: 'deny-overrides', id: 'p', name: 'p', rules }], request, 'deny', 'and').allowed
}

/**
 * `when()`'s own documentation ends with "build a reusable condition and spread
 * it across multiple rules", and the callback signature is
 * `(w: When) => When` - it *returns* a builder. Returning one other than the
 * one handed in dropped it on the floor and left `{ all: [] }` behind: an allow
 * rule with no conditions is an unconditional grant, which is the strongest
 * fail-open this package can produce from a chain that looks correct.
 */
describe('a condition callback that returns a different builder', () => {
  const ownerOrAdmin = () => when().or((o) => o.isOwner().role('admin'))

  it('keeps the returned group on a rule instead of granting unconditionally', () => {
    const rule = defineRule('post.update')
      .allow()
      .on('update')
      .of('post')
      .when(() => ownerOrAdmin())
      .build()

    expect(verdict([rule], REQUEST({}, ['reader'])), 'a stranger must not be allowed').toBe(false)
    expect(verdict([rule], REQUEST({}, ['admin']))).toBe(true)
  })

  it('keeps it on `whenAny` too', () => {
    const rule = defineRule('post.update')
      .allow()
      .on('update')
      .of('post')
      .whenAny(() => when().role('admin'))
      .build()

    expect(verdict([rule], REQUEST({}, ['reader']))).toBe(false)
    expect(verdict([rule], REQUEST({}, ['admin']))).toBe(true)
  })

  it('keeps it on a role permission, where an empty group grants the permission outright', () => {
    const role = defineRole('editor')
      .grantWhen('update', 'post', () => when().attr('department', 'eq', 'engineering'))
      .build()
    const rbac = rolesToPolicy([role])

    expect(verdict([...rbac.rules], REQUEST({ department: 'sales' }, ['editor']))).toBe(false)
    expect(verdict([...rbac.rules], REQUEST({ department: 'engineering' }, ['editor']))).toBe(true)
  })

  it('keeps it on a policy-level inline rule', () => {
    const policy = definePolicy('posts')
      .algorithm('deny-overrides')
      .rule('post.update', (r) =>
        r
          .allow()
          .on('update')
          .of('post')
          .when(() => when().role('admin')),
      )
      .build()

    expect(verdict([...policy.rules], REQUEST({}, ['reader']))).toBe(false)
    expect(verdict([...policy.rules], REQUEST({}, ['admin']))).toBe(true)
  })

  it('refuses the ambiguous chain rather than silently picking one half', () => {
    // Conditions on the builder that was handed in *and* a different builder
    // returned: there is no reading of that which keeps both, so it is an
    // authoring mistake, not a shape to guess at.
    expect(() =>
      defineRule('post.update')
        .allow()
        .on('update')
        .of('post')
        .when((w) => {
          w.role('editor')
          return when().role('admin')
        })
        .build(),
    ).toThrow(/both/i)
  })

  it('the ordinary chain, which returns the builder it was given, is untouched', () => {
    const rule = defineRule('post.update')
      .allow()
      .on('update')
      .of('post')
      .when((w) => w.role('admin'))
      .build()

    expect(verdict([rule], REQUEST({}, ['reader']))).toBe(false)
    expect(verdict([rule], REQUEST({}, ['admin']))).toBe(true)
  })
})

/**
 * `buildAll()` handed out the builder's own live array, so an emitted group was
 * a window onto a builder that could still be chained - and two rules built
 * from one reusable group shared a single array instance. The engine freezes
 * the policies it loads, so one policy's freeze reached into another's rule.
 */
describe('an emitted condition group is a snapshot, not a window', () => {
  it('does not grow when the builder is chained afterwards', () => {
    const w = when().role('admin')
    const group = w.buildAll()
    w.role('root')
    expect(group.all).toHaveLength(1)
  })

  it('gives each build call its own array', () => {
    const w = when().role('admin')
    expect(w.buildAll().all).not.toBe(w.buildAll().all)
    expect(w.buildAny().any).not.toBe(w.buildAll().all)
  })

  it('survives one holder freezing what it was given', () => {
    const shared = when().role('admin')
    const first = shared.buildAll()
    Object.freeze(first.all)
    // A second rule built from the same reusable group must still be buildable:
    // before, both rules pointed at the one array, and freezing for policy A
    // made B's conditions immutable too.
    expect(() => shared.role('root')).not.toThrow()
    expect(shared.buildAll().all).toHaveLength(2)
    expect(first.all).toHaveLength(1)
  })
})

/**
 * The variadic helpers emit `{ operator: 'in', value: [...] }`. Called with no
 * arguments at all that is `in: []` - a condition no request can satisfy. On an
 * allow rule it is dead weight; on a **deny** rule the deny can never fire, and
 * the guard the author wrote is not there. The validator called the policy
 * valid, because the shape is.
 */
describe('a variadic helper called with nothing to match', () => {
  it.each(['roles', 'scopes', 'resourceType'] as const)('refuses `%s()`', (method) => {
    expect(() => when()[method]()).toThrow(new RegExp(method))
  })

  it('the deny rule that used to disappear now cannot be written by accident', () => {
    expect(() =>
      defineRule('deny-banned')
        .deny()
        .on('update')
        .of('post')
        .when((w) => w.roles())
        .build(),
    ).toThrow(/roles/)
  })

  it('an explicitly empty list is still allowed - that one may be computed', () => {
    // `in` with a list built at runtime can legitimately come out empty, and it
    // means what it says: nothing matches. Only the zero-argument call, which
    // no author writes on purpose, is refused.
    const rule = defineRule('r')
      .deny()
      .on('update')
      .of('post')
      .when((w) => w.in('subject.roles', []))
      .build()
    expect(verdict([rule], REQUEST({}, ['admin']))).toBe(false)
  })

  it('one argument is a normal call', () => {
    const rule = defineRule('r')
      .allow()
      .on('update')
      .of('post')
      .when((w) => w.roles('admin'))
      .build()
    expect(verdict([rule], REQUEST({}, ['admin']))).toBe(true)
    expect(verdict([rule], REQUEST({}, ['reader']))).toBe(false)
  })
})

/**
 * The type parameters of `when()` are named `TScope` third and `TRole` fourth,
 * and were handed to `When` in the opposite order, so `.role()` demanded a
 * scope literal and `.scope()` a role. Nothing failed at runtime - it made the
 * typed surface lie, which is the only thing these generics exist for.
 */
describe('when() forwards its type parameters to the slots it names', () => {
  type Action = 'update'
  type Resource = 'post'
  type Role = 'admin' | 'editor'
  type Scope = 'org-1' | 'org-2'

  it('accepts a role for role() and a scope for scope()', () => {
    const w = when<Action, Resource, Role, Scope>()
    w.role('admin')
    w.scope('org-1')
    expect(w.buildAll().all).toHaveLength(2)
  })

  it('rejects the two the other way round', () => {
    const w = when<Action, Resource, Role, Scope>()
    // @ts-expect-error - 'org-1' is a scope, not a role
    w.role('org-1')
    // @ts-expect-error - 'admin' is a role, not a scope
    w.scope('admin')
    expect(w.buildAll().all).toHaveLength(2)
  })
})

/**
 * A key holding `undefined` is not the same object as a key that is absent.
 * The memory, file and http stores keep the caller's own object, so the key
 * survives; anything that passes the policy through `JSON.stringify` or a
 * `jsonb` column drops it. The same authored policy therefore read back
 * unequal from two adapters - `Object.keys` disagreed, `'description' in
 * policy` disagreed, and a consumer branching on either got two answers from
 * one write.
 *
 * The builders are the source of those objects, so the omission belongs here
 * rather than in each store. The one default the stores *do* impose,
 * `version: 1`, is theirs to add on the write path - the builder must not
 * pre-empt it, or an author who never set a version cannot be told apart from
 * one who set it to 1.
 */
describe('the builders emit absent keys, not keys holding undefined', () => {
  const minimalRule = (id: string) => defineRule<'read', 'doc'>(id).allow().on('read').of('doc')

  it('leaves every optional policy key out when the author set none', () => {
    const policy = definePolicy<'read', 'doc'>('minimal').name('Minimal').addRule(minimalRule('r').build()).build()

    expect(Object.keys(policy).sort()).toEqual(['algorithm', 'id', 'name', 'rules'])
    expect('description' in policy).toBe(false)
    expect('version' in policy).toBe(false)
    expect('targets' in policy).toBe(false)
  })

  it('keeps every optional policy key the author did set', () => {
    const policy = definePolicy<'read', 'doc'>('full')
      .name('Full')
      .desc('every optional key written')
      .version(7)
      .target({ resources: ['doc'] })
      .addRule(minimalRule('r').build())
      .build()

    expect(policy.description).toBe('every optional key written')
    expect(policy.version).toBe(7)
    expect(policy.targets).toEqual({ resources: ['doc'] })
  })

  it('does not invent version 1, so "unset" and "set to 1" stay distinguishable', () => {
    const unset = definePolicy<'read', 'doc'>('unset').name('Unset').addRule(minimalRule('a').build()).build()
    const one = definePolicy<'read', 'doc'>('one').name('One').version(1).addRule(minimalRule('b').build()).build()

    expect('version' in unset).toBe(false)
    expect('version' in one).toBe(true)
    expect(one.version).toBe(1)
  })

  it('leaves the optional rule keys out when the author set none', () => {
    const rule = minimalRule('r').build()

    expect('description' in rule).toBe(false)
    expect('metadata' in rule).toBe(false)
  })

  it('leaves the optional role keys out when the author set none', () => {
    const role = defineRole<'viewer', 'read', 'doc'>('viewer').name('Viewer').grant('read', 'doc').build()

    expect('description' in role).toBe(false)
    expect('inherits' in role).toBe(false)
    expect('scope' in role).toBe(false)
    expect('metadata' in role).toBe(false)
  })

  it('survives a JSON round trip unchanged, which is what the stores do to it', () => {
    const policy = definePolicy<'read', 'doc'>('round-trip')
      .name('Round trip')
      .addRule(minimalRule('r').build())
      .build()
    const role = defineRole<'viewer', 'read', 'doc'>('viewer').name('Viewer').grant('read', 'doc').build()

    expect(JSON.parse(JSON.stringify(policy))).toEqual(policy)
    expect(JSON.parse(JSON.stringify(role))).toEqual(role)
  })
})
