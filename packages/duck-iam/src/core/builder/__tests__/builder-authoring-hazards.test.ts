import { describe, expect, it } from 'vitest'
import { evaluate } from '../../evaluate/evaluate'
import { rolesToPolicy } from '../../rbac'
import type { AccessControl, IamPrimitives, IamRequest } from '../../types'
import { definePolicy } from '../policy'
import { defineRole } from '../role'
import { defineRule } from '../rule'
import { when } from '../when'

// Authoring mistakes that still build but mean something else, often no condition at all.
// Each case asserts the engine's verdict, not the emitted shape.

const REQUEST = (attributes: IamPrimitives.Attributes, roles: string[] = []): IamRequest.IAccessRequest => ({
  action: 'update',
  resource: { attributes: { ownerId: 'someone-else' }, type: 'post' },
  subject: { attributes, id: 'u1', roles },
})

function verdict(rules: AccessControl.IRule[], request: IamRequest.IAccessRequest): boolean {
  return evaluate([{ algorithm: 'deny-overrides', id: 'p', name: 'p', rules }], request, 'deny', 'and').allowed
}

// Returning a reusable group from the callback must keep it; dropping it leaves `{ all: [] }`, an unconditional grant.
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
    // Conditions on the given builder and a different returned one cannot both be kept.
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

// Rules built from one reusable group must not share its array: the engine freezes the policies it loads.
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
    // Freezing one rule's group must leave the shared builder usable for the next rule.
    expect(() => shared.role('root')).not.toThrow()
    expect(shared.buildAll().all).toHaveLength(2)
    expect(first.all).toHaveLength(1)
  })
})

// A zero-argument variadic helper builds `in: []`, which matches nothing and so disables a deny rule.
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
    // A computed `in` list may legitimately be empty; only the zero-argument helper call is refused.
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

// Type-level only: a swapped TRole/TScope would make `.role()` demand a scope and `.scope()` a role.
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

// Stores that keep the object keep an `undefined` key; JSON-backed ones drop it, so adapters would disagree.
// `version: 1` is the stores' default to add, not the builder's.
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
