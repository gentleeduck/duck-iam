import { describe, expect, it } from 'vitest'
import { definePolicy, defineRule, RuleBuilder } from '..'

/**
 * `PolicyBuilder.rule()` carried the comment "an untouched RuleBuilder has no
 * effect and `build()` refuses it". It did not. `RuleBuilder` starts at
 * `allow` / `['*']` / `['*']` / `{all:[]}` - the broadest possible grant - and
 * `build()` returned it, so `.rule('x', (r) => { ...forgot... })` silently
 * pushed an unconditional allow-everything rule into the policy.
 *
 * The validator already *detects* this shape (`BROAD_ALLOW`,
 * `validate.libs.ts`), but it is `type:'warning'` and `build()` keeps only
 * `type:'error'`, so the verdict was computed and dropped on the floor with no
 * console output and no return channel. Nobody ever saw it.
 *
 * The fix refuses a builder whose *grant shape* was never set. It is
 * deliberately narrower than promoting `BROAD_ALLOW` to an error: a deliberate
 * `allow * *` (an admin policy) still builds, and `validatePolicy` still
 * accepts stored policies that carry one. Only "nobody said anything at all"
 * is refused, which is exactly what the comment always claimed.
 */
describe('RuleBuilder refuses an untouched builder', () => {
  it('a bare build() throws instead of returning allow-everything', () => {
    expect(() => new RuleBuilder('r1').build()).toThrow(/never configured/)
  })

  it('defineRule(id).build() throws for the same reason', () => {
    expect(() => defineRule('r1').build()).toThrow(/never configured/)
  })

  it('a rule() callback that configures nothing fails the policy build', () => {
    expect(() =>
      definePolicy('p1')
        .rule('r1', (r) => r)
        .build(),
    ).toThrow(/never configured/)
  })

  it('a rule() callback that drops its return still fails', () => {
    // The callback mutates nothing and returns a *different* untouched builder.
    expect(() =>
      definePolicy('p1')
        .rule('r1', () => new RuleBuilder('other'))
        .build(),
    ).toThrow(/never configured/)
  })

  it('description/priority/metadata alone do not count as configuring the grant', () => {
    // None of these narrow what is granted; the rule is still allow * * with
    // no conditions, so it must still be refused.
    expect(() => defineRule('r1').desc('todo').priority(5).meta({ owner: 'team' }).build()).toThrow(/never configured/)
  })

  it('an explicit broad grant is still allowed - this is the opt-in', () => {
    const rule = defineRule('r1').allow().build()
    expect(rule.effect).toBe('allow')
    expect(rule.actions).toEqual(['*'])
    expect(rule.resources).toEqual(['*'])
    expect(rule.conditions).toEqual({ all: [] })
  })

  it('an explicit deny with no narrowing is allowed - fail-closed direction', () => {
    expect(defineRule('r1').deny().build().effect).toBe('deny')
  })

  it('each grant-shaping method on its own is enough to permit build()', () => {
    expect(() => defineRule('a').allow().build()).not.toThrow()
    expect(() => defineRule('b').deny().build()).not.toThrow()
    expect(() => defineRule('c').on('read').build()).not.toThrow()
    expect(() => defineRule('d').of('post').build()).not.toThrow()
    expect(() => defineRule('e').forScope('org-1').build()).not.toThrow()
    // `'*'` narrows nothing but is still an explicit statement, not silence.
    expect(() => defineRule('e2').forScope('*').build()).not.toThrow()
    expect(() =>
      defineRule('f')
        .when((w) => w.eq('action', 'read'))
        .build(),
    ).not.toThrow()
  })

  it('an ordinary narrowed rule is unaffected', () => {
    const rule = defineRule('r1').allow().on('read').of('post').build()
    expect(rule.actions).toEqual(['read'])
    expect(rule.resources).toEqual(['post'])
  })
})

/**
 * The first cut of the refusal above gated on *which methods were called*, not
 * on what the rule became - so three shapes still built the exact
 * allow-everything rule it exists to refuse. The realistic one is
 * `.forScope(...tenantIds)` with a runtime-empty array: `forScope` set the flag
 * before discovering it had no scope to apply, so a rule meant to be
 * tenant-restricted built global, unconditional, and passed the guard.
 *
 * The asymmetry between `when` and `whenAny` is deliberate and is the reason
 * they are treated differently below. `evalConditionGroup` runs `.every` over
 * an `all` group and `.some` over an `any` group, so on an empty group
 * `{all: []}` is **true** - it matches every request - while `{any: []}` is
 * **false** and matches none. An empty `when` is therefore a silent broad
 * grant; an empty `whenAny` is a rule that can never fire, which is harmless
 * and is a legitimate result of building a condition list from an empty
 * collection.
 */
describe('the refusal gates on what the rule became, not on which methods were called', () => {
  it('forScope() with no scopes throws rather than building a global rule', () => {
    expect(() => defineRule('r1').forScope().build()).toThrow(/no scopes/)
  })

  it('forScope(...[]) - the runtime-empty spread - throws for the same reason', () => {
    // The dangerous shape: the author wrote a tenant restriction and the list
    // was empty, so before this the restriction evaporated into `allow * *`.
    const tenantIds: string[] = []
    expect(() =>
      defineRule('r1')
        .forScope(...tenantIds)
        .build(),
    ).toThrow(/no scopes/)
  })

  it('an empty forScope is refused even when the grant was otherwise configured', () => {
    // `_grantShapeSet` is already true here, so only forScope's own check can
    // catch this - and this is the shape that actually reaches production.
    const tenantIds: string[] = []
    expect(() =>
      defineRule('r1')
        .allow()
        .on('read')
        .of('post')
        .forScope(...tenantIds)
        .build(),
    ).toThrow(/no scopes/)
  })

  it('when() whose callback adds nothing does not count as configuring the grant', () => {
    // Produces `{all: []}`, which matches every request - a silent broad grant.
    expect(() =>
      defineRule('r1')
        .when((w) => w)
        .build(),
    ).toThrow(/never configured/)
  })

  it('whenAny() whose callback adds nothing is allowed - it fails closed', () => {
    // `{any: []}` matches nothing, so the rule can never grant. Building a
    // condition list from an empty collection is legitimate and safe.
    const rule = defineRule('r1')
      .whenAny((w) => w)
      .build()
    expect(rule.conditions).toEqual({ any: [] })
  })

  it('a when() that does add a condition still counts', () => {
    expect(() =>
      defineRule('r1')
        .when((w) => w.eq('action', 'read'))
        .build(),
    ).not.toThrow()
  })

  it('forScope("*") is still explicit, not silence', () => {
    expect(() => defineRule('r1').forScope('*').build()).not.toThrow()
  })
})
