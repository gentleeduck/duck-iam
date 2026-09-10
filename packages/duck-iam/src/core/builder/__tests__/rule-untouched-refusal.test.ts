import { describe, expect, it } from 'vitest'
import { definePolicy, defineRule, RuleBuilder } from '..'

// An untouched RuleBuilder is allow `*` on `*` unconditionally, so `build()` refuses it. `BROAD_ALLOW` is only a
// warning, so a deliberate `.allow()` broad grant still builds.
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
    // None of these narrow the grant, so the rule is still an unconditional allow * *.
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

// An empty `forScope` or `when` would still build allow-everything, so both are refused. An empty `whenAny`
// is allowed: `{all: []}` matches every request, `{any: []}` matches none.
describe('the refusal gates on what the rule became, not on which methods were called', () => {
  it('forScope() with no scopes throws rather than building a global rule', () => {
    expect(() => defineRule('r1').forScope().build()).toThrow(/no scopes/)
  })

  it('forScope(...[]) - the runtime-empty spread - throws for the same reason', () => {
    // The realistic shape: a tenant restriction whose list came back empty.
    const tenantIds: string[] = []
    expect(() =>
      defineRule('r1')
        .forScope(...tenantIds)
        .build(),
    ).toThrow(/no scopes/)
  })

  it('an empty forScope is refused even when the grant was otherwise configured', () => {
    // `_grantShapeSet` is already true here, so only forScope's own check can catch this.
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
    // `{any: []}` matches nothing, so the rule can never grant.
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
