import { describe, expect, it } from 'vitest'
import type { AccessControl, DotPath, IamClient } from '..'
import { iamCreateEvalCaches } from '../caches'

// Compile-time assertions. There is no `vitest --typecheck` step in this repo,
// but `tsconfig.json` includes `src/**/*`, so `tsc --noEmit` (`bun run
// check-types`) is what makes these fail.
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false
type Expect<T extends true> = T
type Extends<A, B> = A extends B ? true : false

// DotPath.DotPaths
type _DotPathsNested = Expect<Equal<DotPath.DotPaths<{ a: { b: string }; c: number }>, 'a' | 'a.b' | 'c'>>
type _DotPathsArrayIsLeaf = Expect<Equal<DotPath.DotPaths<{ roles: string[] }>, 'roles'>>
type _DotPathsSkipsFunctions = Expect<Equal<DotPath.DotPaths<{ fn: () => void; a: string }>, 'a'>>
type _DotPathsBailsOnIndexSignature = Expect<Equal<DotPath.DotPaths<Record<string, string>>, never>>

// DotPath.PathValue
type _PathValueDeep = Expect<
  Equal<
    DotPath.PathValue<{ subject: { attributes: { status: 'active' | 'banned' } } }, 'subject.attributes.status'>,
    'active' | 'banned'
  >
>
type _PathValueMiss = Expect<Equal<DotPath.PathValue<{ a: { b: string } }, 'a.nope'>, never>>

// DotPath.FlexibleDotPaths — closed contexts stay narrow, open bags accept any string.
type _FlexibleClosed = Expect<Equal<DotPath.FlexibleDotPaths<{ a: { b: string } }>, 'a' | 'a.b'>>
type _FlexibleClosedRejects = Expect<Equal<Extends<'nope', DotPath.FlexibleDotPaths<{ a: string }>>, false>>
type _FlexibleOpenAccepts = Expect<
  Extends<'anything.at.all', DotPath.FlexibleDotPaths<{ subject: { attributes: DotPath.IAnyAttributes } }>>
>

// DotPath.DollarPaths
type _DollarPaths = Expect<Equal<DotPath.DollarPaths<{ a: string; b: { c: number } }>, '$a' | '$b' | '$b.c'>>

// Attribute-bag path extractors (AttrPaths / IsPlainObject leaf rules).
type _SubjectAttrs = Expect<
  Equal<DotPath.SubjectAttrs<{ subject: { attributes: { profile: { tier: string } } } }>, 'profile' | 'profile.tier'>
>
type _ResourceAttrsNested = Expect<
  Equal<
    DotPath.ResourceAttrs<{ resource: { attributes: { owner: { id: string }; name: string } } }>,
    'owner' | 'owner.id' | 'name'
  >
>
type _EnvAttrsOpenBagWidensToString = Expect<Equal<DotPath.EnvAttrs<{ environment: DotPath.IAnyAttributes }>, string>>
type _AttrValue = Expect<
  Equal<DotPath.AttrValue<{ profile: { tier: 'gold' | 'silver' } }, 'profile.tier'>, 'gold' | 'silver'>
>

// Per-resource narrowing: `'*'` merges every declared resource's attributes.
type ResCtx = { resourceAttributes: { post: { ownerId: string }; comment: { flagged: boolean } } }
type _ResolvedNarrow = Expect<Equal<DotPath.ResolvedResourceAttrPaths<ResCtx, 'post'>, 'ownerId'>>
type _ResolvedWildcard = Expect<Equal<DotPath.ResolvedResourceAttrPaths<ResCtx, '*'>, 'ownerId' | 'flagged'>>

// AccessControl mode-conditional returns.
type _ModeResultProd = Expect<Equal<AccessControl.ModeResult<'production'>, boolean>>
type _ModeResultDev = Expect<Equal<AccessControl.ModeResult<'development'>, AccessControl.IDecision>>
type _ModePermMapProd = Expect<Equal<AccessControl.ModePermissionMap<'production'>, Record<string, boolean>>>

// IamClient.PermissionKey shapes.
type ReadPostKey = IamClient.PermissionKey<'read', 'post', 'org'>
type _KeyPlain = Expect<Extends<'read:post', ReadPostKey>>
type _KeyWithResourceId = Expect<Extends<'read:post:p-1', ReadPostKey>>
type _KeyScoped = Expect<Extends<'org:read:post', ReadPostKey>>
type _KeyScopedWithResourceId = Expect<Extends<'org:read:post:p-1', ReadPostKey>>
type _KeyRejectsUnknownAction = Expect<Equal<Extends<'delete:post', ReadPostKey>, false>>

// PartialPermissionMap is what `engine.permissions()` actually returns.
type _PartialAllowsEmpty = Expect<Extends<Record<string, never>, IamClient.PartialPermissionMap<'read', 'post', 'org'>>>

describe('iamCreateEvalCaches()', () => {
  it('returns empty regex and path maps', () => {
    const caches = iamCreateEvalCaches()
    expect(caches.regex).toBeInstanceOf(Map)
    expect(caches.path).toBeInstanceOf(Map)
    expect(caches.regex.size).toBe(0)
    expect(caches.path.size).toBe(0)
  })

  it('returns a distinct pair of maps per call', () => {
    const a = iamCreateEvalCaches()
    const b = iamCreateEvalCaches()
    expect(a.regex).not.toBe(b.regex)
    expect(a.path).not.toBe(b.path)
    expect(a.regex).not.toBe(a.path)
  })

  it('does not leak entries between instances', () => {
    const a = iamCreateEvalCaches()
    a.regex.set('^x$', /^x$/)
    a.path.set('subject.id', ['subject', 'id'])
    const b = iamCreateEvalCaches()
    expect(b.regex.size).toBe(0)
    expect(b.path.size).toBe(0)
  })

  it('matches the shape the evaluators accept as `caches`', () => {
    const caches: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> } = iamCreateEvalCaches()
    expect(Object.keys(caches).sort()).toEqual(['path', 'regex'])
  })
})
