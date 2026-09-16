import { describe, expect, it } from 'vitest'
import { detectCatastrophicRegex, getCachedRegex, MAX_REGEX_INPUT_LENGTH } from '../conditions.libs'

// A separator confines quantifiers only when the atoms cannot match it; `.` matches `/`,
// so an object-store glob backtracks O(n^4).

/** The glob, with escaped separators. */
const GLOB = String.raw`^.*\/.*\/.*\/.*\.json$`
/** Same shape, unescaped `/` - what an author actually types. */
const GLOB_PLAIN = '^.*/.*/.*/.*\\.json$'

describe('unbounded quantifiers separated by characters they can match', () => {
  it('the reported glob is refused, in both spellings', () => {
    expect({
      escaped: detectCatastrophicRegex(GLOB).safe,
      plain: detectCatastrophicRegex(GLOB_PLAIN).safe,
    }).toEqual({ escaped: false, plain: false })
  })

  it('the reason names the competing atoms rather than a bare count', () => {
    const reason = detectCatastrophicRegex(GLOB_PLAIN).reason ?? ''
    expect(reason).toMatch(/unbounded quantifiers competing for the same characters/)
  })

  it('a refused pattern never compiles, so the stall is unreachable from a request', () => {
    expect(getCachedRegex(GLOB_PLAIN, new Map())).toBeNull()
  })

  it('separators the atoms cannot match still keep a pattern linear and allowed', () => {
    // `[a-z]` matches neither `@` nor `.`, so each `+` is confined to one segment.
    expect({
      dottedPath: detectCatastrophicRegex(String.raw`^[a-z]+\.[a-z]+\.[a-z]+$`).safe,
      email: detectCatastrophicRegex(String.raw`[a-z]+@[a-z]+\.[a-z]+`).safe,
      urnish: detectCatastrophicRegex('^[a-z]+:[a-z]+:[a-z]+$').safe,
    }).toEqual({ dottedPath: true, email: true, urnish: true })
  })

  it('a run of two stays allowed - O(n^2) is affordable inside the input cap', () => {
    expect({
      prefixSuffix: detectCatastrophicRegex('^.*foo.*$').safe,
      single: detectCatastrophicRegex(String.raw`^.*\.json$`).safe,
    }).toEqual({ prefixSuffix: true, single: true })
  })

  it('an optional separator does not break a run, since it separates nothing', () => {
    expect(detectCatastrophicRegex('^.*x?.*y?.*$').safe).toBe(false)
  })

  it('the shapes that were already refused still are', () => {
    expect({
      adjacent: detectCatastrophicRegex('^.*.*$').safe,
      nested: detectCatastrophicRegex('^(a+)+$').safe,
    }).toEqual({ adjacent: false, nested: false })
  })

  it('an allowed pattern runs in linear time at the input cap', () => {
    const compiled = getCachedRegex(String.raw`^[a-z]+@[a-z]+\.[a-z]+$`, new Map())
    expect(compiled).not.toBeNull()
    const input = 'a'.repeat(MAX_REGEX_INPUT_LENGTH)
    const started = performance.now()
    compiled?.test(input)
    // Generous: the point is milliseconds, not minutes.
    expect(performance.now() - started).toBeLessThan(1_000)
  })
})
