/**
 * `duck-auth doctor` imports an `auth.ts` and calls `strict()` on its `auth` export. It called it with no
 * arguments at all, and `assertStrict` reads `opts.compliance` before anything else, so every invocation —
 * against a healthy config and a broken one alike — died on a TypeError that the catch below reported as
 * `strict() rejected: Cannot read properties of undefined (reading 'compliance')`. The one command whose
 * whole job is to surface misconfigurations ran no check, and had no test.
 */
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { __doctor } from '../index'

const fixture = (name: string) => join(import.meta.dirname, 'fixtures', `${name}-auth.ts`)

/** Runs the command with both streams captured, since it reports through them rather than by returning. */
async function run(...args: string[]): Promise<{ code: number; err: string; out: string }> {
  const out: string[] = []
  const err: string[] = []
  vi.spyOn(process.stdout, 'write').mockImplementation((c) => {
    out.push(String(c))
    return true
  })
  vi.spyOn(process.stderr, 'write').mockImplementation((c) => {
    err.push(String(c))
    return true
  })
  const code = await __doctor(args)
  return { code, err: err.join(''), out: out.join('') }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('duck-auth doctor', () => {
  it('passes a config with no production footgun in it', async () => {
    const { code, out } = await run(fixture('healthy'))
    expect(out).toContain('AuthEngine.strict() OK')
    expect(code).toBe(0)
  })

  it('names the footguns rather than dying before it reaches them', async () => {
    const { code, err } = await run(fixture('footgun'))
    expect(code).toBe(1)
    // Each of these is a separate check inside `strict()`, so reaching all four says it ran the body and
    // not merely that it threw something.
    expect(err).toMatch(/Memory adapter/)
    expect(err).toMatch(/Limiter adapter required/)
    expect(err).toMatch(/must use https/)
    expect(err).toMatch(/no provider registered/)
  })

  it('asks about production, which is the only env whose checks exist', async () => {
    // `strict()` returns immediately for development and test, so a doctor passing either would report
    // this same fixture as healthy. This preamble is written by the production branch and nothing else.
    const { err } = await run(fixture('footgun'))
    expect(err).toContain('production strict() checks failed')
  })

  it('separates a crash from a verdict, which is what hid this', async () => {
    const { code, err } = await run(fixture('crashing'))
    expect(code).toBe(1)
    expect(err).toContain('could not run strict()')
    expect(err).not.toContain('strict() rejected')
  })

  it('refuses a path that is not there', async () => {
    const { code, err } = await run(join(import.meta.dirname, 'fixtures', 'absent-auth.ts'))
    expect(code).toBe(1)
    expect(err).toContain('file not found')
  })

  it('refuses a module that exports no `auth`', async () => {
    const { code, err } = await run(join(import.meta.dirname, 'doctor.test.ts'))
    expect(code).toBe(1)
    expect(err).toMatch(/does not export a named `auth`/)
  })
})
