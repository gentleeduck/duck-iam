import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import * as Core from '../core'
import * as Conditions from '../core/conditions'
import { IamRegexInputTooLargeError } from '../core/conditions'
import * as Iam from '../index'
import type * as ExpressAdapter from '../server/express'
import type * as HonoAdapter from '../server/hono'
import type * as NestAdapter from '../server/nest'
import type * as NextAdapter from '../server/next'

// Tagged condition errors exist for `instanceof` routing, which needs an exported class. The list is read from
// `conditions.libs.ts`, so a new `Iam...Error` missing from a barrel fails here.
const DECLARED_ERRORS: string[] = [
  ...readFileSync(join(__dirname, '../core/conditions/conditions.libs.ts'), 'utf8').matchAll(
    /^export class (Iam\w+Error) extends Error/gm,
  ),
].map((m) => m[1] as string)

describe('every tagged condition error is reachable', () => {
  it('finds the classes it is meant to be checking', () => {
    // Without this the loops below are satisfied by an empty list.
    expect(DECLARED_ERRORS.length).toBeGreaterThanOrEqual(5)
    expect(DECLARED_ERRORS).toContain('IamRegexInputTooLargeError')
  })

  it.each(DECLARED_ERRORS)('%s is exported from the conditions barrel', (name) => {
    expect(Object.hasOwn(Conditions, name)).toBe(true)
  })

  it.each(DECLARED_ERRORS)('%s is exported from the core barrel', (name) => {
    expect(Object.hasOwn(Core, name)).toBe(true)
  })

  it.each(DECLARED_ERRORS)('%s is exported from the package root', (name) => {
    expect(Object.hasOwn(Iam, name)).toBe(true)
  })

  it.each(DECLARED_ERRORS)('%s carries a duck-iam/ tag distinct from every other', (name) => {
    const tags = DECLARED_ERRORS.map((n) => {
      const ctor = Reflect.get(Conditions, n)
      // Every one of these takes (field, ...rest) with string-ish arguments.
      return typeof ctor === 'function' ? Reflect.get(new ctor('f', 'x', 'y'), 'tag') : undefined
    })
    const own = tags[DECLARED_ERRORS.indexOf(name)]
    expect(String(own)).toMatch(/^duck-iam\//)
    expect(tags.filter((t) => t === own)).toHaveLength(1)
  })

  it('is a constructible Error subclass', () => {
    const err = new IamRegexInputTooLargeError('subject.id', 10_000)
    expect(err).toBeInstanceOf(Error)
    expect(err.field).toBe('subject.id')
    expect(err.length).toBe(10_000)
  })

  it('keeps its stable tag', () => {
    expect(new IamRegexInputTooLargeError('f', 1).tag).toBe('duck-iam/regex-input-too-large')
  })

  it('is the class the evaluator actually throws', async () => {
    const { evalMatchesOp, MAX_REGEX_INPUT_LENGTH } = await import('../core/conditions/conditions.libs')
    expect(() => evalMatchesOp('a'.repeat(MAX_REGEX_INPUT_LENGTH + 1), '^a')).toThrow(IamRegexInputTooLargeError)
  })
})

// Types that appear in root-exported signatures must be nameable. Type-only, so these are compile-time checks.
describe('types used in public signatures are nameable', () => {
  it('Batch.Result can annotate an assignRoles result', () => {
    const result: Core.Batch.Result<{ subjectId: string }, Core.Batch.Change> = {
      applied: 1,
      outcomes: [{ ok: true, row: { subjectId: 'u1' }, value: { changed: true } }],
    }
    expect(result.applied).toBe(1)
  })

  it('Pending.Invalidation can annotate a buffered entry', () => {
    const entry: Core.Pending.Invalidation = { kind: 'subject', subjectId: 'u1' }
    expect(entry.kind).toBe('subject')
  })

  // An unexported handler type in an exported signature gives consumers TS4023. `check-types` does the real
  // checking; the runtime expects only keep the bindings referenced.
  it('the express handler types a consumer must name are exported', () => {
    const mw: ExpressAdapter.Middleware = (_req, _res, next) => next()
    const routerLike: (r: () => ExpressAdapter.ExpressRouterLike) => ExpressAdapter.ExpressRouterLike = (r) => r()
    expect(typeof mw).toBe('function')
    expect(typeof routerLike).toBe('function')
  })

  it('the hono, next and nest handler types a consumer must name are exported', () => {
    const honoMw: HonoAdapter.HonoMiddleware = async () => undefined
    const nextHandler: NextAdapter.RouteHandler = async () => new Response(null)
    const nestCtxUser: (c: NestAdapter.NestExecutionContext) => NestAdapter.NestExecutionContext = (c) => c
    expect(typeof honoMw).toBe('function')
    expect(typeof nextHandler).toBe('function')
    expect(typeof nestCtxUser).toBe('function')
  })
})
