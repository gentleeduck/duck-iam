import { describe, expect, it } from 'vitest'
import * as Core from '../core'
import { IAM_ERRORS, IamError } from '../core/errors'
import * as Iam from '../index'
import type * as ExpressAdapter from '../server/express'
import type * as HonoAdapter from '../server/hono'
import type * as NestAdapter from '../server/nest'
import type * as NextAdapter from '../server/next'

describe('IamError construction', () => {
  it('uses the code as the message', () => {
    expect(new IamError('IAM_ENGINE_FAIL_OPEN_NOT_CONFIRMED').message).toBe('IAM_ENGINE_FAIL_OPEN_NOT_CONFIRMED')
  })

  it('is an Error, so existing catch blocks and instanceof still work', () => {
    expect(new IamError('IAM_ENGINE_FAIL_OPEN_NOT_CONFIRMED')).toBeInstanceOf(Error)
  })
})

describe('the code map', () => {
  it('is where every code takes its status from', () => {
    for (const [code, status] of Object.entries(IAM_ERRORS)) {
      expect(new IamError(code as never).status).toBe(status)
    }
  })
})

// @ts-expect-error a code that carries something cannot be raised without it
void new IamError('IAM_ROLE_NOT_FOUND')

describe('IamError, IAM_ERRORS and errors.validation are reachable from the package root', () => {
  it('IamError and IAM_ERRORS are exported from the core barrel', () => {
    expect(Object.hasOwn(Core, 'IamError')).toBe(true)
    expect(Object.hasOwn(Core, 'IAM_ERRORS')).toBe(true)
  })

  it('IamError and IAM_ERRORS are exported from the package root', () => {
    expect(Object.hasOwn(Iam, 'IamError')).toBe(true)
    expect(Object.hasOwn(Iam, 'IAM_ERRORS')).toBe(true)
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
