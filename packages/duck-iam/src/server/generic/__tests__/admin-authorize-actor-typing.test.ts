import { describe, expect, it } from 'vitest'
import type { IamExpress } from '../../express'
import type { IamHono } from '../../hono'
import type { IamNest } from '../../nest'
import type { IamNext } from '../../next'
import { type IamAdminAuthzAnswer, iamIsNameableActor, iamRunAdminAuthz } from '../index'

// Each adapter's `IAdminAuthorize` must admit an actor, as the gate's warning asks, not just a boolean.
// The annotated declarations below fail `check-types` if any narrows back to `boolean`.
type ExpressReq = Parameters<IamExpress.IAdminAuthorize>[0]
type NextReq = Parameters<IamNext.IAdminAuthorize>[0]
type HonoCtx = Parameters<IamHono.IAdminAuthorize>[0]
type NestReq = Parameters<IamNest.IAdminAuthorize>[0]

/** A request carrying an authenticated user, as express would present it. */
const WITH_USER = { id: 'req-1', user: { id: 'admin-7', role: 'admin' } }

/** The authenticated user an admin gate would look up. */
interface User {
  id: string
  role: string
}

/**
 * Reads the user off a request, with a concrete return type.
 * NOTE: not `Reflect.get`: its `any` is assignable to `boolean`, so the declarations below would assert nothing.
 */
function userOf(req: unknown): User {
  const user: unknown = Reflect.get(Object(req), 'user')
  const id: unknown = Reflect.get(Object(user), 'id')
  const role: unknown = Reflect.get(Object(user), 'role')
  return { id: typeof id === 'string' ? id : '', role: typeof role === 'string' ? role : '' }
}

/** The shape the warning asks for, declared against each adapter's own type with no cast. */
const expressActor: IamExpress.IAdminAuthorize = (req: ExpressReq) => userOf(req)
const nextActor: IamNext.IAdminAuthorize = (req: NextReq) => userOf(req)
const honoActor: IamHono.IAdminAuthorize = (c: HonoCtx) => userOf(c)
const nestActor: IamNest.IAdminAuthorize = (req: NestReq) => userOf(req)

/** The `@example` shape. A boolean still authorizes; it just names no one. */
const expressBoolean: IamExpress.IAdminAuthorize = (req: ExpressReq) => userOf(req).role === 'admin'

/** A subject id, which is what the audit event's `actor` is for. */
const expressSubjectId: IamExpress.IAdminAuthorize = () => 'admin-7'

/** An async gate, since real ones hit a session store. */
const expressAsync: IamExpress.IAdminAuthorize = async () => ({ id: 'admin-7' })

describe('an admin authorize may return the actor, in the type as well as at runtime', () => {
  it('every framework adapter accepts an actor-returning gate', () => {
    // The real assertion is the one `tsc` made; this only keeps the declarations referenced.
    // All four share one gate, so behaviour is exercised through express below.
    for (const gate of [expressActor, nextActor, honoActor, nestActor]) {
      expect(typeof gate).toBe('function')
      expect(gate.length).toBe(1)
    }
  })

  it('returning the user object records it as the actor', async () => {
    const result = await iamRunAdminAuthz(WITH_USER, null, expressActor)
    expect(result).toEqual({ phase: 'ok', actor: { id: 'admin-7', role: 'admin' } })
  })

  it('a subject id is an actor', async () => {
    expect(await iamRunAdminAuthz(WITH_USER, null, expressSubjectId)).toEqual({ phase: 'ok', actor: 'admin-7' })
  })

  it('an async gate is an actor', async () => {
    expect(await iamRunAdminAuthz(WITH_USER, null, expressAsync)).toEqual({ phase: 'ok', actor: { id: 'admin-7' } })
  })

  it('the documented boolean shape still authorizes, and still names no one', async () => {
    // Widening the type must not change what a boolean does.
    expect(await iamRunAdminAuthz(WITH_USER, null, expressBoolean)).toEqual({ phase: 'ok', actor: undefined })
    expect(await iamRunAdminAuthz({ user: { id: 'u-2', role: 'viewer' } }, null, expressBoolean)).toEqual({
      phase: 'unauthorized',
    })
  })

  it('the type and the runtime predicate agree on what names someone', () => {
    // `iamIsNameableActor` is the runtime half of `IamAdminActor`, so the two must agree.
    const nameable: IamAdminAuthzAnswer[] = ['admin-7', { id: 'admin-7' }]
    for (const value of nameable) expect(iamIsNameableActor(value), `${String(value)} should name someone`).toBe(true)
    // An array satisfies `object` but names no one; the type cannot express that exclusion.
    expect(iamIsNameableActor([])).toBe(false)
    for (const value of [true, false, null, undefined, '', '   '] as IamAdminAuthzAnswer[]) {
      expect(iamIsNameableActor(value), `${String(value)} should name no one`).toBe(false)
    }
  })
})
