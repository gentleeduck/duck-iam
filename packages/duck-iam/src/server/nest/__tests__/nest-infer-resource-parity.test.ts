import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine/engine'
import { IAM_UNKNOWN_RESOURCE, iamDefaultResource } from '../../generic'
import { iamNestAccessGuard } from '../index'

/**
 * Nest's `inferResource` and the shared `iamDefaultResource` that express, hono
 * and next use must name the same resource for the same request, or a policy
 * written against one framework silently does not apply in the other.
 */
function makeCtx(opts: { method?: string; path?: string; routePath?: string }) {
  return {
    getHandler() {
      const handler = function h() {}
      Object.defineProperty(handler, '__accessMeta', { value: { infer: true } })
      return handler
    },
    switchToHttp() {
      return {
        getRequest() {
          return {
            headers: {},
            method: opts.method ?? 'GET',
            params: {},
            path: opts.path ?? '/',
            route: opts.routePath === undefined ? undefined : { path: opts.routePath },
            user: { id: 'u1' },
          }
        },
      }
    },
  }
}

async function inferredResource(opts: { path?: string; routePath?: string }): Promise<unknown> {
  const engine = new IamEngine({ adapter: new IamMemoryAdapter({ roles: [] }), cacheTTL: 0 })
  const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
  await iamNestAccessGuard(engine)(makeCtx(opts))
  const resource = can.mock.calls[0]?.[2]
  can.mockRestore()
  return typeof resource === 'object' && resource !== null ? Reflect.get(resource, 'type') : resource
}

/**
 * `request.route` is an Express-ism. `@nestjs/platform-fastify` exposes
 * `routeOptions.url` (v5) / `routerPath` (v4) and sets no `route`, so this is
 * the normal path there, not an edge case - and it used to take the *last*
 * segment, authorizing `/posts/42` against the id `42`.
 */
describe('no route template: agrees with iamDefaultResource', () => {
  it.each([
    '/posts/42',
    '/orgs/o1/members/m2',
    '/admin',
    '/',
    '/admin/%252e%252e/posts',
    '/%zz/admin',
    '/posts/%252e%252e/admin',
    '/posts/../admin',
  ])('%s', async (path) => {
    expect(await inferredResource({ path })).toBe(iamDefaultResource(path).type)
  })

  // Control: the agreement above is not "both say unknown for everything".
  it('control: a plain path still yields its own first segment', () => {
    expect(iamDefaultResource('/posts/42').type).toBe('posts')
    expect(iamDefaultResource('/admin/%252e%252e/posts').type).toBe(IAM_UNKNOWN_RESOURCE)
  })
})

/**
 * `'*'` is the engine's wildcard *pattern* sentinel: `matchesResource` returns
 * true for it unconditionally. Returning it as a request's resource *type*
 * inverted the intent - a `@Get('*')` route matched every `resources: ['*']`
 * allow rule and no targeted deny.
 */
describe('route template', () => {
  it.each([
    ['/posts/:id', 'posts'],
    ['/orgs/:orgId/members/:id', 'orgs'],
    ['/admin', 'admin'],
    ['/', 'root'],
    ['/secrets/*', 'secrets'],
    ['/*', IAM_UNKNOWN_RESOURCE],
    ['*', IAM_UNKNOWN_RESOURCE],
    ['/:id', 'root'],
  ])('%s -> %s', async (routePath, expected) => {
    expect(await inferredResource({ path: '/whatever/1', routePath })).toBe(expected)
  })

  it('names the same resource as the raw-path branch for the common shape', async () => {
    expect(await inferredResource({ path: '/posts/42', routePath: '/posts/:id' })).toBe(
      await inferredResource({ path: '/posts/42' }),
    )
  })
})

/**
 * The ambiguity check runs *before* the template branch, and its comment
 * records why: express matched `/public/*` for `/public/../admin`, so nest
 * returned a confident `public` and authorized the request as public while
 * hono and next served `/admin`.
 *
 * Every template case above supplies a safe path beside the template
 * (`path: '/whatever/1'`), and every ambiguous-path case above supplies no
 * template - so the one combination the guard exists for was never built, and
 * deleting the guard left the whole file green. These pair the two.
 */
describe('an ambiguous path outranks a matched route template', () => {
  it.each([
    ['/public/../admin', '/public/*'],
    ['/public/%2e%2e/admin', '/public/*'],
    ['/posts/../../etc/passwd', '/posts/:id'],
    ['/a/./b', '/a/*'],
  ])('%s matched as %s still names no resource', async (path, routePath) => {
    expect(await inferredResource({ path, routePath })).toBe(IAM_UNKNOWN_RESOURCE)
  })

  it('control: the same template with an unambiguous path names its resource', async () => {
    // Without this, a guard that refused every templated request would pass.
    expect(await inferredResource({ path: '/public/index.html', routePath: '/public/*' })).toBe('public')
    expect(await inferredResource({ path: '/posts/42', routePath: '/posts/:id' })).toBe('posts')
  })
})
