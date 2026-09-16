import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine/engine'
import { IAM_UNKNOWN_RESOURCE, iamDefaultResource } from '../../generic'
import { iamNestAccessGuard } from '../index'

// Nest's `inferResource` must name the same resource as the shared `iamDefaultResource` (express, hono, next),
// or a policy written for one framework does not apply in another.
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

// INFO: `request.route` is Express-only; `@nestjs/platform-fastify` sets none, so this is its normal path.
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

// SECURITY: `'*'` is the engine's wildcard sentinel, so a `@Get('*')` route must not be typed as `*`.
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

// SECURITY: express matches `/public/*` for `/public/../admin`, so the ambiguity check must run before the template.
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
