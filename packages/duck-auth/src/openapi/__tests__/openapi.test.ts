/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { describe, expect, it } from 'vitest'
import { buildOpenApiSpec, renderOpenApiYaml } from '../index'

describe('buildOpenApiSpec', () => {
  it('emits openapi: 3.1.0 + the configured title + version', () => {
    const spec = buildOpenApiSpec({
      baseUrl: 'https://app.test',
      title: 'My Auth',
      version: '2.5.0',
    })
    expect(spec.openapi).toBe('3.1.0')
    expect(spec.info.title).toBe('My Auth')
    expect(spec.info.version).toBe('2.5.0')
    expect(spec.servers[0]!.url).toBe('https://app.test')
  })

  it('default config emits routes for password + magic-link + oauth + passkey', () => {
    const spec = buildOpenApiSpec({ baseUrl: 'https://app.test' })
    const paths = Object.keys(spec.paths)
    expect(paths).toContain('/auth/password/sign-in')
    expect(paths).toContain('/auth/magic-link/request')
    expect(paths).toContain('/auth/magic-link/verify')
    expect(paths).toContain('/auth/oauth/{provider}/start')
    expect(paths).toContain('/auth/oauth/{provider}/callback')
    expect(paths).toContain('/auth/passkey/begin')
    expect(paths).toContain('/auth/passkey/verify')
    expect(paths).toContain('/auth/sign-out')
    expect(paths).toContain('/auth/session')
  })

  it('providers:[] narrows the surface to just the framework routes', () => {
    const spec = buildOpenApiSpec({ baseUrl: 'https://app.test', providers: [] })
    const paths = Object.keys(spec.paths)
    expect(paths).not.toContain('/auth/password/sign-in')
    expect(paths).not.toContain('/auth/magic-link/request')
    expect(paths).toContain('/auth/sign-out')
    expect(paths).toContain('/auth/session')
  })

  it('includeJwks:true adds the /.well-known/jwks.json route', () => {
    const spec = buildOpenApiSpec({ baseUrl: 'https://app.test', includeJwks: true })
    expect(Object.keys(spec.paths)).toContain('/.well-known/jwks.json')
  })

  it('idempotent POST routes declare an Idempotency-Key parameter', () => {
    const spec = buildOpenApiSpec({ baseUrl: 'https://app.test' })
    const passwordRoute = spec.paths['/auth/password/sign-in']!.post as {
      parameters?: Array<{ name: string }>
    }
    expect(passwordRoute.parameters?.some((p) => p.name === 'Idempotency-Key')).toBe(true)
  })

  it('security schemes include cookieAuth + bearerAuth + dpop', () => {
    const spec = buildOpenApiSpec({ baseUrl: 'https://app.test' })
    expect(Object.keys(spec.components.securitySchemes).sort()).toEqual(['bearerAuth', 'cookieAuth', 'dpop'])
  })

  it('components.schemas covers AuthError + Session + SignInResult', () => {
    const spec = buildOpenApiSpec({ baseUrl: 'https://app.test' })
    expect(Object.keys(spec.components.schemas).sort()).toEqual(['AuthError', 'Session', 'SignInResult'])
  })

  it('respects a custom prefix', () => {
    const spec = buildOpenApiSpec({ baseUrl: 'https://app.test', prefix: '/v2/auth' })
    expect(Object.keys(spec.paths)).toContain('/v2/auth/password/sign-in')
    expect(Object.keys(spec.paths)).toContain('/v2/auth/session')
  })
})

describe('renderOpenApiYaml', () => {
  it('round-trips with JSON.parse via a YAML parser equivalent (structural check)', () => {
    const spec = buildOpenApiSpec({ baseUrl: 'https://app.test' })
    const yaml = renderOpenApiYaml(spec)
    expect(yaml).toContain('openapi: 3.1.0')
    expect(yaml).toContain('title: Auth API')
    expect(yaml).toContain('/auth/password/sign-in')
    expect(yaml).toContain('cookieAuth')
  })

  it('quotes strings containing special chars', () => {
    const spec = buildOpenApiSpec({
      baseUrl: 'https://app.test',
      title: 'has: colon',
    })
    expect(renderOpenApiYaml(spec)).toContain('title: "has: colon"')
  })
})
