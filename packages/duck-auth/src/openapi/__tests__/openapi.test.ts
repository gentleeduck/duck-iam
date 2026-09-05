import { describe, expect, it } from 'vitest'
import type { Sessions } from '~/core/sessions/sessions.types'
import { buildOpenApiSpec, renderOpenApiYaml } from '../index'

describe('authBuildOpenApiSpec', () => {
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

describe('authRenderOpenApiYaml', () => {
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

/**
 * The documented `Session` shape has to match the bytes the handler actually
 * sends. `Response.json(session)` is `JSON.stringify`, so every `Date` on the
 * row leaves as an ISO string - which the spec used to document as `integer`,
 * giving every generated client a `number` for a field that is a string.
 */
describe('the Session schema describes what the handler serialises', () => {
  const NOW = new Date('2026-09-04T09:00:00.000Z')
  const LATER = new Date('2026-09-04T10:00:00.000Z')

  const row: Sessions.Me = {
    aal: 2,
    absoluteExpiresAt: LATER,
    actingAs: null,
    createdAt: NOW,
    csrfHash: null,
    expiresAt: LATER,
    factors: [{ completedAt: NOW, method: 'totp' }],
    fingerprint: null,
    fresh: true,
    id: 's1',
    identityId: 'i1',
    ip: null,
    kind: 'user',
    rotatedAt: NOW,
    tenantId: null,
    userAgent: null,
  }

  /** The JSON type names a value legitimately answers to. */
  function jsonTypesOf(value: unknown): string[] {
    if (value === null) return ['null']
    if (Array.isArray(value)) return ['array']
    if (typeof value === 'number') return Number.isInteger(value) ? ['number', 'integer'] : ['number']
    if (typeof value === 'object') return ['object']
    return [typeof value]
  }

  const wire = JSON.parse(JSON.stringify(row)) as Record<string, unknown>
  const schema = buildOpenApiSpec({ baseUrl: 'https://app.test' }).components.schemas.Session as {
    properties: Record<string, { type?: string | string[]; format?: string; items?: unknown }>
  }

  for (const [field, declared] of Object.entries(schema.properties)) {
    if (!(field in wire)) continue
    it(`${field} arrives as the spec declares`, () => {
      const allowed = Array.isArray(declared.type) ? declared.type : [declared.type]
      expect(jsonTypesOf(wire[field]).some((actual) => allowed.includes(actual))).toBe(true)
    })
  }

  it('every documented date field is a parseable ISO string', () => {
    for (const [field, declared] of Object.entries(schema.properties)) {
      if (declared.format !== 'date-time') continue
      const value = wire[field]
      expect(typeof value, `${field} must serialise to a string`).toBe('string')
      expect(Number.isFinite(new Date(value as string).getTime())).toBe(true)
    }
  })

  it('the nested factor timestamp is documented the same way', () => {
    const items = schema.properties.factors?.items as { properties: Record<string, { format?: string }> }
    expect(items.properties.completedAt?.format).toBe('date-time')
    expect(typeof (wire.factors as Record<string, unknown>[])[0]?.completedAt).toBe('string')
  })
})
