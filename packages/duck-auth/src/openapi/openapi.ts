/** OpenAPI 3.1 spec emitter for the framework-adapter routes. */

import type { OpenApi } from './openapi.types'

/** Build the OpenAPI 3.1 spec for the configured providers. */
export function buildOpenApiSpec(cfg: OpenApi.Cfg): OpenApi.ISpec {
  const title = cfg.title ?? 'Auth API'
  const version = cfg.version ?? '0.1.0'
  const prefix = cfg.prefix ?? '/auth'
  const providers = new Set(cfg.providers ?? ['magic-link', 'oauth', 'passkey', 'totp'])

  const spec: OpenApi.ISpec = {
    openapi: '3.1.0',
    info: {
      title,
      version,
      description:
        'Routes mounted by `@gentleduck/auth` framework adapters. Exact mount paths depend on adapter configuration; this spec uses the defaults.',
    },
    servers: [{ url: cfg.baseUrl }],
    paths: {},
    components: {
      schemas: {
        AuthError: schemaAuthError(),
        Session: schemaSession(),
        SessionResult: schemaSessionResult(),
      },
      securitySchemes: {
        cookieAuth: { type: 'apiKey', in: 'cookie', name: '__Host-duck-sid' },
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        dpop: { type: 'apiKey', in: 'header', name: 'DPoP' },
      },
    },
    security: [{ cookieAuth: [] }, { bearerAuth: [] }],
  }

  // The routes the framework adapters register at default config, one for one with `mountHono`'s skip
  // flags. `/signin` takes any registered provider by id, so no provider gates it.
  spec.paths[`${prefix}/signin`] = {
    post: routeSignsIn({
      summary: 'Sign in through a registered provider',
      body: {
        type: 'object',
        required: ['providerId'],
        properties: {
          providerId: { type: 'string', pattern: '^[a-zA-Z0-9_-]{1,64}$' },
          input: { type: 'object', additionalProperties: true },
        },
      },
    }),
  }

  spec.paths[`${prefix}/signout`] = {
    post: {
      summary: 'Revoke the current session',
      security: [{ cookieAuth: [] }, { bearerAuth: [] }],
      responses: {
        '200': { description: 'Session revoked; clears the session cookie' },
        '401': errResponse(),
      },
    },
  }

  spec.paths[`${prefix}/session`] = {
    get: {
      summary: 'Return the current session and identity',
      security: [{ cookieAuth: [] }, { bearerAuth: [] }],
      responses: { '200': okJson(refSessionResult()), '401': errResponse() },
    },
  }

  spec.paths[`${prefix}/providers/{id}/begin`] = {
    post: routePost({
      summary: 'Begin a two-step provider flow (oauth start, magic-link request, ...)',
      // Provider-specific; `magic-link` takes `{ email }`, oauth takes none.
      body: { type: 'object', additionalProperties: true },
      ok: { type: 'object', additionalProperties: true },
      params: [pathParam('id')],
    }),
  }

  if (providers.has('oauth')) {
    spec.paths[`${prefix}/providers/{provider}/callback`] = {
      get: {
        summary: 'Complete an oauth authorization-code flow + issue a session',
        parameters: [
          pathParam('provider'),
          { name: 'code', in: 'query', required: true, schema: { type: 'string' } },
          { name: 'state', in: 'query', required: true, schema: { type: 'string' } },
        ],
        responses: {
          '200': signedInResponse(),
          '302': { description: 'Redirect carried by the provider intents' },
          '400': errResponse(),
          '401': stepUpResponse(),
        },
      },
    }
  }

  if (providers.has('magic-link')) {
    spec.paths[`${prefix}/magic-link/verify`] = {
      get: {
        summary: 'Exchange a magic-link token for a session',
        parameters: [{ name: 'token', in: 'query', required: true, schema: { type: 'string' } }],
        responses: {
          '200': signedInResponse(),
          '302': { description: 'Redirect carried by the provider intents' },
          '400': errResponse(),
          '401': stepUpResponse(),
        },
      },
    }
  }

  if (providers.has('passkey')) {
    spec.paths[`${prefix}/passkey/begin`] = {
      post: routePost({
        summary: 'Issue WebAuthn authentication options',
        body: {
          type: 'object',
          required: ['sessionId'],
          properties: { email: { type: 'string', format: 'email' }, sessionId: { type: 'string' } },
        },
        ok: { type: 'object', additionalProperties: true },
      }),
    }
    spec.paths[`${prefix}/passkey/complete`] = {
      post: routeSignsIn({
        summary: 'Verify a WebAuthn assertion + issue a session',
        body: {
          type: 'object',
          required: ['sessionId', 'response'],
          properties: { sessionId: { type: 'string' }, response: { type: 'object' } },
        },
      }),
    }
  }

  if (providers.has('totp')) {
    spec.paths[`${prefix}/mfa/totp/begin`] = {
      post: routeAuthed({
        summary: 'Begin TOTP enrollment',
        body: { type: 'object', properties: { label: { type: 'string', maxLength: 128 } } },
        ok: { type: 'object', additionalProperties: true },
      }),
    }
    spec.paths[`${prefix}/mfa/totp/confirm`] = {
      post: routeAuthed({
        summary: 'Confirm TOTP enrollment with a code',
        body: totpCodeBody(),
        ok: { type: 'object', additionalProperties: true },
      }),
    }
    spec.paths[`${prefix}/mfa/totp/verify`] = {
      post: routeAuthed({
        summary: 'Verify a TOTP code against the enrolled factor',
        body: totpCodeBody(),
        ok: { type: 'object', properties: { ok: { type: 'boolean' } } },
      }),
    }
    spec.paths[`${prefix}/mfa/totp/remove`] = {
      post: routeAuthed({
        summary: 'Remove the enrolled TOTP factor; requires a satisfied step-up',
        body: totpCodeBody(),
        ok: { type: 'object', properties: { ok: { type: 'boolean' } } },
      }),
    }
    spec.paths[`${prefix}/mfa/backup-codes/regenerate`] = {
      post: routeAuthed({
        summary: 'Replace the identity backup codes; requires a satisfied step-up',
        body: { type: 'object' },
        ok: { type: 'object', additionalProperties: true },
      }),
    }
  }

  if (cfg.includeJwks) {
    spec.paths['/.well-known/jwks.json'] = {
      get: {
        summary: 'JSON Web Key Set for verifying issued JWT access tokens',
        responses: {
          '200': okJson({
            type: 'object',
            properties: { keys: { type: 'array', items: { type: 'object' } } },
          }),
        },
      },
    }
  }

  return spec
}

/**
 * Renders the spec as YAML. A trivial emitter over primitives, arrays and objects in their natural
 * order: enough for the shape built here, and not a general-purpose YAML library.
 */
export function renderOpenApiYaml(spec: OpenApi.ISpec): string {
  return yamlify(spec, 0)
}

function yamlify(value: unknown, indent: number): string {
  const pad = '  '.repeat(indent)
  if (value === null || value === undefined) return 'null\n'
  if (typeof value === 'string') return `${quoteIfNeeded(value)}\n`
  if (typeof value === 'number' || typeof value === 'boolean') return `${String(value)}\n`
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]\n'
    let out = '\n'
    for (const item of value) {
      const rendered = yamlify(item, indent + 1).trimEnd()
      if (rendered.includes('\n')) {
        out += `${pad}- ${rendered.slice(0, rendered.indexOf('\n'))}\n`
        out += `${rendered.slice(rendered.indexOf('\n') + 1)}\n`
      } else {
        out += `${pad}- ${rendered}\n`
      }
    }
    return out
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value)
    if (keys.length === 0) return '{}\n'
    let out = indent === 0 ? '' : '\n'
    for (const k of keys) {
      const v: unknown = Reflect.get(value, k)
      const head = `${pad}${quoteKey(k)}:`
      if (v !== null && typeof v === 'object') {
        out += `${head}${yamlify(v, indent + 1)}`
      } else {
        out += `${head} ${yamlify(v, indent + 1)}`
      }
    }
    return out
  }
  return `${String(value)}\n`
}

function quoteIfNeeded(s: string): string {
  if (/[:#\n]|^\s|\s$|^-/.test(s)) return JSON.stringify(s)
  return s
}

function quoteKey(s: string): string {
  if (/^[A-Za-z0-9_\-./]+$/.test(s)) return s
  return JSON.stringify(s)
}

function schemaAuthError(): Record<string, unknown> {
  return {
    type: 'object',
    required: ['code', 'status'],
    properties: {
      code: { type: 'string', pattern: '^AUTH/[A-Z_]+$' },
      status: { type: 'integer', minimum: 100, maximum: 599 },
      detail: { type: 'string' },
    },
    additionalProperties: true,
  }
}

function schemaSession(): Record<string, unknown> {
  return {
    type: 'object',
    required: ['id', 'aal', 'expiresAt'],
    properties: {
      id: { type: 'string', description: 'Server-side session id (authSha256 of plaintext sid)' },
      identityId: { type: ['string', 'null'] },
      // `null` on every session of a single-tenant deployment, so the old
      // non-nullable `string` described the uncommon case as the only one.
      tenantId: { type: ['string', 'null'] },
      kind: { type: 'string', enum: ['guest', 'user', 'apikey'] },
      aal: { type: 'integer', enum: [1, 2, 3] },
      factors: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            method: {
              type: 'string',
              enum: ['password', 'passkey', 'totp', 'oauth', 'magic-link', 'webauthn', 'sms', 'api-key', 'backup-code'],
            },
            completedAt: { format: 'date-time', type: 'string' },
          },
        },
      },
      // ISO strings, not epoch integers: the handler answers `Response.json(session)`, and
      // `JSON.stringify` writes a `Date` as `"2026-09-04T09:00:00.000Z"`. Declaring `integer` here
      // generates a client typing these `number` for a field that is a string on the wire.
      createdAt: { format: 'date-time', type: 'string' },
      updatedAt: { format: 'date-time', type: 'string' },
      rotatedAt: { format: 'date-time', type: 'string' },
      expiresAt: { format: 'date-time', type: 'string' },
      absoluteExpiresAt: { format: 'date-time', type: 'string' },
      fresh: { type: 'boolean' },
      // Captured at create for hijack detection. Non-secret, and the handler already writes them, so
      // leaving them undeclared only made the generated client narrower than the wire.
      ip: { type: ['string', 'null'] },
      userAgent: { type: ['string', 'null'] },
      fingerprint: { type: ['string', 'null'] },
      actingAs: {
        type: ['object', 'null'],
        properties: {
          realIdentityId: { type: 'string' },
          startedAt: { format: 'date-time', type: 'string' },
          reason: { type: 'string' },
          expiresAt: { format: 'date-time', type: 'string' },
        },
      },
    },
  }
}

/** Every sign-in completing route answers the same way: the session rides in the `Set-Cookie` the
 *  transport issues, and the body is empty. Read it back with `GET /session`. */
function signedInResponse(): Record<string, unknown> {
  return {
    description: 'Signed in. The session cookie is set and the body is empty; read it with GET /session.',
    headers: { 'Set-Cookie': { schema: { type: 'string' } } },
  }
}

/** A second factor is an error, not a 200 with a flag: the engine throws `AUTH_STEP_UP_REQUIRED` and
 *  the adapter maps it to a 401 carrying `detail.challenge`. */
function stepUpResponse(): Record<string, unknown> {
  return {
    description: 'AuthError; `AUTH_STEP_UP_REQUIRED` carries `detail.challenge` with the allowed methods.',
    content: { 'application/json': { schema: { $ref: '#/components/schemas/AuthError' } } },
  }
}

/** What `GET /session` answers: the envelope, not a bare session. Both members are null when no
 *  session resolves, which is a 200 and not a 401. */
function schemaSessionResult(): Record<string, unknown> {
  return {
    type: 'object',
    required: ['session', 'identity'],
    properties: {
      session: { oneOf: [{ $ref: '#/components/schemas/Session' }, { type: 'null' }] },
      identity: { type: ['object', 'null'], additionalProperties: true },
    },
  }
}

function pathParam(name: string): Record<string, unknown> {
  return { name, in: 'path', required: true, schema: { type: 'string' } }
}

/** The `{ code }` body the three TOTP routes share; `parseBodyStringField` bounds it at 64. */
function totpCodeBody(): Record<string, unknown> {
  return { type: 'object', required: ['code'], properties: { code: { type: 'string', maxLength: 64 } } }
}

function refSessionResult(): Record<string, unknown> {
  return { $ref: '#/components/schemas/SessionResult' }
}

function okJson(schema: Record<string, unknown>): Record<string, unknown> {
  return {
    description: 'Successful response',
    content: { 'application/json': { schema } },
  }
}

function errResponse(): Record<string, unknown> {
  return {
    description: 'AuthError',
    content: { 'application/json': { schema: { $ref: '#/components/schemas/AuthError' } } },
  }
}

function routePost(opts: {
  summary: string
  body: Record<string, unknown>
  ok: Record<string, unknown>
  params?: Array<Record<string, unknown>>
  security?: Array<Record<string, never[]>>
}): Record<string, unknown> {
  const route: Record<string, unknown> = {
    summary: opts.summary,
    requestBody: {
      required: true,
      content: { 'application/json': { schema: opts.body } },
    },
    responses: {
      '200': okJson(opts.ok),
      '400': errResponse(),
      '401': errResponse(),
      '429': errResponse(),
    },
  }
  if (opts.params) route.parameters = opts.params
  if (opts.security) route.security = opts.security
  return route
}

/** A route that completes a sign-in: no response body, and a 401 that may be a step-up demand. */
function routeSignsIn(opts: {
  summary: string
  body: Record<string, unknown>
  params?: Array<Record<string, unknown>>
}): Record<string, unknown> {
  const route = routePost({ ...opts, ok: {} })
  route.responses = {
    '200': signedInResponse(),
    '400': errResponse(),
    '401': stepUpResponse(),
    '429': errResponse(),
  }
  return route
}

/** A route the adapter refuses without a resolved session. */
function routeAuthed(opts: {
  summary: string
  body: Record<string, unknown>
  ok: Record<string, unknown>
}): Record<string, unknown> {
  return routePost({ ...opts, security: [{ cookieAuth: [] }, { bearerAuth: [] }] })
}
