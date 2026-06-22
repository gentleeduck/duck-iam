/** OpenAPI 3.1 spec emitter for the framework-adapter routes. */

/** Build the OpenAPI 3.1 spec for the configured providers. */
export function authBuildOpenApiSpec(config: AuthOpenApi.IConfig): AuthOpenApi.ISpec {
  const title = config.title ?? 'Auth API'
  const version = config.version ?? '0.1.0'
  const prefix = config.prefix ?? '/auth'
  const providers = new Set(config.providers ?? ['password', 'magic-link', 'oauth', 'passkey'])

  const spec: AuthOpenApi.ISpec = {
    openapi: '3.1.0',
    info: {
      title,
      version,
      description:
        'Routes mounted by `@gentleduck/auth` framework adapters. Exact mount paths depend on adapter configuration; this spec uses the defaults.',
    },
    servers: [{ url: config.baseUrl }],
    paths: {},
    components: {
      schemas: {
        AuthError: schemaAuthError(),
        AuthSession: schemaSession(),
        SignInResult: schemaSignInResult(),
      },
      securitySchemes: {
        cookieAuth: { type: 'apiKey', in: 'cookie', name: '__Host-duck-sid' },
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        dpop: { type: 'apiKey', in: 'header', name: 'DPoP' },
      },
    },
    security: [{ cookieAuth: [] }, { bearerAuth: [] }],
  }

  if (providers.has('password')) {
    spec.paths[`${prefix}/password/sign-in`] = {
      post: routePost({
        summary: 'Sign in with email + password',
        body: schemaPasswordCompleteIn(),
        ok: refSignInResult(),
        idempotent: true,
      }),
    }
  }

  if (providers.has('magic-link')) {
    spec.paths[`${prefix}/magic-link/request`] = {
      post: routePost({
        summary: 'Issue a one-time magic-link token to the email channel',
        body: { type: 'object', properties: { email: { type: 'string', format: 'email' } }, required: ['email'] },
        ok: { type: 'object', properties: { delivered: { type: 'boolean' } } },
        idempotent: true,
      }),
    }
    spec.paths[`${prefix}/magic-link/verify`] = {
      post: routePost({
        summary: 'Exchange a magic-link token for a session',
        body: { type: 'object', properties: { token: { type: 'string' } }, required: ['token'] },
        ok: refSignInResult(),
        idempotent: true,
      }),
    }
  }

  if (providers.has('oauth')) {
    spec.paths[`${prefix}/oauth/{provider}/start`] = {
      get: {
        summary: 'Begin an OAuth authorization-code flow',
        parameters: [pathProvider()],
        responses: { '302': { description: 'Redirect to the provider authorization endpoint' } },
      },
    }
    spec.paths[`${prefix}/oauth/{provider}/callback`] = {
      get: {
        summary: 'Complete an OAuth authorization-code flow + issue a session',
        parameters: [
          pathProvider(),
          { name: 'code', in: 'query', required: true, schema: { type: 'string' } },
          { name: 'state', in: 'query', required: true, schema: { type: 'string' } },
        ],
        responses: {
          '200': okJson(refSignInResult()),
          '400': errResponse(),
          '401': errResponse(),
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
          properties: { email: { type: 'string', format: 'email' }, sessionId: { type: 'string' } },
          required: ['sessionId'],
        },
        ok: { type: 'object', additionalProperties: true },
        idempotent: false,
      }),
    }
    spec.paths[`${prefix}/passkey/verify`] = {
      post: routePost({
        summary: 'Verify a WebAuthn assertion + issue a session',
        body: {
          type: 'object',
          properties: { sessionId: { type: 'string' }, response: { type: 'object' } },
          required: ['sessionId', 'response'],
        },
        ok: refSignInResult(),
        idempotent: true,
      }),
    }
  }

  spec.paths[`${prefix}/sign-out`] = {
    post: {
      summary: 'Revoke the current session',
      security: [{ cookieAuth: [] }, { bearerAuth: [] }],
      responses: { '204': { description: 'No content' }, '401': errResponse() },
    },
  }

  spec.paths[`${prefix}/session`] = {
    get: {
      summary: 'Return the current session and identity',
      security: [{ cookieAuth: [] }, { bearerAuth: [] }],
      responses: {
        '200': okJson({ $ref: '#/components/schemas/AuthSession' }),
        '401': errResponse(),
      },
    },
  }

  if (config.includeJwks) {
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
 * Render the spec as YAML. Trivial emitter: handles primitives + arrays +
 * objects in their natural order. Sufficient for the OpenApiSpec shape we
 * produce; not a general-purpose YAML library.
 */
export function authRenderOpenApiYaml(spec: AuthOpenApi.ISpec): string {
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
      tenantId: { type: 'string' },
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
            completedAt: { type: 'integer' },
          },
        },
      },
      expiresAt: { type: 'integer' },
      absoluteExpiresAt: { type: 'integer' },
      fresh: { type: 'boolean' },
    },
  }
}

function schemaSignInResult(): Record<string, unknown> {
  return {
    type: 'object',
    oneOf: [
      {
        type: 'object',
        required: ['session'],
        properties: { session: { $ref: '#/components/schemas/AuthSession' } },
      },
      {
        type: 'object',
        required: ['mfaRequired'],
        properties: {
          mfaRequired: { type: 'boolean', enum: [true] },
          methods: { type: 'array', items: { type: 'string' } },
        },
      },
    ],
  }
}

function schemaPasswordCompleteIn(): Record<string, unknown> {
  return {
    type: 'object',
    required: ['email', 'password'],
    properties: {
      email: { type: 'string', format: 'email' },
      password: { type: 'string', minLength: 8, maxLength: 4096 },
    },
  }
}

function refSignInResult(): Record<string, unknown> {
  return { $ref: '#/components/schemas/SignInResult' }
}

function pathProvider(): Record<string, unknown> {
  return {
    name: 'provider',
    in: 'path',
    required: true,
    schema: { type: 'string', enum: ['authGoogle', 'authGithub'] },
  }
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
  idempotent?: boolean
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
  if (opts.idempotent) {
    route.parameters = [
      {
        name: 'AuthIdempotency-Key',
        in: 'header',
        required: false,
        schema: { type: 'string', maxLength: 200 },
        description: 'Optional client-supplied key; replays the cached response within ttl.',
      },
    ]
  }
  return route
}

export namespace AuthOpenApi {
  export interface IConfig {
    /** Server URL the routes are mounted under. */
    baseUrl: string
    /** Spec title. Default `Auth API`. */
    title?: string
    /** Spec version. Default `0.1.0`. */
    version?: string
    /** Mount prefix; routes are emitted under `${baseUrl}${prefix}/<name>`. Default `/auth`. */
    prefix?: string
    /** Enabled providers; controls which routes appear. Default emits all. */
    providers?: Array<'password' | 'magic-link' | 'oauth' | 'passkey'>
    /** Add `/.well-known/jwks.json` to the spec (JWT transport only). Default false. */
    includeJwks?: boolean
  }

  export interface ISpec {
    openapi: '3.1.0'
    info: { title: string; version: string; description?: string }
    servers: Array<{ url: string }>
    paths: Record<string, Record<string, unknown>>
    components: {
      schemas: Record<string, unknown>
      securitySchemes: Record<string, unknown>
    }
    security: Array<Record<string, never[]>>
  }
}
