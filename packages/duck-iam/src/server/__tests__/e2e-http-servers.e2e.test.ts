// Real-HTTP sweep over the five server integrations, driven from a raw socket so the request-target bytes are exact.
// SECURITY: the subject may read `public` and nothing on `admin`, so no request may ever reach the `/admin` handler.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { connect } from 'node:net'
import { Hono } from 'hono'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine'
import type { AccessControl, IamRequest } from '../../core/types'
import { iamAccessMiddleware as expressAccessMiddleware } from '../express'
import { iamActionForMethod, iamDefaultResource, iamExtractEnvironment, iamNormalizePathname } from '../generic'
import { iamAccessMiddleware as honoAccessMiddleware } from '../hono'
import { IamAuthorize, iamNestAccessGuard } from '../nest'
import { createIamNextMiddleware } from '../next'

// ---------------------------------------------------------------------------
// Fixture: one subject, one grant. `public/read` yes, `admin/*` no.
// ---------------------------------------------------------------------------

type Action = 'read' | 'create' | 'update' | 'delete' | 'unknown'
type ResourceType = 'public' | 'admin' | 'unknown' | 'root'
type RoleId = 'viewer'
type Scope = 'org-1'

const SUBJECT = 'user-viewer'

const viewerRole: AccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'viewer',
  name: 'Viewer',
  permissions: [{ action: 'read', resource: 'public' }],
}

/** One engine call as the integration derived it. */
interface RecordedCall {
  subject: string
  action: string
  resource: IamRequest.IResource
  environment: IamRequest.IEnvironment | undefined
  scope: string | undefined
}

interface Instrumented {
  engine: IamEngine<Action, ResourceType, RoleId, Scope>
  adapter: IamMemoryAdapter<Action, ResourceType, RoleId, Scope>
  calls: RecordedCall[]
  /** Set to make every subsequent `can()` throw, to test fail-closed. */
  explode: { on: boolean }
}

/** Builds an engine whose `can` records the (subject, action, resource, environment, scope) each integration asked. */
function makeEngine(
  opts: {
    policies?: AccessControl.IPolicy<Action, ResourceType, RoleId>[]
    policyCombine?: AccessControl.PolicyCombine
  } = {},
): Instrumented {
  const adapter = new IamMemoryAdapter<Action, ResourceType, RoleId, Scope>({
    assignments: { [SUBJECT]: ['viewer'] },
    policies: opts.policies ?? [],
    roles: [viewerRole],
  })
  const engine = new IamEngine<Action, ResourceType, RoleId, Scope>({
    adapter,
    cacheTTL: 0,
    ...(opts.policyCombine ? { policyCombine: opts.policyCombine } : {}),
  })
  const calls: RecordedCall[] = []
  const explode = { on: false }
  const original = engine.can.bind(engine)
  engine.can = async (
    subject: string,
    action: Action,
    resource: IamRequest.IResource<ResourceType>,
    environment?: IamRequest.IEnvironment,
    scope?: Scope,
  ) => {
    calls.push({ action, environment, resource, scope, subject })
    if (explode.on) throw new Error('engine exploded')
    return original(subject, action, resource, environment, scope)
  }
  return { adapter, calls, engine, explode }
}

// ---------------------------------------------------------------------------
// Raw HTTP client: `fetch` would normalise the request-target before sending.
// ---------------------------------------------------------------------------

interface RawResponse {
  status: number
  headers: Record<string, string>
  body: string
  /** Parsed JSON body when the body parses, else undefined. */
  json: Record<string, unknown> | undefined
  /** True when the socket closed before a status line arrived. */
  aborted: boolean
}

/** Undo `Transfer-Encoding: chunked` framing. */
function dechunk(raw: string): string {
  let rest = raw
  let out = ''
  while (rest.length > 0) {
    const eol = rest.indexOf('\r\n')
    if (eol === -1) break
    const size = Number.parseInt(rest.slice(0, eol).split(';')[0] ?? '', 16)
    if (!Number.isInteger(size) || size <= 0) break
    out += rest.slice(eol + 2, eol + 2 + size)
    rest = rest.slice(eol + 2 + size + 2)
  }
  return out
}

/**
 * Sends a literal request line, headers and body down a socket and parses the reply.
 * `requestTarget` goes out verbatim: no encoding, no dot-segment resolution.
 */
function raw(
  port: number,
  method: string,
  requestTarget: string,
  opts: { headers?: [string, string][]; body?: string } = {},
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, '127.0.0.1')
    const chunks: Buffer[] = []
    socket.setTimeout(10_000, () => {
      socket.destroy(new Error('raw request timed out'))
    })
    socket.on('connect', () => {
      const headers: [string, string][] = [
        ['Host', `127.0.0.1:${port}`],
        ['Connection', 'close'],
        ...(opts.headers ?? []),
      ]
      if (opts.body !== undefined) {
        headers.push(['Content-Length', String(Buffer.byteLength(opts.body))])
      }
      const head = `${method} ${requestTarget} HTTP/1.1\r\n${headers
        .map(([k, v]) => `${k}: ${v}`)
        .join('\r\n')}\r\n\r\n`
      socket.write(head)
      if (opts.body !== undefined) socket.write(opts.body)
    })
    socket.on('data', (d: Buffer) => chunks.push(d))
    socket.on('error', reject)
    socket.on('close', () => {
      const text = Buffer.concat(chunks).toString('utf8')
      const split = text.indexOf('\r\n\r\n')
      if (split === -1) {
        resolve({ aborted: true, body: text, headers: {}, json: undefined, status: 0 })
        return
      }
      const headLines = text.slice(0, split).split('\r\n')
      const statusLine = headLines[0] ?? ''
      const status = Number(statusLine.split(' ')[1] ?? 0)
      const headers: Record<string, string> = {}
      for (const line of headLines.slice(1)) {
        const idx = line.indexOf(':')
        if (idx > 0) headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim()
      }
      const rawBody = text.slice(split + 4)
      // Node sends `res.end(buffer)` without Content-Length as chunked; undo it or JSON assertions read undefined.
      const body = headers['transfer-encoding']?.includes('chunked') ? dechunk(rawBody) : rawBody
      let json: Record<string, unknown> | undefined
      try {
        const parsed: unknown = JSON.parse(body)
        json = typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : undefined
      } catch {
        json = undefined
      }
      resolve({ aborted: false, body, headers, json, status })
    })
  })
}

/** A booted framework under test. */
interface Rig {
  name: string
  port: number
  calls: RecordedCall[]
  explode: { on: boolean }
  close: () => Promise<void>
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address()
      if (addr === null || typeof addr === 'string') {
        reject(new Error('server did not bind to a TCP port'))
        return
      }
      resolve(addr.port)
    })
  })
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.closeAllConnections?.()
    server.close(() => resolve())
  })
}

const JSON_HEADERS = { 'content-type': 'application/json' }

// ---------------------------------------------------------------------------
// Rig: express (real express, real listener)
// ---------------------------------------------------------------------------

/** Bridges the structurally typed middleware onto express's nominal `RequestHandler`; the casts change no value. */
function useIamMiddleware(
  app: { use: (h: (req: never, res: never, next: (err?: unknown) => void) => void) => unknown },
  mw: ReturnType<typeof expressAccessMiddleware>,
): void {
  app.use((req, res, next) => {
    void mw(req as never, res as never, next)
  })
}

async function startExpress({ calls, engine, explode }: Instrumented): Promise<Rig> {
  const { default: express } = await import('express')
  const app = express()
  app.disable('x-powered-by')
  app.use(express.json({ strict: false, type: () => true }))
  // Identity is set by trusted upstream auth, exactly as the JSDoc prescribes.
  app.use((req, _res, next) => {
    ;(req as unknown as { user: { id: string } }).user = { id: SUBJECT }
    next()
  })
  useIamMiddleware(app, expressAccessMiddleware(engine))
  app.all('/admin{/*rest}', (_req, res) => {
    res.json({ served: 'admin' })
  })
  app.all('/public{/*rest}', (_req, res) => {
    res.json({ served: 'public' })
  })
  app.use((_req, res) => {
    res.status(404).json({ served: 'none' })
  })
  const server = app.listen(0, '127.0.0.1')
  await new Promise<void>((resolve, reject) => {
    server.once('listening', () => resolve())
    server.once('error', reject)
  })
  const addr = server.address()
  if (addr === null || typeof addr === 'string') throw new Error('express did not bind')
  return {
    calls,
    close: () => closeServer(server),
    explode,
    name: 'express',
    port: addr.port,
  }
}

/**
 * Positive control outside `RIG_NAMES`: express with `trustProxy` on, the only rig where a forwarded IP should arrive.
 * Without it, five `undefined` IPs would satisfy every `environment.ip` agreement check.
 */
async function startExpressTrustingProxy({ calls, engine, explode }: Instrumented): Promise<Rig> {
  const { default: express } = await import('express')
  const app = express()
  app.disable('x-powered-by')
  // The app trusts its proxies, so `req.ip` is already the client address and `iamExtractEnvironment` reads it first.
  app.set('trust proxy', true)
  app.use((req, _res, next) => {
    ;(req as unknown as { user: { id: string } }).user = { id: SUBJECT }
    next()
  })
  useIamMiddleware(
    app,
    expressAccessMiddleware(engine, {
      // The documented opt-in, verbatim from `iamExtractEnvironment`'s JSDoc.
      getEnvironment: (req) => iamExtractEnvironment(req, { trustProxy: true }),
    }),
  )
  app.all('/public{/*rest}', (_req, res) => {
    res.json({ served: 'public' })
  })
  app.use((_req, res) => {
    res.status(404).json({ served: 'none' })
  })
  const server = app.listen(0, '127.0.0.1')
  await new Promise<void>((resolve, reject) => {
    server.once('listening', () => resolve())
    server.once('error', reject)
  })
  const addr = server.address()
  if (addr === null || typeof addr === 'string') throw new Error('express-trusted did not bind')
  return { calls, close: () => closeServer(server), explode, name: 'express-trusted', port: addr.port }
}

// ---------------------------------------------------------------------------
// Rig: hono, over a copy of `@hono/node-server`'s node -> fetch bridge (the package is not installed here).
// INFO: WHATWG `URL` parsing in that bridge, not hono, resolves dot segments.
// ---------------------------------------------------------------------------

function nodeToFetchServer(handler: (request: Request) => Promise<Response>): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      void (async () => {
        let response: Response
        try {
          const headers = new Headers()
          for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) {
            const name = req.rawHeaders[i]
            const value = req.rawHeaders[i + 1]
            if (name === undefined || value === undefined) continue
            try {
              headers.append(name, value)
            } catch {
              // The fetch layer refuses this header; a real fetch runtime drops it too.
            }
          }
          const host = req.headers.host ?? '127.0.0.1'
          const body = chunks.length > 0 ? Buffer.concat(chunks) : undefined
          const request = new Request(`http://${host}${req.url ?? '/'}`, {
            body,
            headers,
            method: req.method,
          })
          response = await handler(request)
        } catch (err) {
          // A fetch runtime cannot represent this request (`Request` forbids TRACE). 501 means the bridge refused it,
          // not the authorization layer.
          res.writeHead(501, JSON_HEADERS)
          res.end(JSON.stringify({ bridgeError: err instanceof Error ? err.message : String(err) }))
          return
        }
        const out: Record<string, string> = {}
        response.headers.forEach((v, k) => {
          out[k] = v
        })
        res.writeHead(response.status, out)
        res.end(Buffer.from(await response.arrayBuffer()))
      })()
    })
  })
}

async function startHono({ calls, engine, explode }: Instrumented): Promise<Rig> {
  const app = new Hono<{ Variables: { userId: string } }>()
  app.use('*', async (c, next) => {
    c.set('userId', SUBJECT)
    await next()
  })
  // `as never` only bridges hono's context generics to the structural `HonoContext`.
  app.use('*', honoAccessMiddleware(engine) as never)
  app.all('/admin', (c) => c.json({ served: 'admin' }))
  app.all('/admin/*', (c) => c.json({ served: 'admin' }))
  app.all('/public', (c) => c.json({ served: 'public' }))
  app.all('/public/*', (c) => c.json({ served: 'public' }))
  app.all('*', (c) => c.json({ served: 'none' }, 404))
  const server = nodeToFetchServer(async (request) => app.fetch(request))
  const port = await listen(server)
  return { calls, close: () => closeServer(server), explode, name: 'hono', port }
}

// ---------------------------------------------------------------------------
// Rig: next. The middleware takes a WHATWG `Request`, as under `next start`, over the same bridge.
// The routing below stands in for the app router.
// ---------------------------------------------------------------------------

async function startNext({ calls, engine, explode }: Instrumented): Promise<Rig> {
  const middleware = createIamNextMiddleware<Action, ResourceType, RoleId, Scope>(engine, {
    getUserId: () => SUBJECT,
    rules: [
      { pattern: '/admin', resource: 'admin' },
      { pattern: '/public', resource: 'public' },
    ],
  })
  const server = nodeToFetchServer(async (request) => {
    const denial = await middleware(request)
    if (denial) return denial
    const path = new URL(request.url).pathname
    if (path === '/admin' || path.startsWith('/admin/')) return Response.json({ served: 'admin' })
    if (path === '/public' || path.startsWith('/public/')) return Response.json({ served: 'public' })
    return Response.json({ served: 'none' }, { status: 404 })
  })
  const port = await listen(server)
  return { calls, close: () => closeServer(server), explode, name: 'next', port }
}

// ---------------------------------------------------------------------------
// Rig: nest (NestFactory over platform-express). Decorators are applied imperatively, so no
// `experimentalDecorators` flag is needed; Nest reads the same metadata.
// ---------------------------------------------------------------------------

async function startNest({ calls, engine, explode }: Instrumented): Promise<Rig> {
  await import('reflect-metadata')
  const nestCommon = await import('@nestjs/common')
  const { NestFactory } = await import('@nestjs/core')

  const guardFn = iamNestAccessGuard<Action, ResourceType, RoleId, Scope>(engine)

  class AccessGuard {
    canActivate(context: unknown): Promise<boolean> {
      // The integration's own contract: `canActivate` is this function.
      return guardFn(context as never)
    }
  }
  nestCommon.Injectable()(AccessGuard)

  class RigController {
    admin(): { served: string } {
      return { served: 'admin' }
    }
    public(): { served: string } {
      return { served: 'public' }
    }
  }
  const proto = RigController.prototype
  for (const [method, route] of [
    ['admin', '/admin/*splat'],
    ['public', '/public/*splat'],
  ] as const) {
    const descriptor = Object.getOwnPropertyDescriptor(proto, method)
    if (!descriptor) throw new Error(`missing controller method ${method}`)
    IamAuthorize({ infer: true })(proto, method, descriptor)
    nestCommon.All(route)(proto, method, descriptor)
  }
  nestCommon.UseGuards(AccessGuard)(RigController)
  nestCommon.Controller()(RigController)

  class RigModule {}
  nestCommon.Module({ controllers: [RigController], providers: [AccessGuard] })(RigModule)

  const app = await NestFactory.create(RigModule, { logger: false })
  // Trusted upstream auth, as in the other rigs: the guard's default `getUserId` reads `req.user.id`.
  app.use((req: { user?: { id: string } }, _res: unknown, next: () => void) => {
    req.user = { id: SUBJECT }
    next()
  })
  await app.listen(0, '127.0.0.1')
  const url = await app.getUrl()
  const port = Number(new URL(url).port)
  if (!Number.isInteger(port) || port <= 0) throw new Error(`nest bound to a bad port: ${url}`)
  return {
    calls,
    close: async () => {
      await app.close()
    },
    explode,
    name: 'nest',
    port,
  }
}

// ---------------------------------------------------------------------------
// Rig: generic. A plain `node:http` server wired with the exported helpers.
// ---------------------------------------------------------------------------

async function startGeneric({ calls, engine, explode }: Instrumented): Promise<Rig> {
  const server = createServer((req, res) => {
    void (async () => {
      const target = req.url ?? '/'
      const q = target.indexOf('?')
      const rawPath = q === -1 ? target : target.slice(0, q)
      try {
        const allowed = await engine.can(
          SUBJECT,
          iamActionForMethod(req.method) as Action,
          iamDefaultResource(rawPath) as IamRequest.IResource<ResourceType>,
          iamExtractEnvironment(req),
          undefined,
        )
        if (!allowed) {
          res.writeHead(403, JSON_HEADERS)
          res.end(JSON.stringify({ error: 'Forbidden' }))
          return
        }
      } catch {
        res.writeHead(500, JSON_HEADERS)
        res.end(JSON.stringify({ error: 'Internal server error' }))
        return
      }
      // Routing mirrors the derivation: canonical path, not the raw target.
      const path = iamNormalizePathname(rawPath)
      const served =
        path === '/admin' || path.startsWith('/admin/')
          ? 'admin'
          : path === '/public' || path.startsWith('/public/')
            ? 'public'
            : 'none'
      res.writeHead(served === 'none' ? 404 : 200, JSON_HEADERS)
      res.end(JSON.stringify({ served }))
    })()
  })
  const port = await listen(server)
  return { calls, close: () => closeServer(server), explode, name: 'generic', port }
}

// ---------------------------------------------------------------------------

const rigs: Record<string, Rig> = {}
const RIG_NAMES = ['express', 'hono', 'next', 'nest', 'generic'] as const
type RigName = (typeof RIG_NAMES)[number]

/** Boots the five integrations plus the trusting-proxy control, each on a fresh engine from `factory`. */
async function startAll(factory: () => Instrumented): Promise<Record<string, Rig>> {
  const started = await Promise.all([
    startExpress(factory()),
    startHono(factory()),
    startNext(factory()),
    startNest(factory()),
    startGeneric(factory()),
    startExpressTrustingProxy(factory()),
  ])
  const out: Record<string, Rig> = {}
  for (const r of started) out[r.name] = r
  return out
}

beforeAll(async () => {
  Object.assign(rigs, await startAll(() => makeEngine()))
}, 60_000)

afterAll(async () => {
  await Promise.all(Object.values(rigs).map((r) => r.close()))
})

function rig(name: RigName): Rig {
  const found = rigs[name]
  if (!found) throw new Error(`rig ${name} never started - the suite must fail, not skip`)
  return found
}

async function hit(
  name: RigName,
  method: string,
  target: string,
  opts: { headers?: [string, string][]; body?: string } = {},
): Promise<RawResponse & { derived: RecordedCall | undefined }> {
  const r = rig(name)
  const before = r.calls.length
  const res = await raw(r.port, method, target, opts)
  return { ...res, derived: r.calls[before] }
}

// ===========================================================================
// 0. Harness proof. If these fail, nothing below means anything.
// ===========================================================================

describe('harness', () => {
  it('starts a real listener for all five integrations', () => {
    for (const name of RIG_NAMES) {
      expect(rigs[name], `${name} rig missing`).toBeDefined()
      expect(rig(name).port, `${name} port`).toBeGreaterThan(0)
    }
  })

  it('delivers the request-target verbatim, without fetch-style canonicalisation', async () => {
    // A literal `%2e%2e` target gets a real response, so the raw socket path works.
    const res = await hit('express', 'GET', '/public/%2e%2e/public')
    expect(res.status).not.toBe(0)
    expect(res.aborted).toBe(false)
  })

  it('grants public/read and denies admin to the fixture subject', async () => {
    const ok = await hit('express', 'GET', '/public/thing')
    expect(ok.status).toBe(200)
    expect(ok.json?.served).toBe('public')
    const no = await hit('express', 'GET', '/admin/thing')
    expect(no.status).toBe(403)
  })

  it('records what each integration asked the engine', async () => {
    const res = await hit('express', 'GET', '/public/thing')
    expect(res.derived).toBeDefined()
    expect(res.derived?.subject).toBe(SUBJECT)
    expect(res.derived?.action).toBe('read')
    expect(res.derived?.resource.type).toBe('public')
  })
})

// ===========================================================================
// 1. Path bypass. The invariant: the `/admin` handler must never run.
// ===========================================================================

/** Request-targets that all route into `/admin` on at least one framework. */
const ADMIN_TARGETS: [label: string, target: string][] = [
  ['plain', '/admin/x'],
  ['dot-dot literal', '/admin/../public'],
  ['dot-dot single-encoded', '/admin/%2e%2e/public'],
  ['encoded slash after dot-dot', '/admin/..%2fpublic'],
  ['dot-dot double-encoded', '/admin/%252e%252e/public'],
  ['dot segment', '/admin/./x'],
  ['duplicate slash', '/admin//x'],
  ['leading duplicate slash', '//admin/x'],
  ['semicolon traversal', '/admin/..;/public'],
  ['backslash traversal', '/admin\\..\\public'],
  ['trailing slash', '/admin/x/'],
  ['null byte', '/admin/x%00.txt'],
  ['uppercase', '/ADMIN/x'],
  ['encoded first letter', '/%61dmin/x'],
  ['fullwidth solidus', '/admin／..／public'],
  ['query smuggle', '/admin/x?p=/../public'],
  ['long path', `/admin/${'a'.repeat(4000)}`],
]

for (const name of RIG_NAMES) {
  describe(`path bypass - ${name}`, () => {
    for (const [label, target] of ADMIN_TARGETS) {
      it(`never serves the admin handler for ${label}: ${JSON.stringify(target)}`, async () => {
        const res = await hit(name, 'GET', target)
        // 501: the fetch bridge could not represent the request, so nothing was authorized or served.
        if (res.status === 501) return
        const servedAdmin = res.status === 200 && res.json?.served === 'admin'
        expect(
          servedAdmin,
          `${name} served the admin handler for ${JSON.stringify(target)}; ` +
            `authorization was asked about resource ` +
            `${JSON.stringify(res.derived?.resource.type)} (status ${res.status})`,
        ).toBe(false)
      })
    }
  })
}

// ===========================================================================
// 1b. Controls: without these, a rig that 404s everything passes section 1 vacuously.
// ===========================================================================

describe('controls - every rig really guards', () => {
  for (const name of RIG_NAMES) {
    it(`${name} allows the granted request and denies the ungranted one`, async () => {
      const ok = await hit(name, 'GET', '/public/thing')
      expect(ok.status, `${name} GET /public/thing`).toBe(200)
      expect(ok.json?.served).toBe('public')

      const denied = await hit(name, 'GET', '/admin/thing')
      expect([401, 403], `${name} GET /admin/thing returned ${denied.status}`).toContain(denied.status)
      expect(denied.json?.served).toBeUndefined()
    })
  }
})

// ===========================================================================
// 2. Method handling.
// ===========================================================================

describe('method handling', () => {
  for (const name of RIG_NAMES) {
    it(`${name}: HEAD on a GET-guarded admin route is still denied`, async () => {
      const res = await hit(name, 'HEAD', '/admin/thing')
      if (res.status === 501) return
      expect([401, 403], `${name} HEAD /admin/thing -> ${res.status}`).toContain(res.status)
    })

    it(`${name}: OPTIONS on the admin route is denied`, async () => {
      const res = await hit(name, 'OPTIONS', '/admin/thing')
      if (res.status === 501) return
      // A framework-level OPTIONS short-circuit is a separate issue; the admin body must never appear.
      expect(res.json?.served).not.toBe('admin')
    })

    it(`${name}: an unmapped verb yields the unknown action, never 'read'`, async () => {
      // PROPFIND is not in IAM_METHOD_ACTION_MAP, so it must not inherit `read`.
      const res = await hit(name, 'PROPFIND', '/public/thing')
      if (res.status === 501) return
      if (res.derived) {
        expect(res.derived.action, `${name} PROPFIND action`).toBe('unknown')
      }
      expect(res.json?.served, `${name} PROPFIND served the handler`).not.toBe('public')
    })

    it(`${name}: X-HTTP-Method-Override does not change the derived action`, async () => {
      const res = await hit(name, 'GET', '/public/thing', {
        headers: [['X-HTTP-Method-Override', 'DELETE']],
      })
      if (res.status === 501) return
      if (res.derived) {
        expect(res.derived.action, `${name} override header`).toBe('read')
      }
    })
  }

  it('a lowercase method is rejected by the HTTP parser before any integration sees it', async () => {
    const res = await raw(rig('express').port, 'get', '/public/thing')
    expect(res.status === 400 || res.aborted).toBe(true)
  })

  it('an unknown verb reaches the integration and is denied, not allowed', async () => {
    const res = await hit('express', 'FROBNICATE', '/public/thing')
    // Node's parser accepts some unknown well-formed methods and rejects others; either way nothing is served.
    if (!res.aborted && res.status !== 400) {
      expect(res.json?.served).toBeUndefined()
    }
  })
})

// ===========================================================================
// 3. Environment derivation. `env.ip` and `env.userAgent` feed ABAC conditions, so who controls them matters.
// ===========================================================================

async function envFor(name: RigName, headers: [string, string][]): Promise<IamRequest.IEnvironment | undefined> {
  const res = await hit(name, 'GET', '/public/thing', { headers })
  return res.derived?.environment
}

describe('environment derivation', () => {
  it('records an environment on every integration', async () => {
    for (const name of RIG_NAMES) {
      const env = await envFor(name, [])
      expect(env, `${name} passed no environment to the engine`).toBeDefined()
      expect(typeof env?.timestamp, `${name} timestamp`).toBe('number')
    }
  })

  it('all five integrations agree on the client IP for the same request', async () => {
    const headers: [string, string][] = [['X-Forwarded-For', '203.0.113.7, 70.41.3.18, 150.172.238.178']]
    const seen: Record<string, string | undefined> = {}
    for (const name of RIG_NAMES) seen[name] = (await envFor(name, headers))?.ip
    const distinct = new Set(Object.values(seen))
    expect(distinct.size, `integrations disagree on environment.ip for the same request: ${JSON.stringify(seen)}`).toBe(
      1,
    )
  })

  it('a client cannot set environment.ip with a header it invents', async () => {
    // SECURITY: the peer is 127.0.0.1; echoing the header as env.ip lets a caller steer IP-conditioned policy.
    const spoofable: string[] = []
    for (const name of RIG_NAMES) {
      const env = await envFor(name, [['X-Forwarded-For', '10.0.0.1']])
      if (env?.ip === '10.0.0.1') spoofable.push(name)
    }
    expect(
      spoofable,
      `these integrations echo an unverified X-Forwarded-For into environment.ip: ${spoofable.join(', ')}`,
    ).toEqual([])
  })

  it('x-real-ip is treated the same way across integrations', async () => {
    const seen: Record<string, string | undefined> = {}
    for (const name of RIG_NAMES) seen[name] = (await envFor(name, [['X-Real-IP', '198.51.100.9']]))?.ip
    expect(new Set(Object.values(seen)).size, `x-real-ip divergence: ${JSON.stringify(seen)}`).toBe(1)
  })

  it('duplicate X-Forwarded-For headers resolve identically across integrations', async () => {
    const headers: [string, string][] = [
      ['X-Forwarded-For', '203.0.113.7'],
      ['X-Forwarded-For', '198.51.100.9'],
    ]
    const seen: Record<string, string | undefined> = {}
    for (const name of RIG_NAMES) seen[name] = (await envFor(name, headers))?.ip
    expect(new Set(Object.values(seen)).size, `duplicate-XFF divergence: ${JSON.stringify(seen)}`).toBe(1)
  })

  it('an IPv4-mapped IPv6 XFF resolves to one answer across integrations', async () => {
    const mapped: Record<string, string | undefined> = {}
    for (const name of RIG_NAMES) mapped[name] = (await envFor(name, [['X-Forwarded-For', '::ffff:10.0.0.1']]))?.ip
    // Must match everywhere: a policy comparing `environment.ip` to a literal is written once, not per framework.
    expect(new Set(Object.values(mapped)).size, `IPv4-mapped divergence: ${JSON.stringify(mapped)}`).toBe(1)
  })

  /** Positive control: five `undefined` IPs agree perfectly, so this reads an absolute value off the wire. */
  async function trustedEnvFor(headers: [string, string][]): Promise<IamRequest.IEnvironment | undefined> {
    const r = rigs['express-trusted']
    if (!r) throw new Error('express-trusted rig never started - the suite must fail, not skip')
    const before = r.calls.length
    await raw(r.port, 'GET', '/public/thing', { headers })
    return r.calls[before]?.environment
  }

  it('a trusting integration really does put the forwarded client IP into env.ip', async () => {
    // The leftmost hop is the original client, per the XFF convention.
    expect((await trustedEnvFor([['X-Forwarded-For', '203.0.113.7, 70.41.3.18, 150.172.238.178']]))?.ip).toBe(
      '203.0.113.7',
    )
  })

  it('with no forwarding header the same rig reports the socket peer', async () => {
    // The other half of the control: `env.ip` also comes from the connection itself, not only a header.
    const ip = (await trustedEnvFor([]))?.ip
    expect(ip, 'the trusting rig reported no ip for a direct connection').toBeDefined()
    expect(ip).toMatch(/127\.0\.0\.1|::1/)
  })

  it('the same request on the five default integrations yields no ip at all', async () => {
    // Only the app knows how many proxies front it, so the default is no IP rather than a guess a client can steer.
    for (const name of RIG_NAMES) {
      const env = await envFor(name, [['X-Forwarded-For', '203.0.113.7, 70.41.3.18']])
      expect(env?.ip, `${name} filled environment.ip without the opt-in`).toBeUndefined()
    }
  })

  it('an oversized user-agent is dropped rather than forwarded to conditions', async () => {
    for (const name of RIG_NAMES) {
      const env = await envFor(name, [['User-Agent', 'u'.repeat(4096)]])
      expect(env?.userAgent, `${name} forwarded a 4096-char user-agent`).toBeUndefined()
    }
  })

  it('a user-agent just under the cap survives on every integration', async () => {
    const ua = `x${'u'.repeat(2046)}y`
    for (const name of RIG_NAMES) {
      const env = await envFor(name, [['User-Agent', ua]])
      expect(env?.userAgent, `${name} dropped a legal 2048-char user-agent`).toBe(ua)
    }
  })
})

// ===========================================================================
// 4. Fail-closed. An authorization system that errors must deny.
// ===========================================================================

describe('fail closed when the engine throws', () => {
  for (const name of RIG_NAMES) {
    it(`${name} denies rather than falling through to the handler`, async () => {
      const r = rig(name)
      r.explode.on = true
      try {
        const res = await hit(name, 'GET', '/public/thing')
        expect(
          res.json?.served,
          `${name} ran the route handler after the engine threw (status ${res.status}, body ${res.body.slice(0, 200)})`,
        ).toBeUndefined()
        expect([401, 403, 500, 501], `${name} status after engine throw`).toContain(res.status)
      } finally {
        r.explode.on = false
      }
    })

    it(`${name} does not leak the engine's error message to the client`, async () => {
      const r = rig(name)
      r.explode.on = true
      try {
        const res = await hit(name, 'GET', '/public/thing')
        expect(res.body, `${name} echoed the internal error`).not.toContain('engine exploded')
      } finally {
        r.explode.on = false
      }
    })
  }
})

describe("a route's own error belongs to the framework, not to the guard", () => {
  // Express is the one adapter that still calls its downstream inside the authz try. It is harmless because
  // express dispatches each layer inside a try of its own and turns a throw into `next(err)` - measured here
  // rather than assumed, since the same shape in `withIamAccess` was not harmless.
  it('express hands a throwing route to the app error handler, not to the iam onError', async () => {
    const { default: express } = await import('express')
    const { engine } = makeEngine()
    const iamOnError = vi.fn(
      (_err: Error, _req: unknown, res: { status: (n: number) => { json: (b: unknown) => void } }) => {
        res.status(500).json({ answered: 'iam-onError' })
      },
    )
    const appSaw: string[] = []
    const app = express()
    app.use((req, _res, next) => {
      Reflect.set(req, 'user', { id: SUBJECT })
      next()
    })
    const mw = expressAccessMiddleware(engine, { onError: iamOnError as never })
    app.use((req, res, next) => {
      void mw(req as never, res as never, next)
    })
    app.get('/public/sync', () => {
      throw new Error('route blew up')
    })
    app.get('/public/async', async () => {
      throw new Error('route blew up')
    })
    app.use(
      (err: Error, _req: unknown, res: { status: (n: number) => { json: (b: unknown) => void } }, _next: unknown) => {
        appSaw.push(err.message)
        res.status(500).json({ answered: 'app-error-handler' })
      },
    )
    const server = app.listen(0, '127.0.0.1')
    const port = await new Promise<number>((resolve, reject) => {
      server.once('error', reject)
      server.once('listening', () => {
        const addr = server.address()
        if (addr === null || typeof addr === 'string') reject(new Error('express did not bind'))
        else resolve(addr.port)
      })
    })

    try {
      const answered: Record<string, unknown> = {}
      for (const spelling of ['sync', 'async']) {
        const res = await raw(port, 'GET', `/public/${spelling}`)
        answered[spelling] = res.json?.answered
      }
      expect({ answered, appSaw, iamOnErrorCalls: iamOnError.mock.calls.length }).toEqual({
        answered: { async: 'app-error-handler', sync: 'app-error-handler' },
        appSaw: ['route blew up', 'route blew up'],
        iamOnErrorCalls: 0,
      })
    } finally {
      await closeServer(server as unknown as Server)
    }
  })
})

// ===========================================================================
// 5. Cross-framework agreement matrix.
// ===========================================================================

const PARITY_TARGETS = [
  '/public/thing',
  '/admin/thing',
  '/admin/../public',
  '/admin/%2e%2e/public',
  '/public/../admin',
  '/public/%2e%2e/admin',
  '//admin/thing',
  '/%61dmin/thing',
  '/ADMIN/thing',
  '/admin/./thing',
  '/admin//thing',
  '/public/thing/',
]

/** What the wire says happened: did the guarded handler run, and for what? */
function verdictOf(res: RawResponse): string {
  if (res.status === 501) return 'bridge-refused'
  if (res.status >= 500) return 'error'
  if (res.status === 401 || res.status === 403) return 'deny'
  if (res.status === 404) return 'no-route'
  const served = res.json?.served
  return typeof served === 'string' ? `serve:${served}` : `status:${res.status}`
}

describe('cross-framework agreement', () => {
  for (const target of PARITY_TARGETS) {
    it(`five integrations agree on ${JSON.stringify(target)}`, async () => {
      const matrix: Record<string, { verdict: string; resource: string | undefined; action: string | undefined }> = {}
      for (const name of RIG_NAMES) {
        const res = await hit(name, 'GET', target)
        matrix[name] = {
          action: res.derived?.action,
          resource: res.derived?.resource.type,
          verdict: verdictOf(res),
        }
      }
      // `no-route` is a rig routing artefact: a framework that matched no route made no decision.
      const decisive = Object.entries(matrix).filter(([, v]) => v.verdict !== 'no-route')

      // SECURITY: the handler that ran must be the one authorized; identical verdicts are only a convenience.
      for (const [name, v] of decisive) {
        if (!v.verdict.startsWith('serve:')) continue
        expect(
          v.resource,
          `${name} served ${v.verdict.slice(6)} having authorized ${JSON.stringify(v.resource)} for ${target}`,
        ).toBe(v.verdict.slice(6))
      }

      // Agreement is not achievable for a traversal: `new Request(url)` resolves dot segments, so hono and next
      // authorize and serve `/public`, while express, nest and generic refuse the raw target. Both are safe.
      const RESOLVED_BY_THE_PLATFORM = target.includes('/../') || target.includes('/%2e%2e/')
      if (RESOLVED_BY_THE_PLATFORM) return
      const verdicts = new Set(decisive.map(([, v]) => v.verdict))
      expect(verdicts.size, `verdict divergence on ${target}: ${JSON.stringify(matrix)}`).toBe(1)
    })
  }
})

// ===========================================================================
// 6. Body-derived subject ids: `getUserId` may read the body, so a malformed id must never authorize.
// ===========================================================================

/** An express rig whose subject id comes straight from the JSON body, so malformed ids cross the boundary. */
async function startBodySubjectExpress(): Promise<{
  port: number
  calls: RecordedCall[]
  close: () => Promise<void>
}> {
  const { default: express } = await import('express')
  const { calls, engine } = makeEngine()

  const app = express()
  app.use(express.json({ strict: false, type: () => true }))
  useIamMiddleware(
    app,
    expressAccessMiddleware(engine, {
      // Unvalidated on purpose: the test is what the integration does with whatever the body carried.
      getUserId: (req) => {
        const body: unknown = req.body
        if (typeof body !== 'object' || body === null) return null
        const value: unknown = Reflect.get(body, 'userId')
        // The cast forwards a non-string as-is; that is the case under test.
        return value === undefined ? null : (value as string)
      },
    }),
  )
  app.all('/public{/*rest}', (_req, res) => {
    res.json({ served: 'public' })
  })
  app.use((_req, res) => {
    res.status(404).json({ served: 'none' })
  })
  const server = app.listen(0, '127.0.0.1')
  await new Promise<void>((resolve, reject) => {
    server.once('listening', () => resolve())
    server.once('error', reject)
  })
  const addr = server.address()
  if (addr === null || typeof addr === 'string') throw new Error('body rig did not bind')
  return { calls, close: () => closeServer(server), port: addr.port }
}

describe('body-derived subject id', () => {
  let bodyRig: Awaited<ReturnType<typeof startBodySubjectExpress>>

  beforeAll(async () => {
    bodyRig = await startBodySubjectExpress()
  })
  afterAll(async () => {
    await bodyRig.close()
  })

  async function post(body: string): Promise<RawResponse & { derived: RecordedCall | undefined }> {
    const before = bodyRig.calls.length
    const res = await raw(bodyRig.port, 'POST', '/public/thing', {
      body,
      headers: [['Content-Type', 'application/json']],
    })
    return { ...res, derived: bodyRig.calls[before] }
  }

  const cases: [label: string, body: string][] = [
    ['absent', '{}'],
    ['empty string', '{"userId":""}'],
    ['whitespace', '{"userId":"   "}'],
    ['null', '{"userId":null}'],
    ['number zero', '{"userId":0}'],
    ['number nonzero', '{"userId":42}'],
    ['boolean true', '{"userId":true}'],
    ['object', '{"userId":{"id":"user-viewer"}}'],
    ['array', '{"userId":["user-viewer"]}'],
    ['wildcard', '{"userId":"*"}'],
    ['colon separator', '{"userId":"user-viewer:read"}'],
    ['at separator', '{"userId":"user-viewer@org-1"}'],
    ['prototype key', '{"userId":"__proto__"}'],
    ['constructor key', '{"userId":"constructor"}'],
    ['very long', `{"userId":"${'u'.repeat(100_000)}"}`],
  ]

  for (const [label, body] of cases) {
    it(`never authorizes a request whose subject id is ${label}`, async () => {
      const res = await post(body)
      expect(
        res.json?.served,
        `body ${label} reached the handler (status ${res.status}, derived subject ` +
          `${JSON.stringify(res.derived?.subject)})`,
      ).not.toBe('public')
    })
  }

  it('a non-string subject id never reaches engine.can as a subject', async () => {
    const offenders: string[] = []
    for (const [label, body] of cases) {
      const res = await post(body)
      if (res.derived !== undefined && typeof res.derived.subject !== 'string') {
        offenders.push(`${label} -> ${JSON.stringify(res.derived.subject)}`)
      }
    }
    expect(offenders, `non-string subject ids crossed into engine.can: ${offenders.join('; ')}`).toEqual([])
  })

  it('the legitimate subject in the same wiring is still allowed', async () => {
    const res = await post('{"userId":"user-viewer"}')
    // POST maps to `create`, which the role does not grant; the GET proves the rig is not denying everything.
    expect(res.status).toBe(403)
    const before = bodyRig.calls.length
    const get = await raw(bodyRig.port, 'GET', '/public/thing', {
      body: '{"userId":"user-viewer"}',
      headers: [['Content-Type', 'application/json']],
    })
    expect(bodyRig.calls[before]?.subject).toBe('user-viewer')
    expect(get.status).toBe(200)
  })
})

// ===========================================================================
// 7. IP-conditioned ABAC over real HTTP: a forwarding header must never satisfy an `environment.ip` rule.
// ===========================================================================

const OFFICE_IP = '10.0.0.1'

const officeAdminPolicy: AccessControl.IPolicy<Action, ResourceType, RoleId> = {
  algorithm: 'allow-overrides',
  id: 'admin-from-office',
  name: 'admin readable from the office IP',
  rules: [
    {
      actions: ['read'],
      conditions: { all: [{ field: 'environment.ip', operator: 'eq', value: OFFICE_IP }] },
      effect: 'allow',
      id: 'office-only',
      priority: 100,
      resources: ['admin'],
    },
  ],
}

describe('IP-conditioned policy over real HTTP', () => {
  const ipRigs: Record<string, Rig> = {}

  beforeAll(async () => {
    Object.assign(
      ipRigs,
      await startAll(() => makeEngine({ policies: [officeAdminPolicy], policyCombine: 'allow-overrides' })),
    )
  }, 60_000)
  afterAll(async () => {
    await Promise.all(Object.values(ipRigs).map((r) => r.close()))
  })

  it('the policy really grants admin when the environment IP matches', async () => {
    // Proved against the engine directly; proving it through an integration would be circular.
    const { engine } = makeEngine({ policies: [officeAdminPolicy], policyCombine: 'allow-overrides' })
    const adminResource = { attributes: {}, type: 'admin' } as const
    await expect(engine.can(SUBJECT, 'read', adminResource, { ip: OFFICE_IP, timestamp: Date.now() })).resolves.toBe(
      true,
    )
    await expect(
      engine.can(SUBJECT, 'read', adminResource, { ip: '203.0.113.1', timestamp: Date.now() }),
    ).resolves.toBe(false)
  })

  it('a client cannot satisfy an IP-conditioned admin grant with a header', async () => {
    // The socket peer is always 127.0.0.1, so reaching the admin handler means the header decided.
    const escalated: string[] = []
    for (const name of RIG_NAMES) {
      const r = ipRigs[name]
      if (!r) throw new Error(`ip rig ${name} missing`)
      const res = await raw(r.port, 'GET', '/admin/secret', {
        headers: [['X-Forwarded-For', OFFICE_IP]],
      })
      if (res.status === 200 && res.json?.served === 'admin') escalated.push(name)
    }
    expect(
      escalated,
      `a plain 'X-Forwarded-For: ${OFFICE_IP}' header escalated to the admin handler on: ${escalated.join(', ')}`,
    ).toEqual([])
  })

  it('X-Real-IP is the same lever as X-Forwarded-For', async () => {
    const escalated: string[] = []
    for (const name of RIG_NAMES) {
      const r = ipRigs[name]
      if (!r) throw new Error(`ip rig ${name} missing`)
      const res = await raw(r.port, 'GET', '/admin/secret', { headers: [['X-Real-IP', OFFICE_IP]] })
      if (res.status === 200 && res.json?.served === 'admin') escalated.push(name)
    }
    expect(escalated, `X-Real-IP escalated on: ${escalated.join(', ')}`).toEqual([])
  })

  it('an XFF chain whose leftmost hop is forged is not accepted as the client', async () => {
    // Proxies append, so the leftmost hop is whatever the client sent; trusting it is the classic spoof.
    const escalated: string[] = []
    for (const name of RIG_NAMES) {
      const r = ipRigs[name]
      if (!r) throw new Error(`ip rig ${name} missing`)
      const res = await raw(r.port, 'GET', '/admin/secret', {
        headers: [['X-Forwarded-For', `${OFFICE_IP}, 203.0.113.9, 198.51.100.4`]],
      })
      if (res.status === 200 && res.json?.served === 'admin') escalated.push(name)
    }
    expect(escalated, `a forged leftmost XFF hop escalated on: ${escalated.join(', ')}`).toEqual([])
  })
})

// ===========================================================================
// 8. Printed matrix, not an assertion: what each integration derived and served, as a reproduction table.
// ===========================================================================

describe('agreement matrix (printed)', () => {
  it('prints the derived tuple and wire verdict per framework', async () => {
    const rows: string[] = []
    for (const target of PARITY_TARGETS) {
      for (const name of RIG_NAMES) {
        const res = await hit(name, 'GET', target)
        rows.push(
          [
            target.padEnd(24),
            name.padEnd(8),
            `resource=${String(res.derived?.resource.type ?? '-')}`.padEnd(20),
            `action=${String(res.derived?.action ?? '-')}`.padEnd(16),
            verdictOf(res),
          ].join(' | '),
        )
      }
    }
    // eslint-disable-next-line no-console
    console.log(`\nAGREEMENT MATRIX\n${rows.join('\n')}\n`)
    expect(rows.length).toBe(PARITY_TARGETS.length * RIG_NAMES.length)
  })
})

// ===========================================================================
// 9. Printed record of the status each malformed subject shape produced.
// ===========================================================================

describe('malformed subject id (printed)', () => {
  it('prints status and derived subject per body shape', async () => {
    const local = await startBodySubjectExpress()
    try {
      const rows: string[] = []
      for (const body of [
        '{}',
        '{"userId":""}',
        '{"userId":"   "}',
        '{"userId":null}',
        '{"userId":0}',
        '{"userId":42}',
        '{"userId":true}',
        '{"userId":{"id":"user-viewer"}}',
        '{"userId":["user-viewer"]}',
        '{"userId":"*"}',
      ]) {
        const before = local.calls.length
        const res = await raw(local.port, 'GET', '/public/thing', {
          body,
          headers: [['Content-Type', 'application/json']],
        })
        rows.push(
          `${body.padEnd(34)} status=${String(res.status).padEnd(4)} derivedSubject=${JSON.stringify(
            local.calls[before]?.subject,
          )}`,
        )
      }
      console.log(`\nMALFORMED SUBJECT MATRIX\n${rows.join('\n')}\n`)
      expect(rows.length).toBe(10)
    } finally {
      await local.close()
    }
  })
})
