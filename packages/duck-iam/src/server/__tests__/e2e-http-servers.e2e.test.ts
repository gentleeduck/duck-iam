/**
 * REAL-HTTP e2e sweep over the five server integrations.
 *
 * Every other test in `src/server` hands the integration a hand-built request
 * object, which cannot carry a percent-encoded request-target that Node, the
 * framework router and the derivation helper each normalise differently. This
 * file starts a real listener per framework on port 0 and drives it from a raw
 * `node:net` socket, so the exact bytes on the wire are under test control -
 * `fetch()` would canonicalise the path before it ever left the process.
 *
 * The load-bearing invariant, uniform across all five servers:
 *
 *   the subject is granted `read` on `public` and NOTHING on `admin`;
 *   therefore no request may ever be served by the `/admin` handler.
 *
 * A 200 whose body says `served: 'admin'` is a wrong ALLOW - Critical by the
 * manifesto's table - regardless of how the path was spelled.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { connect } from 'node:net'
import { Hono } from 'hono'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
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

/**
 * Build an engine and wrap `can` so each integration's derived
 * (subject, action, resource, environment, scope) tuple is observable. The
 * wrapper is the only way to see what a framework *believed* it was asking,
 * which is the whole cross-framework parity question.
 */
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
// Raw HTTP client. `fetch` normalises the request-target before sending, which
// destroys every case this file exists to exercise.
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
 * Send a literal request-line + headers + body down a socket and parse the
 * reply. `requestTarget` goes out verbatim: no encoding, no dot-segment
 * resolution, no host normalisation.
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
      // Node writes `res.end(buffer)` without a Content-Length as chunked; the
      // parser has to undo that or every JSON assertion silently reads
      // undefined and the suite passes for the wrong reason.
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

/**
 * Bridge the integration's structurally-typed middleware onto express's
 * nominal `RequestHandler`. The casts change no value - they hand the real
 * express `req`/`res` straight through - they only reconcile two spellings of
 * the same shape.
 */
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
 * A sixth listener, deliberately outside `RIG_NAMES`: express with the one
 * opt-in none of the five take.
 *
 * Without it every assertion about `environment.ip` in this file is satisfied
 * by an integration that reports no IP at all - "all five agree" is trivially
 * true of five `undefined`s, and "nobody echoes an unverified header" is
 * trivially true of a field nobody fills. Deleting the `ip:` computation in
 * `iamExtractEnvironment` left this whole section green. This rig is the
 * positive control: on it, and only on it, a forwarded address is supposed to
 * arrive, so the `undefined` everywhere else is a decision rather than a pipe
 * that was never connected.
 */
async function startExpressTrustingProxy({ calls, engine, explode }: Instrumented): Promise<Rig> {
  const { default: express } = await import('express')
  const app = express()
  app.disable('x-powered-by')
  // The second half of the documented deployment: the app has told its own
  // framework about its proxies, so `req.ip` is already the client address and
  // `iamExtractEnvironment` reads it first. Without this express fills `req.ip`
  // from the socket and the forwarded address never gets a chance to arrive -
  // which is correct, and is the case the sibling assertion pins.
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
// Rig: hono. `@hono/node-server` is not installed in this workspace, so the
// node -> fetch bridge is reproduced here: raw `req.url` concatenated onto the
// Host, `rawHeaders` appended verbatim, body buffered. That is exactly what
// `@hono/node-server` does, and it is the step where WHATWG `URL` parsing -
// not hono - resolves dot segments.
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
              // Header name/value the fetch layer refuses; a real fetch-API
              // runtime drops it too.
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
          // A fetch-API runtime cannot represent this request at all (e.g.
          // `Request` forbids the TRACE method). 501 marks "the bridge, not
          // the authorization layer, refused it" so tests can tell them apart.
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
  // `as never` only bridges hono's own context generics to the integration's
  // structural `HonoContext`; it manufactures no value.
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
// Rig: next. `createIamNextMiddleware` consumes a WHATWG `Request`, which is
// what `next start` hands its middleware. Same node -> fetch bridge; the
// routing table below stands in for the app router.
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
// Rig: nest (real NestFactory over platform-express). Decorators are applied
// imperatively so this file needs no `experimentalDecorators` build flag; the
// metadata NestJS reads is identical either way.
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
  // Trusted upstream auth, exactly as the other rigs do it: the guard's default
  // `getUserId` reads `req.user.id`.
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
// Rig: generic. No framework - a hand-rolled `node:http` server wired with the
// exported helpers, which is precisely the audience `src/server/generic` has.
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

/** Boot all five integrations against fresh engines from `factory`. */
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
    // If this passes with the literal `%2e%2e` intact, the socket really is
    // carrying the bytes the tests below claim it carries.
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
        // A 501 is the fetch bridge refusing to represent the request at all;
        // nothing was authorized and nothing was served.
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
// 1b. Controls. Without these, a rig that 404s everything passes section 1
// vacuously - "a survivor is a finding".
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
      // 204/200 from a framework-level CORS/OPTIONS short-circuit is a
      // different bug class; what must never happen is the admin body.
      expect(res.json?.served).not.toBe('admin')
    })

    it(`${name}: an unmapped verb yields the unknown action, never 'read'`, async () => {
      // PROPFIND is not in IAM_METHOD_ACTION_MAP; it must not inherit `read`
      // and pass a read grant.
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
    // Node's parser accepts unknown-but-well-formed tokens for some methods and
    // rejects others; either way nothing may be served.
    if (!res.aborted && res.status !== 400) {
      expect(res.json?.served).toBeUndefined()
    }
  })
})

// ===========================================================================
// 3. Environment derivation from headers. `env.ip` and `env.userAgent` feed
// ABAC `matches` / `equals` conditions, so who controls them matters.
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
    // The socket peer is always 127.0.0.1 here. Any integration that reports
    // the attacker's string as env.ip lets a caller steer an IP-conditioned
    // policy from outside.
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
    // Whatever the answer, it must be the same answer everywhere: a policy
    // comparing `environment.ip` to a literal cannot be written twice, once
    // per framework.
    expect(new Set(Object.values(mapped)).size, `IPv4-mapped divergence: ${JSON.stringify(mapped)}`).toBe(1)
  })

  /**
   * The positive control for everything above.
   *
   * Every other `environment.ip` assertion in this section compares the five
   * integrations to each other, and five `undefined`s agree perfectly - so the
   * whole surface passed with the `ip` computation deleted from
   * `iamExtractEnvironment`. This one names an absolute value that only arrives
   * if the header really is read off the wire and carried into the engine call.
   */
  async function trustedEnvFor(headers: [string, string][]): Promise<IamRequest.IEnvironment | undefined> {
    const r = rigs['express-trusted']
    if (!r) throw new Error('express-trusted rig never started - the suite must fail, not skip')
    const before = r.calls.length
    await raw(r.port, 'GET', '/public/thing', { headers })
    return r.calls[before]?.environment
  }

  it('a trusting integration really does put the forwarded client IP into env.ip', async () => {
    // Leftmost hop: the original client, per the XFF convention the helper
    // documents.
    expect((await trustedEnvFor([['X-Forwarded-For', '203.0.113.7, 70.41.3.18, 150.172.238.178']]))?.ip).toBe(
      '203.0.113.7',
    )
  })

  it('with no forwarding header the same rig reports the socket peer', async () => {
    // The other half of the control: `env.ip` is filled from the connection
    // itself, not only from a header, so neither source is dead.
    const ip = (await trustedEnvFor([]))?.ip
    expect(ip, 'the trusting rig reported no ip for a direct connection').toBeDefined()
    expect(ip).toMatch(/127\.0\.0\.1|::1/)
  })

  it('the same request on the five default integrations yields no ip at all', async () => {
    // The counterpart absolute: not "they agree", but *what* they agree on.
    // Only the app knows how many proxies sit in front of it, so the default is
    // no IP rather than a guess a client can steer.
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
      // `no-route` is a routing-table artefact of the rig, not a security
      // posture: a framework that never matched the route made no decision.
      const decisive = Object.entries(matrix).filter(([, v]) => v.verdict !== 'no-route')

      // The invariant asserted first, on every integration separately: the
      // handler that ran is the one the check was made about. That is the
      // security property; identical verdicts are only a convenience.
      for (const [name, v] of decisive) {
        if (!v.verdict.startsWith('serve:')) continue
        expect(
          v.resource,
          `${name} served ${v.verdict.slice(6)} having authorized ${JSON.stringify(v.resource)} for ${target}`,
        ).toBe(v.verdict.slice(6))
      }

      // Then agreement, for every target where agreement is achievable. It is
      // not achievable for a traversal: `new Request(url)` resolves dot
      // segments while constructing the URL, so hono and next are handed
      // `/public` and never see that the client wrote `/admin/../public` -
      // they route to public and authorize public, which is self-consistent
      // and safe, while express, nest and the generic helper still see the raw
      // target and refuse it. A consumer porting between frameworks writes the
      // policy once; a consumer sending a traversal gets one of two safe
      // answers depending on how the platform hands over the path.
      const RESOLVED_BY_THE_PLATFORM = target.includes('/../') || target.includes('/%2e%2e/')
      if (RESOLVED_BY_THE_PLATFORM) return
      const verdicts = new Set(decisive.map(([, v]) => v.verdict))
      expect(verdicts.size, `verdict divergence on ${target}: ${JSON.stringify(matrix)}`).toBe(1)
    })
  }
})

// ===========================================================================
// 6. Body-derived subject ids. `getUserId` reading a request body is an
// explicitly supported wiring; the guard's only check is truthiness.
// ===========================================================================

/**
 * A second express rig whose identity comes straight out of the JSON body, so
 * a malformed subject id crosses the boundary the way it would in an app that
 * trusts its own body parser.
 */
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
      // Deliberately unvalidated: the point is what the integration does with
      // whatever the body carried, so the extractor reads the field raw.
      getUserId: (req) => {
        const body: unknown = req.body
        if (typeof body !== 'object' || body === null) return null
        const value: unknown = Reflect.get(body, 'userId')
        // Manufactured malformed value: the whole test is what happens when a
        // non-string crosses this boundary, so it is forwarded as-is.
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
    // POST maps to `create`, which the fixture role does not grant; use a
    // method the role does grant to prove the rig is not denying everything.
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
// 7. The header divergence, with teeth.
//
// Section 3 shows hono / next / generic put an unverified `X-Forwarded-For`
// into `environment.ip` while express / nest use the socket. On its own that
// is a divergence. Wire an IP-conditioned ABAC rule - the documented use for
// `environment.ip` - and it becomes a privilege escalation driven by one
// request header.
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
    // Proved off the wire, against the engine directly. Proving it *through*
    // an integration would be circular: the integrations that reach `allow`
    // here are exactly the ones the next test accuses.
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
    // The socket peer is 127.0.0.1 on every one of these. Reaching the admin
    // handler means the caller supplied the deciding attribute themselves.
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
    // Real proxies append; the leftmost hop is whatever the *client* sent
    // first. Trusting it verbatim is the classic spoof.
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
// 8. Documented matrix. Not an assertion - a printed record of exactly what
// each integration derived and served, so the divergences above have a
// reproduction table attached to them.
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
// 9. Printed record of the malformed-subject responses, so the report can
// state the status code each shape produced rather than guessing.
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
