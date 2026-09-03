/**
 * Minimal real-Redis harness for the cross-process invalidation e2e suites.
 *
 * The package has no redis client dependency and adding one is out of this
 * agent's namespace, so this speaks RESP2 over a raw socket. That is not a
 * workaround - it is what makes the failure modes reachable: the suites below
 * need to drop a subscriber connection mid-run, publish a forged envelope, and
 * replay a captured one. A managed client hides all three.
 */
import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { connect, type Socket } from 'node:net'
import { promisify } from 'node:util'
import type { IamRedisInvalidator } from '../index'

const exec = promisify(execFile)

/**
 * Deliberately NOT the shared `duck-iam-e2e` label. `src/test/e2e-containers.ts`
 * sweeps every container carrying that label on startup, so with several agents
 * running suites concurrently the shared Postgres gets torn down underneath a
 * run in progress. This suite therefore owns both of its backends.
 */
export const E2E_LABEL = 'duck-iam-e2e-invalidation'
export const REDIS_LABEL = E2E_LABEL
const REDIS_IMAGE = 'redis:7-alpine'
const PG_IMAGE = 'postgres:16-alpine'
const PG_USER = 'duckiam'
const PG_PASSWORD = 'duckiam'
const PG_DB = 'duckiam_inv_e2e'
const READY_TIMEOUT_MS = 120_000

async function docker(args: string[], timeout?: number): Promise<string> {
  const { stdout } = await exec('docker', args, { encoding: 'utf8', timeout })
  return stdout.trim()
}

export async function dockerAvailable(): Promise<boolean> {
  try {
    await docker(['info', '--format', '{{.ServerVersion}}'], 5_000)
    return true
  } catch {
    return false
  }
}

async function waitUntilReachable(port: number): Promise<void> {
  const deadline = Date.now() + READY_TIMEOUT_MS
  let lastError = ''
  while (Date.now() < deadline) {
    const ok = await new Promise<boolean>((resolve) => {
      const socket = connect({ host: '127.0.0.1', port })
      const done = (result: boolean) => {
        socket.destroy()
        resolve(result)
      }
      socket.once('connect', () => done(true))
      socket.once('error', (err) => {
        lastError = err.message
        done(false)
      })
      socket.setTimeout(1000, () => done(false))
    })
    if (ok) return
    await new Promise((r) => setTimeout(r, 100))
  }
  throw new Error(`redis 127.0.0.1:${port} never accepted a connection: ${lastError}`)
}

/** Bring up a throwaway Redis on an ephemeral host port. Labelled for sweep-up. */
export async function startRedis(): Promise<{ name: string; port: number }> {
  const name = `${REDIS_LABEL}-${randomBytes(4).toString('hex')}`
  await docker(['run', '-d', '--name', name, '--label', REDIS_LABEL, '-p', '0:6379', REDIS_IMAGE])
  const raw = await docker(['port', name, '6379'])
  const portText = raw.split('\n')[0]?.split(':').pop()
  const port = Number(portText)
  if (!Number.isInteger(port) || port <= 0) {
    throw new Error(`could not read published redis port: ${JSON.stringify(raw)}`)
  }
  await waitUntilReachable(port)
  // A published port is not a ready server; prove a command round-trips. A
  // fresh connection per attempt - redis closes the socket while it is still
  // loading, and a reused handle would just keep reporting that first close.
  const deadline = Date.now() + READY_TIMEOUT_MS
  for (;;) {
    let probe: RedisConn | null = null
    try {
      probe = await RedisConn.open(port)
      const pong = await probe.command('PING')
      probe.close()
      if (pong === 'PONG') break
    } catch (err) {
      probe?.close()
      if (Date.now() > deadline) throw err
    }
    await new Promise((r) => setTimeout(r, 100))
  }
  return { name, port }
}

/** Poll an in-container probe until it succeeds. */
async function waitUntilReady(name: string, probe: string[]): Promise<void> {
  const deadline = Date.now() + READY_TIMEOUT_MS
  let lastError = ''
  while (Date.now() < deadline) {
    try {
      await docker(['exec', name, ...probe])
      return
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err)
      await new Promise((r) => setTimeout(r, 250))
    }
  }
  throw new Error(`${name} was not ready within ${READY_TIMEOUT_MS}ms: ${lastError}`)
}

/** Bring up a throwaway Postgres owned by this suite. Returns its connection URL. */
export async function startPostgres(): Promise<{ name: string; url: string }> {
  const name = `${E2E_LABEL}-pg-${randomBytes(4).toString('hex')}`
  await docker([
    'run',
    '-d',
    '--name',
    name,
    '--label',
    E2E_LABEL,
    '-p',
    '0:5432',
    '-e',
    `POSTGRES_USER=${PG_USER}`,
    '-e',
    `POSTGRES_PASSWORD=${PG_PASSWORD}`,
    '-e',
    `POSTGRES_DB=${PG_DB}`,
    PG_IMAGE,
  ])
  await waitUntilReady(name, ['pg_isready', '-U', PG_USER, '-d', PG_DB])
  // `pg_isready` flips true once during init, before the server restarts for
  // real connections; prove a query round-trips before handing the URL out.
  await waitUntilReady(name, ['psql', '-U', PG_USER, '-d', PG_DB, '-c', 'SELECT 1'])
  const raw = await docker(['port', name, '5432'])
  const port = Number(raw.split('\n')[0]?.split(':').pop())
  if (!Number.isInteger(port) || port <= 0) throw new Error(`could not read published pg port: ${JSON.stringify(raw)}`)
  await waitUntilReachable(port)
  return { name, url: `postgres://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${port}/${PG_DB}` }
}

export async function removeContainer(name: string): Promise<void> {
  try {
    await docker(['rm', '-f', name])
  } catch (err) {
    console.warn(`[e2e-invalidation] could not remove ${name}: ${err instanceof Error ? err.message : err}`)
  }
}

export async function removeRedis(name: string): Promise<void> {
  try {
    await docker(['rm', '-f', name])
  } catch (err) {
    console.warn(`[e2e-invalidation] could not remove ${name}: ${err instanceof Error ? err.message : err}`)
  }
}

/** Remove containers a crashed earlier run leaked. */
export async function removeRedisStrays(): Promise<void> {
  const ids = await docker(['ps', '-aq', '--filter', `label=${REDIS_LABEL}`])
  if (ids.length === 0) return
  await docker(['rm', '-f', ...ids.split('\n')])
}

export type Reply = string | number | null | Reply[]

interface ParseResult {
  value: Reply
  next: number
}

/** RESP2 decoder. Returns `null` when the buffer holds no complete reply yet. */
function parseResp(buf: Buffer, off: number): ParseResult | null {
  if (off >= buf.length) return null
  const crlf = buf.indexOf('\r\n', off, 'utf8')
  if (crlf < 0) return null
  const type = buf[off]
  const head = buf.toString('utf8', off + 1, crlf)
  const after = crlf + 2
  if (type === 0x2b /* + */) return { next: after, value: head }
  if (type === 0x2d /* - */) throw new Error(`redis error: ${head}`)
  if (type === 0x3a /* : */) return { next: after, value: Number(head) }
  if (type === 0x24 /* $ */) {
    const len = Number(head)
    if (len === -1) return { next: after, value: null }
    if (buf.length < after + len + 2) return null
    return { next: after + len + 2, value: buf.toString('utf8', after, after + len) }
  }
  if (type === 0x2a /* * */) {
    const count = Number(head)
    if (count === -1) return { next: after, value: null }
    const items: Reply[] = []
    let cursor = after
    for (let i = 0; i < count; i++) {
      const item = parseResp(buf, cursor)
      if (!item) return null
      items.push(item.value)
      cursor = item.next
    }
    return { next: cursor, value: items }
  }
  throw new Error(`unsupported RESP type byte ${String(type)}`)
}

function encodeCommand(args: readonly string[]): Buffer {
  let out = `*${args.length}\r\n`
  for (const a of args) out += `$${Buffer.byteLength(a, 'utf8')}\r\n${a}\r\n`
  return Buffer.from(out, 'utf8')
}

/**
 * One Redis connection. Enough RESP2 for PUBLISH/SUBSCRIBE plus deliberate
 * connection destruction, which is the point.
 */
export class RedisConn {
  private _socket: Socket
  private _buf: Buffer = Buffer.alloc(0)
  private _queue: Array<{ resolve: (r: Reply) => void; reject: (e: Error) => void }> = []
  private _handlers = new Map<string, Set<(message: string) => void>>()
  private _closed = false
  private _shuttingDown = false
  /** Every message ever seen on this connection, for replay/forgery cases. */
  readonly received: Array<{ channel: string; payload: string }> = []

  private constructor(socket: Socket) {
    this._socket = socket
    socket.on('data', (chunk: Buffer) => this._onData(chunk))
    socket.on('error', () => {
      /* surfaced through pending command rejection below */
    })
    socket.on('close', () => {
      this._closed = true
      const pending = this._queue.splice(0, this._queue.length)
      // A deliberate teardown must not manufacture unhandled rejections for
      // replies that will now never arrive; only an unexpected drop rejects.
      for (const p of pending) {
        if (this._shuttingDown) p.resolve(null)
        else p.reject(new Error('redis connection closed'))
      }
    })
  }

  static open(port: number): Promise<RedisConn> {
    return new Promise((resolve, reject) => {
      const socket = connect({ host: '127.0.0.1', port })
      socket.setNoDelay(true)
      socket.once('connect', () => resolve(new RedisConn(socket)))
      socket.once('error', reject)
    })
  }

  get closed(): boolean {
    return this._closed
  }

  private _onData(chunk: Buffer): void {
    this._buf = this._buf.length === 0 ? chunk : Buffer.concat([this._buf, chunk])
    for (;;) {
      let parsed: ParseResult | null
      try {
        parsed = parseResp(this._buf, 0)
      } catch (err) {
        const head = this._queue.shift()
        head?.reject(err instanceof Error ? err : new Error(String(err)))
        this._buf = Buffer.alloc(0)
        return
      }
      if (!parsed) return
      this._buf = this._buf.subarray(parsed.next)
      this._dispatch(parsed.value)
    }
  }

  private _dispatch(value: Reply): void {
    if (Array.isArray(value) && value[0] === 'message' && typeof value[1] === 'string') {
      const channel = value[1]
      const payload = typeof value[2] === 'string' ? value[2] : ''
      this.received.push({ channel, payload })
      const set = this._handlers.get(channel)
      if (set) for (const h of set) h(payload)
      return
    }
    const head = this._queue.shift()
    head?.resolve(value)
  }

  command(...args: string[]): Promise<Reply> {
    if (this._closed) return Promise.reject(new Error('redis connection closed'))
    return new Promise<Reply>((resolve, reject) => {
      this._queue.push({ reject, resolve })
      this._socket.write(encodeCommand(args))
    })
  }

  async subscribeChannel(channel: string, handler: (message: string) => void): Promise<void> {
    let set = this._handlers.get(channel)
    if (!set) {
      set = new Set()
      this._handlers.set(channel, set)
      await this.command('SUBSCRIBE', channel)
    }
    set.add(handler)
  }

  async unsubscribeChannel(channel: string): Promise<void> {
    this._handlers.delete(channel)
    // The engine calls this as `void client.unsubscribe(...)` on dispose; a
    // rejection here would surface as an unhandled rejection in the runner.
    await this.command('UNSUBSCRIBE', channel).catch(() => null)
  }

  /** Hard-kill the socket without a QUIT: what a network partition looks like. */
  destroy(): void {
    this._closed = true
    this._socket.destroy()
  }

  close(): void {
    this._shuttingDown = true
    this._closed = true
    this._socket.end()
    this._socket.destroy()
  }
}

/**
 * `IPubSubLike` over two real connections (Redis forbids commands other than
 * (p)subscribe on a subscriber connection), matching how ioredis/node-redis are
 * meant to be wired.
 */
export function pubSubOver(pub: RedisConn, sub: RedisConn): IamRedisInvalidator.IPubSubLike {
  return {
    publish(channel, message) {
      return pub.command('PUBLISH', channel, message)
    },
    subscribe(channel, handler) {
      return sub.subscribeChannel(channel, handler)
    },
    unsubscribe(channel) {
      return sub.unsubscribeChannel(channel)
    },
  }
}

/** Poll `probe` until it returns true, or the deadline passes. Returns elapsed ms, or `null`. */
export async function waitFor(probe: () => Promise<boolean> | boolean, timeoutMs: number): Promise<number | null> {
  const t0 = Date.now()
  const deadline = t0 + timeoutMs
  for (;;) {
    if (await probe()) return Date.now() - t0
    if (Date.now() >= deadline) return null
    await new Promise((r) => setTimeout(r, 5))
  }
}
