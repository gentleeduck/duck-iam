// E2E: a dead Redis adapter must deny, and a dead invalidation bus must not extend a revoked grant past cacheTTL.
// Owns its own Redis container on a free port, so nothing shared is disturbed.
import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { createServer } from 'node:net'
import { promisify } from 'node:util'
import Redis from 'ioredis'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { type IamRedis, IamRedisAdapter } from '../../../adapters/redis'
import { createIamRedisInvalidator } from '../../../invalidators/redis'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

const exec = promisify(execFile)

const REDIS_IMAGE = 'redis:7-alpine'
const READY_TIMEOUT_MS = 90_000

async function docker(args: string[], timeout = 90_000): Promise<string> {
  const { stdout } = await exec('docker', args, { encoding: 'utf8', timeout })
  return stdout.trim()
}

async function freePort(): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const srv = createServer()
    srv.once('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address()
      if (addr === null || typeof addr === 'string') {
        srv.close()
        reject(new Error('could not allocate a port'))
        return
      }
      const { port } = addr
      srv.close(() => resolve(port))
    })
  })
}

async function waitUntilReady(name: string, probe: string[]): Promise<void> {
  const deadline = Date.now() + READY_TIMEOUT_MS
  let last = ''
  while (Date.now() < deadline) {
    try {
      await docker(['exec', name, ...probe], 15_000)
      return
    } catch (err) {
      last = err instanceof Error ? err.message : String(err)
      await new Promise((r) => setTimeout(r, 250))
    }
  }
  throw new Error(`${name} never became ready: ${last}`)
}

/** Narrows ioredis to the adapter's surface, written out rather than cast so the real driver meets the contract. */
function likeClient(redis: Redis): IamRedis.ILike {
  return {
    del: (...keys) => redis.del(...keys),
    eval: (script, numkeys, ...keysAndArgs) => redis.eval(script, numkeys, ...keysAndArgs),
    get: (key) => redis.get(key),
    hdel: (key, ...fields) => redis.hdel(key, ...fields),
    hget: (key, field) => redis.hget(key, field),
    hgetall: (key) => redis.hgetall(key),
    hkeys: (key) => redis.hkeys(key),
    hset: (key, field, value) => redis.hset(key, field, value),
    hvals: (key) => redis.hvals(key),
    sadd: (key, ...members) => redis.sadd(key, ...members),
    set: (key, value) => redis.set(key, value),
    smembers: (key) => redis.smembers(key),
    srem: (key, ...members) => redis.srem(key, ...members),
  }
}

let containerName = ''
let redisPort = 0
const clients: Redis[] = []

function newClient(): Redis {
  const client = new Redis({
    // Bounded retries: an unbounded offline queue turns "Redis is gone" into a hang, not a deny.
    host: '127.0.0.1',
    maxRetriesPerRequest: 1,
    port: redisPort,
    retryStrategy: (times) => Math.min(times * 100, 1000),
  })
  client.on('error', () => {})
  clients.push(client)
  return client
}

const DOC = { attributes: {}, type: 'doc' } as const

function engineOn(
  client: Redis,
  opts: { cacheTTL?: number; onError?: (e: Error) => void; prefix?: string } = {},
): IamEngine<string, string, string, string, 'development'> {
  return new IamEngine<string, string, string, string, 'development'>({
    adapter: new IamRedisAdapter<string, string, string, string>({
      client: likeClient(client),
      keyPrefix: opts.prefix ?? 'res:',
    }),
    adapterTimeoutMs: 1500,
    cacheTTL: opts.cacheTTL ?? 0,
    mode: 'development',
    ...(opts.onError ? { hooks: { onError: (e: Error) => opts.onError?.(e) } } : {}),
  })
}

beforeAll(async () => {
  await docker(['info', '--format', '{{.ServerVersion}}'], 10_000)
  containerName = `duck-iam-resilience-redis-${randomBytes(4).toString('hex')}`
  redisPort = await freePort()
  await docker([
    'run',
    '-d',
    '--name',
    containerName,
    '--label',
    'duck-iam-e2e-owned',
    '-p',
    `127.0.0.1:${redisPort}:6379`,
    REDIS_IMAGE,
  ])
  await waitUntilReady(containerName, ['redis-cli', 'ping'])

  await seed()
}, 180_000)

/** Rewrites the fixture before every test: Redis has no volume here, so a stopped container loses the catalog. */
async function seed(): Promise<void> {
  const boot = engineOn(newClient())
  await boot.admin.saveRole({ id: 'admin', name: 'admin', permissions: [{ action: 'read', resource: 'doc' }] })
  await boot.admin.assignRole('u1', 'admin')
  expect(await boot.can('u1', 'read', DOC)).toBe(true)
}

beforeEach(async () => {
  await seed()
}, 60_000)

afterAll(async () => {
  await docker(['unpause', containerName]).catch(() => {})
  await docker(['start', containerName]).catch(() => {})
  for (const c of clients) c.disconnect()
  if (containerName) await docker(['rm', '-f', '-v', containerName]).catch(() => {})
}, 120_000)

async function whilePaused<T>(body: () => Promise<T>): Promise<T> {
  await docker(['pause', containerName])
  try {
    return await body()
  } finally {
    await docker(['unpause', containerName])
  }
}

describe('E2E fail-closed: the Redis the decision is READ from', () => {
  it('a check against a frozen Redis denies', async () => {
    const errors: Error[] = []
    const engine = engineOn(newClient(), { onError: (e) => errors.push(e) })
    expect(await engine.can('u1', 'read', DOC)).toBe(true)

    const t0 = Date.now()
    const d = await whilePaused(() => engine.check('u1', 'read', DOC))
    const elapsed = Date.now() - t0

    console.info(`[resilience] redis frozen: verdict=${d.allowed ? 'ALLOW' : 'deny'} after ${elapsed}ms`)
    expect(d.allowed).toBe(false)
    expect(errors.length).toBeGreaterThan(0)
  }, 90_000)

  it('a batch permissions() against a frozen Redis denies every entry', async () => {
    const engine = engineOn(newClient())
    expect(await engine.can('u1', 'read', DOC)).toBe(true)

    const map = await whilePaused(() =>
      engine.permissions('u1', [
        { action: 'read', resource: 'doc' },
        { action: 'write', resource: 'doc' },
      ]),
    )
    expect(Object.values(map)).toEqual([false, false])
  }, 90_000)

  it('a check against a stopped Redis denies, and recovers when it returns', async () => {
    const engine = engineOn(newClient())
    expect(await engine.can('u1', 'read', DOC)).toBe(true)

    await docker(['stop', '-t', '0', containerName])
    const denied = await engine.can('u1', 'read', DOC)
    await docker(['start', containerName])
    await waitUntilReady(containerName, ['redis-cli', 'ping'])

    expect(denied).toBe(false)

    // A restarted Redis comes back empty, so reseed before recovery can mean anything.
    await seed()

    let recovered = false
    const deadline = Date.now() + 30_000
    while (Date.now() < deadline && !recovered) {
      recovered = await engine.can('u1', 'read', DOC)
      if (!recovered) await new Promise((r) => setTimeout(r, 500))
    }
    expect(recovered).toBe(true)
  }, 150_000)

  it('20 concurrent checks against a frozen Redis all deny', async () => {
    const engine = engineOn(newClient())
    expect(await engine.can('u1', 'read', DOC)).toBe(true)

    const results = await whilePaused(async () =>
      Promise.all(Array.from({ length: 20 }, (_, i) => engine.can(`c${i}`, 'read', DOC))),
    )
    expect(results.every((r) => r === false)).toBe(true)
  }, 90_000)
})

describe('E2E: a dead invalidation bus must not extend a stale grant', () => {
  it('a revoke whose broadcast Redis swallowed still takes effect within cacheTTL', async () => {
    const ttlSeconds = 2
    const pubA = newClient()
    const subA = newClient()
    const publishErrors: Error[] = []

    // Instance A: reads through its own Redis client, subscribes to the bus.
    const invalidatorA = createIamRedisInvalidator({
      client: {
        publish: (channel, message) => pubA.publish(channel, message),
        subscribe: async (channel, handler) => {
          subA.on('message', (_ch, msg) => handler(msg))
          await subA.subscribe(channel)
        },
        unsubscribe: async (channel) => {
          await subA.unsubscribe(channel)
        },
      },
      onPublishError: (err) => publishErrors.push(err),
      secret: 'test-secret',
    })

    const a = new IamEngine<string, string, string, string, 'development'>({
      adapter: new IamRedisAdapter<string, string, string, string>({
        client: likeClient(newClient()),
        keyPrefix: 'res:',
      }),
      adapterTimeoutMs: 1500,
      cacheTTL: ttlSeconds,
      invalidator: invalidatorA,
      mode: 'development',
    })
    // Instance B does the write, on its own connection and its own caches.
    const b = engineOn(newClient(), { cacheTTL: ttlSeconds })

    await b.admin.assignRole('stale-user', 'admin')
    expect(await a.can('stale-user', 'read', DOC)).toBe(true)

    // B has no invalidator, so A never hears of the revoke; only cacheTTL can end the stale grant.
    await b.admin.revokeRole('stale-user', 'admin')

    const t0 = Date.now()
    const observed: { allowed: boolean; at: number }[] = []
    const deadline = t0 + ttlSeconds * 1000 + 8_000
    while (Date.now() < deadline) {
      const allowed = await a.can('stale-user', 'read', DOC)
      observed.push({ allowed, at: Date.now() - t0 })
      if (!allowed) break
      await new Promise((r) => setTimeout(r, 100))
    }
    const firstDeny = observed.find((o) => !o.allowed)

    console.info(
      `[resilience] revoked grant honoured by the other instance for ${firstDeny ? `${firstDeny.at}ms` : '>TTL+8000ms (NEVER REVOKED)'} (cacheTTL=${ttlSeconds * 1000}ms); publish errors seen: ${publishErrors.length}`,
    )
    a.dispose()

    expect(firstDeny, 'a revoked grant outlived cacheTTL on the other instance').toBeDefined()
    expect(firstDeny?.at).toBeLessThan(ttlSeconds * 1000 + 3_000)
  }, 120_000)

  it('a publish against a dead Redis routes to onPublishError instead of going unhandled', async () => {
    const publishErrors: Error[] = []
    const unhandled: unknown[] = []
    const onUnhandled = (reason: unknown) => unhandled.push(reason)
    process.on('unhandledRejection', onUnhandled)

    const pub = newClient()
    const invalidator = createIamRedisInvalidator({
      client: {
        // ioredis and node-redis both return a promise here, which `IPubSubLike.publish` allows.
        publish: (channel, message) => pub.publish(channel, message),
        subscribe: () => {},
      },
      onPublishError: (err) => publishErrors.push(err),
      secret: 'test-secret',
    })
    const engine = new IamEngine<string, string, string, string, 'development'>({
      adapter: new IamRedisAdapter<string, string, string, string>({
        client: likeClient(newClient()),
        keyPrefix: 'res:',
      }),
      adapterTimeoutMs: 1500,
      cacheTTL: 0,
      invalidator,
      mode: 'development',
    })

    await docker(['stop', '-t', '0', containerName])
    // The local invalidation must still apply even though the broadcast fails.
    expect(() => engine.cache.invalidate()).not.toThrow()
    // Give ioredis time to exhaust its retries and reject the publish.
    await new Promise((r) => setTimeout(r, 3000))
    await docker(['start', containerName])
    await waitUntilReady(containerName, ['redis-cli', 'ping'])
    engine.dispose()
    process.off('unhandledRejection', onUnhandled)

    console.info(
      `[resilience] publish against a dead Redis: onPublishError fired ${publishErrors.length} time(s); unhandled rejections observed: ${unhandled.length}`,
    )

    // WARN: under Node's default `--unhandled-rejections=throw`, an uncaught async publish rejection ends the process.
    expect(unhandled, 'a failed publish must not surface as an unhandled rejection').toEqual([])
    expect(publishErrors.length, 'onPublishError must fire when the broadcast fails').toBeGreaterThan(0)
  }, 150_000)
})
