/**
 * E2E: `IamRedisAdapter` on a real `valkey/valkey:9-alpine` and ioredis, covering what the in-repo fake cannot: how a real
 * client materialises `HGETALL`, and two connections writing at once. Starts and removes its own container.
 */
import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { connect } from 'node:net'
import { promisify } from 'node:util'
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { dockerIsUp as sharedDockerIsUp } from '../../test/e2e-env'
import { runAdapterCompliance } from '../__compliance__/compliance'
import { OPTIONAL_SUPPORT } from '../__compliance__/optional-support'
import { IamMemoryAdapter } from '../memory'
import { type IamRedis, IamRedisAdapter } from '../redis'

// The shared matrix sets no per-case timeout, and a real container round trip can exceed vitest's 5s default.
// 30s is still a bound: a CRUD round trip that needs longer is hung, not slow.
vi.setConfig({ testTimeout: 30_000 })

const exec = promisify(execFile)

/** The adapter separates role from scope with a NUL; source stays plain ASCII. */
const NUL = String.fromCharCode(0)

async function docker(args: string[], timeout = 60_000): Promise<string> {
  const { stdout } = await exec('docker', args, { encoding: 'utf8', timeout })
  return stdout.trim()
}

/** The shared probe from `src/test/e2e-env.ts`: one budget, so a busy daemon is not mistaken for an absent one. */
const dockerIsUp = sharedDockerIsUp

async function waitFor(what: string, probe: () => Promise<boolean>, budgetMs = 60_000): Promise<void> {
  const deadline = Date.now() + budgetMs
  while (Date.now() < deadline) {
    if (await probe()) return
    await new Promise((r) => setTimeout(r, 200))
  }
  throw new Error(`${what} was not ready within ${budgetMs}ms`)
}

const CONTAINER = `duck-iam-adapterconf-redis-${randomBytes(4).toString('hex')}`

async function startRedis(): Promise<number> {
  await docker([
    'run',
    '-d',
    '--name',
    CONTAINER,
    '--label',
    'duck-iam-e2e-owned',
    '-p',
    '0:6379',
    'valkey/valkey:9-alpine',
  ])
  await waitFor(`${CONTAINER} answering PING`, async () => {
    try {
      const out = await docker(['exec', CONTAINER, 'valkey-cli', 'PING'], 10_000)
      return out.includes('PONG')
    } catch {
      return false
    }
  })
  const published = await docker(['port', CONTAINER, '6379'])
  const port = Number(published.split('\n')[0]?.split(':').pop())
  if (!Number.isInteger(port) || port <= 0) throw new Error(`no published port: ${published}`)
  await waitFor(`127.0.0.1:${port}`, async () => {
    return await new Promise<boolean>((resolve) => {
      const socket = connect({ host: '127.0.0.1', port })
      const done = (ok: boolean) => {
        socket.destroy()
        resolve(ok)
      }
      socket.once('connect', () => done(true))
      socket.once('error', () => done(false))
      socket.setTimeout(1_000, () => done(false))
    })
  })
  return port
}

const DOCKER_UP = await dockerIsUp()
let bootError: string | undefined
let PORT: number | undefined
if (DOCKER_UP) {
  try {
    PORT = await startRedis()
  } catch (err) {
    bootError = err instanceof Error ? err.message : String(err)
  }
}

const clients: Redis[] = []

/**
 * A real ioredis connection, exposed through the adapter's minimal `ILike` surface.
 * NOTE: spelled out rather than passed through, so the compiler checks the structural match without a cast.
 */
function realClient(port: number): IamRedis.ILike & { raw: Redis } {
  const redis = new Redis(port, '127.0.0.1', { lazyConnect: false, maxRetriesPerRequest: 2 })
  clients.push(redis)
  return {
    del: (...keys: string[]) => redis.del(...keys),
    eval: (script: string, numkeys: number, ...rest: string[]) => redis.eval(script, numkeys, ...rest),
    get: (key: string) => redis.get(key),
    hdel: (key: string, ...fields: string[]) => redis.hdel(key, ...fields),
    hget: (key: string, field: string) => redis.hget(key, field),
    hgetall: (key: string) => redis.hgetall(key),
    hkeys: (key: string) => redis.hkeys(key),
    hset: (key: string, field: string, value: string) => redis.hset(key, field, value),
    hvals: (key: string) => redis.hvals(key),
    // Optional on `ILike`, but `deleteRole` uses it to find grants naming the role;
    // omitting it would test the degraded path.
    keys: (pattern: string) => redis.keys(pattern),
    raw: redis,
    sadd: (key: string, ...members: string[]) => redis.sadd(key, ...members),
    set: (key: string, value: string) => redis.set(key, value),
    smembers: (key: string) => redis.smembers(key),
    srem: (key: string, ...members: string[]) => redis.srem(key, ...members),
  }
}

afterAll(async () => {
  await Promise.all(clients.map((c) => c.quit().catch(() => undefined)))
  if (DOCKER_UP) await docker(['rm', '-f', '-v', CONTAINER]).catch(() => '')
})

describe('E2E harness reachability (redis)', () => {
  it('starts a Redis server whenever docker is available', () => {
    // Guard against a skipped suite passing vacuously. CI provisions the backend up front, so there it is required.
    if (process.env.CI) {
      expect(bootError, 'the container failed to start in CI, where it is provisioned').toBeUndefined()
      expect(PORT, 'no redis in CI, where the workflow provisions one - the suite skipped').toBeDefined()
      return
    }
    if (!DOCKER_UP) {
      expect(PORT, 'docker is down, so no redis is expected').toBeUndefined()
      return
    }
    expect(bootError, 'docker is up but the redis container failed to start').toBeUndefined()
    expect(PORT, 'docker is up but no redis was provisioned - the suite would have skipped').toBeDefined()
  })
})

// ---------------------------------------------------------------------------
// The shared matrix, against the real server.
// ---------------------------------------------------------------------------
if (PORT !== undefined) {
  const shared = realClient(PORT)
  let n = 0
  runAdapterCompliance(
    'IamRedisAdapter @ real Redis',
    async () => {
      // A fresh key prefix per call gives an empty adapter and proves it never reaches outside its namespace.
      n += 1
      return new IamRedisAdapter<string, string, string, string>({ client: shared, keyPrefix: `c${n}:` })
    },
    { supports: OPTIONAL_SUPPORT.IamRedisAdapter },
  )
}

const suite = PORT !== undefined ? describe : describe.skip

suite('IamRedisAdapter against a real server', () => {
  let client: IamRedis.ILike & { raw: Redis }
  let adapter: IamRedisAdapter<string, string, string, string>
  let prefix = ''
  let round = 0

  beforeAll(() => {
    client = realClient(PORT as number)
  })

  /** Fresh namespace per case; nothing here depends on another case's keys. */
  function reset(): void {
    round += 1
    prefix = `t${round}:`
    adapter = new IamRedisAdapter<string, string, string, string>({ client, keyPrefix: prefix })
  }

  describe('how a real client materialises a hash', () => {
    it('a role stored under the id __proto__ survives listRoles, not only getRole', async () => {
      reset()
      await adapter.saveRole({ id: '__proto__', name: 'P', permissions: [] })
      // `getRole` is an HGET and cannot lose it.
      expect((await adapter.getRole('__proto__'))?.id).toBe('__proto__')
      // INFO: `listRoles` is HGETALL; clients build the result with `out[field] = value`, which for `__proto__`
      // hits the inherited setter and drops the row.
      expect((await adapter.listRoles()).map((r) => r.id)).toEqual(['__proto__'])
    })

    it('a policy stored under the id __proto__ survives listPolicies', async () => {
      reset()
      await adapter.savePolicy({ algorithm: 'deny-overrides', id: '__proto__', name: 'P', rules: [] })
      expect((await adapter.getPolicy('__proto__'))?.id).toBe('__proto__')
      expect((await adapter.listPolicies()).map((p) => p.id)).toEqual(['__proto__'])
    })

    it('listRoles and getRole agree for every id the write accepted', async () => {
      reset()
      const ids = ['plain', 'a:b', 'a@b', 'a/b', 'a\nb', 'ロール-✓', 'role-🚀', '__proto__', 'constructor']
      const accepted: string[] = []
      for (const id of ids) {
        const ok = await adapter.saveRole({ id, name: `n-${id}`, permissions: [] }).then(
          () => true,
          () => false,
        )
        if (ok) accepted.push(id)
      }
      const listed = (await adapter.listRoles()).map((r) => r.id).sort()
      expect(listed).toEqual([...accepted].sort())
    })
  })

  describe('ids that collide with the assignment encoding', () => {
    it.each([
      ['a colon', 'a:b'],
      ['an at sign', 'a@b'],
      ['a slash', 'a/b'],
      ['a newline', 'a\nb'],
      ['a space', 'a b'],
      ['unicode', 'ロール-✓'],
      ['an emoji', 'role-🚀'],
      ['four thousand characters', `r-${'x'.repeat(4000)}`],
    ])('round-trips or refuses a role id containing %s', async (_label, id) => {
      reset()
      const refusal = await adapter.saveRole({ id, name: `n-${id}`, permissions: [] }).then(
        () => null,
        (err: unknown) => String(err),
      )
      if (refusal !== null) {
        expect(await adapter.getRole(id).catch(() => null)).toBeNull()
        return
      }
      expect((await adapter.getRole(id))?.id).toBe(id)
      await adapter.assignRole('u1', id)
      expect(await adapter.getSubjectRoles('u1')).toEqual([id])
      await adapter.revokeRole('u1', id)
      expect(await adapter.getSubjectRoles('u1')).toEqual([])
    })

    it('a role id holding a NUL byte is refused by the write, not only by the grant', async () => {
      reset()
      const id = `a${NUL}b`
      // NUL is the assignment member separator, so `assignRole` refuses it;
      // `saveRole` must not accept an id that can then never be granted.
      const saved = await adapter.saveRole({ id, name: 'N', permissions: [] }).then(
        () => true,
        () => false,
      )
      const granted = await adapter.assignRole('u1', id).then(
        () => true,
        () => false,
      )
      expect(
        saved && !granted,
        'saveRole accepted an id that assignRole then refused - the store holds an ungrantable role',
      ).toBe(false)
    })

    it('a scope holding a NUL byte cannot forge a different grant', async () => {
      reset()
      await adapter.saveRole({ id: 'editor', name: 'E', permissions: [] })
      await expect(adapter.assignRole('u1', 'editor', `org${NUL}1`)).rejects.toThrow(/NUL/)
      expect(await adapter.getSubjectRoles('u1')).toEqual([])
      expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
    })
  })

  describe('corrupt values must not read as absent', () => {
    it('an attributes blob holding JSON null throws rather than answering {}', async () => {
      reset()
      await client.set(`${prefix}attrs:u1`, 'null')
      // SECURITY: `{}` here would retire every deny rule that tests an attribute.
      await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow('IAM_ATTRIBUTES_CORRUPT')
    })

    it('an attributes blob holding a JSON array throws', async () => {
      reset()
      await client.set(`${prefix}attrs:u1`, '[1,2]')
      await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow('IAM_ATTRIBUTES_CORRUPT')
    })

    it('an attributes blob that is not JSON at all throws', async () => {
      reset()
      await client.set(`${prefix}attrs:u1`, 'not json')
      await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow('IAM_ATTRIBUTES_CORRUPT')
    })

    it('a stored __proto__ attribute key is refused, not read past', async () => {
      reset()
      await client.set(`${prefix}attrs:u1`, JSON.stringify(JSON.parse('{"__proto__":{"tier":"gold"},"team":"A"}')))
      // SECURITY: a `__proto__` key means corruption or an attack, so the whole bag is refused, not read in part.
      await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow('IAM_ATTRIBUTES_CORRUPT')
      expect(({} as Record<string, unknown>).tier, 'Object.prototype was polluted by the read').toBeUndefined()
    })

    it('a role member with no separator is a global grant, not a scoped one', async () => {
      reset()
      await adapter.saveRole({ id: 'editor', name: 'E', permissions: [] })
      // The shape written by a hand-rolled script, or by a much older version.
      await client.sadd(`${prefix}assignments:u1`, 'editor')
      expect(await adapter.getSubjectRoles('u1')).toEqual(['editor'])
      expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
    })

    it('a member whose scope half is empty decodes as global on both reads', async () => {
      reset()
      // `role\0` - the encoding's own spelling of "no scope".
      await client.sadd(`${prefix}assignments:u1`, `editor${NUL}`)
      expect(await adapter.getSubjectRoles('u1')).toEqual(['editor'])
      expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
    })
  })

  describe('two connections at once', () => {
    it('concurrent identical grants converge on one member', async () => {
      reset()
      const other = realClient(PORT as number)
      const b = new IamRedisAdapter<string, string, string, string>({ client: other, keyPrefix: prefix })
      await adapter.saveRole({ id: 'editor', name: 'Editor', permissions: [] })
      await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 === 0 ? adapter : b).assignRole('u1', 'editor')))
      expect(await client.smembers(`${prefix}assignments:u1`)).toEqual([`editor${NUL}`])
      expect(await adapter.getSubjectRoles('u1')).toEqual(['editor'])
    }, 30_000)

    it('a revoke on one connection is visible to the other immediately', async () => {
      reset()
      const other = realClient(PORT as number)
      const b = new IamRedisAdapter<string, string, string, string>({ client: other, keyPrefix: prefix })
      await adapter.saveRole({ id: 'editor', name: 'Editor', permissions: [] })
      await adapter.assignRole('u1', 'editor')
      expect(await b.getSubjectRoles('u1')).toEqual(['editor'])
      await b.revokeRole('u1', 'editor')
      // The adapter holds no cache, so this read is the server's answer.
      expect(await adapter.getSubjectRoles('u1')).toEqual([])
    }, 30_000)

    it('a revoke racing a grant from another connection leaves a consistent set', async () => {
      reset()
      const other = realClient(PORT as number)
      const b = new IamRedisAdapter<string, string, string, string>({ client: other, keyPrefix: prefix })
      await adapter.saveRole({ id: 'editor', name: 'Editor', permissions: [] })
      for (let i = 0; i < 10; i++) {
        await adapter.assignRole('u1', 'editor')
        await Promise.all([b.revokeRole('u1', 'editor'), adapter.assignRole('u1', 'editor')])
        const members = await client.smembers(`${prefix}assignments:u1`)
        expect(await adapter.getSubjectRoles('u1')).toEqual(members.length === 0 ? [] : ['editor'])
        await adapter.revokeRole('u1', 'editor')
      }
    }, 30_000)

    it('concurrent setSubjectAttributes from two connections keeps a readable bag', async () => {
      reset()
      const other = realClient(PORT as number)
      const b = new IamRedisAdapter<string, string, string, string>({ client: other, keyPrefix: prefix })
      await Promise.all([
        adapter.setSubjectAttributes('u1', { team: 'A' }),
        b.setSubjectAttributes('u1', { plan: 'p' }),
      ])
      const attrs = await adapter.getSubjectAttributes('u1')
      // Last-writer-wins is acceptable; an unparseable blob is not.
      expect(Object.keys(attrs).length).toBeGreaterThan(0)
    }, 30_000)
  })

  describe('agreement with the in-memory reference for the same calls', () => {
    it('the two adapters answer the same role sets for the same script', async () => {
      reset()
      const mem = new IamMemoryAdapter<string, string, string, string>()
      const script = async (a: IamRedisAdapter<string, string, string, string> | IamMemoryAdapter) => {
        await a.saveRole({ id: 'editor', name: 'E', permissions: [] })
        await a.saveRole({ id: 'viewer', name: 'V', permissions: [] })
        await a.assignRole('u1', 'editor')
        await a.assignRole('u1', 'viewer', 'org-1')
        await a.assignRole('u1', 'viewer', 'org-2')
        await a.revokeRole('u1', 'viewer', 'org-1')
        return {
          global: (await a.getSubjectRoles('u1')).sort(),
          scoped: (await (a.getSubjectScopedRoles?.('u1') ?? Promise.resolve([]))).map((s) => `${s.role}@${s.scope}`),
        }
      }
      expect(await script(adapter)).toEqual(await script(mem))
    })
  })
})
