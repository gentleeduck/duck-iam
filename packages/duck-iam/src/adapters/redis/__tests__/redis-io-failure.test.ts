import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../../core/types'
import { type IamRedis, IamRedisAdapter } from '../index'

type A = 'read'
type R = 'post'
type Ro = 'viewer' | 'editor'
type S = 'org-1'

const CONN_ERR = new Error('Redis connection to 127.0.0.1:6379 failed - ECONNREFUSED')

/** Client whose every command rejects, simulating a downed Redis. */
function downClient(): IamRedis.ILike {
  const fail = async (): Promise<never> => {
    throw CONN_ERR
  }
  return {
    del: fail,
    get: fail,
    hdel: fail,
    hget: fail,
    hgetall: fail,
    hkeys: fail,
    hset: fail,
    hvals: fail,
    sadd: fail,
    set: fail,
    smembers: fail,
    srem: fail,
  }
}

/** Client where a single named command rejects and everything else is a no-op. */
function clientFailingOn(command: keyof IamRedis.ILike): IamRedis.ILike {
  const client: IamRedis.ILike = {
    async del() {
      return 0
    },
    async get() {
      return null
    },
    async hdel() {
      return 0
    },
    async hget() {
      return null
    },
    async hgetall() {
      return {}
    },
    async hkeys() {
      return []
    },
    async hset() {
      return 1
    },
    async hvals() {
      return []
    },
    async sadd() {
      return 1
    },
    async set() {
      return 'OK'
    },
    async smembers() {
      return []
    },
    async srem() {
      return 0
    },
  }
  Reflect.set(client, command, async () => {
    throw CONN_ERR
  })
  return client
}

const policy: AccessControl.IPolicy<A, R, Ro> = {
  algorithm: 'deny-overrides',
  id: 'p1',
  name: 'Allow Read',
  rules: [{ actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 10, resources: ['post'] }],
}

describe('IamRedisAdapter connection failure', () => {
  it('read paths surface the connection error instead of degrading to an empty result', async () => {
    const adapter = new IamRedisAdapter<A, R, Ro, S>({ client: downClient() })
    await expect(adapter.listPolicies()).rejects.toThrow(/ECONNREFUSED/)
    await expect(adapter.getPolicy('p1')).rejects.toThrow(/ECONNREFUSED/)
    await expect(adapter.listRoles()).rejects.toThrow(/ECONNREFUSED/)
    await expect(adapter.getRole('editor')).rejects.toThrow(/ECONNREFUSED/)
    await expect(adapter.getSubjectRoles('user-1')).rejects.toThrow(/ECONNREFUSED/)
    await expect(adapter.getSubjectScopedRoles('user-1')).rejects.toThrow(/ECONNREFUSED/)
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(/ECONNREFUSED/)
  })

  it('write paths surface the connection error instead of reporting success', async () => {
    const adapter = new IamRedisAdapter<A, R, Ro, S>({ client: downClient() })
    await expect(adapter.savePolicy(policy)).rejects.toThrow(/ECONNREFUSED/)
    await expect(adapter.deletePolicy('p1')).rejects.toThrow(/ECONNREFUSED/)
    await expect(adapter.assignRole('user-1', 'editor')).rejects.toThrow(/ECONNREFUSED/)
    await expect(adapter.revokeRole('user-1', 'editor', 'org-1')).rejects.toThrow(/ECONNREFUSED/)
    await expect(adapter.setSubjectAttributes('user-1', { team: 'A' })).rejects.toThrow(/ECONNREFUSED/)
  })

  it('setSubjectAttributes still fails when the write fails, even though a corrupt read is tolerated', async () => {
    // `getSubjectAttributes` failing is swallowed by design (corrupt-blob
    // recovery); the SET itself failing must not be.
    const adapter = new IamRedisAdapter<A, R, Ro, S>({ client: clientFailingOn('set') })
    await expect(adapter.setSubjectAttributes('user-1', { team: 'A' })).rejects.toThrow(/ECONNREFUSED/)
  })

  it('a failed serialised write does not wedge later writes to the same assignments key', async () => {
    // `_runSerialised` chains per-key tasks; a rejected task must clear the
    // lock so the next caller is not blocked behind a permanently-rejected
    // promise.
    let failNext = true
    const client = clientFailingOn('smembers')
    Reflect.set(client, 'sadd', async () => {
      if (failNext) {
        failNext = false
        throw CONN_ERR
      }
      return 1
    })
    const adapter = new IamRedisAdapter<A, R, Ro, S>({ client })
    await expect(adapter.assignRole('user-1', 'editor')).rejects.toThrow(/ECONNREFUSED/)
    await expect(adapter.assignRole('user-1', 'editor')).resolves.toBeUndefined()
  })

  it.each([
    ['null', 'null'],
    ['array', '[]'],
    ['number', '42'],
    ['boolean', 'true'],
  ])('getSubjectAttributes rejects a %s attributes blob rather than returning {}', async (_label, blob) => {
    const client = clientFailingOn('hgetall')
    Reflect.set(client, 'get', async () => blob)
    const reported: string[] = []
    const adapter = new IamRedisAdapter<A, R, Ro, S>({
      client,
      onPolicyError: (err) => reported.push(err.message),
    })
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(/corrupted attributes/)
    expect(reported).toHaveLength(1)
  })
})
