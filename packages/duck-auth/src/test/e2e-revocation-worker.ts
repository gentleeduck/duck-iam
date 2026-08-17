/**
 * Child process for the multi-instance revocation e2e test.
 *
 * Plan `C3-engine/01-jwt-instant-revocation.md` keeps an in-memory revocation
 * registry fresh over pub/sub. That design **cannot be validated in one
 * process** — a single instance both publishes and subscribes, and `RedisEvents`
 * dedupes its own messages by instance id, so the fan-out path never executes.
 *
 * This worker is a real second instance: its own process, its own connections,
 * its own `RedisEvents` instance id. It reports what it observed back through
 * Redis so the parent can measure propagation without parsing stdout.
 *
 * Usage: bun run src/test/e2e-revocation-worker.ts <redisUrl> <runId> <workerId>
 */
import Redis from 'ioredis'
import type { RedisLike } from '~/adapters/redis/redis-like'
import { RedisEvents } from '~/core/events/events.redis'

const [, , redisUrl, runId, workerId] = process.argv
if (!redisUrl || !runId || !workerId) {
  console.error('usage: worker <redisUrl> <runId> <workerId>')
  process.exit(1)
}

const READY_KEY = `${runId}:ready`
const RESULT_KEY = `${runId}:results`
const LIFETIME_MS = 15_000

/** ioredis -> the `RedisEvents.Client` surface (RedisLike + publish/subscribe). */
function toEventsClient(cmd: Redis, sub: Redis): RedisEvents.Client {
  const base: Partial<RedisLike.Client> = {
    get: (k) => cmd.get(k),
    set: async (k, v, o) => (o?.ex !== undefined ? cmd.set(k, v, 'EX', o.ex) : cmd.set(k, v)),
    del: (...keys) => cmd.del(...keys),
    expire: (k, s) => cmd.expire(k, s),
    incr: (k) => cmd.incr(k),
    sadd: (k, ...m) => cmd.sadd(k, ...m),
    srem: (k, ...m) => cmd.srem(k, ...m),
    smembers: (k) => cmd.smembers(k),
    scan: async (cursor, opts) => {
      const args: (string | number)[] = [cursor]
      if (opts?.match) args.push('MATCH', opts.match)
      if (opts?.count) args.push('COUNT', opts.count)
      return (await cmd.scan(...(args as [string]))) as [string, string[]]
    },
  }
  return {
    ...(base as RedisLike.Client),
    publish: (channel, message) => cmd.publish(channel, message),
    subscribe: async (channel, handler) => {
      // A subscribed ioredis connection cannot issue other commands, which is
      // exactly why this worker holds two.
      await sub.subscribe(channel)
      const onMessage = (ch: string, msg: string) => {
        if (ch === channel) void handler(ch, msg)
      }
      sub.on('message', onMessage)
      return async () => {
        sub.off('message', onMessage)
        await sub.unsubscribe(channel)
      }
    },
  }
}

async function main(): Promise<void> {
  const cmd = new Redis(redisUrl as string)
  const sub = new Redis(redisUrl as string)
  const bus = new RedisEvents({ redis: toEventsClient(cmd, sub) })

  // The registry this simulates: identityId -> revocation instant.
  const revoked = new Map<string, number>()

  bus.on('authz.revoked', (p) => {
    const at = Date.now()
    const payload = p as unknown as { identityId: string; at: number }
    revoked.set(payload.identityId, payload.at)
    void cmd.rpush(
      RESULT_KEY,
      JSON.stringify({
        workerId,
        identityId: payload.identityId,
        publishedAt: payload.at,
        receivedAt: at,
        latencyMs: at - payload.at,
        registrySize: revoked.size,
      }),
    )
  })

  // Subscription is established lazily on first `on()`; give it a beat before
  // declaring ready, otherwise the parent can publish into a void.
  await new Promise((r) => setTimeout(r, 300))
  await cmd.rpush(READY_KEY, workerId)

  setTimeout(async () => {
    await cmd.quit()
    await sub.quit()
    process.exit(0)
  }, LIFETIME_MS)
}

void main()
