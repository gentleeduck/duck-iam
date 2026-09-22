/** Child process for the multi-instance revocation e2e test. */
import Redis from 'ioredis'
import type { ValkeyClient, ValkeySubscriberClient } from '~/adapters/valkey'
import { RedisEvents } from '~/core/events/events.redis'
import { valkeyPubSubAdapter } from '~/core/events/events.valkey'

/** Read a required positional arg. Returns `string`, so callers need no cast. */
function required(value: string | undefined, name: string): string {
  if (value !== undefined && value.length > 0) return value
  console.error(`usage: worker <redisUrl> <runId> <workerId> (missing ${name})`)
  process.exit(1)
}

const redisUrl = required(process.argv[2], 'redisUrl')
const runId = required(process.argv[3], 'runId')
const workerId = required(process.argv[4], 'workerId')

const READY_KEY = `${runId}:ready`
const RESULT_KEY = `${runId}:results`
const LIFETIME_MS = 15_000

async function main(): Promise<void> {
  const cmd = new Redis(redisUrl)
  const sub = new Redis(redisUrl)
  const bus = new RedisEvents({
    redis: valkeyPubSubAdapter(
      cmd as unknown as ValkeyClient.Me & { publish(channel: string, message: string): Promise<number> },
      sub as unknown as ValkeySubscriberClient.Me,
    ),
  })

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
