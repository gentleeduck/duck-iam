import { type ValkeyClient, type ValkeySubscriberClient, valkeyAdapter } from '~/adapters/valkey/valkey-like'
import { RedisEvents } from './events.redis'

/**
 * Adapts an ioredis/iovalkey `{ cmd, sub }` connection pair to {@link RedisEvents.Client}.
 * `cmd` carries ordinary commands and `PUBLISH`; `sub` is dedicated to `SUBSCRIBE` (see
 * {@link ValkeySubscriberClient}) since a connection in subscriber mode cannot run
 * ordinary commands. ioredis delivers every subscribed channel through one shared
 * `'message'` event rather than a per-call callback, so this filters by channel;
 * `RedisEvents.on()` subscribes at most once per channel and unsubscribes at most once
 * when its local handlers drain to zero, so it never needs concurrent listeners on the
 * same channel.
 */
export function valkeyPubSubAdapter(
  cmd: ValkeyClient.Me & { publish(channel: string, message: string): Promise<number> },
  sub: ValkeySubscriberClient.Me,
): RedisEvents.Client {
  return {
    ...valkeyAdapter(cmd),
    publish: (channel, message) => cmd.publish(channel, message),
    subscribe: async (channel, onMessage) => {
      const listener = (ch: string, message: string) => {
        if (ch === channel) void onMessage(ch, message)
      }
      sub.on('message', listener)
      await sub.subscribe(channel)
      return async () => {
        sub.off('message', listener)
        await sub.unsubscribe(channel)
      }
    },
  }
}

/**
 * {@link RedisEvents}, driven by an ioredis/iovalkey `{ cmd, sub }` connection pair via
 * {@link valkeyPubSubAdapter}. `sub` must be a connection dedicated to this call.
 */
export function valkeyEvents(
  cfg: Omit<RedisEvents.Cfg, 'redis'> & {
    cmd: ValkeyClient.Me & { publish(channel: string, message: string): Promise<number> }
    sub: ValkeySubscriberClient.Me
  },
): RedisEvents {
  const { cmd, sub, ...rest } = cfg
  return new RedisEvents({ ...rest, redis: valkeyPubSubAdapter(cmd, sub) })
}
