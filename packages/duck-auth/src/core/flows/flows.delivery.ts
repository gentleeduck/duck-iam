import type { Channel } from '~/channels/channels.types'
import type { Events } from '~/core/events'

/** A send whose result is read. */
export async function deliver(
  events: Pick<Events.IBus, 'emit'>,
  flow: string,
  channel: Channel.Channel,
  input: Channel.SendInput,
): Promise<Channel.SendResult> {
  try {
    const result = await channel.send(input)
    if (!result.ok) {
      // Not the channel's own error text: it can carry the rendered body, and with it the token URL.
      await events.emit('signin.failed', { providerId: flow, reason: 'channel.send rejected delivery' })
    }
    return result
  } catch (err) {
    await events.emit('signin.failed', {
      providerId: flow,
      reason: `channel.send threw: ${err instanceof Error ? err.message : String(err)}`,
    })
    return { error: 'channel.send threw', ok: false, retryable: true }
  }
}
