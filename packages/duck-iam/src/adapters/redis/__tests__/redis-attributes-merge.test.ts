import { describe, expect, it } from 'vitest'
import type { IamRedis } from '../index'
import { IamRedisAdapter } from '../index'

// `setSubjectAttributes` must overwrite a corrupt stored blob but refuse to merge after a failed `GET`, which would
// replace the whole bag. Both halves are tested so fixing one cannot break the other.

/** Only the two commands the attribute path uses, with a breakable `GET`. */
class Client implements Partial<IamRedis.ILike> {
  failGet = false
  strings = new Map<string, string>()
  async get(key: string): Promise<string | null> {
    if (this.failGet) throw new Error('ECONNRESET: redis went away')
    return this.strings.get(key) ?? null
  }
  async set(key: string, value: string): Promise<unknown> {
    this.strings.set(key, value)
    return 'OK'
  }
}

/** Seeds `{suspended: true, tier: 'gold'}` and hands back the pieces. */
async function seeded() {
  const client = new Client()
  const errors: unknown[] = []
  const adapter = new IamRedisAdapter({ client: client as never, onPolicyError: (e) => errors.push(e) })
  await adapter.setSubjectAttributes('u1', { suspended: true, tier: 'gold' })
  // Read the key back rather than hard-coding the adapter's key layout.
  const key = [...client.strings.keys()][0]
  if (key === undefined) throw new Error('probe setup failed: nothing was stored')
  const stored = (): unknown => JSON.parse(client.strings.get(key) ?? 'null')
  return { adapter, client, errors, key, stored }
}

describe('redis setSubjectAttributes distinguishes corruption from a failed read', () => {
  it('CONTROL: a healthy merge keeps the attribute the caller did not mention', async () => {
    const { adapter, stored } = await seeded()
    await adapter.setSubjectAttributes('u1', { tier: 'silver' })
    expect(stored()).toEqual({ suspended: true, tier: 'silver' })
  })

  it('a failed GET refuses the write instead of replacing the bag', async () => {
    const { adapter, client, stored } = await seeded()
    client.failGet = true
    await expect(adapter.setSubjectAttributes('u1', { tier: 'silver' })).rejects.toThrow(/ECONNRESET/)
    client.failGet = false
    // `suspended` survives and `tier` is unchanged: a refused write lands nothing.
    expect(stored()).toEqual({ suspended: true, tier: 'gold' })
  })

  it('a failed GET is not swallowed into the policy-error channel', async () => {
    const { adapter, client, errors } = await seeded()
    client.failGet = true
    await adapter.setSubjectAttributes('u1', { tier: 'silver' }).catch(() => undefined)
    // A driver outage is not a policy problem, so it must not be reported there as if handled.
    expect(errors).toEqual([])
  })

  it('a corrupt blob is still recoverable, so the operator is not locked out', async () => {
    const { adapter, client, key, stored } = await seeded()
    client.strings.set(key, '["not an object"]')
    await adapter.setSubjectAttributes('u1', { tier: 'silver' })
    expect(stored()).toEqual({ tier: 'silver' })
  })

  it('a corrupt blob still reports through onPolicyError', async () => {
    const { adapter, client, errors, key } = await seeded()
    client.strings.set(key, 'not json at all')
    await adapter.setSubjectAttributes('u1', { tier: 'silver' })
    expect(errors.length).toBeGreaterThan(0)
  })

  it('the corruption signal is matched by name, so a duplicated package copy still matches', async () => {
    const { adapter, client, key } = await seeded()
    client.strings.set(key, '["not an object"]')
    const err = await adapter.getSubjectAttributes('u1').then(
      () => null,
      (e: unknown) => e,
    )
    expect(err).toBeInstanceOf(Error)
    expect((err as Error).name).toBe('IamRedisCorruptAttributesError')
  })
})
