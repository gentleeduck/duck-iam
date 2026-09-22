import { createHash } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createIamRedisInvalidator, type IamRedisInvalidator } from '../index'

// SECURITY: warnings name the channel, which carries the tenant id; the tenant segment must appear only as a stable
// digest, since anyone with PUBLISH rights can trigger a drop warning.

const TENANT = 'acme-corp-billing'

function bus(): IamRedisInvalidator.IPubSubLike {
  const handlers: ((m: string) => void)[] = []
  return {
    publish(_channel, message) {
      for (const h of handlers) h(message)
    },
    subscribe(_channel, h) {
      handlers.push(h)
    },
    unsubscribe() {},
  }
}

describe('drop warning does not disclose the tenant id', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })

  afterEach(() => {
    warnSpy.mockRestore()
  })

  async function forceDrop(tenantId: string): Promise<string> {
    const client = bus()
    const receiver = createIamRedisInvalidator({ client, secret: 'shared-secret', tenantId })
    await receiver.subscribe(() => {})
    // Unparseable under a secret: dropped as unverifiable, which is what warns.
    client.publish('ignored', 'not json at all')
    const line = warnSpy.mock.calls
      .map((c: unknown[]) => String(c[0]))
      .find((m: string) => m.includes('dropping unverifiable'))
    expect(line, 'expected a drop warning to have been emitted').toBeDefined()
    return line ?? ''
  }

  it('omits the tenant id from the warning', async () => {
    expect(await forceDrop(TENANT)).not.toContain(TENANT)
  })

  it('still names the operator-chosen base channel, so the log stays actionable', async () => {
    expect(await forceDrop(`${TENANT}-2`)).toContain('iam:invalidate')
  })

  // No per-process salt: the same tenant must read the same on every host, or incidents cannot be correlated.
  it('derives the token from the tenant id alone, with no per-process salt', async () => {
    const tenantId = `${TENANT}-stable`
    const expected = createHash('sha256').update(tenantId).digest('hex').slice(0, 8)
    expect(await forceDrop(tenantId)).toContain(`tenant:${expected}`)
  })

  it('gives two tenants two different tokens', async () => {
    const a = await forceDrop(`${TENANT}-a`)
    warnSpy.mockClear()
    const b = await forceDrop(`${TENANT}-b`)
    const token = (line: string): string => line.match(/tenant:([0-9a-f]{8})/)?.[1] ?? ''
    expect(token(a)).not.toBe('')
    expect(token(a)).not.toBe(token(b))
  })
})

// Subscribe and unsubscribe failure warnings redact the tenant too; a broker hiccup is enough to trigger them.
describe('subscribe and unsubscribe failures do not disclose the tenant id either', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })

  afterEach(() => {
    warnSpy.mockRestore()
  })

  function lineContaining(needle: string): string {
    const line = warnSpy.mock.calls.map((c: unknown[]) => String(c[0])).find((m: string) => m.includes(needle))
    expect(line, `expected a warning containing ${needle}`).toBeDefined()
    return line ?? ''
  }

  it('a failed subscribe warns without naming the tenant', async () => {
    const tenantId = `${TENANT}-sub`
    const client: IamRedisInvalidator.IPubSubLike = {
      publish() {},
      subscribe() {
        throw new Error('NOAUTH Authentication required')
      },
      unsubscribe() {},
    }
    const receiver = createIamRedisInvalidator({ client, tenantId })
    await receiver.subscribe(() => {})

    const line = lineContaining('subscribe to')
    expect(line).not.toContain(tenantId)
    expect(line).toContain('iam:invalidate')
    expect(line).toContain(`tenant:${createHash('sha256').update(tenantId).digest('hex').slice(0, 8)}`)
  })

  it('a failed unsubscribe warns without naming the tenant', async () => {
    const tenantId = `${TENANT}-unsub`
    const client: IamRedisInvalidator.IPubSubLike = {
      publish() {},
      subscribe() {},
      unsubscribe() {
        return Promise.reject(new Error('connection reset'))
      },
    }
    const receiver = createIamRedisInvalidator({ client, tenantId })
    const off = await receiver.subscribe(() => {})
    off()
    // Let the rejection handler attached to the returned thenable run.
    await Promise.resolve()
    await Promise.resolve()

    const line = lineContaining('unsubscribe from')
    expect(line).not.toContain(tenantId)
    expect(line).toContain('iam:invalidate')
  })
})
