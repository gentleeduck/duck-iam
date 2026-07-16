/**
 * Stress test for `Credential.IStore.patchMetadata` on the memory
 * adapter: concurrent patches converge, version monotonically
 * increases, and partial patches don't clobber earlier keys.
 */

import { describe, expect, it } from 'vitest'
import { credentialInput } from '~/test/store-inputs'
import { MemoryAdapter } from '../index'

describe('memory.credentials.patchMetadata - concurrency & convergence', () => {
  it('100 concurrent disjoint patches all land', async () => {
    const adapter = new MemoryAdapter()
    const c = await adapter.credentials.upsert(
      credentialInput({ identityId: 'u', kind: 'passkey', metadata: { counter: 0 }, secret: 's' }),
      {},
    )
    await Promise.all(
      Array.from({ length: 100 }, (_, i) => adapter.credentials.patchMetadata(c.id, { [`k${i}`]: i }, {})),
    )
    const row = await adapter.credentials.findById(c.id, {})
    const meta = row?.metadata as Record<string, unknown>
    expect(meta.counter).toBe(0)
    for (let i = 0; i < 100; i++) expect(meta[`k${i}`]).toBe(i)
    expect(row?.version).toBeGreaterThan(100)
  })

  it('overlapping patches: the last write of a shared key wins; version still bumps cleanly', async () => {
    const adapter = new MemoryAdapter()
    const c = await adapter.credentials.upsert(
      credentialInput({ identityId: 'u', kind: 'passkey', metadata: { counter: 0 }, secret: 's' }),
      {},
    )
    for (let i = 1; i <= 25; i++) {
      await adapter.credentials.patchMetadata(c.id, { counter: i }, {})
    }
    const row = await adapter.credentials.findById(c.id, {})
    expect((row?.metadata as { counter: number }).counter).toBe(25)
    expect(row?.version).toBe(c.version + 25)
  })

  it('patch never deletes a pre-existing key not mentioned in the patch', async () => {
    const adapter = new MemoryAdapter()
    const c = await adapter.credentials.upsert(
      credentialInput({
        identityId: 'u',
        kind: 'passkey',
        metadata: { aaguid: 'abc', backedUp: false, counter: 1, deviceType: 'singleDevice' },
        secret: 's',
      }),
      {},
    )
    await adapter.credentials.patchMetadata(c.id, { counter: 2 }, {})
    const row = await adapter.credentials.findById(c.id, {})
    const m = row?.metadata as Record<string, unknown>
    expect(m.aaguid).toBe('abc')
    expect(m.backedUp).toBe(false)
    expect(m.deviceType).toBe('singleDevice')
    expect(m.counter).toBe(2)
  })

  it('patch on a revoked credential still succeeds (revoke is informational, not a lock)', async () => {
    const adapter = new MemoryAdapter()
    const c = await adapter.credentials.upsert(
      credentialInput({ identityId: 'u', kind: 'passkey', metadata: { counter: 1 }, secret: 's' }),
      {},
    )
    await adapter.credentials.revoke(c.id, {})
    await adapter.credentials.patchMetadata(c.id, { counter: 5 }, {})
    const row = await adapter.credentials.findById(c.id, {})
    expect((row?.metadata as { counter: number }).counter).toBe(5)
    expect(row?.revokedAt).toBeDefined()
  })

  it('patch on a missing id throws AUTH/UNAUTHENTICATED', async () => {
    const adapter = new MemoryAdapter()
    await expect(adapter.credentials.patchMetadata('missing', { x: 1 }, {})).rejects.toMatchObject({
      code: 'AUTH_UNAUTHENTICATED',
    })
  })
})
