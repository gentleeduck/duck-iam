/**
 * AAL=3 detection edge cases for `MfaFacet.eligibleAal`. The base
 * mfa.test.ts covers AAL=1/2 transitions; here we exercise the
 * passkey hardware-binding path added per NIST 800-63B.
 */

import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import { credentialInput } from '~/test/store-inputs'
import { DEFAULT_MFA_CONFIG } from '../mfa.constants'
import { MfaFacet } from '../mfa.facet'

describe('MfaFacet.eligibleAal - AAL=3 detection (NIST 800-63B hardware binding)', () => {
  let adapter: MemoryAdapter
  let facet: MfaFacet

  beforeEach(() => {
    adapter = new MemoryAdapter()
    facet = new MfaFacet(adapter.credentials, new InMemoryEvents(), DEFAULT_MFA_CONFIG)
  })

  it('returns 3 when the user has a hardware-bound passkey + signed in with passkey', async () => {
    await adapter.credentials.upsert(
      credentialInput({
        identityId: 'u',
        kind: 'passkey',
        metadata: { backedUp: false, counter: 0, deviceType: 'singleDevice' },
        secret: 'cred-id',
      }),
      {},
    )
    expect(await facet.eligibleAal('u', ['passkey', 'password'])).toBe(3)
  })

  it('returns 2 when the passkey is cloud-synced (backedUp:true), even with two factors', async () => {
    await adapter.credentials.upsert(
      credentialInput({
        identityId: 'u',
        kind: 'passkey',
        metadata: { backedUp: true, counter: 0, deviceType: 'multiDevice' },
        secret: 'cred-id',
      }),
      {},
    )
    expect(await facet.eligibleAal('u', ['passkey', 'password'])).toBe(2)
  })

  it('returns 2 when deviceType is singleDevice but backedUp is true (e.g. local-only-but-synced)', async () => {
    await adapter.credentials.upsert(
      credentialInput({
        identityId: 'u',
        kind: 'passkey',
        metadata: { backedUp: true, counter: 0, deviceType: 'singleDevice' },
        secret: 'cred-id',
      }),
      {},
    )
    expect(await facet.eligibleAal('u', ['passkey', 'password'])).toBe(2)
  })

  it('returns 2 when current factor set does NOT include authPasskey (even if user has one)', async () => {
    await adapter.credentials.upsert(
      credentialInput({
        identityId: 'u',
        kind: 'passkey',
        metadata: { backedUp: false, counter: 0, deviceType: 'singleDevice' },
        secret: 'cred-id',
      }),
      {},
    )
    expect(await facet.eligibleAal('u', ['password', 'totp'])).toBe(2)
  })

  it('returns 3 when ANY of the user passkeys is hardware-bound', async () => {
    await adapter.credentials.upsert(
      credentialInput({
        identityId: 'u',
        kind: 'passkey',
        metadata: { backedUp: true, counter: 0, deviceType: 'multiDevice' },
        secret: 'cred-1',
      }),
      {},
    )
    await adapter.credentials.upsert(
      credentialInput({
        identityId: 'u',
        kind: 'passkey',
        metadata: { backedUp: false, counter: 0, deviceType: 'singleDevice' },
        secret: 'cred-2',
      }),
      {},
    )
    expect(await facet.eligibleAal('u', ['passkey', 'password'])).toBe(3)
  })

  it('AAL drops back to 1 with only a single factor regardless of passkey hardware binding', async () => {
    await adapter.credentials.upsert(
      credentialInput({
        identityId: 'u',
        kind: 'passkey',
        metadata: { backedUp: false, counter: 0, deviceType: 'singleDevice' },
        secret: 'cred-1',
      }),
      {},
    )
    expect(await facet.eligibleAal('u', ['passkey'])).toBe(1)
  })

  it('missing passkey metadata fields gracefully fall back to AAL=2', async () => {
    await adapter.credentials.upsert(
      credentialInput({
        identityId: 'u',
        kind: 'passkey',
        metadata: {},
        secret: 'cred-1',
      }),
      {},
    )
    expect(await facet.eligibleAal('u', ['passkey', 'password'])).toBe(2)
  })
})
