import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { credentialInput } from '~/test/store-inputs'
import { ApiKeysFacet } from '../api-key.facet'

function build() {
  const adapter = new MemoryAdapter()
  const events = new InMemoryEvents()
  const facet = new ApiKeysFacet(adapter.credentials, events, { randomToken: randomToken, sha256: sha256 })
  return { adapter, facet }
}

async function plantMalformedMetadata(adapter: MemoryAdapter, identityId: string, metadata: unknown) {
  // Direct adapter write to seed a row with a metadata shape that the
  // facet's create() method would never produce. Mirrors what a buggy
  // store / schema drift / pre-migration value looks like.
  const cred = await adapter.credentials.upsert(
    credentialInput({
      identityId,
      kind: 'api-key',
      secret: 'ignored-hash',
      // Metadata typed as `unknown` at the contract; the adapter
      // happily stores whatever we give it.
      metadata: metadata as Record<string, unknown>,
    }),
    {},
  )
  return cred
}

describe('ApiKeysFacet - metadata parser', () => {
  let adapter: MemoryAdapter
  let facet: ApiKeysFacet
  const identityId = 'identity-1'

  beforeEach(() => {
    ;({ adapter, facet } = build())
  })

  describe('list()', () => {
    it('projects { name: "", scopes: [] } when metadata is null', async () => {
      await plantMalformedMetadata(adapter, identityId, null)
      const keys = await facet.list(identityId)
      expect(keys).toHaveLength(1)
      expect(keys[0]!.name).toBe('')
      expect(keys[0]!.scopes).toEqual([])
    })

    it('projects defaults when metadata is a primitive (string)', async () => {
      await plantMalformedMetadata(adapter, identityId, 'oops')
      const keys = await facet.list(identityId)
      expect(keys[0]!.name).toBe('')
      expect(keys[0]!.scopes).toEqual([])
    })

    it('projects defaults when metadata is an array (the cast would have crashed downstream)', async () => {
      await plantMalformedMetadata(adapter, identityId, ['admin', 'editor'])
      const keys = await facet.list(identityId)
      expect(keys[0]!.name).toBe('')
      expect(keys[0]!.scopes).toEqual([])
    })

    it('coerces non-string `name` to ""', async () => {
      await plantMalformedMetadata(adapter, identityId, { name: 42, scopes: ['admin'] })
      const keys = await facet.list(identityId)
      expect(keys[0]!.name).toBe('')
      expect(keys[0]!.scopes).toEqual(['admin'])
    })

    it('coerces non-array `scopes` to []', async () => {
      await plantMalformedMetadata(adapter, identityId, { name: 'CI key', scopes: 'admin' })
      const keys = await facet.list(identityId)
      expect(keys[0]!.name).toBe('CI key')
      // Without the parser, this would have been the string 'admin'
      // typed as string[] - and `requireScopes(['admin']).filter` would
      // have crashed with TypeError downstream.
      expect(keys[0]!.scopes).toEqual([])
      expect(Array.isArray(keys[0]!.scopes)).toBe(true)
    })

    it('filters non-string entries out of `scopes`', async () => {
      await plantMalformedMetadata(adapter, identityId, {
        name: 'CI key',
        scopes: ['admin', 42, null, { x: 1 }, 'editor', undefined, true],
      })
      const keys = await facet.list(identityId)
      expect(keys[0]!.scopes).toEqual(['admin', 'editor'])
    })

    it('passes well-formed metadata through unchanged', async () => {
      await plantMalformedMetadata(adapter, identityId, {
        name: 'CI key',
        scopes: ['deploy', 'logs:read'],
      })
      const keys = await facet.list(identityId)
      expect(keys[0]!.name).toBe('CI key')
      expect(keys[0]!.scopes).toEqual(['deploy', 'logs:read'])
    })
  })

  describe('verify()', () => {
    it('returns sanitized scopes even when adapter row carries malformed scopes', async () => {
      // Seed a malformed row directly (mirrors an adapter / schema-drift
      // condition where the credential's metadata was written by a
      // legacy / buggy code path). The plaintext token mapping
      // `${prefix}${random}` -> `sha256` lets us round-trip verify().
      const plaintext = `ak_live_${randomToken(32)}`
      const hash = sha256(plaintext)
      await adapter.credentials.upsert(
        credentialInput({
          identityId,
          kind: 'api-key',
          secret: hash,
          metadata: { name: 42, scopes: ['deploy', 42, null, 'logs:read'] },
        }),
        {},
      )
      const result = await facet.verify(plaintext)
      expect(result.identityId).toBe(identityId)
      // Non-string entries filtered; valid strings preserved.
      expect(result.scopes).toEqual(['deploy', 'logs:read'])
    })
  })

  describe('rotate()', () => {
    it('rotates a key whose metadata was malformed; new key carries sanitized scopes', async () => {
      const cred = await plantMalformedMetadata(adapter, identityId, {
        name: 42, // non-string name
        scopes: ['admin', null, 'editor'], // mixed-type scopes
      })
      const { key } = await facet.rotate(cred.id)
      expect(key.name).toBe('') // non-string name coerced
      expect(key.scopes).toEqual(['admin', 'editor']) // bad entry dropped
    })
  })
})
