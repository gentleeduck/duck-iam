/**
 * A verify already in flight must not write the key back as it found it. Ported from better-auth's
 * `api-key.test.ts`; `verify` stamps `lastUsedAt` after the revoke check, on a row read before the revoke.
 *
 * Three guards stop that write resurrecting the key - the version bump losing its CAS, `rotate` writing only
 * `lastUsedAt` and `secret`, and `rotate` refusing a gone id - and these cases fail only once the first two
 * are both removed, which is what makes them worth keeping.
 */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { orNull } from '~/core/answer'
import type { Credential } from '~/core/credentials'
import { randomToken, sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { ApiKeysFacet } from '../api-key'
import { DEFAULT_APIKEYS_CONFIG } from '../api-key.constants'

function facetOver(store: Credential.Store): ApiKeysFacet {
  return new ApiKeysFacet(store, new InMemoryEvents(), { randomToken, sha256 }, DEFAULT_APIKEYS_CONFIG)
}

/** One store, two facets: `plain` mints and reads back, `raced` is the verify that gets interrupted. */
function build(during: (store: Credential.Store) => Promise<void>) {
  const adapter = new MemoryAdapter()
  const base = adapter.credentials
  return {
    adapter,
    plain: facetOver(base),
    raced: facetOver(interleave(base, () => during(base))),
  }
}

/** Runs `during` once, after `verify` reads the row and before its `lastUsedAt` write goes out. */
function interleave(store: Credential.Store, during: () => Promise<void>): Credential.Store {
  let fired = false
  return new Proxy(store, {
    get(target, prop, receiver) {
      if (prop !== 'findByHashedSecret') return Reflect.get(target, prop, receiver)
      return async (...args: Parameters<Credential.Store['findByHashedSecret']>) => {
        const found = await target.findByHashedSecret(...args)
        if (!fired) {
          fired = true
          await during()
        }
        return found
      }
    },
  })
}

/** `verify` fires its `lastUsedAt` write without awaiting it, so the assertions wait a turn for it. */
async function settle(): Promise<void> {
  await new Promise((resolve) => setImmediate(resolve))
}

describe('a revoke landing mid-verify stays landed', () => {
  it('does not re-enable the key the verify had already read as live', async () => {
    let id = ''
    const { adapter, plain, raced } = build(async (store) => {
      await orNull(store.revoke(id, {}))
    })
    const { key, plaintext } = await plain.create('user-1', { name: 'ci', scopes: ['deploy'], session: null })
    id = key.id
    // The verify answers off a live row; the write that follows must not put the row back as it read it.
    await raced.verify(plaintext).catch(() => undefined)
    await settle()
    expect((await adapter.credentials.findById(key.id, {})).revokedAt).not.toBeNull()
  })

  it('leaves the key refused on the next verify, which is what the revoke was for', async () => {
    let id = ''
    const { plain, raced } = build(async (store) => {
      await orNull(store.revoke(id, {}))
    })
    const { key, plaintext } = await plain.create('user-1', { name: 'ci', scopes: ['deploy'], session: null })
    id = key.id
    await raced.verify(plaintext).catch(() => undefined)
    await settle()
    await expect(plain.verify(plaintext)).rejects.toMatchObject({ code: 'AUTH_APIKEY_REVOKED' })
  })

  it('does not recreate a key deleted while the verify was running', async () => {
    let id = ''
    const { adapter, plain, raced } = build(async (store) => {
      await orNull(store.delete(id, {}))
    })
    const { key, plaintext } = await plain.create('user-1', { name: 'ci', scopes: ['deploy'], session: null })
    id = key.id
    await raced.verify(plaintext).catch(() => undefined)
    await settle()
    expect(await orNull(adapter.credentials.findById(key.id, {}))).toBeNull()
  })

  it('still stamps lastUsedAt when nothing raced it, so the write under test is real', async () => {
    const { adapter, plain } = build(async () => undefined)
    const { key, plaintext } = await plain.create('user-1', { name: 'ci', scopes: ['deploy'], session: null })
    expect((await adapter.credentials.findById(key.id, {})).lastUsedAt).toBeNull()
    await plain.verify(plaintext)
    await settle()
    expect((await adapter.credentials.findById(key.id, {})).lastUsedAt).toBeInstanceOf(Date)
  })
})
