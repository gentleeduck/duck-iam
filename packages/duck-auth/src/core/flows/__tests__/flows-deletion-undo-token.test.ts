/**
 * D2's token half. `cancelAccountDeletion` had exactly one gate - an `authorize`
 * callback - which is the operator's route. A user clicking "undo" in their mail
 * has the mail and no admin rights, so the grace window `restorableUntil`
 * advertises was reachable only by asking support.
 *
 * `completeAccountDeletion` now mints a single-use undo token, expiring exactly
 * when the window does, and `cancelAccountDeletion` takes either that or the
 * callback - one or the other, never both.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthTestChannel } from '~/channels/console'
import { RECOVERY_PURPOSES } from '~/core/credentials/credentials'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

type CancelInput = Parameters<AuthEngine<MyProfile>['flows']['cancelAccountDeletion']>[0]

describe('account deletion - the undo token', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  let identityId: string
  let channel: AuthTestChannel

  /** request -> complete, returning what `completeAccountDeletion` answered. */
  async function deleteAccount(completeOpts: Record<string, unknown> = {}) {
    await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId })
    const url = (channel.outbox.at(-1)!.vars as { url: string }).url
    const token = new URL(url).searchParams.get('token')!
    return auth.flows.completeAccountDeletion({ token, ...completeOpts })
  }

  beforeEach(async () => {
    adapter = new MemoryAdapter<MyProfile>()
    auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app',
      transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
      providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
    })
    const ident = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    identityId = ident.id
    channel = new AuthTestChannel()
  })

  describe('minting', () => {
    it('completeAccountDeletion returns an undo token', async () => {
      const result = await deleteAccount()
      expect(typeof result.cancellationToken).toBe('string')
      expect(result.cancellationToken.length).toBeGreaterThan(20)
    })

    it('the token is stored hashed, never in plaintext', async () => {
      const { cancellationToken } = await deleteAccount()
      const rows = await adapter.credentials.listByIdentity(identityId, 'recovery', {})
      const undo = rows.filter(
        (r) => (r.metadata as { purpose?: string } | null)?.purpose === RECOVERY_PURPOSES.accountDeletionCancel,
      )
      expect(undo).toHaveLength(1)
      expect(undo[0]!.secret).not.toBe(cancellationToken)
    })

    it('it expires exactly when the grace window does', async () => {
      const { restorableUntil } = await deleteAccount()
      const rows = await adapter.credentials.listByIdentity(identityId, 'recovery', {})
      const undo = rows.find(
        (r) => (r.metadata as { purpose?: string } | null)?.purpose === RECOVERY_PURPOSES.accountDeletionCancel,
      )!
      expect(undo.expiresAt?.getTime()).toBe(restorableUntil)
    })

    it('nothing is minted when the deletion itself fails', async () => {
      await expect(auth.flows.completeAccountDeletion({ token: 'not-a-real-token' })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
      expect(await adapter.credentials.listByIdentity(identityId, 'recovery', {})).toEqual([])
    })

    it('the undo mail is only sent when channels are supplied', async () => {
      await deleteAccount()
      // One mail: the deletion confirmation. No undo mail without `channels`.
      expect(channel.outbox.map((m) => m.templateId)).toEqual(['account-deletion'])
    })

    it('with channels, the undo link is mailed and carries the token', async () => {
      const { cancellationToken } = await deleteAccount({ channels: { email: channel } })
      const last = channel.outbox.at(-1)!
      expect(last.templateId).toBe('account-deletion-cancel')
      const url = new URL((last.vars as { url: string }).url)
      expect(url.pathname).toBe('/auth/cancel-deletion')
      expect(url.searchParams.get('token')).toBe(cancellationToken)
    })

    it('an unsafe callbackPath falls back to the default rather than being used', async () => {
      await deleteAccount({ callbackPath: 'https://evil.example/steal', channels: { email: channel } })
      const url = new URL((channel.outbox.at(-1)!.vars as { url: string }).url)
      expect(url.origin).toBe('https://app')
      expect(url.pathname).toBe('/auth/cancel-deletion')
    })
  })

  describe('redeeming', () => {
    it('the token restores the account with no callback at all', async () => {
      const { cancellationToken } = await deleteAccount()
      expect(await adapter.identities.find({ id: identityId })).toBeNull()

      const cancelled = await auth.flows.cancelAccountDeletion({ token: cancellationToken })
      expect(cancelled.identityId).toBe(identityId)
      expect(cancelled.identity.deletedAt).toBeNull()
      expect(await adapter.identities.find({ id: identityId })).not.toBeNull()
    })

    it('it is single-use', async () => {
      const { cancellationToken } = await deleteAccount()
      await auth.flows.cancelAccountDeletion({ token: cancellationToken })
      await expect(auth.flows.cancelAccountDeletion({ token: cancellationToken })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    })

    it('the spent row is gone, not left revoked', async () => {
      const { cancellationToken } = await deleteAccount()
      await auth.flows.cancelAccountDeletion({ token: cancellationToken })
      const rows = await adapter.credentials.listByIdentity(identityId, 'recovery', {})
      expect(
        rows.filter(
          (r) => (r.metadata as { purpose?: string } | null)?.purpose === RECOVERY_PURPOSES.accountDeletionCancel,
        ),
      ).toEqual([])
    })

    it('a bogus token is refused', async () => {
      await deleteAccount()
      await expect(auth.flows.cancelAccountDeletion({ token: 'not-a-real-token' })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
      expect(await adapter.identities.find({ id: identityId })).toBeNull()
    })

    it('the deletion token is not an undo token', async () => {
      // Both are `kind: 'recovery'`; only `metadata.purpose` separates them.
      await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId })
      const deletionToken = new URL((channel.outbox.at(-1)!.vars as { url: string }).url).searchParams.get('token')!
      await auth.flows.completeAccountDeletion({ token: deletionToken })

      await expect(auth.flows.cancelAccountDeletion({ token: deletionToken })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    })

    it('an expired token reports expiry, and does not restore', async () => {
      const { cancellationToken, restorableUntil } = await deleteAccount()
      vi.useFakeTimers()
      try {
        vi.setSystemTime(new Date(restorableUntil + 1_000))
        await expect(auth.flows.cancelAccountDeletion({ token: cancellationToken })).rejects.toMatchObject({
          code: 'AUTH_RECOVERY_TOKEN_EXPIRED',
        })
      } finally {
        vi.useRealTimers()
      }
      expect(await adapter.identities.find({ id: identityId })).toBeNull()
    })

    it('a token whose identity was erased is refused, not honoured', async () => {
      // Erase cascades to the credential table in every dialect, so the undo
      // token is gone with the account and the lookup finds nothing.
      const { cancellationToken } = await deleteAccount()
      await auth.identities.erase(identityId, { reason: 'test' })
      await expect(auth.flows.cancelAccountDeletion({ token: cancellationToken })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    })

    it('a restore that throws leaves no live token for a second identical attempt', async () => {
      const { cancellationToken } = await deleteAccount()
      // Wind the grace window shut so `restore` refuses: nothing in the public API produces an expired
      // row, and a hidden row keeps its address, so nobody can take that out from under it either.
      const hidden = adapter.raw.identities.get(identityId)
      if (hidden) hidden.deletedAt = new Date(Date.now() - 1000)
      // Two different refusals, and the pair is the point: the first is the window, the second is the
      // token, which proves the failed attempt still spent it.
      await expect(auth.flows.cancelAccountDeletion({ token: cancellationToken })).rejects.toMatchObject({
        code: 'AUTH_GRACE_EXPIRED',
      })
      await expect(auth.flows.cancelAccountDeletion({ token: cancellationToken })).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    })
  })

  describe('one gate or the other, never both', () => {
    it('passing a token and a callback is a wiring error', async () => {
      const { cancellationToken } = await deleteAccount()
      const input = {
        authorize: async () => true,
        identityId,
        token: cancellationToken,
      } as unknown as CancelInput
      await expect(auth.flows.cancelAccountDeletion(input)).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
      expect(await adapter.identities.find({ id: identityId })).toBeNull()
    })

    it('a bad token does not fall through to a callback that would say yes', async () => {
      await deleteAccount()
      const input = { authorize: async () => true, token: 'not-a-real-token' } as unknown as CancelInput
      await expect(auth.flows.cancelAccountDeletion(input)).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
      expect(await adapter.identities.find({ id: identityId })).toBeNull()
    })

    it('neither gate is still a wiring error', async () => {
      await deleteAccount()
      await expect(auth.flows.cancelAccountDeletion({} as unknown as CancelInput)).rejects.toMatchObject({
        code: 'AUTH_MISCONFIGURED',
      })
    })

    it('the callback route still works and never consults a token', async () => {
      await deleteAccount()
      const seen: string[] = []
      const cancelled = await auth.flows.cancelAccountDeletion({
        authorize: async (id) => {
          seen.push(id)
          return true
        },
        identityId,
      })
      expect(seen).toEqual([identityId])
      expect(cancelled.identity.deletedAt).toBeNull()
    })

    it('the token names its own subject - it cannot be pointed at another account', async () => {
      const other = await auth.identities.create({ profile: { username: 'b@x.com', email: 'b@x.com' } })
      const { cancellationToken } = await deleteAccount()
      // `identityId` alongside a token is refused outright, so there is no
      // shape in which the caller's id can override the token's subject.
      const input = { identityId: other.id, token: cancellationToken } as unknown as CancelInput
      await expect(auth.flows.cancelAccountDeletion(input)).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })

      const cancelled = await auth.flows.cancelAccountDeletion({ token: cancellationToken })
      expect(cancelled.identityId).toBe(identityId)
    })
  })
})
