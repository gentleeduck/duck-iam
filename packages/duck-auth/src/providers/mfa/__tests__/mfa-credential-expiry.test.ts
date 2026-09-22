/**
 * An `expiresAt` on a `totp` or `webauthn-mfa` row was written and then honoured by nothing: six readers
 * on `MfaImpl` filtered on `revokedAt` alone, while `verifyBackupCode` on the same class and both
 * internal facets already paired it with `isCredentialExpired`. `isStandingFactor` has always read an
 * elapsed expiry as revocation for every kind, so the lockout guard and these readers disagreed about
 * whether the same row was still there.
 */

import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { toCredentialCreate } from '~/core/credentials/credentials'
import type { Credential } from '~/core/credentials/credentials.types'
import { InMemoryEvents } from '~/core/events'
import { totpAt } from '../internal/totp'
import { MfaImpl } from '../mfa'
import { DEFAULT_MFA_CONFIG } from '../mfa.constants'

const ID = 'user-1'
const FUTURE = new Date(Date.now() + 60 * 60_000)

/** `create` refuses an `expiresAt` that already precedes `createdAt`, so an expired row is only ever
 *  reached by elapsing into it - which is exactly why nothing noticed the readers were not looking. */
const SOON = () => new Date(Date.now() + 20)
const elapse = () => new Promise((r) => setTimeout(r, 40))

describe('MfaImpl honours a credential expiry', () => {
  let adapter: MemoryAdapter
  let facet: MfaImpl

  beforeEach(() => {
    adapter = new MemoryAdapter()
    facet = new MfaImpl(adapter.credentials, new InMemoryEvents(), DEFAULT_MFA_CONFIG)
  })

  /** Read at the moment it is used, so a step index does not go stale across a clock boundary. */
  const nowStep = () => Math.floor(Date.now() / 1000 / 30)

  /** Enrol for real, then re-write the one row with a deadline on it. The store has no update, so the
   *  row is recreated from what `confirmTotpEnrollment` actually wrote rather than from a guess at it. */
  async function enrolledTotp(expiresAt: Date | null): Promise<string> {
    const challenge = await facet.beginTotpEnrollment(ID, 'alice@x.com')
    await facet.confirmTotpEnrollment(ID, totpAt(challenge.secret, nowStep()))
    const [row] = await adapter.credentials.listByIdentity(ID, 'totp', {})
    if (!row) throw new Error('enrolment wrote no row')
    await adapter.credentials.delete(row.id, {})
    await adapter.credentials.create(
      toCredentialCreate({ expiresAt, identityId: ID, kind: 'totp', metadata: row.metadata, secret: row.secret }),
      {},
    )
    return challenge.secret
  }

  /** The shape `registerWebauthnMfa` writes, which is what the readers under test see. */
  async function webauthnRow(expiresAt: Date | null): Promise<Credential.Me> {
    return adapter.credentials.create(
      toCredentialCreate({
        expiresAt,
        identityId: ID,
        kind: 'webauthn-mfa',
        metadata: { counter: 0, publicKey: Buffer.from('pk').toString('base64url'), transports: [] },
        secret: 'cred-id-1',
      }),
      {},
    )
  }

  describe('totp', () => {
    it('refuses a code from an enrolment whose deadline has passed', async () => {
      const secret = await enrolledTotp(SOON())
      await elapse()
      expect(await facet.verifyTotp(ID, totpAt(secret, nowStep() + 1))).toBe(false)
    })

    it('still accepts one whose deadline has not, so the check is a deadline and not a ban', async () => {
      const secret = await enrolledTotp(FUTURE)
      await elapse()
      expect(await facet.verifyTotp(ID, totpAt(secret, nowStep() + 1))).toBe(true)
    })

    it('and one with no deadline at all', async () => {
      const secret = await enrolledTotp(null)
      await elapse()
      expect(await facet.verifyTotp(ID, totpAt(secret, nowStep() + 1))).toBe(true)
    })

    it('stops counting an expired enrolment, which is what a password reset reads to require MFA', async () => {
      await enrolledTotp(SOON())
      await elapse()
      expect(await facet.hasTotp(ID)).toBe(false)
    })

    it('counts a live one', async () => {
      await enrolledTotp(FUTURE)
      expect(await facet.hasTotp(ID)).toBe(true)
    })

    it('lets a new enrolment start once the old one has expired, rather than refusing for ever', async () => {
      await enrolledTotp(SOON())
      await elapse()
      await expect(facet.beginTotpEnrollment(ID, 'alice@x.com')).resolves.toMatchObject({
        secret: expect.any(String),
      })
    })

    it('still refuses a new enrolment over a live one', async () => {
      await enrolledTotp(FUTURE)
      await expect(facet.beginTotpEnrollment(ID, 'alice@x.com')).rejects.toMatchObject({
        code: 'AUTH_MFA_REQUIRED',
      })
    })
  })

  describe('webauthn-mfa', () => {
    /** Answers a fixed challenge and records nothing; the assertion never gets as far as a real one. */
    const challengeStore = {
      put: async () => {},
      take: async () => 'challenge-value',
      get: async () => 'challenge-value',
    }
    /** Reached only if the credential passed the liveness check, which is the assertion. */
    const unreachableModule = {
      generateAuthenticationOptions: async (o: { allowCredentials: unknown }) => ({
        challenge: 'challenge-value',
        ...o,
      }),
      verifyAuthenticationResponse: async () => {
        throw new Error('the expired credential reached the webauthn module')
      },
    }

    it('stops offering a credential whose deadline has passed', async () => {
      await webauthnRow(SOON())
      await elapse()
      const options = await facet.beginWebauthnMfaVerify(ID, {
        challengeKey: 'k',
        challengeStore,
        rpID: 'x.test',
        // biome-ignore lint/suspicious/noExplicitAny: a stub standing in for @simplewebauthn/server.
        webauthnModule: unreachableModule as any,
      })
      expect(options.allowCredentials).toEqual([])
    })

    it('still offers a live one', async () => {
      await webauthnRow(FUTURE)
      const options = await facet.beginWebauthnMfaVerify(ID, {
        challengeKey: 'k',
        challengeStore,
        rpID: 'x.test',
        // biome-ignore lint/suspicious/noExplicitAny: a stub standing in for @simplewebauthn/server.
        webauthnModule: unreachableModule as any,
      })
      expect(options.allowCredentials).toEqual([{ id: 'cred-id-1', type: 'public-key' }])
    })

    it('refuses an assertion against it, before the webauthn module is ever consulted', async () => {
      await webauthnRow(SOON())
      await elapse()
      const verified = await facet.verifyWebauthnMfa(ID, {
        challengeKey: 'k',
        challengeStore,
        expectedOrigins: 'https://x.test',
        response: { id: 'cred-id-1' },
        rpID: 'x.test',
        // biome-ignore lint/suspicious/noExplicitAny: throws if the expired credential gets past the guard.
        webauthnModule: unreachableModule as any,
      })
      expect(verified).toBe(false)
    })

    it('stops counting an expired credential', async () => {
      await webauthnRow(SOON())
      await elapse()
      expect(await facet.hasWebauthnMfa(ID)).toBe(false)
    })

    it('counts a live one', async () => {
      await webauthnRow(FUTURE)
      expect(await facet.hasWebauthnMfa(ID)).toBe(true)
    })
  })
})
