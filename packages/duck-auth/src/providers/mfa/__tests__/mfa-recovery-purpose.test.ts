/**
 * `kind: 'recovery'` names six unrelated token families - a password reset, a
 * verification mail, a pending account deletion, an in-flight signup, an MFA
 * backup code and a remembered device - and `metadata.purpose` is the only thing
 * that tells them apart.
 *
 * Both backup-code implementations used to ignore it. `deleteByKind(id,
 * 'recovery')` meant "wipe all six", so minting codes cancelled whatever the
 * user was holding; and `listByIdentity(id, 'recovery')` fed all six to the
 * verifier, so any of the other five was a candidate second factor.
 */

import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { RECOVERY_PURPOSES, toCredentialUpsert } from '~/core/credentials/credentials'
import { randomToken, sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { identityInput } from '~/test/store-inputs'
import { BackupCodesFacet } from '../internal/backup-codes'
import { RememberMeFacet } from '../internal/remember-me'
import { MfaImpl } from '../mfa'
import { DEFAULT_MFA_CONFIG } from '../mfa.constants'

const OTHER_PURPOSES = [
  RECOVERY_PURPOSES.passwordReset,
  RECOVERY_PURPOSES.emailVerification,
  RECOVERY_PURPOSES.accountDeletion,
  RECOVERY_PURPOSES.signupFlow,
  RECOVERY_PURPOSES.trustedDevice,
]

describe('recovery-kind overload', () => {
  let adapter: MemoryAdapter
  let facet: BackupCodesFacet
  let mfa: MfaImpl
  let identityId: string

  /** One live `recovery` row per non-backup-code purpose, plus its plaintext. */
  async function plantOtherPurposes(): Promise<Map<string, string>> {
    const tokens = new Map<string, string>()
    for (const purpose of OTHER_PURPOSES) {
      const token = randomToken(32)
      tokens.set(purpose, token)
      await adapter.credentials.upsert(
        toCredentialUpsert({
          identityId,
          kind: 'recovery',
          secret: sha256(token),
          metadata: { purpose },
        }),
        {},
      )
    }
    return tokens
  }

  const livePurposes = async (): Promise<string[]> => {
    const rows = await adapter.credentials.listByIdentity(identityId, 'recovery', {})
    return rows.map((r) => (r.metadata as { purpose?: string } | null)?.purpose ?? '<none>').sort()
  }

  beforeEach(async () => {
    adapter = new MemoryAdapter()
    facet = new BackupCodesFacet(adapter.credentials, { authRandomToken: randomToken, authSha256: sha256 })
    mfa = new MfaImpl(adapter.credentials, new InMemoryEvents(), DEFAULT_MFA_CONFIG)
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
    )
    identityId = ident.id
  })

  describe('the rows a backup-code set writes', () => {
    it('BackupCodesFacet.generate stamps every row with the backup-code purpose', async () => {
      await facet.generate(identityId)
      expect(await livePurposes()).toEqual(Array(10).fill(RECOVERY_PURPOSES.mfaBackupCode))
    })

    it('MfaImpl.regenerateBackupCodes stamps every row with the backup-code purpose', async () => {
      await mfa.regenerateBackupCodes(identityId)
      const purposes = await livePurposes()
      expect(purposes).toHaveLength(DEFAULT_MFA_CONFIG.backupCodeCount)
      expect(new Set(purposes)).toEqual(new Set([RECOVERY_PURPOSES.mfaBackupCode]))
    })
  })

  describe('minting codes does not cancel the other five', () => {
    it('BackupCodesFacet.generate leaves every other purpose alone', async () => {
      await plantOtherPurposes()
      await facet.generate(identityId)
      expect(await livePurposes()).toEqual(
        [...OTHER_PURPOSES, ...Array(10).fill(RECOVERY_PURPOSES.mfaBackupCode)].sort(),
      )
    })

    it('MfaImpl.regenerateBackupCodes leaves every other purpose alone', async () => {
      await plantOtherPurposes()
      await mfa.regenerateBackupCodes(identityId)
      const purposes = await livePurposes()
      for (const purpose of OTHER_PURPOSES) expect(purposes).toContain(purpose)
    })

    it('regenerating replaces only the previous code set', async () => {
      await plantOtherPurposes()
      const first = await facet.generate(identityId)
      const second = await facet.generate(identityId)
      expect(await facet.verify(identityId, first.codes[0]!)).toBe(false)
      expect(await facet.verify(identityId, second.codes[0]!)).toBe(true)
      expect(await livePurposes()).toContain(RECOVERY_PURPOSES.passwordReset)
    })

    it('revokeAll wipes the codes and nothing else', async () => {
      await plantOtherPurposes()
      await facet.generate(identityId)
      await facet.revokeAll(identityId)
      expect(await livePurposes()).toEqual([...OTHER_PURPOSES].sort())
    })

    it('a remembered device survives a backup-code regeneration', async () => {
      const remember = new RememberMeFacet(adapter.credentials, {
        authRandomToken: randomToken,
        authSha256: sha256,
      })
      const { token } = await remember.issue(identityId)
      await facet.generate(identityId)
      expect(await remember.verify(token)).toMatchObject({ identityId })
    })
  })

  describe('the other five are not second factors', () => {
    it('BackupCodesFacet.verify refuses a token of another purpose', async () => {
      const tokens = await plantOtherPurposes()
      await facet.generate(identityId)
      for (const [, token] of tokens) {
        // The stored hash is sha256 of the raw token; hand `verify` exactly the
        // string that produced it, so only the purpose filter can refuse it.
        expect(await facet.verify(identityId, token)).toBe(false)
      }
    })

    it('MfaImpl.verifyBackupCode refuses a token of another purpose', async () => {
      const tokens = await plantOtherPurposes()
      await mfa.regenerateBackupCodes(identityId)
      for (const [, token] of tokens) {
        expect(await mfa.verifyBackupCode(identityId, token)).toBe(false)
      }
    })

    it('a token of another purpose whose hash was stored the way verify computes it is still refused', async () => {
      // Belt and braces: the case-folding in both verifiers means a random
      // base64url token can never collide by accident. Plant one that would.
      const token = 'not-a-backup-code'
      await adapter.credentials.upsert(
        toCredentialUpsert({
          identityId,
          kind: 'recovery',
          secret: sha256(token.trim().toLowerCase()),
          metadata: { purpose: RECOVERY_PURPOSES.passwordReset },
        }),
        {},
      )
      expect(await mfa.verifyBackupCode(identityId, token)).toBe(false)
    })

    it('a purposeless recovery row is not a backup code either', async () => {
      const token = 'legacy-row'
      await adapter.credentials.upsert(
        toCredentialUpsert({ identityId, kind: 'recovery', secret: sha256(token.trim().toLowerCase()) }),
        {},
      )
      expect(await mfa.verifyBackupCode(identityId, token)).toBe(false)
    })
  })

  describe('remaining() counts backup codes, not recovery rows', () => {
    it('the other five purposes do not inflate the count', async () => {
      await plantOtherPurposes()
      expect(await facet.remaining(identityId)).toBe(0)
      await facet.generate(identityId)
      expect(await facet.remaining(identityId)).toBe(10)
    })

    it('consuming a code decrements the count by one', async () => {
      await plantOtherPurposes()
      const { codes } = await facet.generate(identityId)
      expect(await facet.verify(identityId, codes[0]!)).toBe(true)
      expect(await facet.remaining(identityId)).toBe(9)
    })
  })
})
