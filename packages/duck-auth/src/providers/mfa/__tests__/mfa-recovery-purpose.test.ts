/**
 * `kind: 'recovery'` names six unrelated token families - a password reset, a
 * verification mail, a pending account deletion, an in-flight signup, an MFA
 * backup code and a remembered device - and `metadata.purpose` is the only thing
 * that tells them apart.
 */

import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { getCredentialPurpose, toCredentialCreate } from '~/core/credentials/credentials'
import { RECOVERY_PURPOSES } from '~/core/credentials/credentials.constants'
import { randomToken, sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { identityInput } from '~/test/store-inputs'
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
  let mfa: MfaImpl
  let identityId: string

  /** One live `recovery` row per non-backup-code purpose, plus its plaintext. Each is in the form
   *  `verifyBackupCode` hashes, so only the purpose filter can refuse it. */
  async function plantOtherPurposes(): Promise<Map<string, string>> {
    const tokens = new Map<string, string>()
    for (const [i, purpose] of OTHER_PURPOSES.entries()) {
      const token = `other-purpose${i}`
      tokens.set(purpose, token)
      await adapter.credentials.create(
        toCredentialCreate({
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
    return rows.map((r) => getCredentialPurpose(r) ?? '<none>').sort()
  }

  beforeEach(async () => {
    adapter = new MemoryAdapter()
    mfa = new MfaImpl(adapter.credentials, new InMemoryEvents(), DEFAULT_MFA_CONFIG)
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
    )
    identityId = ident.id
  })

  describe('minting and removing codes does not touch the other five', () => {
    it('regenerating stamps every code with the backup-code purpose and leaves the rest alone', async () => {
      await plantOtherPurposes()
      await mfa.regenerateBackupCodes(identityId)
      expect(await livePurposes()).toEqual(
        [...OTHER_PURPOSES, ...Array(DEFAULT_MFA_CONFIG.backupCodeCount).fill(RECOVERY_PURPOSES.mfaBackupCode)].sort(),
      )
    })

    it('regenerating replaces only the previous code set', async () => {
      await plantOtherPurposes()
      const [first = ''] = await mfa.regenerateBackupCodes(identityId)
      const [second = ''] = await mfa.regenerateBackupCodes(identityId)
      expect(await mfa.verifyBackupCode(identityId, first)).toBe(false)
      expect(await mfa.verifyBackupCode(identityId, second)).toBe(true)
      expect(await livePurposes()).toContain(RECOVERY_PURPOSES.passwordReset)
    })

    it('removeBackupCodes wipes the codes and nothing else', async () => {
      await plantOtherPurposes()
      await mfa.regenerateBackupCodes(identityId)
      await mfa.removeBackupCodes(identityId)
      expect(await livePurposes()).toEqual([...OTHER_PURPOSES].sort())
    })

    it('a remembered device survives a backup-code regeneration', async () => {
      const remember = new RememberMeFacet(adapter.credentials, {
        authRandomToken: randomToken,
        authSha256: sha256,
      })
      const { token } = await remember.issue(identityId)
      await mfa.regenerateBackupCodes(identityId)
      expect(await remember.verify(token)).toMatchObject({ identityId })
    })
  })

  describe('the other five are not second factors', () => {
    it('verifyBackupCode refuses a token of another purpose', async () => {
      const tokens = await plantOtherPurposes()
      await mfa.regenerateBackupCodes(identityId)
      for (const [, token] of tokens) {
        expect(await mfa.verifyBackupCode(identityId, token)).toBe(false)
      }
    })

    const CANONICAL = 'abcde-fghjk'

    it('a purposeless recovery row is not a backup code either', async () => {
      await adapter.credentials.create(
        toCredentialCreate({ identityId, kind: 'recovery', secret: sha256(CANONICAL) }),
        {},
      )
      expect(await mfa.verifyBackupCode(identityId, CANONICAL)).toBe(false)
    })

    it('the same row under the backup-code purpose is spent', async () => {
      await adapter.credentials.create(
        toCredentialCreate({
          identityId,
          kind: 'recovery',
          secret: sha256(CANONICAL),
          metadata: { purpose: RECOVERY_PURPOSES.mfaBackupCode },
        }),
        {},
      )
      expect(await mfa.verifyBackupCode(identityId, CANONICAL)).toBe(true)
    })
  })

  describe('remainingBackupCodes counts backup codes, not recovery rows', () => {
    it('the other five purposes do not inflate the count', async () => {
      await plantOtherPurposes()
      expect(await mfa.remainingBackupCodes(identityId)).toBe(0)
      await mfa.regenerateBackupCodes(identityId)
      expect(await mfa.remainingBackupCodes(identityId)).toBe(DEFAULT_MFA_CONFIG.backupCodeCount)
    })
  })
})
