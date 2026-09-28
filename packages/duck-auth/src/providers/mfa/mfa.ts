import { createHash, randomBytes } from 'node:crypto'
import { orNull } from '~/core/answer'
import { resolveCompliance } from '~/core/compliance'
import {
  getCredentialPurpose,
  isCredentialExpired,
  isRevoked,
  toCredentialCreate,
} from '~/core/credentials/credentials'
import { RECOVERY_PURPOSES } from '~/core/credentials/credentials.constants'
import type { Credential } from '~/core/credentials/credentials.types'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import type { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import type { Events } from '~/core/events/events.types'
import type { Identities } from '~/core/identities'
import { getProfileNumber, isProfileBooleanFalse, isProfileBooleanTrue, isRecord } from '~/core/predicates/predicates'
import type { Provider } from '~/core/provider/provider.types'
import type { TenantContext } from '~/core/tenant/tenant.types'
import { knownTransports, loadWebAuthn, parsePasskeyMetadata } from '~/providers/passkey/passkey'
import { DEFAULT_PASSKEY_CONFIG } from '~/providers/passkey/passkey.constants'
import type { Passkey } from '~/providers/passkey/passkey.types'
import { buildOtpAuthUri, generateSecret, matchTotpStep } from './internal/totp'
import { DEFAULT_MFA_CONFIG } from './mfa.constants'
import type { Mfa } from './mfa.types'

/**
 * TOTP and backup codes. TOTP secrets live in the credentials store as `kind: 'totp'`, base32
 * plaintext; backup codes are hashed under `kind: 'recovery'` with
 * `metadata.purpose: 'mfa-backup-code'`, single-use.
 *
 * WARN: that purpose is load-bearing. `recovery` is shared by six token families
 * ({@link RECOVERY_PURPOSES}), so reading or deleting the kind without filtering on it lets
 * regenerating backup codes void a pending password reset.
 */
export class MfaImpl {
  readonly id = 'mfa'
  readonly kind = 'mfa' as const
  private readonly _cfg: Omit<Mfa.Cfg, 'compliance'>

  constructor(
    readonly _credentials: Credential.Store,
    readonly _events: Events.IBus,
    readonly cfg?: Partial<Mfa.Cfg>,
  ) {
    const floor = cfg?.compliance ? resolveCompliance(cfg.compliance).mfa.backupCodeCount : 0
    this._cfg = {
      issuer: cfg?.issuer ?? DEFAULT_MFA_CONFIG.issuer,
      backupCodeCount: Math.max(cfg?.backupCodeCount ?? DEFAULT_MFA_CONFIG.backupCodeCount, floor),
      backupCodeLen: cfg?.backupCodeLen ?? DEFAULT_MFA_CONFIG.backupCodeLen,
    }
    // SECURITY: a short code is guessable, and a count under one deletes the codes and mints none.
    if (
      !Number.isInteger(this._cfg.backupCodeCount) ||
      this._cfg.backupCodeCount < 1 ||
      this._cfg.backupCodeCount > 64
    ) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `mfa: backupCodeCount must be a whole number between 1 and 64, got ${String(this._cfg.backupCodeCount)}`,
      })
    }
    if (!Number.isInteger(this._cfg.backupCodeLen) || this._cfg.backupCodeLen < 8 || this._cfg.backupCodeLen > 64) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `mfa: backupCodeLen must be a whole number between 8 and 64, got ${String(this._cfg.backupCodeLen)}`,
      })
    }
  }

  /** Re-bind to a caller's transaction: the credential store already on it, and a bus that buffers
   *  until commit. Lives here because `_cfg` is derived in the constructor. */
  withClient(stores: Provider.Stores, events: Events.IBus): MfaImpl {
    return new MfaImpl(stores.credentials, events, this.cfg)
  }

  /** Answers the `otpauth://` URI to render as a QR code. The secret is persisted at once under
   *  `metadata.confirmed = false`, which `confirmTotpEnrollment` flips. */
  async beginTotpEnrollment(
    identityId: string,
    accountName: string,
    ctx: TenantContext = {},
  ): Promise<Mfa.TotpEnrollChallenge> {
    // Capped, so a multi-MB accountName cannot bloat the otpauth URI, and with it the QR-code SVG the
    // client is handed.
    if (typeof accountName !== 'string' || accountName.length === 0 || accountName.length > 256) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
    // SECURITY: refused, not replaced: starting an enrollment must not delete a confirmed factor without the
    // step-up `removeTotp` demands. The predicate is `hasTotp`'s.
    const existing = await this._credentials.listByIdentity(identityId, 'totp', ctx)
    if (
      existing.some((r) => !isRevoked(r) && !isCredentialExpired(r) && isProfileBooleanTrue(r.metadata, 'confirmed'))
    ) {
      throw new AuthError('AUTH_MFA_REQUIRED', { methods: ['totp'] })
    }
    // SECURITY: any second factor blocks this, not only TOTP, or a password alone enrolls a TOTP beside a
    // WebAuthn factor and steps up with its backup codes.
    if (await this.hasWebauthnMfa(identityId, ctx)) {
      throw new AuthError('AUTH_MFA_REQUIRED', { methods: ['webauthn'] })
    }
    const secret = generateSecret()
    await this._credentials.deleteByKind(identityId, 'totp', ctx)
    await this._credentials.create(
      toCredentialCreate({
        identityId,
        kind: 'totp',
        secret,
        metadata: { confirmed: false },
      }),
      ctx,
    )
    return {
      secret,
      uri: buildOtpAuthUri({ secret, issuer: this._cfg.issuer, accountName }),
    }
  }

  /** Confirm enrollment against the first code, which is what makes TOTP count as an enrolled factor.
   *  Emits `mfa.enrolled`. */
  async confirmTotpEnrollment(
    identityId: string,
    code: string,
    ctx: TenantContext = {},
  ): Promise<{ ok: true; backupCodes: string[] } | { ok: false }> {
    const rows = await this._credentials.listByIdentity(identityId, 'totp', ctx)
    const row = rows.find(
      (r) => !isRevoked(r) && !isCredentialExpired(r) && isProfileBooleanFalse(r.metadata, 'confirmed'),
    )
    if (!row) throw new AuthError('AUTH_MFA_REQUIRED', { methods: ['totp'] })
    const step = matchTotpStep(row.secret, code)
    if (step === null) return { ok: false }

    // The confirming code is spent too, so it cannot be replayed into a step-up on the enrollment it
    // just created. Conditional, as in `verifyTotp`, so two confirms racing on one code mint one set.
    try {
      await this._credentials.patchMetadata(row.id, { confirmed: true, lastTotpStep: step }, ctx, row.version)
    } catch (err) {
      if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') return { ok: false }
      throw err
    }

    // Minted on first enrollment; the plaintext is shown once.
    const backupCodes = await this.regenerateBackupCodes(identityId, ctx)
    await this._events.emit('mfa.enrolled', { identityId, method: 'totp' })
    return { ok: true, backupCodes }
  }

  /** Against the confirmed enrollment, for step-up.
   *  SECURITY: single-use within the window, per NIST SP 800-63B. The drift window spans three steps, so
   *  an unspent code stays replayable for about ninety seconds. */
  async verifyTotp(identityId: string, code: string, ctx: TenantContext = {}): Promise<boolean> {
    if (typeof code !== 'string' || code.length === 0 || code.length > 64) return false
    const rows = await this._credentials.listByIdentity(identityId, 'totp', ctx)
    // SECURITY: `isCredentialExpired` beside `isRevoked`. Six readers on this class paired only the
    // second, so an `expiresAt` on a `totp` or `webauthn-mfa` row was written and honoured by nothing,
    // while `isStandingFactor` had always read an elapsed expiry as revocation.
    const row = rows.find(
      (r) => !isRevoked(r) && !isCredentialExpired(r) && isProfileBooleanTrue(r.metadata, 'confirmed'),
    )
    if (!row) return false
    if (typeof row.secret !== 'string') return false

    const step = matchTotpStep(row.secret, code)
    if (step === null) return false

    const lastStep = getProfileNumber(row.metadata, 'lastTotpStep')
    if (lastStep !== undefined && step <= lastStep) return false

    // The compare-and-set is what makes the comparison above single-use. Unconditional, it is two steps,
    // and two verifications that both read before either wrote both pass it. Conditional, the loser's
    // write matches no row, and anyone reading afterwards reads the step it recorded.
    try {
      await this._credentials.patchMetadata(row.id, { lastTotpStep: step }, ctx, row.version)
    } catch (err) {
      if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') return false
      throw err
    }
    return true
  }

  /** Confirmed enrollments only. */
  async hasTotp(identityId: string, ctx: TenantContext = {}): Promise<boolean> {
    const rows = await this._credentials.listByIdentity(identityId, 'totp', ctx)
    // A strict boolean read, as in `verifyTotp`.
    return rows.some((r) => !isRevoked(r) && !isCredentialExpired(r) && isProfileBooleanTrue(r.metadata, 'confirmed'))
  }

  /** Removes every TOTP credential for the identity, and every remembered device, and emits `mfa.removed`.
   *  Answers how many TOTP rows went, so `0` tells "turned off" from "nothing to turn off"; the rows carry
   *  the shared secret and are not returned. */
  async removeTotp(identityId: string, ctx: TenantContext = {}): Promise<{ removed: number }> {
    if (typeof identityId !== 'string' || identityId.length === 0 || identityId.length > 256) {
      return { removed: 0 }
    }
    const gone = await this._credentials.deleteByKind(identityId, 'totp', ctx)
    // A remembered device was trusted to skip the factor that just went.
    await this._credentials.deleteByKindAndPurpose(identityId, 'recovery', RECOVERY_PURPOSES.trustedDevice, ctx)
    await this._events.emit('mfa.removed', { identityId, method: 'totp' })
    return { removed: gone.length }
  }

  /** Revokes the match atomically. The boolean is deliberately generic, so "code exists but wrong" and
   *  "code unknown" cannot be told apart. Case, spaces and hyphens are forgiven. */
  async verifyBackupCode(identityId: string, code: string, ctx: TenantContext = {}): Promise<boolean> {
    // Capped before hashing, against a multi-MB DoS; the longest code is 65 characters.
    if (typeof code !== 'string' || code.length > 128) return false
    const bare = code.toLowerCase().replace(/[\s-]/g, '')
    if (bare.length === 0) return false
    // The form `regenerateBackupCodes` hashes.
    const codeHash = sha256(`${bare.slice(0, 5)}-${bare.slice(5)}`)
    const rows = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    // Every row, with timingSafeEqual, to flatten the per-byte timing signal that would otherwise
    // recover the short code.
    let matched: Credential.Me | undefined
    for (const r of rows) {
      // Backup codes only: the other five `recovery` purposes are tokens the user holds for entirely
      // different reasons, and none of them is a factor.
      if (getCredentialPurpose(r) !== RECOVERY_PURPOSES.mfaBackupCode) continue
      if (!isRevoked(r) && !isCredentialExpired(r) && timingSafeEqual(r.secret, codeHash) && matched === undefined) {
        matched = r
      }
    }
    if (!matched) return false
    // SECURITY: the compare-and-set claim makes the code single-use; `revoke` alone is unconditional.
    const burnt = sha256(randomToken(32))
    try {
      await this._credentials.rotate(matched.id, burnt, matched.version, ctx)
    } catch (err) {
      // Losing the race is a code someone else already spent, which is a miss like any other.
      if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') return false
      throw err
    }
    // Soft-revoked too, so a reuse attempt surfaces as a known-consumed row rather than an absent one.
    await this._credentials.revoke(matched.id, ctx)
    // Audited, since a spent code stands in for the factor.
    await this._events.emit('recovery.mfa.escalated', { credentialId: matched.id, identityId })
    return true
  }

  /** Revokes the previous codes; the plaintext comes back once. */
  async regenerateBackupCodes(identityId: string, ctx: TenantContext = {}): Promise<string[]> {
    // A base32-ish alphabet, with the ambiguous 0, o, 1, i and l left out.
    const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789'
    // By purpose, not by kind: regenerating codes replaces the codes and leaves the identity's reset,
    // verification, deletion, signup and trusted-device tokens where they were.
    await this._credentials.deleteByKindAndPurpose(identityId, 'recovery', RECOVERY_PURPOSES.mfaBackupCode, ctx)
    const codes: string[] = []
    for (let i = 0; i < this._cfg.backupCodeCount; i++) {
      // SECURITY: `node:crypto`, never a `globalThis.crypto` that may be absent.
      let bare = ''
      for (const byte of randomBytes(this._cfg.backupCodeLen)) bare += ALPHABET[byte % ALPHABET.length]
      // Hyphenated after the fifth character, to be readable.
      const code = `${bare.slice(0, 5)}-${bare.slice(5)}`
      codes.push(code)
      await this._credentials.create(
        toCredentialCreate({
          identityId,
          kind: 'recovery',
          secret: sha256(code),
          metadata: { purpose: RECOVERY_PURPOSES.mfaBackupCode },
        }),
        ctx,
      )
    }
    return codes
  }

  /** Live backup codes, for a "you have N left" prompt. */
  async remainingBackupCodes(identityId: string, ctx: TenantContext = {}): Promise<number> {
    const rows = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    return rows.filter(
      (r) => getCredentialPurpose(r) === RECOVERY_PURPOSES.mfaBackupCode && !isRevoked(r) && !isCredentialExpired(r),
    ).length
  }

  /** Removes every backup code for the identity and emits `mfa.removed`. See {@link MfaImpl.removeTotp}. */
  async removeBackupCodes(identityId: string, ctx: TenantContext = {}): Promise<{ removed: number }> {
    const purpose = RECOVERY_PURPOSES.mfaBackupCode
    const gone = await this._credentials.deleteByKindAndPurpose(identityId, 'recovery', purpose, ctx)
    await this._events.emit('mfa.removed', { identityId, method: 'backup-code' })
    return { removed: gone.length }
  }

  // WebAuthn-MFA, second factor only; `@simplewebauthn/server` is loaded lazily.

  /** Answers the registration options the client passes to `navigator.credentials.create`, persisting
   *  the challenge under `opts.challengeKey` so the confirm step can verify it. */
  async beginWebauthnMfaEnrollment(
    identityId: string,
    opts: Mfa.WebauthnMfaEnrollOpts,
    ctx: TenantContext = {},
  ): Promise<Passkey.RegistrationOptions> {
    const challengeTtlMs = opts.challengeTtlMs ?? 5 * 60_000
    if (!Number.isFinite(challengeTtlMs) || challengeTtlMs <= 0) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `mfa: challengeTtlMs must be a finite positive number (got ${challengeTtlMs})`,
      })
    }
    const webauthn = await loadWebAuthn(opts.webauthnModule)
    const existing = await this._credentials.listByIdentity(identityId, 'webauthn-mfa', ctx)
    const options = await webauthn.generateRegistrationOptions({
      rpName: opts.rpName,
      rpID: opts.rpID,
      userName: opts.userName,
      // 32 hashed bytes, the passkey provider's size, so no two identities collide whatever the id's length.
      userID: new Uint8Array(createHash('sha256').update(identityId, 'utf8').digest()),
      attestationType: opts.attestation ?? 'none',
      // As at passkey registration: an authenticator already enrolled is not enrolled twice.
      excludeCredentials: existing
        .filter((c) => !isRevoked(c))
        .map((c) => ({ id: c.secret, type: 'public-key' as const })),
      authenticatorSelection: {
        userVerification: opts.userVerification ?? 'preferred',
        residentKey: 'discouraged',
      },
      supportedAlgorithmIDs: opts.supportedAlgorithmIDs ?? DEFAULT_PASSKEY_CONFIG.supportedAlgorithmIDs,
    })
    await opts.challengeStore.put(`mfa-reg:${opts.challengeKey}`, options.challenge, challengeTtlMs)
    return options
  }

  /** Confirms the enrollment and persists the credential row. */
  async confirmWebauthnMfaEnrollment(
    identityId: string,
    opts: Mfa.WebauthnMfaConfirmOpts,
    ctx: TenantContext = {},
  ): Promise<{ credentialId: string }> {
    const challenge = await orNull(opts.challengeStore.take(`mfa-reg:${opts.challengeKey}`))
    if (!challenge) throw new AuthError('AUTH_PASSKEY_MISMATCH')
    const webauthn = await loadWebAuthn(opts.webauthnModule)
    const v = await webauthn
      .verifyRegistrationResponse({
        response: opts.response,
        expectedChallenge: challenge,
        expectedOrigin: opts.expectedOrigins,
        expectedRPID: opts.rpID,
        requireUserVerification: (opts.userVerification ?? 'preferred') === 'required',
        // SECURITY: as at passkey registration, only a key algorithm enrollment offered.
        supportedAlgorithmIDs: opts.supportedAlgorithmIDs ?? DEFAULT_PASSKEY_CONFIG.supportedAlgorithmIDs,
      })
      .catch(() => {
        // The verifier refuses by throwing a plain Error, which left as an unmapped 500.
        throw new AuthError('AUTH_PASSKEY_MISMATCH')
      })
    if (!v.verified || !v.registrationInfo) throw new AuthError('AUTH_PASSKEY_MISMATCH')
    const cred = v.registrationInfo.credential
    // As at passkey registration, WebAuthn 7.1 fails an id past the cap.
    if (cred.id.length > DEFAULT_PASSKEY_CONFIG.maxCredentialIdChars) throw new AuthError('AUTH_PASSKEY_MISMATCH')
    // SECURITY: as at passkey registration, an id already registered is refused: verify answers the newest
    // row that carries it, so a second one locked the owner out of this factor.
    if (await orNull(this._credentials.findByHashedSecret(cred.id, 'webauthn-mfa', ctx))) {
      throw new AuthError('AUTH_PASSKEY_MISMATCH')
    }
    const row = await this._credentials.create(
      toCredentialCreate({
        identityId,
        kind: 'webauthn-mfa',
        secret: cred.id,
        metadata: {
          publicKey: Buffer.from(cred.publicKey).toString('base64url'),
          counter: cred.counter,
          transports: knownTransports(cred.transports),
        },
      }),
      ctx,
    )
    await this._events.emit('mfa.enrolled', { identityId, method: 'webauthn' })
    return { credentialId: row.id }
  }

  /** For an authenticated user. Answers the authentication options the client passes to
   *  `navigator.credentials.get`. */
  async beginWebauthnMfaVerify(
    identityId: string,
    opts: Mfa.WebauthnMfaVerifyBeginOpts,
    ctx: TenantContext = {},
  ): Promise<Passkey.AuthenticationOptions> {
    const challengeTtlMs = opts.challengeTtlMs ?? 5 * 60_000
    if (!Number.isFinite(challengeTtlMs) || challengeTtlMs <= 0) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `mfa: challengeTtlMs must be a finite positive number (got ${challengeTtlMs})`,
      })
    }
    const webauthn = await loadWebAuthn(opts.webauthnModule)
    const creds = await this._credentials.listByIdentity(identityId, 'webauthn-mfa', ctx)
    const allowCredentials = creds
      // As in `verifyTotp`: `!c.revokedAt` let a `revokedAt: 0` through as live, which offered a
      // revoked credential as `allowCredentials` in the next assertion challenge.
      .filter((c) => !isRevoked(c) && !isCredentialExpired(c))
      .map((c) => ({ id: c.secret, type: 'public-key' as const }))
    const options = await webauthn.generateAuthenticationOptions({
      rpID: opts.rpID,
      allowCredentials,
      userVerification: opts.userVerification ?? 'preferred',
    })
    await opts.challengeStore.put(`mfa-auth:${opts.challengeKey}`, options.challenge, challengeTtlMs)
    return options
  }

  /** Refuses a signature mismatch, a counter rollback and an unknown credential. */
  async verifyWebauthnMfa(
    identityId: string,
    opts: Mfa.WebauthnMfaVerifyOpts,
    ctx: TenantContext = {},
  ): Promise<boolean> {
    const challenge = await orNull(opts.challengeStore.take(`mfa-auth:${opts.challengeKey}`))
    if (!challenge) return false
    if (!isRecord(opts.response)) return false
    const credId = opts.response.id
    if (
      typeof credId !== 'string' ||
      credId.length === 0 ||
      credId.length > DEFAULT_PASSKEY_CONFIG.maxCredentialIdChars
    ) {
      return false
    }
    const cred = await orNull(this._credentials.findByHashedSecret(credId, 'webauthn-mfa', ctx))
    // Explicit `!== undefined`: a falsy check lets `revokedAt: 0` pass as not revoked.
    if (!cred || cred.identityId !== identityId || isRevoked(cred) || isCredentialExpired(cred)) return false
    // Fail-closed, so out-of-sync metadata never reaches `Buffer.from`.
    const meta = parsePasskeyMetadata(cred.metadata)
    if (!meta) return false
    const webauthn = await loadWebAuthn(opts.webauthnModule)
    const v = await webauthn
      .verifyAuthenticationResponse({
        response: opts.response,
        expectedChallenge: challenge,
        expectedOrigin: opts.expectedOrigins,
        expectedRPID: opts.rpID,
        credential: {
          // The id the browser knows, which enrollment stored as the secret, not the row's own id.
          id: cred.secret,
          publicKey: Buffer.from(meta.publicKey, 'base64url'),
          // 0 turns off the verifier's own count check, which throws before the signature is checked and so
          // cannot report; the check below runs on a verified signature and reports the rollback.
          counter: 0,
          transports: meta.transports,
        },
        requireUserVerification: (opts.userVerification ?? 'preferred') === 'required',
      })
      // The verifier refuses by throwing a plain Error, which left as an unmapped 500 from a method that
      // answers a boolean.
      .catch(() => null)
    if (!v?.verified) return false
    // Counter-rollback detection, WebAuthn L2 6.1.3. `parsePasskeyMetadata` already refused a stored count
    // that is not finite; a reported NaN would skip the check.
    const newCounter = v.authenticationInfo.newCounter
    const oldCounter = meta.counter
    if (!Number.isFinite(newCounter)) return false
    // SECURITY: the pair, as 6.1.3 puts it: "if either ... is nonzero". A count that falls back to 0 is
    // the cloned authenticator.
    let rollback = (newCounter !== 0 || oldCounter !== 0) && newCounter <= oldCounter
    // SECURITY: recording the count is what makes the comparison above mean anything. Left unwritten, as
    // it was, the stored count never leaves its enrollment value and every later assertion is measured
    // against a baseline the authenticator passed long ago - so a clone replaying any count above it is
    // waved through, which is the one thing 6.1.3 is for.
    if (!rollback && newCounter > oldCounter) {
      try {
        await this._credentials.patchMetadata(cred.id, { counter: newCounter }, ctx, cred.version)
      } catch (err) {
        if (!(err instanceof AuthError && err.code === 'AUTH_STALE_WRITE')) throw err
        rollback = true
      }
    }
    if (rollback) {
      await this._events.emit('suspicious', {
        identityId,
        signal: 'webauthn-mfa-counter-rollback',
        score: 1,
        meta: { credentialId: cred.id, oldCounter, newCounter },
      })
      return false
    }
    return true
  }

  /** Active credentials only. */
  async hasWebauthnMfa(identityId: string, ctx: TenantContext = {}): Promise<boolean> {
    const rows = await this._credentials.listByIdentity(identityId, 'webauthn-mfa', ctx)
    return rows.some((r) => !isRevoked(r) && !isCredentialExpired(r))
  }

  /** Remove every WebAuthn-MFA credential for the identity, and every remembered device. See
   *  {@link MfaImpl.removeTotp}. */
  async removeWebauthnMfa(identityId: string, ctx: TenantContext = {}): Promise<{ removed: number }> {
    const gone = await this._credentials.deleteByKind(identityId, 'webauthn-mfa', ctx)
    await this._credentials.deleteByKindAndPurpose(identityId, 'recovery', RECOVERY_PURPOSES.trustedDevice, ctx)
    await this._events.emit('mfa.removed', { identityId, method: 'webauthn' })
    return { removed: gone.length }
  }
}

/** The MFA provider, ready to hand to `providers`. */
export function mfa<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(cfg?: Mfa.CfgInput): (auth: AuthEngine<Profile, Tenant, OrgMeta>) => MfaImpl {
  return (auth) => new MfaImpl(auth.cfg.stores.credentials, auth.events, cfg)
}
