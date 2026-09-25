import { randomBytes } from 'node:crypto'
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
import {
  getProfileNumber,
  getProfileString,
  isProfileBooleanFalse,
  isProfileBooleanTrue,
} from '~/core/predicates/predicates'
import type { Provider } from '~/core/provider/provider.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import type { TenantContext } from '~/core/tenant/tenant.types'
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
    // SECURITY: `toApiKeysCfg` refuses a short `randomBytes` and its comment names the failure -
    // `randomToken(0)` answers `''`, so every key minted is the bare prefix. These two are that knob on
    // a second factor and arrived unchecked. Measured: `backupCodeLen: 0` minted ten codes that were all
    // the literal `-`, and `verifyBackupCode` accepted `-` for an account it had never been issued to;
    // `1` leaves 31 possibilities. A count that is not a positive whole number deletes the codes the
    // identity had and mints none, handing the caller `[]` to show the user as their new codes.
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
    // SECURITY: refused, not replaced. This deleted every `totp` row first, confirmed ones included, so
    // starting an enrollment removed the second factor - the attack `/mfa/totp/remove` demands a step-up
    // to stop, through a route that asks for none, and silently, since `removeTotp` is what emits
    // `mfa.removed`. The predicate is `hasTotp`'s, so nothing a verification would accept is destroyed
    // here; re-enrolling goes through `removeTotp`, which is guarded.
    const existing = await this._credentials.listByIdentity(identityId, 'totp', ctx)
    if (
      existing.some((r) => !isRevoked(r) && !isCredentialExpired(r) && isProfileBooleanTrue(r.metadata, 'confirmed'))
    ) {
      throw new AuthError('AUTH_MFA_REQUIRED', { methods: ['totp'] })
    }
    // SECURITY: the guard above reads `totp` rows only, so it saw nothing for an identity whose second factor
    // is WebAuthn - and a caller holding just the password enrolled a factor of its own, took the ten backup
    // codes `confirmTotpEnrollment` mints, and spent one on `completeStepUp`, which sets `aal: 2` on the
    // strength of the code alone. AAL2 without ever touching the key, and the victim's factor untouched, so
    // nothing looks wrong. The question is whether a second factor exists, not whether it is this kind.
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
    const row = rows.find((r) => isProfileBooleanFalse(r.metadata, 'confirmed'))
    if (!row) throw new AuthError('AUTH_MFA_REQUIRED', { methods: ['totp'] })
    const step = matchTotpStep(row.secret, code)
    if (step === null) return { ok: false }

    // The confirming code is spent too, so it cannot be replayed into a step-up on the enrollment it
    // just created.
    await this._credentials.patchMetadata(row.id, { confirmed: true, lastTotpStep: step }, ctx)

    // Minted on first enrollment; the plaintext is shown once.
    const backupCodes = await this._regenerateBackupCodes(identityId, ctx)
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

  /** Removes every TOTP credential for the identity and emits `mfa.removed`. Answers how many went, so
   *  `0` tells "turned off" from "nothing to turn off"; the rows carry the shared secret and are not
   *  returned. */
  async removeTotp(identityId: string, ctx: TenantContext = {}): Promise<{ removed: number }> {
    if (typeof identityId !== 'string' || identityId.length === 0 || identityId.length > 256) {
      return { removed: 0 }
    }
    const gone = await this._credentials.deleteByKind(identityId, 'totp', ctx)
    await this._events.emit('mfa.removed', { identityId, method: 'totp' })
    return { removed: gone.length }
  }

  /** Revokes the match atomically. The boolean is deliberately generic, so "code exists but wrong" and
   *  "code unknown" cannot be told apart. */
  async verifyBackupCode(identityId: string, code: string, ctx: TenantContext = {}): Promise<boolean> {
    // Capped at 64 chars before sha256, against a multi-MB DoS.
    if (typeof code !== 'string' || code.length === 0 || code.length > 64) return false
    const codeHash = sha256(code.trim().toLowerCase())
    const rows = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    // Every row, with timingSafeEqual, to flatten the per-byte timing signal that would otherwise
    // recover the short code.
    let matched: Credential.Me | undefined
    for (const r of rows) {
      // Backup codes only: the other five `recovery` purposes are tokens the user holds for entirely
      // different reasons, and none of them is a factor.
      if (getCredentialPurpose(r) !== RECOVERY_PURPOSES.mfaBackupCode) continue
      // The shared predicates, and expiry among them: this was the one gate reading `revokedAt` raw.
      if (!isRevoked(r) && !isCredentialExpired(r) && timingSafeEqual(r.secret, codeHash) && matched === undefined) {
        matched = r
      }
    }
    if (!matched) return false
    // SECURITY: the CAS claim is what makes the code single-use, as in `BackupCodesFacet.verify`.
    // `revoke` alone is unconditional, so two verifications that both read before either wrote matched
    // this same live row and both answered true, against a class docstring that says single-use.
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
    // A spent recovery code is a second factor bypassed, and the bus carried no trace of it.
    await this._events.emit('recovery.mfa.escalated', { credentialId: matched.id, identityId })
    return true
  }

  /** Revokes the previous codes; the plaintext comes back once. */
  async regenerateBackupCodes(identityId: string, ctx: TenantContext = {}): Promise<string[]> {
    return this._regenerateBackupCodes(identityId, ctx)
  }

  private async _regenerateBackupCodes(identityId: string, ctx: TenantContext): Promise<string[]> {
    // By purpose, not by kind: regenerating codes replaces the codes and leaves the identity's reset,
    // verification, deletion, signup and trusted-device tokens where they were.
    await this._credentials.deleteByKindAndPurpose(identityId, 'recovery', RECOVERY_PURPOSES.mfaBackupCode, ctx)
    const codes: string[] = []
    for (let i = 0; i < this._cfg.backupCodeCount; i++) {
      const code = this._randomBackupCode()
      codes.push(code)
      await this._credentials.create(
        toCredentialCreate({
          identityId,
          kind: 'recovery',
          secret: sha256(code.toLowerCase()),
          metadata: { purpose: RECOVERY_PURPOSES.mfaBackupCode },
        }),
        ctx,
      )
    }
    return codes
  }

  private _randomBackupCode(): string {
    // A base32-ish alphabet, with the ambiguous 0, O, 1, I and L left out.
    const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789'
    // SECURITY: `node:crypto`, like every other random value in this package. This read
    // `globalThis.crypto.getRandomValues` behind a `typeof` guard and, when the guard was false, kept
    // the zero-filled array it had just allocated - every byte indexing the alphabet at 0, so all ten
    // of an account's codes came out `aaaaa-aaaaa` and nothing threw.
    const bytes = randomBytes(this._cfg.backupCodeLen)
    let out = ''
    for (let i = 0; i < bytes.length; i++) {
      const idx = (bytes[i] ?? 0) % ALPHABET.length
      out += ALPHABET[idx]
    }
    // Split into two groups of five, to be readable.
    return `${out.slice(0, 5)}-${out.slice(5)}`
  }

  // WebAuthn-MFA, second factor only; `@simplewebauthn/server` is loaded lazily.

  /** Answers the registration options the client passes to `navigator.credentials.create`, persisting
   *  the challenge under `opts.challengeKey` so the confirm step can verify it. */
  async beginWebauthnMfaEnrollment(
    identityId: string,
    opts: Mfa.WebauthnMfaEnrollOpts,
    ctx: TenantContext = {},
  ): Promise<Passkey.RegistrationOptions> {
    void ctx
    const webauthn = await loadWebAuthnMfa(opts.webauthnModule)
    const options = await webauthn.generateRegistrationOptions({
      rpName: opts.rpName,
      rpID: opts.rpID,
      userName: opts.userName,
      userID: webauthnUserId(identityId),
      attestationType: opts.attestation ?? 'none',
      authenticatorSelection: {
        userVerification: opts.userVerification ?? 'preferred',
        residentKey: 'discouraged',
      },
      supportedAlgorithmIDs: opts.supportedAlgorithmIDs ?? [-8, -7, -257],
    })
    await opts.challengeStore.put(`mfa-reg:${opts.challengeKey}`, options.challenge, opts.challengeTtlMs ?? 5 * 60_000)
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
    const webauthn = await loadWebAuthnMfa(opts.webauthnModule)
    const v = await webauthn.verifyRegistrationResponse({
      response: opts.response,
      expectedChallenge: challenge,
      expectedOrigin: opts.expectedOrigins,
      expectedRPID: opts.rpID,
      requireUserVerification: (opts.userVerification ?? 'preferred') === 'required',
    })
    if (!v.verified || !v.registrationInfo) throw new AuthError('AUTH_PASSKEY_MISMATCH')
    const cred = v.registrationInfo.credential
    const row = await this._credentials.create(
      toCredentialCreate({
        identityId,
        kind: 'webauthn-mfa',
        secret: String(cred.id),
        metadata: {
          publicKey: Buffer.from(cred.publicKey).toString('base64url'),
          counter: cred.counter ?? 0,
          transports: cred.transports ?? [],
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
    const webauthn = await loadWebAuthnMfa(opts.webauthnModule)
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
    await opts.challengeStore.put(`mfa-auth:${opts.challengeKey}`, options.challenge, opts.challengeTtlMs ?? 5 * 60_000)
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
    if (typeof opts.response !== 'object' || opts.response === null) return false
    const idRaw: unknown = Reflect.get(opts.response, 'id')
    // A WebAuthn credential id is base64url random bytes, under 255 raw bytes by spec and so ~340 chars
    // at most; 1024 is generous and still refuses a multi-MB id.
    if (typeof idRaw !== 'string' || idRaw.length === 0 || idRaw.length > 1024) return false
    const credId = idRaw
    const cred = await orNull(this._credentials.findByHashedSecret(credId, 'webauthn-mfa', ctx))
    // Explicit `!== undefined`: a falsy check lets `revokedAt: 0` pass as not revoked.
    if (!cred || cred.identityId !== identityId || isRevoked(cred) || isCredentialExpired(cred)) return false
    // Fail-closed, so out-of-sync metadata never reaches `Buffer.from`.
    const meta = parseWebauthnMfaMetadata(cred.metadata)
    if (!meta) return false
    const webauthn = await loadWebAuthnMfa(opts.webauthnModule)
    const v = await webauthn.verifyAuthenticationResponse({
      response: opts.response,
      expectedChallenge: challenge,
      expectedOrigin: opts.expectedOrigins,
      expectedRPID: opts.rpID,
      credential: {
        id: cred.id,
        publicKey: Buffer.from(meta.publicKey, 'base64url'),
        counter: meta.counter,
        transports: meta.transports,
      },
      requireUserVerification: (opts.userVerification ?? 'preferred') === 'required',
    })
    if (!v.verified) return false
    // Counter-rollback detection, WebAuthn L2 6.1.3: reject a regressed count, but only from an
    // authenticator that advances them. `Number.isFinite` gates a NaN that would skip the check.
    const newCounter = v.authenticationInfo.newCounter
    const oldCounter = meta.counter
    if (!Number.isFinite(newCounter) || !Number.isFinite(oldCounter)) return false
    let rollback = newCounter !== 0 && newCounter <= oldCounter
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

  /** Remove every WebAuthn-MFA credential for the identity. See {@link MfaImpl.removeTotp}. */
  async removeWebauthnMfa(identityId: string, ctx: TenantContext = {}): Promise<{ removed: number }> {
    const gone = await this._credentials.deleteByKind(identityId, 'webauthn-mfa', ctx)
    await this._events.emit('mfa.removed', { identityId, method: 'webauthn' })
    return { removed: gone.length }
  }

  /** The AAL this identity is eligible for given the factors already on the session, which is what
   *  step-up evaluation branches on. */
  async eligibleAal(
    identityId: string,
    currentFactors: Sessions.FactorMethod[],
    ctx: TenantContext = {},
  ): Promise<Sessions.AAL> {
    const distinct = new Set(currentFactors)
    if (distinct.size === 0) return 1
    if (distinct.size === 1) return 1
    // AAL 3 (NIST 800-63B) needs a hardware-bound passkey: `deviceType === 'singleDevice'` and
    // `backedUp === false`.
    if (distinct.has('passkey')) {
      const passkeys = await this._credentials.listByIdentity(identityId, 'passkey', ctx)
      const hardwareBound = passkeys.some((c) => {
        return (
          getProfileString(c.metadata, 'deviceType') === 'singleDevice' && isProfileBooleanFalse(c.metadata, 'backedUp')
        )
      })
      if (hardwareBound) return 3
    }
    // Two or more distinct factors of any kind is AAL 2.
    if (await this.hasTotp(identityId, ctx)) {
      return distinct.has('totp') ? 2 : 1
    }
    return 2
  }
}

/** Structural validator for the WebAuthn-MFA credential metadata, `null` on any mismatch so
 *  `verifyWebauthnMfa` fails closed rather than reaching `Buffer.from(<non-string>, 'base64url')`. */
function parseWebauthnMfaMetadata(raw: unknown): { publicKey: string; counter: number; transports?: string[] } | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null
  const publicKey: unknown = Reflect.get(raw, 'publicKey')
  if (typeof publicKey !== 'string' || publicKey.length === 0) return null
  const counterRaw: unknown = Reflect.get(raw, 'counter')
  const counter = typeof counterRaw === 'number' && Number.isFinite(counterRaw) ? counterRaw : 0
  const transportsRaw: unknown = Reflect.get(raw, 'transports')
  let transports: string[] | undefined
  if (Array.isArray(transportsRaw)) {
    const out: string[] = []
    for (const t of transportsRaw) {
      if (typeof t === 'string') out.push(t)
    }
    transports = out
  }
  return transports !== undefined ? { publicKey, counter, transports } : { publicKey, counter }
}

/** Lazy, so an app that never enrols WebAuthn-MFA pays no peerDep cost. */
async function loadWebAuthnMfa(override?: Mfa.WebauthnLibrary): Promise<Mfa.WebauthnLibrary> {
  if (override) return override
  try {
    const moduleName = '@simplewebauthn/server' as string
    const mod = (await import(moduleName)) as Mfa.WebauthnLibrary
    return mod
  } catch {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail:
        'WebAuthn-MFA requires the @simplewebauthn/server peerDep. ' +
        'Install via `bun add @simplewebauthn/server` (or `npm install @simplewebauthn/server`).',
    })
  }
}

function webauthnUserId(identityId: string): Uint8Array {
  // A 32-byte hashed handle, matching the passkey provider's bound size, so a cross-identity collision
  // is impossible whatever the identityId's length.
  return new Uint8Array(require('node:crypto').createHash('sha256').update(identityId, 'utf8').digest())
}

/** The MFA provider, ready to hand to `providers`. */
export function mfa<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(cfg?: Mfa.CfgInput): (auth: AuthEngine<Profile, Tenant, OrgMeta>) => MfaImpl {
  return (auth) => new MfaImpl(auth.cfg.stores.credentials, auth.events, cfg)
}
