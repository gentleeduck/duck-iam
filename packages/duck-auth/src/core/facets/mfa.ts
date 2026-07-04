import type { AuthPasskeyTypes } from '../../providers/passkey/types'
import { isProfileBooleanTrue } from '../credential-utils'
import { sha256, timingSafeEqual } from '../crypto'
import { AuthError } from '../errors'
import { authGenerateSecret, authVerifyTotp, buildOtpAuthUri } from '../mfa/totp'
import type { Credential } from '../types/identity'
import type { TenantContext } from '../types/infra'
import type { Events } from '../types/provider'
import type { Session } from '../types/session'

// Minimal metadata shapes read by MfaFacet — defined locally to avoid
// core → provider dependency direction.
interface ITotpMetadata {
  confirmed?: boolean
}
interface IPasskeyMetadata {
  deviceType?: string
  backedUp?: boolean
}

export const DEFAULT_MFA_CONFIG: MfaFacet.IConfig = {
  issuer: 'duck-auth',
  backupCodeCount: 10,
  backupCodeLen: 10,
}

/**
 * MFA facet. v0.1 ships TOTP + backup codes. WebAuthn-as-MFA + SMS land
 * later via the same facet shape.
 *
 * Storage: TOTP secrets are persisted in the credentials store as
 * `kind: 'totp'`, base32 plaintext (low-sensitivity vs passwords because
 * a stolen TOTP secret still requires the user's phone to be online during
 * the attack window - and rotation is one-click). Backup codes are
 * persisted hashed as `kind: 'recovery'`, single-use.
 */
export class MfaFacet {
  constructor(
    private readonly _credentials: Credential.Store,
    private readonly _events: Events.IBus,
    private readonly _cfg: MfaFacet.IConfig = DEFAULT_MFA_CONFIG,
  ) {}

  // --- TOTP ---------------------------------------------------------------

  /**
   * Begin TOTP enrollment. Returns the otpauth:// URI so the consumer can
   * render a QR code. Secret is persisted immediately under `metadata.confirmed=false`;
   * a later `confirmTotpEnrollment(identityId, firstCode)` flips it confirmed.
   */
  async beginTotpEnrollment(
    identityId: string,
    accountName: string,
    ctx: TenantContext = {},
  ): Promise<MfaFacet.ITotpEnrollChallenge> {
    // Cap accountName so a multi-MB string cannot bloat the otpauth URI
    // (and therefore the QR-code SVG payload returned to the client).
    if (typeof accountName !== 'string' || accountName.length === 0 || accountName.length > 256) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
    const secret = authGenerateSecret()
    await this._credentials.deleteByKind(identityId, 'totp', ctx)
    await this._credentials.upsert(
      {
        identityId,
        kind: 'totp',
        secret,
        metadata: { confirmed: false },
      },
      ctx,
    )
    return {
      secret,
      uri: buildOtpAuthUri({ secret, issuer: this._cfg.issuer, accountName }),
    }
  }

  /**
   * Confirm enrollment by verifying the user typed in the right code.
   * Required before TOTP counts as an enrolled MFA factor for the identity.
   * Emits `mfa.enrolled` on success.
   */
  async confirmTotpEnrollment(
    identityId: string,
    code: string,
    ctx: TenantContext = {},
  ): Promise<{ ok: true; backupCodes: string[] } | { ok: false }> {
    const rows = await this._credentials.listByIdentity(identityId, 'totp', ctx)
    const row = rows.find((r) => (r.metadata as ITotpMetadata | undefined)?.confirmed === false)
    if (!row) throw new AuthError('AUTH_MFA_REQUIRED', { methods: ['totp'] })
    if (!authVerifyTotp(row.secret, code)) return { ok: false }

    await this._credentials.patchMetadata(row.id, { confirmed: true }, ctx)

    // Generate backup codes on first enrollment. Plaintext shown once.
    const backupCodes = await this._regenerateBackupCodes(identityId, ctx)
    await this._events.emit('mfa.enrolled', { identityId, method: 'totp' })
    return { ok: true, backupCodes }
  }

  /** Verify a TOTP code against the confirmed enrollment. Used by step-up. */
  async verifyTotp(identityId: string, code: string, ctx: TenantContext = {}): Promise<boolean> {
    if (typeof code !== 'string' || code.length === 0 || code.length > 64) return false
    const rows = await this._credentials.listByIdentity(identityId, 'totp', ctx)
    const row = rows.find((r) => r.revokedAt == null && isProfileBooleanTrue(r.metadata, 'confirmed'))
    if (!row) return false
    if (typeof row.secret !== 'string') return false
    return authVerifyTotp(row.secret, code)
  }

  /** True if the identity has a confirmed TOTP enrollment. */
  async hasTotp(identityId: string, ctx: TenantContext = {}): Promise<boolean> {
    const rows = await this._credentials.listByIdentity(identityId, 'totp', ctx)
    // see authVerifyTotp - strict-boolean read.
    return rows.some((r) => r.revokedAt == null && isProfileBooleanTrue(r.metadata, 'confirmed'))
  }

  /** Remove all TOTP credentials for the identity. Emits `mfa.removed`. */
  async removeTotp(identityId: string, ctx: TenantContext = {}): Promise<void> {
    if (typeof identityId !== 'string' || identityId.length === 0 || identityId.length > 256) return
    await this._credentials.deleteByKind(identityId, 'totp', ctx)
    await this._events.emit('mfa.removed', { identityId, method: 'totp' })
  }

  // --- Backup codes -------------------------------------------------------

  /**
   * Verify a backup code. Single-use; matching code is revoked atomically.
   * Generic ok:boolean - callers map false to AUTH/INVALID_CREDENTIALS so
   * an attacker cannot infer "code exists but wrong" vs "code unknown".
   */
  async verifyBackupCode(identityId: string, code: string, ctx: TenantContext = {}): Promise<boolean> {
    // 64-char cap before sha256 to refuse multi-MB DoS.
    if (typeof code !== 'string' || code.length === 0 || code.length > 64) return false
    const codeHash = sha256(code.trim().toLowerCase())
    const rows = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    // Iterate all rows with timingSafeEqual to flatten the per-byte
    // timing signal an attacker could use to recover the short code.
    let matched: Credential.Me | undefined
    for (const r of rows) {
      if (r.revokedAt == null && timingSafeEqual(r.secret, codeHash) && matched === undefined) {
        matched = r
      }
    }
    if (!matched) return false
    await this._credentials.revoke(matched.id, ctx)
    return true
  }

  /** Regenerate backup codes; returns plaintext once. Previous codes revoked. */
  async regenerateBackupCodes(identityId: string, ctx: TenantContext = {}): Promise<string[]> {
    return this._regenerateBackupCodes(identityId, ctx)
  }

  private async _regenerateBackupCodes(identityId: string, ctx: TenantContext): Promise<string[]> {
    await this._credentials.deleteByKind(identityId, 'recovery', ctx)
    const codes: string[] = []
    for (let i = 0; i < this._cfg.backupCodeCount; i++) {
      const code = this._randomBackupCode()
      codes.push(code)
      await this._credentials.upsert(
        {
          identityId,
          kind: 'recovery',
          secret: sha256(code.toLowerCase()),
        },
        ctx,
      )
    }
    return codes
  }

  private _randomBackupCode(): string {
    // base32-ish alphabet (no ambiguous chars 0/O, 1/I/L).
    const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789'
    const bytes = new Uint8Array(this._cfg.backupCodeLen)
    // Node crypto for tests; consumers running in edge runtimes get the same
    // shape via globalThis.crypto.getRandomValues.
    if (typeof globalThis.crypto?.getRandomValues === 'function') {
      globalThis.crypto.getRandomValues(bytes)
    }
    let out = ''
    for (let i = 0; i < bytes.length; i++) {
      const idx = (bytes[i] ?? 0) % ALPHABET.length
      out += ALPHABET[idx]
    }
    // Split into 5-5 groups for readability.
    return `${out.slice(0, 5)}-${out.slice(5)}`
  }

  // WebAuthn-MFA: second-factor only; `@simplewebauthn/server` loaded lazily.

  /** Begin WebAuthn-MFA enrollment. Returns the registration options the
   * client passes to `navigator.credentials.create`. Persists the
   * challenge under the supplied opts.challengeKey so the confirm step
   * can verify it. */
  async beginWebauthnMfaEnrollment(
    identityId: string,
    opts: MfaFacet.IWebauthnMfaEnrollOpts,
    ctx: TenantContext = {},
  ): Promise<AuthPasskeyTypes.IRegistrationOptions> {
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

  /** Confirm WebAuthn-MFA enrollment + persist the credential row. */
  async confirmWebauthnMfaEnrollment(
    identityId: string,
    opts: MfaFacet.IWebauthnMfaConfirmOpts,
    ctx: TenantContext = {},
  ): Promise<{ credentialId: string }> {
    const challenge = await opts.challengeStore.take(`mfa-reg:${opts.challengeKey}`)
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
    const row = await this._credentials.upsert(
      {
        identityId,
        kind: 'webauthn-mfa',
        secret: String(cred.id),
        metadata: {
          publicKey: Buffer.from(cred.publicKey).toString('base64url'),
          counter: cred.counter ?? 0,
          transports: cred.transports ?? [],
        },
      },
      ctx,
    )
    await this._events.emit('mfa.enrolled', { identityId, method: 'webauthn' })
    return { credentialId: row.id }
  }

  /** Begin a WebAuthn-MFA challenge for an authenticated user. Returns
   * the authentication options the client passes to
   * `navigator.credentials.get`. */
  async beginWebauthnMfaVerify(
    identityId: string,
    opts: MfaFacet.IWebauthnMfaVerifyBeginOpts,
    ctx: TenantContext = {},
  ): Promise<AuthPasskeyTypes.IAuthenticationOptions> {
    const webauthn = await loadWebAuthnMfa(opts.webauthnModule)
    const creds = await this._credentials.listByIdentity(identityId, 'webauthn-mfa', ctx)
    const allowCredentials = creds
      // see authVerifyTotp; `!c.revokedAt` let `revokedAt: 0` through
      // as live. Defense ensures revoked WebAuthn-MFA credentials are
      // not offered as allowCredentials in the next assertion challenge.
      .filter((c) => c.revokedAt == null)
      .map((c) => ({ id: c.secret, type: 'public-key' as const }))
    const options = await webauthn.generateAuthenticationOptions({
      rpID: opts.rpID,
      allowCredentials,
      userVerification: opts.userVerification ?? 'preferred',
    })
    await opts.challengeStore.put(`mfa-auth:${opts.challengeKey}`, options.challenge, opts.challengeTtlMs ?? 5 * 60_000)
    return options
  }

  /** Verify a WebAuthn-MFA assertion. Rejects on signature mismatch,
   * counter rollback, or unknown credential. Returns true on success. */
  async verifyWebauthnMfa(
    identityId: string,
    opts: MfaFacet.IWebauthnMfaVerifyOpts,
    ctx: TenantContext = {},
  ): Promise<boolean> {
    const challenge = await opts.challengeStore.take(`mfa-auth:${opts.challengeKey}`)
    if (!challenge) return false
    if (typeof opts.response !== 'object' || opts.response === null) return false
    const idRaw: unknown = Reflect.get(opts.response, 'id')
    // WebAuthn credential IDs are base64url-encoded random bytes (<255 raw bytes
    // per spec -> ~340 chars max). 1024 is generous; rejects multi-MB attacker IDs.
    if (typeof idRaw !== 'string' || idRaw.length === 0 || idRaw.length > 1024) return false
    const credId = idRaw
    const cred = await this._credentials.findByHashedSecret(credId, 'webauthn-mfa', ctx)
    // Explicit `!== undefined`: falsy check would let `revokedAt: 0` pass as not-revoked.
    if (!cred || cred.identityId !== identityId || cred.revokedAt != null) return false
    // Fail-closed shape validation; out-of-sync metadata must not reach Buffer.from.
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
    // counter-rollback detection per WebAuthn L2 section 6.1.3. Reject when
    // the new count regresses (only when the authenticator advances them).
    // Number.isFinite gates against NaN/Infinity from a buggy authenticator
    // that would otherwise let `NaN !== 0 && NaN <= old` fall through false
    // and silently skip the rollback check.
    const newCounter = v.authenticationInfo.newCounter
    const oldCounter = meta.counter
    if (!Number.isFinite(newCounter) || !Number.isFinite(oldCounter)) return false
    if (newCounter !== 0 && newCounter <= oldCounter) {
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

  /** True if the identity has at least one active WebAuthn-MFA credential. */
  async hasWebauthnMfa(identityId: string, ctx: TenantContext = {}): Promise<boolean> {
    const rows = await this._credentials.listByIdentity(identityId, 'webauthn-mfa', ctx)
    return rows.some((r) => r.revokedAt == null)
  }

  /** Remove every WebAuthn-MFA credential for the identity. */
  async removeWebauthnMfa(identityId: string, ctx: TenantContext = {}): Promise<void> {
    await this._credentials.deleteByKind(identityId, 'webauthn-mfa', ctx)
    await this._events.emit('mfa.removed', { identityId, method: 'webauthn' })
  }

  // --- AAL helpers --------------------------------------------------------

  /**
   * Compute the AAL the identity is currently eligible for, given the
   * factors already on the session. Used by step-up evaluation.
   */
  async eligibleAal(
    identityId: string,
    currentFactors: Session.FactorMethod[],
    ctx: TenantContext = {},
  ): Promise<Session.AAL> {
    const distinct = new Set(currentFactors)
    if (distinct.size === 0) return 1
    if (distinct.size === 1) return 1
    // AAL=3 (NIST 800-63B) requires hardware-bound passkey
    // (deviceType === 'singleDevice' && backedUp === false).
    if (distinct.has('passkey')) {
      const passkeys = await this._credentials.listByIdentity(identityId, 'passkey', ctx)
      const hardwareBound = passkeys.some((c) => {
        const m = c.metadata as IPasskeyMetadata | undefined
        return m?.deviceType === 'singleDevice' && m.backedUp === false
      })
      if (hardwareBound) return 3
    }
    // Two or more distinct factors of any kind: AAL=2.
    if (await this.hasTotp(identityId, ctx)) {
      return distinct.has('totp') ? 2 : 1
    }
    return 2
  }
}

/**
 * structural validator for the WebAuthn-MFA credential metadata
 * row. Replaces the `(cred.metadata ?? {}) as { publicKey?: string; ... }`
 * cast - a DB row whose metadata went out of sync (manual update, schema
 * migration, wrong-kind row reuse) would otherwise reach
 * `Buffer.from(<non-string>, 'base64url')` and throw an unhelpful
 * TypeError. Returns null on any shape mismatch so `verifyWebauthnMfa`
 * fail-closes.
 */
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

/**
 * Lazy load of `@simplewebauthn/server` for the WebAuthn-MFA path.
 * Apps that don't enroll WebAuthn-MFA pay zero peerDep cost.
 */
async function loadWebAuthnMfa(override?: MfaFacet.IWebauthnLibrary): Promise<MfaFacet.IWebauthnLibrary> {
  if (override) return override
  try {
    const moduleName = '@simplewebauthn/server' as string
    const mod = (await import(moduleName)) as MfaFacet.IWebauthnLibrary
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
  // 32-byte hashed handle - matches the passkey provider's bound size
  // so cross-identity collisions stay impossible regardless of
  // identityId length.
  return new Uint8Array(require('node:crypto').createHash('sha256').update(identityId, 'utf8').digest())
}

export namespace MfaFacet {
  export interface IConfig {
    /** Brand shown in TOTP authenticator app entries. */
    issuer: string
    /** How many backup codes to generate per enrollment. Default 10. */
    backupCodeCount: number
    /** Backup code length in characters. Default 10. */
    backupCodeLen: number
  }

  export interface ITotpEnrollChallenge {
    secret: string
    uri: string
  }

  /** Structural shape of the `@simplewebauthn/server` module we use. */
  export interface IWebauthnLibrary {
    generateRegistrationOptions(input: unknown): Promise<AuthPasskeyTypes.IRegistrationOptions>
    verifyRegistrationResponse(input: unknown): Promise<{
      verified: boolean
      registrationInfo?: {
        credential: { id: string; publicKey: Uint8Array; counter?: number; transports?: string[] }
      }
    }>
    generateAuthenticationOptions(input: unknown): Promise<AuthPasskeyTypes.IAuthenticationOptions>
    verifyAuthenticationResponse(input: unknown): Promise<{
      verified: boolean
      authenticationInfo: { newCounter: number; credentialID: string; userVerified: boolean }
    }>
  }

  /** Caller-supplied per-session challenge store. The passkey
   * provider's `MemoryPasskeyChallengeStore` is the canonical impl. */
  export interface IWebauthnChallengeStore {
    put(key: string, challenge: string, ttlMs: number): Promise<void>
    take(key: string): Promise<string | null>
  }

  export interface IWebauthnMfaEnrollOpts {
    rpID: string
    rpName: string
    userName: string
    expectedOrigins: string | string[]
    challengeStore: IWebauthnChallengeStore
    /** Stable opaque key (typically the session id) tying enrollment ceremony pieces. */
    challengeKey: string
    challengeTtlMs?: number
    userVerification?: 'required' | 'preferred' | 'discouraged'
    attestation?: 'none' | 'direct' | 'indirect' | 'enterprise'
    /** Algorithm allowlist; default `[-8, -7, -257]` (Ed25519 + ES256 + RS256). */
    supportedAlgorithmIDs?: number[]
    /** Override the library instance (tests). */
    webauthnModule?: IWebauthnLibrary
  }

  export interface IWebauthnMfaConfirmOpts {
    rpID: string
    expectedOrigins: string | string[]
    challengeStore: IWebauthnChallengeStore
    challengeKey: string
    /** The browser's `RegistrationResponseJSON` from `navigator.credentials.create`. */
    response: unknown
    userVerification?: 'required' | 'preferred' | 'discouraged'
    webauthnModule?: IWebauthnLibrary
  }

  export interface IWebauthnMfaVerifyBeginOpts {
    rpID: string
    challengeStore: IWebauthnChallengeStore
    challengeKey: string
    challengeTtlMs?: number
    userVerification?: 'required' | 'preferred' | 'discouraged'
    webauthnModule?: IWebauthnLibrary
  }

  export interface IWebauthnMfaVerifyOpts {
    rpID: string
    expectedOrigins: string | string[]
    challengeStore: IWebauthnChallengeStore
    challengeKey: string
    /** The browser's `AuthenticationResponseJSON` from `navigator.credentials.get`. */
    response: unknown
    userVerification?: 'required' | 'preferred' | 'discouraged'
    webauthnModule?: IWebauthnLibrary
  }
}
