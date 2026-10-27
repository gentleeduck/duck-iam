import { orNull } from '../answer'
import { AuthError } from '../errors'
import type { Identities } from '../identities/identities.types'
import { isExpiredAt, isProfileBooleanTrue } from '../predicates/predicates'
import type { Provider } from '../provider/provider.types'
import type { Sessions } from '../sessions/sessions.types'
import { ALL_TENANTS } from '../tenant/tenant'
import type { TenantContext } from '../tenant/tenant.types'
import { PUBLIC_METADATA_KEYS, RECOVERY_PURPOSES } from './credentials.constants'
import type { Credential } from './credentials.types'

export function isRevoked(row: Pick<Credential.Me, 'revokedAt'>): boolean {
  return row.revokedAt != null
}

/** A `null` expiry never expires; anything unreadable fails closed as expired. */
export function isCredentialExpired(row: Pick<Credential.Me, 'expiresAt'>, now: number = Date.now()): boolean {
  return isExpiredAt(row.expiresAt, now)
}

/** Whether a credential can start a session on its own, which is what "the account is still reachable"
 *  means. A second factor (`totp`, `webauthn-mfa`) cannot; the one-shot tokens under `recovery` and
 *  `magic-link` are spent and gone; and an `oauth` row is the provider link, already counted as one.
 *  The two lockout guards each wrote their own version of this and each missed a clause the other had. */
export function isStandingFactor(row: Pick<Credential.Me, 'kind' | 'revokedAt' | 'expiresAt'>): boolean {
  if (isRevoked(row) || isCredentialExpired(row)) return false
  return row.kind === 'password' || row.kind === 'passkey' || row.kind === 'api-key'
}

/** The factors beside the password `session` still has to step up with: none when the identity holds none, or when
 *  `session` is its own, in this tenant, at AAL 2 and fresh, as `checkStepUp` asks. Named as `completeStepUp` takes
 *  them. Every list is read every time, so how long this takes does not say which are held. */
export async function missingStepUp(
  credentials: Credential.Store,
  identityId: string,
  session: Sessions.Me | null,
  ctx: TenantContext,
): Promise<Sessions.FactorMethod[]> {
  if (
    session?.identityId === identityId &&
    session.tenantId === (ctx.tenantId ?? null) &&
    session.aal >= 2 &&
    session.fresh
  ) {
    return []
  }
  const live = (r: Credential.Me): boolean => !isRevoked(r) && !isCredentialExpired(r)
  const totp = await credentials.listByIdentity(identityId, 'totp', ctx)
  const recovery = await credentials.listByIdentity(identityId, 'recovery', ctx)
  const keys = await credentials.listByIdentity(identityId, 'webauthn-mfa', ctx)
  const passkeys = await credentials.listByIdentity(identityId, 'passkey', ctx)
  const methods: Sessions.FactorMethod[] = []
  if (totp.some((r) => live(r) && isProfileBooleanTrue(r.metadata, 'confirmed'))) methods.push('totp')
  if (recovery.some((r) => live(r) && getCredentialPurpose(r) === RECOVERY_PURPOSES.mfaBackupCode)) {
    methods.push('backup-code')
  }
  if (keys.some(live)) methods.push('webauthn')
  if (passkeys.some(live)) methods.push('passkey')
  return methods
}

/** Refuses with `AUTH_MFA_REQUIRED`, naming {@link missingStepUp}'s methods. Every path that adds, removes or
 *  replaces a factor, mints backup codes or remembers a device asks it, so a password alone changes nothing beside
 *  another factor. */
export async function refuseWithoutStepUp(
  credentials: Credential.Store,
  identityId: string,
  session: Sessions.Me | null,
  ctx: TenantContext,
): Promise<void> {
  const methods = await missingStepUp(credentials, identityId, session, ctx)
  if (methods.length > 0) throw new AuthError('AUTH_MFA_REQUIRED', { methods })
}

/** Drops the secret, and every metadata key the kind does not declare public. */
export function toPublicCredential(row: Credential.Me): Credential.Public {
  const { secret: _secret, ...rest } = row
  if (rest.metadata == null) return rest
  const allowed = PUBLIC_METADATA_KEYS[rest.kind] ?? []
  const metadata: Record<string, unknown> = {}
  for (const key of allowed) {
    if (key in rest.metadata) metadata[key] = rest.metadata[key]
  }
  return { ...rest, metadata }
}

export function getCredentialPurpose(row: Pick<Credential.Me, 'metadata'>): string | undefined {
  const meta = row.metadata
  if (meta == null) return undefined
  const purpose = meta.purpose
  return typeof purpose === 'string' ? purpose : undefined
}

export function toCredentialCreate(
  input: Pick<Credential.CreateInput, 'identityId' | 'kind' | 'secret'> & Partial<Credential.CreateInput>,
): Credential.CreateInput {
  return {
    tenantId: null,
    metadata: null,
    lastUsedAt: null,
    expiresAt: null,
    revokedAt: null,
    ...input,
  }
}

/** Claims a single-use token by rotating its secret to one nobody holds, so the claim and the burn are one
 *  write and every loser of the race sees `AUTH_RECOVERY_TOKEN_INVALID`.
 *  SECURITY: never rotate to `row.secret` - that takes the version while leaving the row findable by hash
 *  until the caller's delete or revoke, and a read landing in that window wins its own CAS. */
export async function burnCredential(
  ctx: { crypto: Provider.Crypto; stores: { credentials: Credential.Store }; tenant: TenantContext },
  row: Pick<Credential.Me, 'id' | 'version'>,
): Promise<void> {
  const burnt = ctx.crypto.authSha256(ctx.crypto.authRandomToken(32))
  try {
    await ctx.stores.credentials.rotate(row.id, burnt, row.version, ctx.tenant)
  } catch (err) {
    if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    throw err
  }
}

/** Unlinks every provider and revokes every live credential but `keepId` on a row whose address was never
 *  proven, twice, so a write already in flight when its sessions went is caught. A row gone in between counts as
 *  revoked. */
export async function evictUnproven<Profile extends Identities.ProfileMetadataBase>(
  stores: Pick<Provider.Stores<Profile>, 'credentials' | 'identities'>,
  identityId: string,
  keepId: string,
): Promise<void> {
  for (let pass = 0; pass < 2; pass++) {
    const held = await stores.identities.find({ id: identityId })
    for (const p of held.providers) await stores.identities.unlink(identityId, p.providerId, p.tenantId)
    for (const c of await stores.credentials.listByIdentity(identityId, null, ALL_TENANTS)) {
      if (!isRevoked(c) && c.id !== keepId) await orNull(stores.credentials.revoke(c.id, ALL_TENANTS))
    }
  }
}
