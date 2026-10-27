import { orNull } from '~/core/answer'
import { burnCredential, evictUnproven, isCredentialExpired, toCredentialCreate } from '~/core/credentials/credentials'
import { LATEST_STORABLE_MS } from '~/core/credentials/credentials.constants'
import { AuthError } from '~/core/errors'
import { refuseRateLimited } from '~/core/events/events.lockout'
import { deliver } from '~/core/flows/flows.delivery'
import { canonicalEmail, type Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import { ALL_TENANTS } from '~/core/tenant/tenant'
import { isSafeCallbackPath } from '~/core/url-validators'
import { NO_IDENTITY_SENTINEL } from '~/providers/passwords/passwords.constants'
import { DEFAULT_MAGIC_LINK_CONFIG } from './magic-link.constants'
import type { MagicLink } from './magic-link.types'

/** Passwordless sign-in by a single-use link sent to the address. */
export class MagicLinkImpl<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>
  implements Provider.Me<MagicLink.BeginInput, MagicLink.CompleteInput, Profile>
{
  readonly id = 'magic-link'
  readonly kind = 'magic-link' as const
  /** Read by `strict()`, which holds the provider and not its options: with no `deliver`, `begin` refuses
   *  every link request. */
  readonly __noDeliver: boolean
  private readonly ttlMs: number
  private readonly prefix: string
  private readonly callbackPath: string

  constructor(private readonly opts: MagicLink.Options<Profile>) {
    this.ttlMs = opts.ttlMs ?? DEFAULT_MAGIC_LINK_CONFIG.ttlMs
    // Stores refuse a deadline they cannot hold, a NaN's or one past 9999, and `begin` writes only for a known
    // address, so the link endpoint would answer 500 for an account that exists and 200 for one that does not.
    if (!Number.isFinite(this.ttlMs) || this.ttlMs <= 0 || Date.now() + this.ttlMs > LATEST_STORABLE_MS) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `magic-link: ttlMs must be a positive number whose deadline a store can hold (got ${this.ttlMs})`,
      })
    }
    this.prefix = opts.limiterKeyPrefix ?? DEFAULT_MAGIC_LINK_CONFIG.limiterKeyPrefix
    // Refused at construction, so a typo like `//evil.com` cannot turn the magic-link URL into a
    // cross-origin redirect that exfiltrates the token: a browser resolves `https://app//evil.com?...`
    // as `https://evil.com?...`.
    if (opts.callbackPath !== undefined && !isSafeCallbackPath(opts.callbackPath)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'magic-link.callbackPath must be a same-origin path (starts with `/`, no `//`, no CR/LF, <=256 chars)',
      })
    }
    this.callbackPath = opts.callbackPath ?? DEFAULT_MAGIC_LINK_CONFIG.callbackPath
    this.__noDeliver = !opts.deliver
  }

  /** Mints a single-use link and hands it to the host's `deliver`. */
  async begin(ctx: Provider.Context<Profile>, input: MagicLink.BeginInput): Promise<Provider.Intent[]> {
    const { email } = input
    // RFC 5321's 254-char cap, which bounds the limiter store and the lookups below.
    if (typeof email !== 'string' || email.length === 0 || email.length > 254) {
      // The shape of the address, not whether it belongs to anyone: an unknown address resolves, so a 401
      // here says the caller failed to authenticate when it only handed over something unusable.
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'magic-link: email must be a 1-254 char string' })
    }
    const send = this.opts.deliver
    if (!send) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'magic-link: no `deliver` configured' })
    }

    // Trimmed and lowercased, so the rate limit, the identity lookup and the stored credential metadata
    // share one key.
    const emailCanonical = canonicalEmail(email) ?? ''
    const limited = await ctx.limiter.consume(`${this.prefix}${emailCanonical}`)
    // No subject: `findIdentityByEmail` is host code on an unauthenticated endpoint, and a spent link
    // bucket stops a mail going out rather than locking anyone out. The call password-reset makes too.
    if (!limited.ok) await refuseRateLimited(ctx.events, limited, null)

    let identityId: string | null =
      (await orNull(this.opts.findIdentityByEmail(emailCanonical, ctx.tenant.tenantId)))?.id ?? null
    if (!identityId && this.opts.autoCreateIdentity) {
      const profile = this.opts.autoCreateProfile?.(emailCanonical)
      if (profile) {
        const created = await ctx.stores.identities.create({
          profile,
          providers: [],
          emailVerified: false,
        })
        identityId = created.id
      }
    }

    // SECURITY: both branches mint and hash a token, then make the same store call against the same
    // table in the same order, or response time answers what the response body refuses to. Returning
    // early for an unknown address made it the measurably faster one. `password-reset.flow` is the
    // sibling doing this, and the shape here follows it.
    const token = ctx.crypto.authRandomToken(32)
    const tokenHash = ctx.crypto.authSha256(token)
    const subjectId = identityId ?? NO_IDENTITY_SENTINEL
    // One live link per account, as a reset has one: an older mail stops working once a newer one is sent.
    await ctx.stores.credentials.deleteByKind(subjectId, 'magic-link', ctx.tenant)
    if (identityId) {
      await ctx.stores.credentials.create(
        toCredentialCreate({
          identityId,
          kind: 'magic-link',
          secret: tokenHash,
          metadata: { email: emailCanonical } satisfies MagicLink.CredentialMetadata,
          expiresAt: new Date(Date.now() + this.ttlMs),
        }),
        ctx.tenant,
      )
    } else {
      // A write cannot be mirrored: `auth_credentials.identity_id` is a foreign key, so there is no row
      // to hang a decoy on. Same table, same tenant scope, one round trip.
      await ctx.stores.credentials.listByIdentity(subjectId, 'magic-link', ctx.tenant)
    }

    const link = new URL(`${ctx.baseUrl}${this.callbackPath}`)
    link.searchParams.set('token', token)
    const identityRow = await orNull(ctx.stores.identities.find({ id: subjectId }))
    if (!identityId || !identityRow) {
      if (identityId) {
        // A race; acking silently avoids leaking whether the identity exists.
        await ctx.events.emit('signin.failed', {
          providerId: 'magic-link',
          reason: 'identity row missing after create; race window',
        })
      }
      return [{ type: 'json', status: 200, body: { ok: true } }]
    }
    // Dispatched without awaiting, so the response shape and latency match between the known- and
    // unknown-identity branches.
    void deliver(ctx.events, send, {
      kind: 'magic-link',
      identity: identityRow,
      tenant: ctx.tenant,
      vars: { ttlMin: Math.round(this.ttlMs / 60_000), url: link.href },
    })
    return [{ type: 'json', status: 200, body: { ok: true } }]
  }

  /** Spends the token and answers the intents that open the session. */
  async complete(ctx: Provider.Context<Profile>, input: MagicLink.CompleteInput): Promise<Provider.InternalIntent[]> {
    const { token } = input
    // Capped at 256 chars against a multi-MB sha256 DoS.
    if (typeof token !== 'string' || token.length === 0 || token.length > 256) {
      throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    }
    const hash = ctx.crypto.authSha256(token)
    const row = await orNull(ctx.stores.credentials.findByHashedSecret(hash, 'magic-link', ctx.tenant))
    // `!= null` reads the null-or-undefined live sentinel as valid and anything else, a Date or a stray
    // `revokedAt: 0`, as revoked; a falsy check would let the `0` through.
    if (!row || row.revokedAt != null) {
      throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    }
    if (isCredentialExpired(row)) {
      void ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
      throw new AuthError('AUTH_RECOVERY_TOKEN_EXPIRED')
    }
    // The link proves the address it was sent to, which proves nothing once the account has moved off it.
    // A deleted account is left to the guard in `flows.signIn`.
    const identity = await orNull(ctx.stores.identities.find({ id: row.identityId }))
    if (identity && canonicalEmail(identity.profile.email) !== row.metadata?.email) {
      throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    }
    await burnCredential(ctx, row)
    // Redeeming the link proves the address. Left unproven, a row whose only credentials are spent links
    // reads to `beginSignUp` as an abandoned sign-up, which anyone may reclaim. And until now anyone could
    // have held the row: their sessions go, then whatever they linked or enrolled, and only then is the address
    // marked proven, so a sweep stopped part-way runs again on the next link.
    const unproven = identity !== null && !identity.emailVerified
    if (unproven) {
      const squatted = await ctx.stores.sessions.listByIdentity(identity.id, ALL_TENANTS)
      await ctx.stores.sessions.deleteAllForIdentity(identity.id, ALL_TENANTS)
      for (const s of squatted) await ctx.events.emit('session.revoked', { sessionId: s.id, identityId: identity.id })
      await evictUnproven(ctx.stores, identity.id, row.id)
      const swept = await ctx.stores.identities.find({ id: identity.id })
      await ctx.stores.identities.update(identity.id, { emailVerified: true }, swept.version)
    }
    // Spent, and live until the row is marked: it is what keeps `beginSignUp` from reading the swept row as abandoned.
    await orNull(ctx.stores.credentials.revoke(row.id, ctx.tenant))
    return [
      {
        type: 'startSession',
        identityId: row.identityId,
        factors: [{ method: 'magic-link', completedAt: new Date() }],
        aal: 1,
        endOtherSessions: unproven,
      },
    ]
  }
}

/** The magic-link provider, ready to hand to `providers`. */
export function magicLink<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  opts: MagicLink.Options<Profile>,
): Provider.Me<MagicLink.BeginInput, MagicLink.CompleteInput, Profile> {
  return new MagicLinkImpl(opts)
}

/** Constructs {@link MagicLinkImpl} directly, for a caller wiring the facet by hand. */
export function magicLinkImpl(...args: ConstructorParameters<typeof MagicLinkImpl>): MagicLinkImpl {
  return new MagicLinkImpl(...args)
}
