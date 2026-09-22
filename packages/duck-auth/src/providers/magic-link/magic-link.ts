import { orNull } from '~/core/answer'
import { isCredentialExpired, toCredentialCreate } from '~/core/credentials/credentials'
import { AuthError } from '~/core/errors'
import { refuseRateLimited } from '~/core/events/events.lockout'
import { canonicalEmail, type Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import { isSafeCallbackPath } from '~/core/url-validators'
import { NO_IDENTITY_SENTINEL } from '~/providers/passwords/passwords.constants'
import { DEFAULT_MAGIC_LINK_CONFIG } from './magic-link.constants'
import type { MagicLink } from './magic-link.types'

/** Passwordless, in two phases: */
export class MagicLinkImpl<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>
  implements Provider.Me<MagicLink.BeginInput, MagicLink.CompleteInput, Profile>
{
  readonly id = 'magic-link'
  readonly kind = 'magic-link' as const
  private readonly ttlMs: number
  private readonly prefix: string
  private readonly callbackPath: string

  constructor(private readonly opts: MagicLink.Options<Profile>) {
    this.ttlMs = opts.ttlMs ?? DEFAULT_MAGIC_LINK_CONFIG.ttlMs
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
  }

  /** Mints a single-use link and sends it over the requested channel. */
  async begin(ctx: Provider.Context<Profile>, input: MagicLink.BeginInput): Promise<Provider.Intent[]> {
    const { email } = input
    const requestedChannel = input.channel ?? 'email'
    // An allowlist, so a hostile caller cannot echo arbitrary strings back through the
    // AUTH_MISCONFIGURED detail.
    const channelKind: 'email' | 'sms' | 'webpush' =
      requestedChannel === 'email' || requestedChannel === 'sms' || requestedChannel === 'webpush'
        ? requestedChannel
        : 'email'
    // RFC 5321's 254-char cap, which bounds the limiter store and the lookups below.
    if (typeof email !== 'string' || email.length === 0 || email.length > 254) {
      // The shape of the address, not whether it belongs to anyone: an unknown address resolves, so a 401
      // here says the caller failed to authenticate when it only handed over something unusable.
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'magic-link: email must be a 1-254 char string' })
    }
    const channel = this.opts.channels[channelKind]
    if (!channel) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `magic-link: channel "${channelKind}" not configured`,
      })
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
    if (identityId) {
      await ctx.stores.credentials.create(
        toCredentialCreate({
          identityId,
          kind: 'magic-link',
          secret: tokenHash,
          metadata: { email: emailCanonical, channel: channelKind } satisfies MagicLink.CredentialMetadata,
          expiresAt: new Date(Date.now() + this.ttlMs),
        }),
        ctx.tenant,
      )
    } else {
      // A write cannot be mirrored: `auth_credentials.identity_id` is a foreign key, so there is no row
      // to hang a decoy on. Same table, same tenant scope, one round trip.
      await ctx.stores.credentials.listByIdentity(subjectId, 'magic-link', ctx.tenant)
    }

    const url = `${ctx.baseUrl}${this.callbackPath}?token=${encodeURIComponent(token)}`
    const identityRow = await orNull(ctx.stores.identities.find({ id: subjectId }))
    // Dispatched without awaiting, so the response shape and latency match between the known- and
    // unknown-identity branches.
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
    void channel
      .send({
        identity: identityRow,
        templateId: 'magic-link',
        vars: { url, ttlMin: Math.round(this.ttlMs / 60_000) },
        tenant: ctx.tenant,
      })
      .then(async (result) => {
        if (!result.ok) {
          // The channel's error metadata is not forwarded: it can carry the rendered body, and with it the
          // token URL.
          await ctx.events.emit('signin.failed', {
            providerId: 'magic-link',
            reason: 'channel.send rejected delivery',
          })
        }
      })
      .catch(async (err) => {
        await ctx.events.emit('signin.failed', {
          providerId: 'magic-link',
          reason: `channel.send threw: ${err instanceof Error ? err.message : String(err)}`,
        })
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
    // A CAS claim that also burns the token, so concurrent requests carrying one token produce one
    // session and the losers see AUTH_RECOVERY_TOKEN_INVALID. Rotating to `row.secret` would claim the
    // version while leaving the row findable by `hash` and unrevoked until the revoke below, which is a
    // window a second redemption reads in and wins its own CAS.
    const burnt = ctx.crypto.authSha256(ctx.crypto.authRandomToken(32))
    try {
      await ctx.stores.credentials.rotate(row.id, burnt, row.version, ctx.tenant)
    } catch (err) {
      if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') {
        throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
      }
      throw err
    }
    await ctx.stores.credentials.revoke(row.id, ctx.tenant)
    return [
      {
        type: 'startSession',
        identityId: row.identityId,
        factors: [{ method: 'magic-link', completedAt: new Date() }],
        aal: 1,
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
