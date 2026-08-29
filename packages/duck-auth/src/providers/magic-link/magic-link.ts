import { isCredentialExpired, toCredentialUpsert } from '~/core/credentials/credentials'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import { isSafeCallbackPath } from '~/core/url-validators'
import { DEFAULT_MAGIC_LINK_CONFIG } from './magic-link.constants'
import type { MagicLink } from './magic-link.types'

/**
 * Magic-link provider - passwordless. Two phases:
 *
 *   begin    {email} -> rate-limit, find-or-(auto)create identity, mint
 *                      a single-use 32-byte token (hashed at rest),
 *                      persist + dispatch via configured channel.
 *
 *   complete {token} -> hash, findByHashedSecret('magic-link'),
 *                      validate expiry + non-revoked, REVOKE on use,
 *                      return startSession intent.
 */
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
    // Refuse a misconfigured callbackPath at construction so a typo like
    // `//evil.com` cannot turn the magic-link URL into a cross-origin redirect
    // that exfiltrates the token (browser resolves `https://app//evil.com?...`
    // as `https://evil.com?...`).
    if (opts.callbackPath !== undefined && !isSafeCallbackPath(opts.callbackPath)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'magic-link.callbackPath must be a same-origin path (starts with `/`, no `//`, no CR/LF, <=256 chars)',
      })
    }
    this.callbackPath = opts.callbackPath ?? DEFAULT_MAGIC_LINK_CONFIG.callbackPath
  }

  async begin(ctx: Provider.Context<Profile>, input: MagicLink.BeginInput): Promise<Provider.Intent[]> {
    const { email } = input
    const requestedChannel = input.channel ?? 'email'
    // Whitelist the channel kind so a hostile caller can't echo arbitrary
    // strings back through AUTH/MISCONFIGURED detail.
    const channelKind: 'email' | 'sms' | 'webpush' =
      requestedChannel === 'email' || requestedChannel === 'sms' || requestedChannel === 'webpush'
        ? requestedChannel
        : 'email'
    // RFC 5321 254-char cap; protects limiter store + downstream lookups.
    if (typeof email !== 'string' || email.length === 0 || email.length > 254) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
    const channel = this.opts.channels[channelKind]
    if (!channel) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `magic-link: channel "${channelKind}" not configured`,
      })
    }

    // Canonical (trim + lowercase) so rate-limit + identity lookup +
    // stored credential metadata all share one key.
    const emailCanonical = email.trim().toLowerCase()
    const limited = await ctx.limiter.consume(`${this.prefix}${emailCanonical}`)
    if (!limited.ok) {
      throw new AuthError('AUTH_RATE_LIMITED', {
        retryAfter: Math.max(0, Math.ceil((limited.resetAt.getTime() - Date.now()) / 1000)),
      })
    }

    let identityId: string | null =
      (await this.opts.findIdentityByEmail(emailCanonical, ctx.tenant.tenantId))?.id ?? null
    if (!identityId) {
      if (!this.opts.autoCreateIdentity) {
        return [{ type: 'json', status: 200, body: { ok: true } }]
      }
      const profile = this.opts.autoCreateProfile?.(emailCanonical)
      if (!profile) {
        return [{ type: 'json', status: 200, body: { ok: true } }]
      }
      const created = await ctx.stores.identities.create({
        profile,
        providers: [{ providerId: 'magic-link', providerSub: null, addedAt: new Date() }],
        emailVerified: false,
      })
      identityId = created.id
    }

    const token = ctx.crypto.authRandomToken(32)
    const tokenHash = ctx.crypto.authSha256(token)
    await ctx.stores.credentials.upsert(
      toCredentialUpsert({
        identityId,
        kind: 'magic-link',
        secret: tokenHash,
        metadata: { email: emailCanonical, channel: channelKind } satisfies MagicLink.CredentialMetadata,
        expiresAt: new Date(Date.now() + this.ttlMs),
      }),
      ctx.tenant,
    )

    const url = `${ctx.baseUrl}${this.callbackPath}?token=${encodeURIComponent(token)}`
    const identityRow = await ctx.stores.identities.findById(identityId)
    // Fire-and-forget the channel dispatch so the wire response shape
    // and latency match between existing- and unknown-identity branches.
    if (!identityRow) {
      // Race; silent ack avoids existence-state leak.
      await ctx.events.emit('signin.failed', {
        providerId: 'magic-link',
        reason: 'identity row missing after upsert; race window',
      })
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
          // Do not forward channel error metadata; it can carry the
          // rendered message body (and therefore the token URL).
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

  async complete(ctx: Provider.Context<Profile>, input: MagicLink.CompleteInput): Promise<Provider.InternalIntent[]> {
    const { token } = input
    // 256-char cap to refuse multi-MB sha256 DoS.
    if (typeof token !== 'string' || token.length === 0 || token.length > 256) {
      throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    }
    const hash = ctx.crypto.authSha256(token)
    const row = await ctx.stores.credentials.findByHashedSecret(hash, 'magic-link', ctx.tenant)
    // `!= null` treats the null/undefined live sentinel as valid and anything
    // else (a Date, or a stray `revokedAt: 0`) as revoked — a falsy check would leak `0`.
    if (!row || row.revokedAt != null) {
      throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    }
    if (isCredentialExpired(row)) {
      void ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
      throw new AuthError('AUTH_RECOVERY_TOKEN_EXPIRED')
    }
    // CAS-claim the row so concurrent requests with the same token
    // produce one session; loser sees AUTH/RECOVERY_TOKEN_INVALID.
    try {
      await ctx.stores.credentials.rotate(row.id, row.secret, row.version, ctx.tenant)
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

/** Factory around {@link MagicLinkImpl} for functional-style config. */
export function magicLink<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  opts: MagicLink.Options<Profile>,
): Provider.Me<MagicLink.BeginInput, MagicLink.CompleteInput, Profile> {
  return new MagicLinkImpl(opts)
}

/** Factory around {@link MagicLinkImpl}, for callers who prefer functions to `new`. */
export function magicLinkImpl(...args: ConstructorParameters<typeof MagicLinkImpl>): MagicLinkImpl {
  return new MagicLinkImpl(...args)
}
