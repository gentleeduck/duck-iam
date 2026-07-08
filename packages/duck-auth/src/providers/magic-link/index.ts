import type { Identity } from '~/core'
import { isCredentialExpired, toCredentialUpsert } from '~/core/credential-utils'
import { AuthError } from '~/core/errors'
import type { Channel } from '~/core/types/infra'
import type { Provider } from '~/core/types/provider'
import { isSafeCallbackPath } from '~/core/url-validators'

export namespace AuthMagicLinkProvider {
  /** Config knobs for {@link authMagicLink}. */
  export interface IOptions<Profile = unknown> {
    /** Channel implementations keyed by their `kind`. */
    channels: { email?: Channel.Channel; sms?: Channel.Channel; webpush?: Channel.Channel }
    /** Library uses this to find the identity given an email. */
    findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
    /**
     * Optional auto-create - if no identity matches the email, create
     * one on link request. Default false.
     */
    autoCreateIdentity?: boolean
    /** Used as the `profile` payload when autoCreating. */
    autoCreateProfile?: (email: string) => Profile
    /** TTL of magic-link token in ms. Default 10 minutes. */
    ttlMs?: number
    /** Per-email rate limit prefix. Default 'magic-link:request:'. */
    limiterKeyPrefix?: string
    /** Path the link lands on; sid appended as `?token=`. */
    callbackPath?: string
  }

  /** Input to begin. */
  export interface IBeginInput {
    email: string
    channel?: 'email' | 'sms' | 'webpush'
  }

  /** Input to complete. */
  export interface ICompleteInput {
    token: string
  }

  /** Shape stored in `Credential.ICredential.metadata` for magic-link credentials. */
  export interface ICredentialMetadata {
    email: string
    channel: 'email' | 'sms' | 'webpush'
  }
}

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
export function authMagicLink<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  opts: AuthMagicLinkProvider.IOptions<Profile>,
): Provider.Me<AuthMagicLinkProvider.IBeginInput, AuthMagicLinkProvider.ICompleteInput, Profile> {
  const ttlMs = opts.ttlMs ?? 10 * 60 * 1000
  const prefix = opts.limiterKeyPrefix ?? 'magic-link:request:'
  // Refuse a misconfigured callbackPath at construction so a typo like
  // `//evil.com` cannot turn the magic-link URL into a cross-origin redirect
  // that exfiltrates the token (browser resolves `https://app//evil.com?...`
  // as `https://evil.com?...`).
  if (opts.callbackPath !== undefined && !isSafeCallbackPath(opts.callbackPath)) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'magic-link.callbackPath must be a same-origin path (starts with `/`, no `//`, no CR/LF, <=256 chars)',
    })
  }
  const callbackPath = opts.callbackPath ?? '/AUTH/magic-link/callback'

  return {
    id: 'magic-link',
    kind: 'magic-link',
    async begin(ctx, input) {
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
      const channel = opts.channels[channelKind]
      if (!channel) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `magic-link: channel "${channelKind}" not configured`,
        })
      }

      // Canonical (trim + lowercase) so rate-limit + identity lookup +
      // stored credential metadata all share one key.
      const emailCanonical = email.trim().toLowerCase()
      const limited = await ctx.limiter.consume(`${prefix}${emailCanonical}`)
      if (!limited.ok) {
        throw new AuthError('AUTH_RATE_LIMITED', {
          retryAfter: Math.max(0, Math.ceil((limited.resetAt.getTime() - Date.now()) / 1000)),
        })
      }

      let identityId: string | null = (await opts.findIdentityByEmail(emailCanonical, ctx.tenant.tenantId))?.id ?? null
      if (!identityId) {
        if (!opts.autoCreateIdentity) {
          return [{ type: 'json', status: 200, body: { ok: true } }]
        }
        const profile = opts.autoCreateProfile?.(emailCanonical)
        if (!profile) {
          return [{ type: 'json', status: 200, body: { ok: true } }]
        }
        const created = await ctx.stores.identities.create(
          {
            profile,
            providers: [{ providerId: 'magic-link', providerSub: null, addedAt: new Date() }],
            tenantId: null,
            emailVerified: false,
          },
          ctx.tenant,
        )
        identityId = created.id
      }

      const token = ctx.crypto.authRandomToken(32)
      const tokenHash = ctx.crypto.authSha256(token)
      await ctx.stores.credentials.upsert(
        toCredentialUpsert({
          identityId,
          kind: 'magic-link',
          secret: tokenHash,
          metadata: { email: emailCanonical, channel: channelKind } satisfies AuthMagicLinkProvider.ICredentialMetadata,
          expiresAt: new Date(Date.now() + ttlMs),
        }),
        ctx.tenant,
      )

      const url = `${ctx.baseUrl}${callbackPath}?token=${encodeURIComponent(token)}`
      const identityRow = await ctx.stores.identities.findById(identityId, ctx.tenant)
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
          vars: { url, ttlMin: Math.round(ttlMs / 60_000) },
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
    },

    async complete(ctx, input) {
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
    },
  }
}
