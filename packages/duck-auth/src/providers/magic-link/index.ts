import { AuthErrorObject } from '../../core/errors'
import type { Channel } from '../../core/types/channel'
import type { Provider } from '../../core/types/provider'

export interface MagicLinkProviderOptions<Profile = unknown> {
  /** Channel implementations keyed by their `kind`. */
  channels: { email?: Channel.IChannel; sms?: Channel.IChannel; webpush?: Channel.IChannel }
  /** Library uses this to find the identity given an email. */
  findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
  /**
   * Optional auto-create — if no identity matches the email, create one on
   * link request. Default false (caller wires its own signup flow).
   */
  autoCreateIdentity?: boolean
  /** Used as the `profile` payload when autoCreating; library supplies email automatically. */
  autoCreateProfile?: (email: string) => Profile
  /** TTL of magic-link token in ms. Default 10 minutes. */
  ttlMs?: number
  /** Per-email rate limit prefix. Default 'magic-link:request:'. */
  limiterKeyPrefix?: string
  /** Path the link lands on; sid appended as `?token=`. */
  callbackPath?: string
}

export interface MagicLinkBeginInput {
  email: string
  channel?: 'email' | 'sms' | 'webpush'
}

export interface MagicLinkCompleteInput {
  token: string
}

/**
 * Magic-link provider — passwordless. Two phases:
 *
 *   begin    {email} → rate-limit, find-or-(auto)create identity, mint a
 *                      single-use 32-byte token (hashed at rest), persist
 *                      as credential kind='magic-link' with expiresAt,
 *                      dispatch via the configured channel. Returns a
 *                      generic `{ok:true}` (no enumeration via response).
 *
 *   complete {token} → hash, findByHashedSecret('magic-link'), validate
 *                      expiry + non-revoked, REVOKE on use (single-use),
 *                      return startSession intent.
 */
export function magicLink<Profile = unknown>(
  opts: MagicLinkProviderOptions<Profile>,
): Provider.IProvider<MagicLinkBeginInput, MagicLinkCompleteInput, Profile> {
  const ttlMs = opts.ttlMs ?? 10 * 60 * 1000
  const prefix = opts.limiterKeyPrefix ?? 'magic-link:request:'
  const callbackPath = opts.callbackPath ?? '/auth/magic-link/callback'

  return {
    id: 'magic-link',
    kind: 'magic-link',
    async begin(ctx, input) {
      const { email } = input
      const channelKind = input.channel ?? 'email'
      if (typeof email !== 'string' || email.length === 0) {
        throw new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
      }
      const channel = opts.channels[channelKind]
      if (!channel) {
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
          detail: `magic-link: channel "${channelKind}" not configured`,
        })
      }

      const limited = await ctx.limiter.consume(`${prefix}${email.toLowerCase()}`)
      if (!limited.ok) {
        throw new AuthErrorObject('AUTH/RATE_LIMITED', {
          retryAfter: Math.max(0, Math.ceil((limited.resetAt - Date.now()) / 1000)),
        })
      }

      let identityId: string | null = (await opts.findIdentityByEmail(email, ctx.tenant.tenantId))?.id ?? null
      if (!identityId) {
        if (!opts.autoCreateIdentity) {
          // Enumeration-safe: respond as if we sent something.
          return [{ type: 'json', status: 200, body: { ok: true } }]
        }
        const profile = (opts.autoCreateProfile?.(email) ?? ({ email } as unknown as Profile)) as Profile
        const created = await ctx.stores.identities.create(
          { profile, providers: [{ providerId: 'magic-link', addedAt: Date.now() }] },
          ctx.tenant,
        )
        identityId = created.id
      }

      const token = ctx.crypto.randomToken(32)
      const tokenHash = ctx.crypto.sha256(token)
      const now = Date.now()
      await ctx.stores.credentials.upsert(
        {
          identityId,
          kind: 'magic-link',
          secret: tokenHash,
          metadata: { email, channel: channelKind },
          expiresAt: now + ttlMs,
        },
        ctx.tenant,
      )

      const url = `${ctx.baseUrl}${callbackPath}?token=${encodeURIComponent(token)}`
      const identityRow = await ctx.stores.identities.findById(identityId, ctx.tenant)
      if (!identityRow) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
      const result = await channel.send({
        identity: identityRow,
        templateId: 'magic-link',
        vars: { url, ttlMin: Math.round(ttlMs / 60_000) },
        tenant: ctx.tenant,
      })
      if (!result.ok) {
        throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
          providerId: 'magic-link',
          detail: result.error ?? 'channel send failed',
        })
      }
      return [{ type: 'json', status: 200, body: { ok: true } }]
    },

    async complete(ctx, input) {
      const { token } = input
      if (typeof token !== 'string' || token.length === 0) {
        throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
      }
      const hash = ctx.crypto.sha256(token)
      const row = await ctx.stores.credentials.findByHashedSecret(hash, 'magic-link', ctx.tenant)
      const now = Date.now()
      if (!row || row.revokedAt) {
        throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
      }
      if (row.expiresAt !== undefined && row.expiresAt < now) {
        // Best-effort cleanup, ignore failure.
        void ctx.stores.credentials.delete(row.id, ctx.tenant).catch(() => {})
        throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_EXPIRED')
      }
      // Single-use: revoke immediately. Even a same-tick replay sees revokedAt.
      await ctx.stores.credentials.revoke(row.id, ctx.tenant)
      return [
        {
          type: 'startSession',
          identityId: row.identityId,
          factors: [{ method: 'magic-link', completedAt: now }],
          aal: 1,
        },
      ]
    },
  }
}
