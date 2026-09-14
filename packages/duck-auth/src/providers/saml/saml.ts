/**
 * Wrapper over `@node-saml/node-saml` (lazy peerDep). Covers:
 *   - SP-initiated sign-in (HTTP-POST binding)
 *   - IdP-initiated SSO (unsolicited SAMLResponse)
 *
 * SP metadata XML generation lives in `saml.metadata.ts`; Single Logout in
 * `saml.slo.ts`. Out of scope: artifact binding. Use node-saml directly if you
 * need a federal/military-grade artifact resolution profile.
 */

import { AuthError } from '~/core/errors'
import { refuseRateLimited } from '~/core/events'
import type { Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import {
  DEFAULT_SAML_CONFIG,
  SAML_HOST_MAX,
  SAML_LIMITER_PREFIX,
  SAML_MFA_AUTHN_CONTEXTS,
  SAML_NAME_ID_MAX,
  SAML_REFUSED,
  SAML_RELAY_STATE_MAX,
  SAML_RESPONSE_MAX,
} from './saml.constants'
import type { Saml } from './saml.types'

const BYTES = new TextEncoder()

/**
 * SAML provider. Standard `Provider.Me` shape so it slots into
 * AuthEngine.providers alongside the password / oauth providers.
 */
export class SamlImpl<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>
  implements Provider.Me<Saml.BeginInput, Saml.CompleteInput, Profile>
{
  readonly id: string
  private readonly _allowedNameIdFormats: readonly string[]
  private readonly _mfaAuthnContexts: ReadonlySet<string>
  readonly kind = 'oauth' as const

  constructor(private readonly cfg: Saml.Options<Profile>) {
    if (!cfg.client) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'samlProvider requires a pre-built `client` (@node-saml/node-saml SAML instance)',
      })
    }
    if (!cfg.callbackUrl) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'samlProvider requires `callbackUrl` (matches IdP AssertionConsumerService URL)',
      })
    }
    // The client is what validates `Destination` and `Recipient` against its own callback, so the
    // two disagreeing meant a response minted for a different ACS was accepted here.
    const clientCallback = (cfg.client as { options?: { callbackUrl?: string } }).options?.callbackUrl
    if (clientCallback !== undefined && clientCallback !== cfg.callbackUrl) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `samlProvider callbackUrl does not match the client's (${cfg.callbackUrl} vs ${clientCallback})`,
      })
    }
    if (!cfg.onSignIn) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'samlProvider requires `onSignIn` (just-in-time identity provisioning hook)',
      })
    }
    // Silence is not an option here: without either, every response is accepted on its own merits
    // and a relay state the IdP echoed back is never compared against the one `begin` issued.
    if (!cfg.verifyRelayState && cfg.allowUnsolicited !== true) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail:
          'samlProvider requires `verifyRelayState`, or `allowUnsolicited: true` to accept IdP-initiated responses with no request to bind to',
      })
    }
    this.id = cfg.providerId ?? DEFAULT_SAML_CONFIG.providerId
    this._allowedNameIdFormats = cfg.allowedNameIdFormats ?? [DEFAULT_SAML_CONFIG.nameIdFormat]
    this._mfaAuthnContexts = new Set(cfg.mfaAuthnContexts ?? SAML_MFA_AUTHN_CONTEXTS)
  }

  async begin(ctx: Provider.Context<Profile>, input: Saml.BeginInput): Promise<Provider.Intent[]> {
    await this._spend(ctx, 'begin')
    // Cap caller-supplied strings before they flow into IdP URL/headers. These come off the request,
    // so a missing one is the caller's mistake and a four hundred, not a boot-time wiring error.
    if (
      typeof input.relayState !== 'string' ||
      input.relayState.length === 0 ||
      input.relayState.length > SAML_RELAY_STATE_MAX ||
      input.relayState.includes('\r') ||
      input.relayState.includes('\n')
    ) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', {
        detail: 'saml.begin requires relayState (1-256 chars, no CR/LF)',
      })
    }
    if (
      typeof input.host !== 'string' ||
      input.host.length === 0 ||
      input.host.length > SAML_HOST_MAX ||
      input.host.includes('\r') ||
      input.host.includes('\n')
    ) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', {
        detail: 'saml.begin requires host (1-253 chars, no CR/LF)',
      })
    }
    const url = await this.cfg.client.getAuthorizeUrlAsync(input.relayState, input.host, {})
    return [{ status: 302, type: 'redirect', url }]
  }

  async complete(ctx: Provider.Context<Profile>, input: Saml.CompleteInput): Promise<Provider.InternalIntent[]> {
    await this._spend(ctx, 'complete')
    await this._assertBoundToARequest(ctx, input)

    // Cap the SAMLResponse BEFORE handing it to `validatePostResponseAsync` so adversarial multi-MB
    // XML cannot reach the parser. Real responses are 5-30 KiB; 1 MiB is generous. Measured in
    // utf-8 bytes, which is what the parser sees: counting utf-16 code units let a body just under
    // the cap be two megabytes on the wire.
    if (
      typeof input.SAMLResponse !== 'string' ||
      input.SAMLResponse.length === 0 ||
      BYTES.encode(input.SAMLResponse).length > SAML_RESPONSE_MAX
    ) {
      throw await this._refusal(ctx, 'SAMLResponse missing or past the size cap')
    }

    let validated: { profile: Saml.Profile | null; loggedOut: boolean }
    try {
      validated = await this.cfg.client.validatePostResponseAsync({ SAMLResponse: input.SAMLResponse })
    } catch (err) {
      throw await this._refusal(ctx, err instanceof Error ? err.message : String(err))
    }
    if (validated.loggedOut || !validated.profile) {
      throw await this._refusal(ctx, 'IdP returned a logout response, not a sign-in')
    }
    const profile = validated.profile
    await this._assertUsableProfile(ctx, profile)

    // Consumed after the signature is verified, so an unsigned body cannot burn a real assertion id.
    if (this.cfg.replayStore && profile.ID !== undefined) {
      if (!(await this.cfg.replayStore.consume(profile.ID))) {
        throw await this._refusal(ctx, `assertion ${profile.ID} has already been consumed`)
      }
    }

    const scoped = this._withAllowedAttributes(profile)
    try {
      this.cfg.profileToIdentityProfile?.(scoped)
    } catch (err) {
      throw await this._refusal(ctx, `profileToIdentityProfile rejected the profile: ${String(err)}`)
    }

    let identityId: string
    try {
      // Consumer code, called after every other guard has passed. Unwrapped, a store outage
      // surfaced as whatever the consumer threw rather than as something an adapter can render.
      ;({ identityId } = await this.cfg.onSignIn({
        profile: scoped,
        ...(ctx.tenant.tenantId !== undefined && { tenantId: ctx.tenant.tenantId }),
      }))
    } catch (err) {
      await ctx.events.emit('signin.failed', {
        providerId: this.id,
        reason: `onSignIn threw: ${err instanceof Error ? err.message : String(err)}`,
      })
      throw new AuthError('AUTH_PROVIDER_FAILED', { detail: SAML_REFUSED, providerId: this.id })
    }

    return [
      {
        // The level the IdP earned, not a literal: a password-only IdP used to mint a session that
        // satisfied every step-up requirement in this library.
        aal: this._mfaAuthnContexts.has(profile.authnContext ?? '') ? 2 : 1,
        factors: [{ completedAt: new Date(), method: 'saml' }],
        identityId,
        type: 'startSession',
      },
    ]
  }

  /** One budget per tenant by default: coarse, but an unauthenticated signature verifier had none. */
  private async _spend(ctx: Provider.Context<Profile>, phase: 'begin' | 'complete'): Promise<void> {
    const key =
      this.cfg.limiterKey?.({ ...(ctx.tenant.tenantId !== undefined && { tenantId: ctx.tenant.tenantId }) }, phase) ??
      `${SAML_LIMITER_PREFIX}${this.id}:${phase}:${ctx.tenant.tenantId ?? '-'}`
    const limited = await ctx.limiter.consume(key)
    if (!limited.ok) await refuseRateLimited(ctx.events, limited, null)
  }

  private async _assertBoundToARequest(ctx: Provider.Context<Profile>, input: Saml.CompleteInput): Promise<void> {
    if (input.relayState === undefined) {
      if (this.cfg.allowUnsolicited !== true) {
        throw await this._refusal(ctx, 'response carried no relayState and unsolicited responses are not accepted')
      }
      return
    }
    if (!this.cfg.verifyRelayState) return
    const bound = await this.cfg.verifyRelayState({
      relayState: input.relayState,
      ...(ctx.tenant.tenantId !== undefined && { tenantId: ctx.tenant.tenantId }),
    })
    if (!bound) throw await this._refusal(ctx, 'relayState did not match a request this tenant issued')
  }

  private async _assertUsableProfile(ctx: Provider.Context<Profile>, profile: Saml.Profile): Promise<void> {
    // The nameID keys just-in-time provisioning. Trimmed, because a length test made a space a name,
    // which is the collapse onto one row the check exists to prevent.
    const nameID = typeof profile.nameID === 'string' ? profile.nameID.trim() : ''
    if (nameID.length === 0 || nameID.length > SAML_NAME_ID_MAX) {
      throw await this._refusal(ctx, 'saml profile missing/invalid nameID')
    }
    // A transient nameID changes on every login, so provisioning keyed on it mints a new account
    // each time. The SP's metadata says which format it asks for; this is where that is enforced.
    if (profile.nameIDFormat !== undefined && !this._allowedNameIdFormats.includes(profile.nameIDFormat)) {
      throw await this._refusal(ctx, `nameID format ${profile.nameIDFormat} is not one this SP accepts`)
    }
    // Provisioning that looks the account up by email keys on a field no guard covered, so two
    // nameIDs asserting one address resolved to one account.
    if (
      profile.email !== undefined &&
      this._allowedNameIdFormats.includes(DEFAULT_SAML_CONFIG.nameIdFormat) &&
      profile.email.trim().toLowerCase() !== nameID.toLowerCase()
    ) {
      throw await this._refusal(ctx, 'asserted email does not match the nameID it arrived with')
    }
  }

  private _withAllowedAttributes(profile: Saml.Profile): Saml.Profile {
    const allowed = this.cfg.allowedAttributes
    if (!allowed || profile.attributes === undefined) return profile
    const attributes: Record<string, string | string[]> = {}
    for (const name of allowed) {
      const value = profile.attributes[name]
      if (value !== undefined) attributes[name] = value
    }
    return { ...profile, attributes }
  }

  /**
   * Emit the real reason to operator audit; answer the caller with one string. Three distinct
   * details told an attacker which part of a forged assertion the verifier objected to, even
   * though none of them carried the XML.
   *
   * Returns rather than throws so a call site reads `throw await`, which narrows what follows it.
   */
  private async _refusal(ctx: Provider.Context<Profile>, reason: string): Promise<AuthError> {
    await ctx.events.emit('signin.failed', { providerId: this.id, reason })
    return new AuthError('AUTH_PROVIDER_FAILED', { detail: SAML_REFUSED, providerId: this.id })
  }
}

/** Factory around {@link SamlImpl} for functional-style config. */
export function saml<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  opts: Saml.Options<Profile>,
): Provider.Me<Saml.BeginInput, Saml.CompleteInput, Profile> {
  return new SamlImpl(opts)
}

/** Factory around {@link SamlImpl}, for callers who prefer functions to `new`. */
export function samlImpl(...args: ConstructorParameters<typeof SamlImpl>): SamlImpl {
  return new SamlImpl(...args)
}
