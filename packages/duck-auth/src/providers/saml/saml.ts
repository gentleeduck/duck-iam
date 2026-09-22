/**
 * A wrapper over `@node-saml/node-saml`, a lazy peerDep, covering SP-initiated sign-in over the
 * HTTP-POST binding and IdP-initiated SSO through an unsolicited SAMLResponse.
 */

import { AuthError } from '~/core/errors'
import { refuseRateLimited } from '~/core/events'
import type { Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import {
  DEFAULT_SAML_CONFIG,
  SAML_ASSERTION_ID_MAX,
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

/** The standard `Provider.Me` shape, so it slots into `AuthEngine.providers` beside the password and
 *  oauth providers. */
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
    const clientCallback = clientOption(cfg.client, 'callbackUrl')
    if (clientCallback !== undefined && clientCallback !== cfg.callbackUrl) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `samlProvider callbackUrl does not match the client's (${cfg.callbackUrl} vs ${String(clientCallback)})`,
      })
    }
    // SECURITY: the client is the only thing here that checks a signature, and nothing else in this
    // wrapper can tell a forged assertion from a real one. Signing the assertion or the response is
    // enough - most IdPs send assertion-only - but a client told to want neither accepts any XML that
    // parses, from anyone who can reach the ACS URL.
    if (
      clientOption(cfg.client, 'wantAssertionsSigned') === false &&
      clientOption(cfg.client, 'wantAuthnResponseSigned') === false
    ) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail:
          'samlProvider was given a client set to verify no signature at all (wantAssertionsSigned and wantAuthnResponseSigned are both false); at least one must stay on',
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

  /** Builds the redirect that carries an AuthnRequest to the IdP. */
  async begin(ctx: Provider.Context<Profile>, input: Saml.BeginInput): Promise<Provider.Intent[]> {
    await this._spend(ctx, 'begin')
    // Capped before they flow into an IdP URL or header. They come off the request, so a missing one is
    // the caller's mistake and a 400, not a boot-time wiring error.
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

  /** Validates the SAMLResponse against the request it answers, and opens the session. */
  async complete(ctx: Provider.Context<Profile>, input: Saml.CompleteInput): Promise<Provider.InternalIntent[]> {
    await this._spend(ctx, 'complete')
    await this._assertBoundToARequest(ctx, input)

    // Capped before `validatePostResponseAsync` sees it, so adversarial multi-MB XML never reaches the
    // parser. A real response is 5-30 KiB and 1 MiB is generous.
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
    if (this.cfg.replayStore) {
      // SECURITY: refused rather than skipped. An assertion with no usable id cannot be replay-checked,
      // and passing it through leaves an operator who wired a replay store with none for exactly the
      // bodies an attacker shapes.
      const assertionId = typeof profile.ID === 'string' ? profile.ID.trim() : ''
      if (assertionId.length === 0 || assertionId.length > SAML_ASSERTION_ID_MAX) {
        throw await this._refusal(ctx, 'assertion carried no usable ID and a replay store is configured')
      }
      if (!(await this.cfg.replayStore.consume(assertionId))) {
        throw await this._refusal(ctx, `assertion ${assertionId} has already been consumed`)
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
        // The level the IdP earned, not a literal: a flat 2 lets a password-only IdP mint a session
        // that satisfies every step-up requirement in this library.
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
    // The nameID keys just-in-time provisioning. Trimmed, because a length test alone made a space a
    // name, which is the collapse onto one row the check exists to prevent.
    const nameID = typeof profile.nameID === 'string' ? profile.nameID.trim() : ''
    if (nameID.length === 0 || nameID.length > SAML_NAME_ID_MAX) {
      throw await this._refusal(ctx, 'saml profile missing/invalid nameID')
    }
    // A transient nameID changes on every login, so provisioning keyed on it mints a new account each
    // time. The SP's metadata says which format it asks for; this is where that is enforced.
    if (profile.nameIDFormat !== undefined && !this._allowedNameIdFormats.includes(profile.nameIDFormat)) {
      throw await this._refusal(ctx, `nameID format ${profile.nameIDFormat} is not one this SP accepts`)
    }
    // Provisioning that looks the account up by email keys on a field no guard covered, so two
    // nameIDs asserting one address resolved to one account.
    // Against the format this assertion arrived with, where it states one. Keyed on the allow-list alone,
    // an SP that accepts `persistent` beside `emailAddress` refused every persistent login, since an
    // opaque nameID never equals an email - the same assertion passed or failed on a setting it knows
    // nothing about. An unstated format still falls back to the allow-list, which fails closed.
    const emailNameId =
      profile.nameIDFormat !== undefined
        ? profile.nameIDFormat === DEFAULT_SAML_CONFIG.nameIdFormat
        : this._allowedNameIdFormats.includes(DEFAULT_SAML_CONFIG.nameIdFormat)
    if (profile.email !== undefined && emailNameId && profile.email.trim().toLowerCase() !== nameID.toLowerCase()) {
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
   * Emits the real reason to the operator audit and answers the caller one string. Three distinct details
   * told an attacker which part of a forged assertion the verifier objected to, even carrying no XML.
   */
  private async _refusal(ctx: Provider.Context<Profile>, reason: string): Promise<AuthError> {
    await ctx.events.emit('signin.failed', { providerId: this.id, reason })
    return new AuthError('AUTH_PROVIDER_FAILED', { detail: SAML_REFUSED, providerId: this.id })
  }
}

/** node-saml keeps its resolved config on `.options`; a client that exposes none reads as `undefined`
 *  throughout and is left to its own defaults. */
function clientOption(client: Saml.Client, key: string): unknown {
  const opts = Reflect.get(client, 'options')
  return typeof opts === 'object' && opts !== null ? Reflect.get(opts, key) : undefined
}

/** The SAML provider, ready to hand to `providers`. */
export function saml<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  opts: Saml.Options<Profile>,
): Provider.Me<Saml.BeginInput, Saml.CompleteInput, Profile> {
  return new SamlImpl(opts)
}

/** Constructs {@link SamlImpl} directly, for a caller wiring the facet by hand. */
export function samlImpl(...args: ConstructorParameters<typeof SamlImpl>): SamlImpl {
  return new SamlImpl(...args)
}
