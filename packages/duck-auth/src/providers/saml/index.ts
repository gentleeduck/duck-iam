/**
 * SAML 2.0 Service Provider. Wraps `@node-saml/node-saml` (lazy
 * peerDep) for the SP-initiated browser SSO profile: begin -> redirect
 * to IdP SSO endpoint with SAMLRequest, complete -> validate the
 * SAMLResponse POSTed to the AssertionConsumerService, extract the
 * subject + attributes, emit a startSession intent.
 *
 * Why lazy peerDep: SAML XML parsing + signature verification is
 * heavyweight (~2 MB after node_modules); apps that do not offer
 * enterprise SSO should not pay for it.
 */

import { AuthErrorObject } from '../../core/errors'
import type { Provider } from '../../core/types/provider'

// 1 MiB cap on SAML response; larger XML inputs are adversarial.
const SAML_RESPONSE_MAX = 1_048_576
// SAML 2.0 binding spec caps RelayState at 80 bytes; 256 is generous
// to accommodate apps that pack a serialized state object.
const SAML_RELAY_STATE_MAX = 256
// DNS hostname max is 253 chars (RFC 1035).
const SAML_HOST_MAX = 253

/**
 * Public surface of the SAML provider. Every type lives inside the
 * namespace so consumers reach for `SamlProvider.IOptions` /
 * `SamlProvider.IProfile` rather than a flat name.
 */
export namespace SamlProvider {
  /**
   * Subset of `@node-saml/node-saml` we depend on. Both v4 + v5 satisfy
   * this shape; consumers without the peerDep get AUTH/MISCONFIGURED
   * on first call.
   */
  export interface IClient {
    getAuthorizeUrlAsync(relayState: string, host: string, opts: Record<string, unknown>): Promise<string>
    validatePostResponseAsync(body: { SAMLResponse: string }): Promise<{
      profile: IProfile | null
      loggedOut: boolean
    }>
  }

  /**
   * Subset of node-saml's profile we extract. Library projects 30+
   * attributes onto the OAuth-style `{ sub, email?, name? }` shape the
   * rest of the auth lib expects.
   */
  export interface IProfile {
    nameID: string
    nameIDFormat?: string
    email?: string
    attributes?: Record<string, string | string[]>
  }

  /** Config knobs for {@link samlProvider}. */
  export interface IOptions<Profile = unknown> {
    /**
     * Provider id reported back to consumers (e.g. `'okta'`,
     * `'azure-saml'`). Default `'saml'`.
     */
    providerId?: string
    /**
     * Pre-built `IClient` (the `@node-saml/node-saml` SAML class
     * instance). Required - SAML configuration is too varied to
     * express declaratively without depending on the library types.
     */
    client: IClient
    /**
     * Callback URL the IdP POSTs the SAMLResponse to. Must exactly
     * match the AssertionConsumerService URL registered with the IdP.
     */
    callbackUrl: string
    /** Translate the SAML profile into the app's `Profile` shape. */
    profileToIdentityProfile?: (profile: IProfile) => Profile
    /**
     * onSignIn hook fires after a successful SAMLResponse. Use to
     * just-in-time provision identities (lookup by `nameID` or
     * `email`, create if missing, return identityId).
     */
    onSignIn: (input: { profile: IProfile; tenantId?: string }) => Promise<{ identityId: string }>
  }

  /** Input to {@link samlProvider}.begin. */
  export interface IBeginInput {
    /** Caller-supplied relay state (CSRF guard); echoed back by IdP. */
    relayState: string
    /** Host the IdP redirects to (your app's origin). */
    host: string
  }

  /** Input to {@link samlProvider}.complete. */
  export interface ICompleteInput {
    /** Raw SAMLResponse param from the IdP POST. */
    SAMLResponse: string
  }
}

/**
 * Build a SAML provider. Returns the standard `Provider.IProvider`
 * shape so it slots into AuthRoot.providers.register alongside the
 * password / OAuth providers.
 */
export function samlProvider<Profile = unknown>(
  opts: SamlProvider.IOptions<Profile>,
): Provider.IProvider<SamlProvider.IBeginInput, SamlProvider.ICompleteInput, Profile> {
  if (!opts.client) {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail: 'samlProvider requires a pre-built `client` (@node-saml/node-saml SAML instance)',
    })
  }
  if (!opts.callbackUrl) {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail: 'samlProvider requires `callbackUrl` (matches IdP AssertionConsumerService URL)',
    })
  }
  if (!opts.onSignIn) {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail: 'samlProvider requires `onSignIn` (just-in-time identity provisioning hook)',
    })
  }
  const providerId = opts.providerId ?? 'saml'
  return {
    id: providerId,
    kind: 'oauth',

    async begin(_ctx, input): Promise<Provider.Intent[]> {
      // Cap caller-supplied strings before they flow into IdP URL/headers.
      if (
        typeof input.relayState !== 'string' ||
        input.relayState.length === 0 ||
        input.relayState.length > SAML_RELAY_STATE_MAX ||
        input.relayState.includes('\r') ||
        input.relayState.includes('\n')
      ) {
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
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
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
          detail: 'saml.begin requires host (1-253 chars, no CR/LF)',
        })
      }
      const url = await opts.client.getAuthorizeUrlAsync(input.relayState, input.host, {})
      return [{ type: 'redirect', url, status: 302 }]
    },

    async complete(ctx, input): Promise<Provider.Intent[]> {
      // cap SAMLResponse BEFORE handing it to
      // `validatePostResponseAsync` so adversarial multi-MB XML cannot
      // reach the parser. Real responses are 5-30 KiB; 1 MiB is generous.
      if (
        typeof input.SAMLResponse !== 'string' ||
        input.SAMLResponse.length === 0 ||
        input.SAMLResponse.length > SAML_RESPONSE_MAX
      ) {
        // Generic detail: do NOT echo size / type - the attacker
        // already knows what they sent, the legit caller bumped the cap.
        throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
          providerId,
          detail: 'invalid SAMLResponse',
        })
      }
      let validated: { profile: SamlProvider.IProfile | null; loggedOut: boolean }
      try {
        validated = await opts.client.validatePostResponseAsync({
          SAMLResponse: input.SAMLResponse,
        })
      } catch (err) {
        // Emit the real reason to operator audit; respond with a
        // generic detail so XML snippets do not reach the wire.
        const reason = err instanceof Error ? err.message : String(err)
        await ctx.events.emit('signin.failed', { providerId, reason })
        throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
          providerId,
          detail: 'SAMLResponse validation failed',
        })
      }
      if (validated.loggedOut || !validated.profile) {
        throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
          providerId,
          detail: 'IdP returned a logout response, not a sign-in',
        })
      }
      // Reject blank/oversize nameID; it drives JIT identity provisioning and
      // an empty value would collapse distinct accounts onto one row, while
      // an oversize one would bloat downstream identity-store writes.
      if (
        typeof validated.profile.nameID !== 'string' ||
        validated.profile.nameID.length === 0 ||
        validated.profile.nameID.length > 512
      ) {
        await ctx.events.emit('signin.failed', { providerId, reason: 'saml profile missing/invalid nameID' })
        throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
          providerId,
          detail: 'invalid SAML profile',
        })
      }

      const { identityId } = await opts.onSignIn({
        profile: validated.profile,
        ...(ctx.tenant.tenantId !== undefined && { tenantId: ctx.tenant.tenantId }),
      })
      return [
        {
          type: 'startSession',
          identityId,
          factors: [{ method: 'oauth', completedAt: Date.now() }],
          aal: 2,
        },
      ]
    },
  }
}
